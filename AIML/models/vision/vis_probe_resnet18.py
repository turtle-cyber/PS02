"""
Vision Model for Phishing Detection - ResNet18 Fine-tuning

This script trains a ResNet18 model on webpage screenshots to classify phishing vs benign pages.
Supports both traditional fine-tuning and optional CLIP zero-shot fallback.
"""

import argparse
import json
from pathlib import Path
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from torchvision import models, transforms
from PIL import Image
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from tqdm import tqdm
import warnings
warnings.filterwarnings('ignore')


class ScreenshotDataset(Dataset):
    """Dataset for webpage screenshots with labels"""

    def __init__(self, image_dir: Path, labels_csv: Path, transform=None):
        """
        Args:
            image_dir: Directory containing screenshots (format: {url_id}.jpg)
            labels_csv: CSV with columns: url_id, label (benign/phishing)
            transform: Optional image transformations
        """
        import pandas as pd
        self.image_dir = image_dir
        self.transform = transform

        # Load labels
        df = pd.read_csv(labels_csv)
        self.label_map = {'benign': 0, 'phishing': 1}
        self.samples = []

        for _, row in df.iterrows():
            img_path = image_dir / f"{row['url_id']}.jpg"
            if img_path.exists():
                label = self.label_map.get(row['label'].lower())
                if label is not None:
                    self.samples.append((img_path, label))

        print(f"Loaded {len(self.samples)} valid samples from {image_dir}")

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        img_path, label = self.samples[idx]

        try:
            image = Image.open(img_path).convert('RGB')
        except Exception as e:
            # Return a black image if loading fails
            print(f"Warning: Failed to load {img_path}: {e}")
            image = Image.new('RGB', (224, 224), color='black')

        if self.transform:
            image = self.transform(image)

        return image, label


def get_transforms(augment=True):
    """Get image transformations for training/validation"""

    if augment:
        # Training transforms with augmentation
        train_transform = transforms.Compose([
            transforms.Resize((256, 256)),
            transforms.RandomCrop(224),
            transforms.RandomHorizontalFlip(p=0.3),
            transforms.ColorJitter(brightness=0.2, contrast=0.2),
            transforms.ToTensor(),
            transforms.Normalize(mean=[0.485, 0.456, 0.406],
                               std=[0.229, 0.224, 0.225])
        ])
    else:
        train_transform = transforms.Compose([
            transforms.Resize((224, 224)),
            transforms.ToTensor(),
            transforms.Normalize(mean=[0.485, 0.456, 0.406],
                               std=[0.229, 0.224, 0.225])
        ])

    # Validation/test transforms (no augmentation)
    val_transform = transforms.Compose([
        transforms.Resize((224, 224)),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406],
                           std=[0.229, 0.224, 0.225])
    ])

    return train_transform, val_transform


def build_model(num_classes=2, pretrained=True, freeze_backbone=False):
    """
    Build ResNet18 model for phishing detection

    Args:
        num_classes: Number of output classes (2 for binary)
        pretrained: Use ImageNet pretrained weights
        freeze_backbone: If True, only train final layer

    Returns:
        model: ResNet18 model
    """
    model = models.resnet18(pretrained=pretrained)

    # Optionally freeze backbone
    if freeze_backbone:
        for param in model.parameters():
            param.requires_grad = False

    # Replace final layer for binary classification
    num_features = model.fc.in_features
    model.fc = nn.Sequential(
        nn.Dropout(0.3),
        nn.Linear(num_features, num_classes)
    )

    return model


def train_epoch(model, dataloader, criterion, optimizer, device):
    """Train for one epoch"""
    model.train()
    running_loss = 0.0
    predictions = []
    targets = []

    for images, labels in tqdm(dataloader, desc="Training", leave=False):
        images = images.to(device)
        labels = labels.to(device)

        # Forward pass
        optimizer.zero_grad()
        outputs = model(images)
        loss = criterion(outputs, labels)

        # Backward pass
        loss.backward()
        optimizer.step()

        running_loss += loss.item() * images.size(0)

        # Store predictions
        _, preds = torch.max(outputs, 1)
        predictions.extend(preds.cpu().numpy())
        targets.extend(labels.cpu().numpy())

    epoch_loss = running_loss / len(dataloader.dataset)
    epoch_acc = accuracy_score(targets, predictions)

    return epoch_loss, epoch_acc


def validate(model, dataloader, criterion, device):
    """Validate model"""
    model.eval()
    running_loss = 0.0
    predictions = []
    probabilities = []
    targets = []

    with torch.no_grad():
        for images, labels in tqdm(dataloader, desc="Validation", leave=False):
            images = images.to(device)
            labels = labels.to(device)

            outputs = model(images)
            loss = criterion(outputs, labels)

            running_loss += loss.item() * images.size(0)

            # Get probabilities and predictions
            probs = torch.softmax(outputs, dim=1)
            _, preds = torch.max(outputs, 1)

            predictions.extend(preds.cpu().numpy())
            probabilities.extend(probs[:, 1].cpu().numpy())  # Phishing class probability
            targets.extend(labels.cpu().numpy())

    epoch_loss = running_loss / len(dataloader.dataset)

    # Calculate metrics
    metrics = {
        'loss': epoch_loss,
        'accuracy': accuracy_score(targets, predictions),
        'precision': precision_score(targets, predictions, zero_division=0),
        'recall': recall_score(targets, predictions, zero_division=0),
        'f1': f1_score(targets, predictions, zero_division=0),
        'auc_roc': roc_auc_score(targets, probabilities) if len(np.unique(targets)) > 1 else 0.0
    }

    return metrics, probabilities, targets


def main():
    parser = argparse.ArgumentParser(description="Train ResNet18 for phishing detection")

    # Data arguments
    parser.add_argument("--train_dir", type=Path, required=True,
                       help="Directory with training screenshots")
    parser.add_argument("--val_dir", type=Path, required=True,
                       help="Directory with validation screenshots")
    parser.add_argument("--train_labels", type=Path, required=True,
                       help="CSV with training labels")
    parser.add_argument("--val_labels", type=Path, required=True,
                       help="CSV with validation labels")

    # Model arguments
    parser.add_argument("--outdir", type=Path, required=True,
                       help="Output directory for model and metrics")
    parser.add_argument("--freeze_backbone", action="store_true",
                       help="Freeze ResNet backbone (only train final layer)")

    # Training arguments
    parser.add_argument("--epochs", type=int, default=20,
                       help="Number of training epochs")
    parser.add_argument("--batch_size", type=int, default=32,
                       help="Batch size")
    parser.add_argument("--lr", type=float, default=1e-4,
                       help="Learning rate")
    parser.add_argument("--weight_decay", type=float, default=1e-5,
                       help="Weight decay (L2 regularization)")
    parser.add_argument("--patience", type=int, default=5,
                       help="Early stopping patience")
    parser.add_argument("--augment", action="store_true",
                       help="Use data augmentation")

    args = parser.parse_args()

    # Create output directory
    args.outdir.mkdir(parents=True, exist_ok=True)

    # Device configuration
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    # Load datasets
    train_transform, val_transform = get_transforms(augment=args.augment)

    train_dataset = ScreenshotDataset(args.train_dir, args.train_labels, train_transform)
    val_dataset = ScreenshotDataset(args.val_dir, args.val_labels, val_transform)

    train_loader = DataLoader(train_dataset, batch_size=args.batch_size,
                             shuffle=True, num_workers=4, pin_memory=True)
    val_loader = DataLoader(val_dataset, batch_size=args.batch_size,
                           shuffle=False, num_workers=4, pin_memory=True)

    print(f"\nDataset sizes:")
    print(f"  Training: {len(train_dataset)} samples")
    print(f"  Validation: {len(val_dataset)} samples")

    # Build model
    model = build_model(num_classes=2, pretrained=True,
                       freeze_backbone=args.freeze_backbone)
    model = model.to(device)

    # Loss and optimizer
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=args.lr,
                          weight_decay=args.weight_decay)

    # Learning rate scheduler
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode='max', factor=0.5, patience=3, verbose=True
    )

    # Training loop
    best_f1 = 0.0
    patience_counter = 0
    history = {'train_loss': [], 'train_acc': [], 'val_metrics': []}

    print(f"\n{'='*60}")
    print(f"Starting training for {args.epochs} epochs...")
    print(f"{'='*60}\n")

    for epoch in range(args.epochs):
        print(f"Epoch {epoch+1}/{args.epochs}")
        print("-" * 40)

        # Train
        train_loss, train_acc = train_epoch(model, train_loader, criterion,
                                           optimizer, device)

        # Validate
        val_metrics, val_probs, val_targets = validate(model, val_loader,
                                                       criterion, device)

        # Update scheduler
        scheduler.step(val_metrics['f1'])

        # Store history
        history['train_loss'].append(train_loss)
        history['train_acc'].append(train_acc)
        history['val_metrics'].append(val_metrics)

        # Print metrics
        print(f"Train Loss: {train_loss:.4f} | Train Acc: {train_acc:.4f}")
        print(f"Val Loss: {val_metrics['loss']:.4f} | Val Acc: {val_metrics['accuracy']:.4f}")
        print(f"Val Precision: {val_metrics['precision']:.4f} | Val Recall: {val_metrics['recall']:.4f}")
        print(f"Val F1: {val_metrics['f1']:.4f} | Val AUC-ROC: {val_metrics['auc_roc']:.4f}")
        print()

        # Save best model
        if val_metrics['f1'] > best_f1:
            best_f1 = val_metrics['f1']
            patience_counter = 0

            # Save model
            torch.save({
                'epoch': epoch,
                'model_state_dict': model.state_dict(),
                'optimizer_state_dict': optimizer.state_dict(),
                'best_f1': best_f1,
                'val_metrics': val_metrics
            }, args.outdir / "resnet18_best.pth")

            print(f" Saved best model (F1: {best_f1:.4f})")
        else:
            patience_counter += 1
            print(f"No improvement ({patience_counter}/{args.patience})")

        # Early stopping
        if patience_counter >= args.patience:
            print(f"\nEarly stopping triggered after {epoch+1} epochs")
            break

        print()

    # Save final model and metrics
    torch.save(model.state_dict(), args.outdir / "resnet18_final.pth")

    with open(args.outdir / "training_history.json", 'w') as f:
        # Convert numpy types to Python types for JSON serialization
        history_serializable = {
            'train_loss': [float(x) for x in history['train_loss']],
            'train_acc': [float(x) for x in history['train_acc']],
            'val_metrics': [
                {k: float(v) for k, v in m.items()}
                for m in history['val_metrics']
            ]
        }
        json.dump(history_serializable, f, indent=2)

    # Save best metrics
    best_epoch_idx = np.argmax([m['f1'] for m in history['val_metrics']])
    best_metrics = history['val_metrics'][best_epoch_idx]

    with open(args.outdir / "best_metrics.json", 'w') as f:
        json.dump({k: float(v) for k, v in best_metrics.items()}, f, indent=2)

    print(f"\n{'='*60}")
    print(f"Training Complete!")
    print(f"{'='*60}")
    print(f"Best F1 Score: {best_f1:.4f}")
    print(f"Best Metrics:")
    for k, v in best_metrics.items():
        print(f"  {k}: {v:.4f}")
    print(f"\nModel saved to: {args.outdir}")


if __name__ == "__main__":
    main()
