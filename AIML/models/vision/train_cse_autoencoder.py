"""Train autoencoder on CSE screenshots for anomaly detection"""
import argparse
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from torchvision import transforms, models
from PIL import Image
from pathlib import Path
import numpy as np
from tqdm import tqdm

class CSEScreenshotDataset(Dataset):
    """Dataset for CSE screenshots (benign only)"""
    def __init__(self, img_dir, transform=None):
        self.img_dir = Path(img_dir)
        self.imgs = list(self.img_dir.glob("*.png")) + list(self.img_dir.glob("*.jpg"))
        self.transform = transform
        print(f"Loaded {len(self.imgs)} CSE screenshots")

    def __len__(self):
        return len(self.imgs)

    def __getitem__(self, idx):
        img_path = self.imgs[idx]
        img = Image.open(img_path).convert('RGB')
        if self.transform:
            img = self.transform(img)
        return img, str(img_path.name)

class ScreenshotAutoencoder(nn.Module):
    """Autoencoder for screenshot anomaly detection"""
    def __init__(self, latent_dim=512):
        super().__init__()
        # Use pretrained ResNet as encoder (output: 512x7x7)
        resnet = models.resnet18(weights='IMAGENET1K_V1')
        self.encoder = nn.Sequential(*list(resnet.children())[:-2])  # Keep spatial dimensions

        # Decoder: upsample from 7x7 to 224x224
        self.decoder = nn.Sequential(
            # 7x7 -> 14x14
            nn.ConvTranspose2d(512, 256, kernel_size=3, stride=2, padding=1, output_padding=1),
            nn.BatchNorm2d(256),
            nn.ReLU(),
            # 14x14 -> 28x28
            nn.ConvTranspose2d(256, 128, kernel_size=3, stride=2, padding=1, output_padding=1),
            nn.BatchNorm2d(128),
            nn.ReLU(),
            # 28x28 -> 56x56
            nn.ConvTranspose2d(128, 64, kernel_size=3, stride=2, padding=1, output_padding=1),
            nn.BatchNorm2d(64),
            nn.ReLU(),
            # 56x56 -> 112x112
            nn.ConvTranspose2d(64, 32, kernel_size=3, stride=2, padding=1, output_padding=1),
            nn.BatchNorm2d(32),
            nn.ReLU(),
            # 112x112 -> 224x224
            nn.ConvTranspose2d(32, 3, kernel_size=3, stride=2, padding=1, output_padding=1),
            nn.Tanh()  # Output in [-1, 1] range
        )

    def forward(self, x):
        # Encode
        features = self.encoder(x)  # [B, 512, 7, 7]
        # Decode
        reconstructed = self.decoder(features)  # [B, 3, 224, 224]
        return reconstructed, features

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--img_dir", default="CSE/out/screenshots")
    ap.add_argument("--outdir", default="models/vision/autoencoder")
    ap.add_argument("--epochs", type=int, default=50)
    ap.add_argument("--batch_size", type=int, default=16)
    ap.add_argument("--lr", type=float, default=1e-4)
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    # Transforms
    transform = transforms.Compose([
        transforms.Resize((224, 224)),
        transforms.ToTensor(),
        transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
    ])

    # Dataset
    dataset = CSEScreenshotDataset(args.img_dir, transform)
    loader = DataLoader(dataset, batch_size=args.batch_size, shuffle=True, num_workers=2)

    # Model
    model = ScreenshotAutoencoder().to(device)
    criterion = nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)

    print(f"\nTraining autoencoder on {len(dataset)} CSE screenshots...")

    best_loss = float('inf')
    for epoch in range(args.epochs):
        model.train()
        epoch_loss = 0.0

        for imgs, _ in tqdm(loader, desc=f"Epoch {epoch+1}/{args.epochs}"):
            imgs = imgs.to(device)

            # Forward
            reconstructed, _ = model(imgs)
            loss = criterion(reconstructed, imgs)

            # Backward
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

            epoch_loss += loss.item()

        avg_loss = epoch_loss / len(loader)
        print(f"Epoch {epoch+1}: Loss = {avg_loss:.4f}")

        if avg_loss < best_loss:
            best_loss = avg_loss
            torch.save(model.state_dict(), outdir / "autoencoder_best.pth")

    print(f"\nBest reconstruction loss: {best_loss:.4f}")
    print(f"Saved to {outdir / 'autoencoder_best.pth'}")
    print("\nUSAGE: High reconstruction error = anomaly (phishing)")

if __name__ == "__main__":
    main()
