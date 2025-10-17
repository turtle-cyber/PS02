"""
Vision Model Inference - Generate phishing probabilities for screenshots

Usage:
    python infer_resnet18.py --model_path out/resnet18_best.pth \
                             --images_dir pages/ \
                             --out_csv predictions.csv
"""

import argparse
import json
from pathlib import Path
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torchvision import models, transforms
from PIL import Image
from tqdm import tqdm


def build_model(checkpoint_path, device):
    """Load trained ResNet18 model"""
    model = models.resnet18(pretrained=False)

    # Replace final layer
    num_features = model.fc.in_features
    model.fc = nn.Sequential(
        nn.Dropout(0.3),
        nn.Linear(num_features, 2)
    )

    # Load checkpoint
    checkpoint = torch.load(checkpoint_path, map_location=device)

    if 'model_state_dict' in checkpoint:
        model.load_state_dict(checkpoint['model_state_dict'])
    else:
        model.load_state_dict(checkpoint)

    model = model.to(device)
    model.eval()

    return model


def get_transform():
    """Get inference transforms (no augmentation)"""
    return transforms.Compose([
        transforms.Resize((224, 224)),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485, 0.456, 0.406],
                           std=[0.229, 0.224, 0.225])
    ])


def predict_image(model, image_path, transform, device):
    """
    Predict phishing probability for single image

    Returns:
        prob: Probability of phishing (0-1)
    """
    try:
        image = Image.open(image_path).convert('RGB')
    except Exception as e:
        print(f"Warning: Failed to load {image_path}: {e}")
        return None

    # Transform and add batch dimension
    image_tensor = transform(image).unsqueeze(0).to(device)

    # Predict
    with torch.no_grad():
        outputs = model(image_tensor)
        probs = torch.softmax(outputs, dim=1)
        phishing_prob = probs[0, 1].item()

    return phishing_prob


def main():
    parser = argparse.ArgumentParser(description="Inference with trained ResNet18")

    parser.add_argument("--model_path", type=Path, required=True,
                       help="Path to trained model checkpoint")
    parser.add_argument("--images_dir", type=Path, required=True,
                       help="Directory containing screenshot images")
    parser.add_argument("--out_csv", type=Path, required=True,
                       help="Output CSV path")
    parser.add_argument("--batch_size", type=int, default=32,
                       help="Batch size for inference")

    args = parser.parse_args()

    # Device
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    # Load model
    print(f"Loading model from {args.model_path}...")
    model = build_model(args.model_path, device)
    print("Model loaded successfully")

    # Get transform
    transform = get_transform()

    # Find all images
    image_paths = list(args.images_dir.glob("*.jpg")) + \
                  list(args.images_dir.glob("*.png"))

    print(f"Found {len(image_paths)} images")

    # Predict
    results = []

    for img_path in tqdm(image_paths, desc="Predicting"):
        url_id = img_path.stem
        prob = predict_image(model, img_path, transform, device)

        if prob is not None:
            results.append({
                'url_id': url_id,
                'p_vis': prob
            })
        else:
            # Failed to load image
            results.append({
                'url_id': url_id,
                'p_vis': 0.5  # Neutral probability for failed images
            })

    # Save results
    df = pd.DataFrame(results)
    df.to_csv(args.out_csv, index=False)

    print(f"\n✓ Saved predictions to {args.out_csv}")
    print(f"  Total images: {len(results)}")
    print(f"  Mean phishing probability: {df['p_vis'].mean():.4f}")
    print(f"  Std: {df['p_vis'].std():.4f}")


if __name__ == "__main__":
    main()
