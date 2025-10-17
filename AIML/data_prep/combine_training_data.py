"""Combine CSE benign + ChromaDB phishing for training"""
import pandas as pd
from pathlib import Path

def main():
    # Load CSE benign data
    cse_benign = pd.read_csv("data/cse_benign.csv")
    print(f"CSE benign: {len(cse_benign)}")

    # Load phishing from ChromaDB (high risk_score domains)
    # Run prepare_training_data.py first to get this
    try:
        phishing = pd.read_csv("data/chromadb_phishing.csv")
        print(f"ChromaDB phishing: {len(phishing)}")
    except:
        print("No chromadb_phishing.csv - using only CSE data")
        phishing = pd.DataFrame()

    # Combine
    if not phishing.empty:
        df = pd.concat([cse_benign, phishing], ignore_index=True)
    else:
        df = cse_benign

    # Shuffle
    df = df.sample(frac=1, random_state=42)

    # Split train/val
    split = int(0.8 * len(df))
    train = df[:split]
    val = df[split:]

    # Save
    train.to_csv("data/train_features.csv", index=False)
    val.to_csv("data/val_features.csv", index=False)

    print(f"\nSaved:")
    print(f"  Train: {len(train)} samples")
    print(f"  Val: {len(val)} samples")
    print(f"  Benign: {(df['label']=='benign').sum()}")
    print(f"  Phishing: {(df['label']=='phishing').sum()}")

if __name__ == "__main__":
    main()
