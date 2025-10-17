"""Prepare training data from ChromaDB + PhishTank"""
import chromadb, pandas as pd, sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from common.fe import extract_features_from_chromadb, REQUIRED_FEATURES

def get_legitimate_data(collection):
    """Get CSE pages as benign samples"""
    results = collection.get(
        where={"$and": [{"cse_id": {"$ne": None}}, {"final_verdict": "benign"}]},
        include=["metadatas"], limit=10000
    )
    features = [extract_features_from_chromadb(m) for m in results['metadatas']]
    df = pd.DataFrame(features)
    df['label'] = 'benign'
    return df

def get_phishing_data(collection):
    """Get high-risk domains as phishing samples"""
    results = collection.get(
        where={"$or": [{"final_verdict": "phishing"}, {"risk_score": {"$gte": 70}}]},
        include=["metadatas"], limit=10000
    )
    features = [extract_features_from_chromadb(m) for m in results['metadatas']]
    df = pd.DataFrame(features)
    df['label'] = 'phishing'
    return df

def load_phishtank(csv_path):
    """Load PhishTank data (download from phishtank.com)"""
    df = pd.read_csv(csv_path)
    # Add features (you'll need to crawl these URLs)
    # For now, create dummy features
    features = {col: 0 for col in REQUIRED_FEATURES}
    df_features = pd.DataFrame([features] * len(df))
    df_features['label'] = 'phishing'
    return df_features

def main():
    client = chromadb.HttpClient(host='localhost', port=8000)
    collection = client.get_collection("domains")

    # Get benign
    benign = get_legitimate_data(collection)
    print(f"Benign: {len(benign)}")

    # Get phishing from ChromaDB
    phishing = get_phishing_data(collection)
    print(f"Phishing (ChromaDB): {len(phishing)}")

    # Combine
    df = pd.concat([benign, phishing], ignore_index=True)
    df = df.sample(frac=1, random_state=42)  # Shuffle

    # Save
    df.to_csv("data/train_features.csv", index=False)
    print(f"Saved {len(df)} samples to data/train_features.csv")

if __name__ == "__main__":
    main()
