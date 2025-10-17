"""Text model inference"""
import argparse, pandas as pd
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model_dir", required=True)
    ap.add_argument("--text_csv", required=True)
    ap.add_argument("--out_csv", required=True)
    args = ap.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(args.model_dir)
    model.eval()
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model.to(device)

    df = pd.read_csv(args.text_csv)
    probs = []
    for text in df['text']:
        inputs = tokenizer(text, truncation=True, max_length=256, return_tensors='pt')
        inputs = {k: v.to(device) for k, v in inputs.items()}
        with torch.no_grad():
            prob = torch.softmax(model(**inputs).logits, dim=1)[0,1].item()
        probs.append(prob)

    df['p_text'] = probs
    df.to_csv(args.out_csv, index=False)

if __name__ == "__main__":
    main()
