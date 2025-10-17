import argparse, json, numpy as np, pandas as pd
from pathlib import Path
from datasets import Dataset
from transformers import (AutoTokenizer, AutoModelForSequenceClassification,
                          TrainingArguments, Trainer)
from sklearn.metrics import accuracy_score, recall_score, f1_score

def load_ds(train_csv, val_csv):
    cols = ["text","label"]  # label ∈ {"benign","phishing"}
    tr = pd.read_csv(train_csv)[cols].dropna().copy()
    va = pd.read_csv(val_csv)[cols].dropna().copy()
    label2id = {"benign":0, "phishing":1}; id2label = {0:"benign", 1:"phishing"}
    tr["label"] = tr["label"].map(label2id)
    va["label"] = va["label"].map(label2id)
    return Dataset.from_pandas(tr), Dataset.from_pandas(va), label2id, id2label

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = (logits.argmax(-1))
    return {
        "accuracy": accuracy_score(labels, preds),
        "recall": recall_score(labels, preds, pos_label=1),
        "f1": f1_score(labels, preds, pos_label=1)
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model_name", default="xlm-roberta-base")  # or "bert-base-multilingual-cased"
    ap.add_argument("--train_csv", required=True)
    ap.add_argument("--val_csv", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--max_len", type=int, default=256)
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--lr", type=float, default=2e-5)
    args = ap.parse_args()

    out = Path(args.outdir); out.mkdir(parents=True, exist_ok=True)
    train_ds, val_ds, label2id, id2label = load_ds(args.train_csv, args.val_csv)
    tok = AutoTokenizer.from_pretrained(args.model_name)

    def tokenize(batch):
        return tok(batch["text"], truncation=True, padding="max_length", max_length=args.max_len)

    train_enc = train_ds.map(tokenize, batched=True)
    val_enc = val_ds.map(tokenize, batched=True)

    model = AutoModelForSequenceClassification.from_pretrained(
        args.model_name, num_labels=2, id2label={0:"benign",1:"phishing"}, label2id={"benign":0,"phishing":1}
    )
    training_args = TrainingArguments(
        output_dir=str(out), learning_rate=args.lr, per_device_train_batch_size=args.batch,
        per_device_eval_batch_size=args.batch, num_train_epochs=args.epochs,
        evaluation_strategy="epoch", load_best_model_at_end=True, metric_for_best_model="f1"
    )

    trainer = Trainer(model=model, args=training_args,
                      train_dataset=train_enc, eval_dataset=val_enc,
                      compute_metrics=compute_metrics)
    trainer.train()
    metrics = trainer.evaluate()
    (out / "text_head_metrics.json").write_text(json.dumps(metrics, indent=2))
    model.save_pretrained(out)
    tok.save_pretrained(out)

if __name__ == "__main__":
    main()
