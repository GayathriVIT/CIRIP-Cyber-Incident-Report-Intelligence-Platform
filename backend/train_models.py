"""
Trains and saves the two lightweight TF-IDF + Logistic Regression models:
  1. Incident type classifier (Phishing / Malware / Ransomware / DDoS / Insider Threat / Data Breach)
  2. Severity predictor (Low / Medium / High / Critical)

Run this once before starting the API server:
    python train_models.py
"""
import os
import sys
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))
from app.ml_pipeline import TfidfLogRegPipeline  # noqa: E402

DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "training_data.csv")


def main():
    if not os.path.exists(DATA_PATH):
        print("Training data not found -- generating synthetic dataset first...")
        os.system(f"{sys.executable} {os.path.join(os.path.dirname(__file__), 'data', 'generate_training_data.py')}")

    df = pd.read_csv(DATA_PATH)
    print(f"Loaded {len(df)} labeled incident reports.")

    print("\n=== Training incident-type classifier ===")
    clf = TfidfLogRegPipeline("incident_classifier")
    metrics = clf.train(df["text"].tolist(), df["incident_type"].tolist())
    print(f"Accuracy: {metrics['accuracy']:.3f}")
    print(metrics["report"])
    clf.save()

    print("\n=== Training severity predictor ===")
    sev = TfidfLogRegPipeline("severity_model")
    metrics = sev.train(df["text"].tolist(), df["severity"].tolist())
    print(f"Accuracy: {metrics['accuracy']:.3f}")
    print(metrics["report"])
    sev.save()

    print("\nModels saved to backend/app/models_store/. You can now start the API:")
    print("    uvicorn app.main:app --reload --port 8000")


if __name__ == "__main__":
    main()
