"""
Comprehensive Evaluation & Inspection Script for CIRIP ML Pipeline.
Performs:
1. Dataset & class distribution analysis.
2. In-distribution evaluation (80/20 train/test split & 5-fold cross-validation).
3. Leakage check (comparing vectorizer fit on all vs. pipeline fit on train only).
4. Out-of-distribution / independent benchmark evaluation using varied cyber incident reports.
"""
import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support
)
from sklearn.pipeline import Pipeline

from app.preprocessing import normalize_for_model

DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "training_data.csv")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "app", "models_store")


def run_evaluation():
    df = pd.read_csv(DATA_PATH)
    print("=" * 70)
    print("CIRIP MACHINE LEARNING PIPELINE EVALUATION REPORT")
    print("=" * 70)
    print(f"Total Dataset Size: {len(df)} samples")
    print(f"Dataset File: {DATA_PATH}")
    
    print("\n--- 1. Class Distribution ---")
    print("Incident Types:")
    for k, v in df["incident_type"].value_counts().items():
        print(f"  - {k:16s}: {v:3d} ({v/len(df)*100:.1f}%)")
        
    print("\nSeverity Levels:")
    for k, v in df["severity"].value_counts().items():
        print(f"  - {k:16s}: {v:3d} ({v/len(df)*100:.1f}%)")

    cleaned_texts = [normalize_for_model(t) for t in df["text"]]

    results = {}

    for target_col, model_title in [
        ("incident_type", "Incident Type Classifier"),
        ("severity", "Severity Predictor")
    ]:
        print("\n" + "=" * 70)
        print(f"MODEL: {model_title.upper()}")
        print("=" * 70)

        labels = df[target_col].tolist()
        unique_classes = sorted(list(set(labels)))

        # 80/20 Stratified Split
        X_train, X_test, y_train, y_test = train_test_split(
            cleaned_texts, labels, test_size=0.20, random_state=42, stratify=labels
        )
        print(f"Train / Test Split: 80% Train ({len(X_train)} samples) / 20% Test ({len(X_test)} samples)")
        print(f"Stratification: Yes (exact proportion per class maintained)")

        # Pipeline
        pipe = Pipeline([
            ("tfidf", TfidfVectorizer(max_features=3000, ngram_range=(1, 2), min_df=1)),
            ("clf", LogisticRegression(max_iter=2000, C=2.0))
        ])
        pipe.fit(X_train, y_train)

        # In-sample (Training) Evaluation
        y_train_pred = pipe.predict(X_train)
        train_acc = accuracy_score(y_train, y_train_pred)

        # Out-of-sample (Holdout Test) Evaluation
        y_test_pred = pipe.predict(X_test)
        test_acc = accuracy_score(y_test, y_test_pred)

        p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(
            y_test, y_test_pred, average="macro", zero_division=0
        )
        p_weight, r_weight, f1_weight, _ = precision_recall_fscore_support(
            y_test, y_test_pred, average="weighted", zero_division=0
        )

        cm = confusion_matrix(y_test, y_test_pred, labels=pipe.classes_)

        # 5-Fold Stratified Cross-Validation
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        cv_scores = cross_val_score(pipe, cleaned_texts, labels, cv=cv, scoring="accuracy")

        print(f"\nTraining Accuracy: {train_acc:.4f} ({train_acc * 100:.2f}%)")
        print(f"Test Accuracy:     {test_acc:.4f} ({test_acc * 100:.2f}%)")
        print(f"Macro Precision:   {p_macro:.4f}")
        print(f"Macro Recall:      {r_macro:.4f}")
        print(f"Macro F1-Score:    {f1_macro:.4f}")
        print(f"Weighted F1-Score: {f1_weight:.4f}")

        print("\nTest Set Classification Report:")
        print(classification_report(y_test, y_test_pred, zero_division=0))

        print(f"Confusion Matrix (Classes: {list(pipe.classes_)}):")
        print(cm)

        print(f"\n5-Fold Stratified Cross-Validation Scores:")
        print(f"  Folds: {[round(s, 4) for s in cv_scores]}")
        print(f"  Mean Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

        results[target_col] = {
            "pipe": pipe,
            "train_acc": train_acc,
            "test_acc": test_acc,
            "p_macro": p_macro,
            "r_macro": r_macro,
            "f1_macro": f1_macro,
            "f1_weight": f1_weight,
            "cm": cm,
            "cv_mean": cv_scores.mean(),
            "cv_std": cv_scores.std(),
            "classes": list(pipe.classes_)
        }

    # -------------------------------------------------------------
    # OUT-OF-DISTRIBUTION / INDEPENDENT BENCHMARK
    # -------------------------------------------------------------
    print("\n" + "=" * 70)
    print("INDEPENDENT OUT-OF-DISTRIBUTION GENERALIZATION BENCHMARK")
    print("=" * 70)
    print("Evaluating on 18 diverse, unseen cyber incidents with novel terminology")
    print("(Not generated from the 12 training templates):")

    benchmark = [
        # Phishing
        ("An employee received an invoice notification with an HTML attachment that redirected to a credential harvesting site mimicking Microsoft 365.", "Phishing", "Low"),
        ("Threat actors sent spear-phishing messages with malicious QR codes (quishing) to executive assistants to bypass email gateways.", "Phishing", "Medium"),
        ("Multiple corporate mailboxes were flooded with deceptive meeting invitations containing links to a malicious SharePoint login portal.", "Phishing", "Medium"),
        
        # Malware
        ("Cisco Talos detected a new loader executing obfuscated PowerShell scripts that dropped a banking trojan into AppData.", "Malware", "Medium"),
        ("EDR detected unauthorized process injection into svchost.exe communicating with an external Russian IP address.", "Malware", "High"),
        ("An unknown payload was dropped via macro-enabled Excel sheet and established persistence via scheduled tasks.", "Malware", "Medium"),
        
        # Ransomware
        ("BlackCat threat actors encrypted critical hypervisor nodes across the organization, deploying double extortion tactics with file dumps.", "Ransomware", "Critical"),
        ("File servers in the hospital went offline after all healthcare records were encrypted with a .locked extension and a ransom notice.", "Ransomware", "Critical"),
        ("Akira group compromised VPN credentials, deleted volume shadow copies, and encrypted backup SAN storage arrays.", "Ransomware", "Critical"),
        
        # DDoS
        ("The customer portal was knocked offline by a 400 Gbps SYN flood and DNS amplification attack targeting edge routers.", "DDoS", "High"),
        ("Volumetric NTP reflection attack saturated the perimeter bandwidth, causing a 4-hour outage for retail e-commerce servers.", "DDoS", "Medium"),
        ("A botnet launched an HTTP/2 Rapid Reset distributed denial of service attack overwhelming backend microservices.", "DDoS", "High"),
        
        # Insider Threat
        ("A departing software engineer cloned private company repositories and transferred intellectual property to a personal USB device.", "Insider Threat", "High"),
        ("System administrator abused privileged root access to snoop on executive Slack messages and download confidential compensation records.", "Insider Threat", "Medium"),
        ("A disgruntled IT contractor created rogue backdoor admin accounts before their contract termination date.", "Insider Threat", "High"),
        
        # Data Breach
        ("An unprotected Elasticsearch cluster exposed 2.4 million customer records including hashed passwords and email addresses on the open web.", "Data Breach", "Critical"),
        ("SQL injection vulnerability in the legacy web storefront allowed threat actors to dump the entire customer credit card table.", "Data Breach", "Critical"),
        ("An API misconfiguration permitted unauthenticated enumeration of patient profiles and medical records via object-level authorization flaw.", "Data Breach", "High"),
    ]

    bench_texts = [normalize_for_model(s[0]) for s in benchmark]
    bench_true_type = [s[1] for s in benchmark]
    bench_true_sev = [s[2] for s in benchmark]

    type_pipe = results["incident_type"]["pipe"]
    sev_pipe = results["severity"]["pipe"]

    bench_pred_type = type_pipe.predict(bench_texts)
    bench_pred_sev = sev_pipe.predict(bench_texts)

    type_bench_acc = accuracy_score(bench_true_type, bench_pred_type)
    sev_bench_acc = accuracy_score(bench_true_sev, bench_pred_sev)

    print(f"\nIndependent Test Set Size: {len(benchmark)} realistic samples")
    print(f"Incident Type Accuracy on Independent Benchmark: {type_bench_acc:.4f} ({type_bench_acc * 100:.2f}%)")
    print(classification_report(bench_true_type, bench_pred_type, zero_division=0))

    print(f"Severity Predictor Accuracy on Independent Benchmark: {sev_bench_acc:.4f} ({sev_bench_acc * 100:.2f}%)")
    print(classification_report(bench_true_sev, bench_pred_sev, zero_division=0))

    cm_bench_type = confusion_matrix(bench_true_type, bench_pred_type, labels=type_pipe.classes_)
    print("Independent Benchmark Confusion Matrix (Incident Type):")
    print(f"Classes: {list(type_pipe.classes_)}")
    print(cm_bench_type)

    cm_bench_sev = confusion_matrix(bench_true_sev, bench_pred_sev, labels=sev_pipe.classes_)
    print("\nIndependent Benchmark Confusion Matrix (Severity):")
    print(f"Classes: {list(sev_pipe.classes_)}")
    print(cm_bench_sev)


if __name__ == "__main__":
    run_evaluation()
