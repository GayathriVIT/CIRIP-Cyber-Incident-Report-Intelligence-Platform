"""
Lightweight ML pipeline used for BOTH incident-type classification and severity
prediction: TF-IDF features + Logistic Regression.

Why this instead of BERT/Llama by default:
  - Trains in seconds on a laptop, no GPU needed.
  - Coefficients give straightforward, honest explainability (see explain()).
  - A transformer/LLM path is offered separately (llm_integration.py) as an
    OPTIONAL advanced upgrade, clearly labeled as LLM-generated rather than a
    trained classifier's prediction.
"""
import os
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

from .preprocessing import normalize_for_model

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models_store")


class TfidfLogRegPipeline:
    def __init__(self, name: str):
        self.name = name
        self.vectorizer = None
        self.model = None
        self.classes_ = None

    def train(self, texts, labels, test_size=0.2, random_state=42):
        cleaned = [normalize_for_model(t) for t in texts]
        self.vectorizer = TfidfVectorizer(max_features=3000, ngram_range=(1, 2), min_df=1)
        X = self.vectorizer.fit_transform(cleaned)

        X_train, X_test, y_train, y_test = train_test_split(
            X, labels, test_size=test_size, random_state=random_state, stratify=labels
        )
        self.model = LogisticRegression(max_iter=2000, C=2.0)
        self.model.fit(X_train, y_train)
        self.classes_ = self.model.classes_

        y_pred = self.model.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, zero_division=0)
        return {"accuracy": acc, "report": report}

    def predict(self, text: str):
        cleaned = normalize_for_model(text)
        X = self.vectorizer.transform([cleaned])
        proba = self.model.predict_proba(X)[0]
        idx = int(np.argmax(proba))
        label = self.model.classes_[idx]
        confidence = float(proba[idx])
        class_probs = {cls: float(p) for cls, p in zip(self.model.classes_, proba)}
        return label, confidence, class_probs, X

    def explain(self, X, predicted_label: str, top_n=8):
        """Explainable AI: returns the top contributing words/features for the
        predicted class, i.e. (tfidf_weight * logistic_regression_coefficient)."""
        feature_names = np.array(self.vectorizer.get_feature_names_out())
        class_idx = list(self.model.classes_).index(predicted_label)
        coefs = self.model.coef_[class_idx] if len(self.model.classes_) > 2 else self.model.coef_[0]

        x_dense = X.toarray()[0]
        contributions = x_dense * coefs
        nonzero_idx = np.nonzero(x_dense)[0]
        ranked = sorted(nonzero_idx, key=lambda i: -abs(contributions[i]))[:top_n]

        return [
            {
                "feature": feature_names[i],
                "tfidf_weight": round(float(x_dense[i]), 4),
                "contribution": round(float(contributions[i]), 4),
            }
            for i in ranked
        ]

    def save(self):
        os.makedirs(MODELS_DIR, exist_ok=True)
        joblib.dump(
            {"vectorizer": self.vectorizer, "model": self.model},
            os.path.join(MODELS_DIR, f"{self.name}.joblib"),
        )

    def load(self):
        path = os.path.join(MODELS_DIR, f"{self.name}.joblib")
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"Model file not found: {path}. Run `python train_models.py` first."
            )
        data = joblib.load(path)
        self.vectorizer = data["vectorizer"]
        self.model = data["model"]
        self.classes_ = self.model.classes_
        return self
