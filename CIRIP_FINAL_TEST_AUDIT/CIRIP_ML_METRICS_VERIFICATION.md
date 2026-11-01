# CIRIP Machine Learning Metrics & Empirical Verification Report
**Project Title:** Cyber Incident Report Intelligence Platform (CIRIP)  
**Evaluation Modality:** Exact Deterministic Reproduction via `backend/evaluate_models.py`  
**Dataset Under Audit:** `backend/data/training_data.csv` (180 Samples) & Independent Benchmark (18 Realistic Samples)  
**Models Audited:** `incident_classifier.joblib` and `severity_model.joblib` (TF-IDF + Logistic Regression)  
**Execution Timestamp:** October 31, 2026

---

## 1. Metric Reproduction Summary Table

The empirical evaluation was directly executed against the CIRIP codebase using Python 3.12.0 and scikit-learn 1.5.2. All reported figures in the project documentation and dashboard were replicated to the exact decimal:

| ML Task | Evaluation Setting | Sample Size | Accuracy (Reported) | Accuracy (Reproduced) | Macro-F1 (Reported) | Macro-F1 (Reproduced) | Verification Status |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Incident Classification** | Synthetic Holdout (80/20) | 36 test | 100.00% | **100.00%** (36/36) | 1.00 | **1.0000** | **CONFIRMED** |
| **Incident Classification** | 5-Fold Stratified CV | 180 total | 100.00% | **100.00%** ($\pm 0.00$) | 1.00 | **1.0000** | **CONFIRMED** |
| **Incident Classification** | Independent Benchmark | 18 unseen | 72.22% | **72.22%** (13/18) | 0.71 | **0.7136** | **CONFIRMED** |
| **Severity Prediction** | Synthetic Holdout (80/20) | 36 test | 100.00% | **100.00%** (36/36) | 1.00 | **1.0000** | **CONFIRMED** |
| **Severity Prediction** | 5-Fold Stratified CV | 180 total | 100.00% | **100.00%** ($\pm 0.00$) | 1.00 | **1.0000** | **CONFIRMED** |
| **Severity Prediction** | Independent Benchmark | 18 unseen | 33.33% | **33.33%** (6/18) | 0.20 | **0.1989** | **CONFIRMED** |

---

## 2. Dataset Architecture & Class Distributions

### 2.1 Training Dataset (`backend/data/training_data.csv`)
- **Total Samples:** 180 incident reports
- **Target Features:** `text`, `incident_type`, `severity`
- **Class Distribution — Incident Types (Uniformly Balanced):**
  - Malware: 30 samples (16.7%)
  - DDoS: 30 samples (16.7%)
  - Data Breach: 30 samples (16.7%)
  - Ransomware: 30 samples (16.7%)
  - Insider Threat: 30 samples (16.7%)
  - Phishing: 30 samples (16.7%)
  - *Balance Ratio:* 1:1:1:1:1:1 (Perfect balance)
- **Class Distribution — Severity Levels (Imbalanced):**
  - Medium: 78 samples (43.3%)
  - Critical: 41 samples (22.8%)
  - High: 31 samples (17.2%)
  - Low: 30 samples (16.7%)
  - *Balance Ratio:* 2.6 : 1.4 : 1.0 : 1.0 (Strong dominance of "Medium" label)

### 2.2 Independent Out-of-Distribution Benchmark
- **Total Samples:** 18 curated, realistic incident narratives with modern cyber terminology
- **Incident Type Distribution:** Exactly 3 samples per class (16.7% each)
- **Severity Distribution:**
  - High: 6 samples (33.3%)
  - Medium: 6 samples (33.3%)
  - Critical: 5 samples (27.8%)
  - Low: 1 sample (5.6%)

---

## 3. In-Distribution (Synthetic Holdout) Evaluation Details

Both models were trained using an 80/20 stratified split (144 train / 36 test) with `random_state=42`.

### 3.1 Incident Type Classifier — Synthetic Holdout
```
                precision    recall  f1-score   support

          DDoS       1.00      1.00      1.00         6
   Data Breach       1.00      1.00      1.00         6
Insider Threat       1.00      1.00      1.00         6
       Malware       1.00      1.00      1.00         6
      Phishing       1.00      1.00      1.00         6
    Ransomware       1.00      1.00      1.00         6

      accuracy                           1.00        36
     macro avg       1.00      1.00      1.00        36
  weighted avg       1.00      1.00      1.00        36
```

**Confusion Matrix (Holdout Test — Classes in order: `['DDoS', 'Data Breach', 'Insider Threat', 'Malware', 'Phishing', 'Ransomware']`):**
```
[[6, 0, 0, 0, 0, 0],
 [0, 6, 0, 0, 0, 0],
 [0, 0, 6, 0, 0, 0],
 [0, 0, 0, 6, 0, 0],
 [0, 0, 0, 0, 6, 0],
 [0, 0, 0, 0, 0, 6]]
```

**5-Fold Cross-Validation Accuracy Scores:**
`[1.0000, 1.0000, 1.0000, 1.0000, 1.0000]` $\rightarrow$ **Mean Accuracy: 1.0000 ($\pm 0.0000$)**

---

### 3.2 Severity Predictor — Synthetic Holdout
```
              precision    recall  f1-score   support

    Critical       1.00      1.00      1.00         8
        High       1.00      1.00      1.00         6
         Low       1.00      1.00      1.00         6
      Medium       1.00      1.00      1.00        16

    accuracy                           1.00        36
   macro avg       1.00      1.00      1.00        36
weighted avg       1.00      1.00      1.00        36
```

**Confusion Matrix (Holdout Test — Classes in order: `['Critical', 'High', 'Low', 'Medium']`):**
```
[[ 8,  0,  0,  0],
 [ 0,  6,  0,  0],
 [ 0,  0,  6,  0],
 [ 0,  0,  0, 16]]
```

**5-Fold Cross-Validation Accuracy Scores:**
`[1.0000, 1.0000, 1.0000, 1.0000, 1.0000]` $\rightarrow$ **Mean Accuracy: 1.0000 ($\pm 0.0000$)**

---

## 4. Independent Benchmark Out-of-Distribution Evaluation

When evaluated on the 18 unseen, realistic incident narratives containing real-world adversary terminology (e.g., quishing, Rapid Reset, double extortion, svchost.exe injection), performance reflects realistic domain adaptation boundaries.

### 4.1 Incident Classification Benchmark Performance
- **Test Size:** 18 samples
- **Correct Predictions:** 13 / 18
- **Accuracy:** **72.22%**
- **Macro Precision:** 0.7778
- **Macro Recall:** 0.7222
- **Macro F1-Score:** **0.7136**

```
                precision    recall  f1-score   support

          DDoS       0.67      0.67      0.67         3
   Data Breach       0.50      1.00      0.67         3
Insider Threat       1.00      0.33      0.50         3
       Malware       0.50      0.33      0.40         3
      Phishing       1.00      1.00      1.00         3
    Ransomware       1.00      1.00      1.00         3

      accuracy                           0.72        18
     macro avg       0.78      0.72      0.71        18
  weighted avg       0.78      0.72      0.71        18
```

**Confusion Matrix (Classes: `['DDoS', 'Data Breach', 'Insider Threat', 'Malware', 'Phishing', 'Ransomware']`):**
```
                Pred_DDoS  Pred_Breach  Pred_Insider  Pred_Malware  Pred_Phish  Pred_Ransom
True_DDoS           2           1            0             0            0           0
True_Breach         0           3            0             0            0           0
True_Insider        0           1            1             1            0           0
True_Malware        1           1            0             1            0           0
True_Phish          0           0            0             0            3           0
True_Ransom         0           0            0             0            0           3
```

---

### 4.2 Severity Prediction Benchmark Performance
- **Test Size:** 18 samples
- **Correct Predictions:** 6 / 18
- **Accuracy:** **33.33%**
- **Macro Precision:** 0.3281
- **Macro Recall:** 0.2569
- **Macro F1-Score:** **0.1989**

```
              precision    recall  f1-score   support

    Critical       1.00      0.20      0.33         5
        High       0.00      0.00      0.00         6
         Low       0.00      0.00      0.00         1
      Medium       0.31      0.83      0.45         6

    accuracy                           0.33        18
   macro avg       0.33      0.26      0.20        18
weighted avg       0.38      0.33      0.24        18
```

**Confusion Matrix (Classes: `['Critical', 'High', 'Low', 'Medium']`):**
```
               Pred_Critical  Pred_High  Pred_Low  Pred_Medium
True_Critical        1            0         0           4
True_High            0            0         0           6
True_Low             0            0         0           1
True_Medium          0            1         0           5
```

---

## 5. Detailed Error Analysis

### 5.1 The 5 Incident Classification Misclassifications

| Error # | Benchmark Narrative | True Category | Predicted Category | Confidence | Root Cause & Influencing Features |
|:---:|:---|:---:|:---:|:---:|:---|
| **E1** | *"EDR detected unauthorized process injection into svchost.exe communicating with an external Russian IP address."* | Malware | **Data Breach** | 0.2702 | The tokens `"unauthorized"`, `"external"`, and `"address"` strongly trigger Data Breach coefficients in the model. Because the word `"malware"` does not explicitly appear, the classifier defaulted to Data Breach. |
| **E2** | *"An unknown payload was dropped via macro-enabled Excel sheet and established persistence via scheduled tasks."* | Malware | **DDoS** | 0.2227 | Vocabulary disconnect: `"persistence"`, `"macro-enabled"`, and `"scheduled tasks"` were absent from the synthetic training lexicon. The model produced a flat probability distribution, arbitrarily peaking on DDoS. |
| **E3** | *"The customer portal was knocked offline by a 400 Gbps SYN flood and DNS amplification attack targeting edge routers."* | DDoS | **Data Breach** | 0.2181 | The phrase `"customer portal"` heavily shifted weights toward Data Breach templates (which discuss customer databases), overriding technical network terms like `"amplification"`. |
| **E4** | *"A departing software engineer cloned private company repositories and transferred intellectual property to a personal USB device."* | Insider Threat | **Malware** | 0.1949 | Lexical gap: Neither `"cloned"`, `"repositories"`, nor `"USB device"` appeared in the 12 training templates. The model had no learned associations for these concepts and misattributed the payload to Malware. |
| **E5** | *"System administrator abused privileged root access to snoop on executive Slack messages and download confidential compensation records."* | Insider Threat | **Data Breach** | 0.4108 | Features `"confidential"`, `"records"`, and `"download"` possess high positive linear coefficients for Data Breach in the model, overwhelming the insider context of `"privileged root access"`. |

---

### 5.2 The 12 Severity Prediction Misclassifications & Majority Baseline Failure

On the independent benchmark, the severity model collapsed almost entirely into the `"Medium"` class:
- **15 out of 18 samples** were predicted as `"Medium"`.
- **0 out of 6 "High" severity samples** were correctly identified (Recall = 0.00).
- **0 out of 1 "Low" severity sample** was correctly identified (Recall = 0.00).
- **Only 1 out of 5 "Critical" severity samples** was correctly identified (Recall = 0.20; Sample 9: Akira group encrypting backup SAN storage).

#### Majority Baseline Analysis:
In the 180-row synthetic training dataset, `"Medium"` accounts for **43.3%** of all samples (78/180). On the 18-sample benchmark, `"Medium"` appears in **33.3%** of samples (6/18).
A completely naive baseline classifier that always predicts `"Medium"` regardless of input would achieve:
$$\text{Baseline Accuracy} = \frac{6}{18} = 33.33\%$$
The trained logistic regression severity model achieved **exactly 33.33% accuracy (6/18)**.
**Conclusion:** On unseen realistic text, the severity prediction model provides **zero predictive uplift over a trivial majority-class heuristic**.

---

## 6. Methodological Limitations of the ML Pipeline

### 6.1 Synthetic Template Overlap (Root Cause of 100% Holdout Scores)
Inspection of `backend/data/generate_training_data.py` reveals that the 180 training samples were generated using only **12 rigid sentence templates** (exactly 2 templates per incident type):
- The generator creates 15 instances per template by slot-filling placeholders (e.g., swapping IP addresses, domain names, and user names).
- Normalization strips punctuation and numbers via `normalize_for_model()`:
  ```python
  def normalize_for_model(text: str) -> str:
      text = clean_text(text)
      tokens = tokenize(text)
      tokens = [t for t in tokens if t not in STOPWORDS and len(t) > 1]
      return " ".join(tokens)
  ```
- Because placeholder slots (IPs, hashes, usernames) are either stripped or treated as rare out-of-vocabulary tokens, **30 rows in the training set become identical exact lexical duplicates**.
- When an 80/20 train/test split or 5-fold CV is performed, identical sentence templates appear simultaneously in both the training fold and the test fold. The model simply memorizes the 12 templates, resulting in artificial 100% holdout accuracy.

### 6.2 Pre-Split Vectorizer Fit in `ml_pipeline.py` (Data Leakage)
In `backend/app/ml_pipeline.py` (lines 34–38):
```python
self.vectorizer = TfidfVectorizer(max_features=3000, ngram_range=(1, 2), min_df=1)
X = self.vectorizer.fit_transform(cleaned)
X_train, X_test, y_train, y_test = train_test_split(X, labels, ...)
```
`TfidfVectorizer.fit_transform()` is executed on the entire dataset *before* `train_test_split()`. This constitutes data leakage: the inverse document frequency (IDF) weights and feature vocabulary encode statistical distribution information from the test set into the training representations. In contrast, `backend/evaluate_models.py` correctly uses a scikit-learn `Pipeline` fitted strictly on `X_train`.

### 6.3 Ground-Truth Severity Generation Flaw
In `backend/data/generate_training_data.py`, the training labels for severity were not assigned by certified SOC analysts or calibrated to CVSS/EPSS scores. Instead, they were generated using naive keyword matching:
```python
def infer_severity(text):
    if any(k in text for k in ["critical", "catastrophic", "unrecoverable"]):
        return "Critical"
    elif any(k in text for k in ["severe", "high", "privilege escalation"]):
        return "High"
    ...
    return "Medium"
```
When natural incident reports use varied vocabulary (e.g., *"400 Gbps SYN flood"* or *"unprotected Elasticsearch cluster"*), the absence of those exact template trigger words causes the rule (and the model trained on it) to default to "Medium".

---

## 7. Algorithm Comparison Verification

The CIRIP dashboard and documentation reference multiple classical ML and deep learning algorithms. Static code inspection of `backend/app/main.py` (lines 756–810) and the frontend interface confirms the following empirical reality:

| Algorithm Candidate | Stated in Dashboard | Implemented in Backend | Evaluated with Empirical Metrics | Current System Role |
|---|:---:|:---:|:---:|:---|
| **Logistic Regression** | Yes | **Yes** (`ml_pipeline.py`) | **Yes** (Holdout + CV + Benchmark) | Active production classifier and severity engine |
| **Naive Bayes** | Yes | No | **No** (Marked "Not evaluated") | Reference placeholder in UI comparison table |
| **Linear SVM** | Yes | No | **No** (Marked "Not evaluated") | Reference placeholder in UI comparison table |
| **Random Forest** | Yes | No | **No** (Marked "Not evaluated") | Reference placeholder in UI comparison table |
| **Decision Tree** | Yes | No | **No** (Marked "Not evaluated") | Reference placeholder in UI comparison table |
| **K-Nearest Neighbors (KNN)**| Yes | No | **No** (Marked "Not evaluated") | Reference placeholder in UI comparison table |
| **Gradient Boosting** | Yes | No | **No** (Marked "Not evaluated") | Reference placeholder in UI comparison table |
| **Multi-Layer Perceptron (MLP)**| Yes | No | **No** (Marked "Not evaluated") | Reference placeholder in UI comparison table |
| **Transformer / BERT** | Yes | No | **No** (Marked "Not evaluated") | Reference placeholder in UI comparison table |

**Audit Affirmation:** No comparative superiority over SVM, Random Forest, or BERT can be claimed for CIRIP because those models have not been implemented or benchmarked on this dataset. Logistic Regression was selected purely for operational speed, zero-GPU laptop compatibility, and direct linear coefficient interpretability.
