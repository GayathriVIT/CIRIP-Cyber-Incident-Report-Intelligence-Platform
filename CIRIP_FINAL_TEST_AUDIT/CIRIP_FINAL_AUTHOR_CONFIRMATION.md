# CIRIP Final Author Confirmation & Academic Audit Questionnaire
**Project Title:** Cyber Incident Report Intelligence Platform (CIRIP)  
**Academic Target:** Vellore Institute of Technology (VIT) — CSI4001 Project-Only Report  
**Target Authors:** Shaktheesh & Gayathri  
**Audit Date:** October 31, 2026  
**Auditor:** Senior Software QA Engineer, Backend Architect & Academic Evaluator  

---

## 1. Overview & Purpose

This document provides a strict separation between:
1. **Technically Verified Information:** Facts, parameters, configurations, and empirical metrics extracted directly from the CIRIP source code and verified in the live execution environment.
2. **Author-Confirmed Information:** Academic, administrative, provenance, and contribution details that cannot be derived from source code alone and must be formally confirmed by the student authors (Shaktheesh and Gayathri) before final report submission.

---

## 2. Information Fully Verified from Codebase & Runtime

The following 14 technical items have been rigorously audited, fact-checked, and confirmed from the source code and execution environment. **The authors do not need to recalculate or guess these items**:

1. **Exact Preprocessing Operations:**
   - Text stripped of leading/trailing whitespace and normalized with `re.sub(r"\s+", " ", text)`.
   - Tokenization via `re.findall(r"[A-Za-z0-9\-\.]+", text.lower())` (explicitly preserves hyphens and periods to protect IPs, CVEs, and domains).
   - Stopword filtering using custom 128-word set (`preprocessing.py: STOPWORDS`).
   - Tokens with length $\le 1$ removed. No lemmatization or stemming applied.
2. **Translation & Multilingual Processing:**
   - Language detection using `langdetect.detect()`.
   - Translation for non-English text via `deep_translator.GoogleTranslator(source='auto', target='en')`.
   - Translated text feeds all downstream ML and NLP pipelines; original text preserved in `language_info`.
3. **ML Architecture & Hyperparameters:**
   - Models: Two TF-IDF + Logistic Regression pipelines (`incident_classifier`, `severity_model`).
   - TF-IDF: `max_features=3000`, `ngram_range=(1, 2)`, `min_df=1`, `sublinear_tf=False`.
   - Estimator: `LogisticRegression(C=2.0, max_iter=2000, solver='lbfgs', random_state=42)`.
   - Feature attribution: Linear coefficient weighting $W_i \times C_{k,i}$.
4. **Reproduced Machine Learning Metrics:**
   - Incident Type Holdout (80/20): **100.00% Accuracy, 1.0000 Macro F1** (36/36 correct).
   - Incident Type 5-Fold CV: **100.00% Accuracy ($\pm 0.00$)**.
   - Incident Type Out-of-Distribution Benchmark: **72.22% Accuracy, 0.7136 Macro F1** (13/18 correct).
   - Severity Prediction Holdout (80/20): **100.00% Accuracy, 1.0000 Macro F1** (36/36 correct).
   - Severity Prediction 5-Fold CV: **100.00% Accuracy ($\pm 0.00$)**.
   - Severity Prediction Out-of-Distribution Benchmark: **33.33% Accuracy, 0.1989 Macro F1** (6/18 correct).
5. **Exact 5 Benchmark Classification Misclassifications:**
   - Sample 5 (True: Malware $\rightarrow$ Pred: Data Breach, conf: 0.2702)
   - Sample 6 (True: Malware $\rightarrow$ Pred: DDoS, conf: 0.2227)
   - Sample 10 (True: DDoS $\rightarrow$ Pred: Data Breach, conf: 0.2181)
   - Sample 13 (True: Insider Threat $\rightarrow$ Pred: Malware, conf: 0.1949)
   - Sample 14 (True: Insider Threat $\rightarrow$ Pred: Data Breach, conf: 0.4108)
6. **Majority Class Baseline Limitation for Severity:**
   - "Medium" severity represents 43.3% of synthetic training data.
   - On the 18-sample benchmark, the model predicted "Medium" for 15 samples, achieving 33.33% accuracy, matching the trivial majority baseline.
7. **Algorithm Evaluation Status in Dashboard:**
   - Implemented & Evaluated: Logistic Regression.
   - Listed but explicitly "Not evaluated": Naive Bayes, Linear SVM, Random Forest, Decision Tree, KNN, Gradient Boosting, MLP, Transformer/BERT.
8. **Threat Scoring Weights & Boundaries:**
   - Score range: $0 – 100$ (deterministic additive model).
   - Severity (up to 25 pts), Malware (up to 15 pts), CVEs (up to 10 pts), IoC richness (up to 20 pts), Attack keywords (up to 10 pts), Past incident correlation (up to 15 pts), High-risk type multiplier (5 pts).
   - Risk bands: Critical Risk (76–100), High Risk (51–75), Moderate Risk (26–50), Low Risk (0–25).
9. **ATT&CK Tactic Progression Mapping:**
   - Maps strictly to 9 MITRE tactics: TA0001 (Initial Access), TA0002 (Execution), TA0003 (Persistence), TA0004 (Privilege Escalation), TA0006 (Credential Access), TA0008 (Lateral Movement), TA0011 (Command & Control), TA0010 (Exfiltration), TA0040 (Impact).
   - Tactic-level mapping only; no technique or sub-technique fabrication.
10. **Threat Correlation Weights & Thresholds:**
    - Hash: 35 pts, IP: 30 pts, Domain: 25 pts, Malware: 20 pts, CVE: 15 pts, Text similarity: up to 15 pts, Keywords: 10 pts, Email: 8 pts, URL: 8 pts.
    - Thresholds: Strongly Related ($\ge 70$), Potentially Related ($40 – 69$), Weakly Related ($10 – 39$).
11. **Campaign Detection Parameters:**
    - Clustering algorithm: Disjoint Set Union (Union-Find) connected components.
    - Confidence threshold: $\ge 40\%$; Minimum cluster size: $\ge 2$ incidents; NATO naming convention.
12. **Summarization Algorithm:**
    - Extractive TextRank: Sentence splitting via regex $\rightarrow$ TF-IDF cosine similarity matrix $\rightarrow$ NetworkX PageRank $\rightarrow$ Top 3 sentences selected preserving original document order.
13. **Mitigation Playbooks:**
    - Fixed rule-based 4-phase playbooks (Immediate, Containment, Recovery, Prevention) across all 6 incident categories.
14. **Software & Runtime Environment:**
    - Python 3.12.0, Windows 11, FastAPI 0.115.0, Uvicorn 0.30.6, scikit-learn 1.5.2, NetworkX 3.3, ReportLab 4.2.5, PyMongo 4.8.0.
    - MongoDB on `localhost:27017` with automatic JSON fallback store at `backend/data/incidents_store.json`.

---

## 3. Author Action Checklist: Items Requiring Confirmation

The following questionnaire must be completed by **Shaktheesh** and **Gayathri** to finalize the VIT CSI4001 report:

### Question 1: Academic Registration Details
- **Course Code & Title:** CSI4001 — Project-Only
- **Class / Slot Number:** `[PLEASE FILL: e.g., L1+L2 / B2 / Virtual]`
- **Project Review Assessment:** `[PLEASE FILL: Review 1 / Review 2 / Final Project Assessment]`
- **Faculty Guide / Evaluator:** `[PLEASE FILL: Name of Guide, Designation, School (e.g., SCOPE)]`

### Question 2: Student Author Identification
- **Author 1 Name:** `[PLEASE FILL: Shaktheesh - Full Official Name]`
  - **Registration Number:** `[PLEASE FILL: e.g., 21BCE0000]`
  - **Email Address:** `[PLEASE FILL: student@vitstudent.ac.in]`
- **Author 2 Name:** `[PLEASE FILL: Gayathri - Full Official Name]`
  - **Registration Number:** `[PLEASE FILL: e.g., 21BCE0000]`
  - **Email Address:** `[PLEASE FILL: student@vitstudent.ac.in]`

### Question 3: Team Contribution Breakdown
*(VIT requires an explicit division of work for multi-member project-only assessments)*:

| Project Component | Primary Contributor | Percentage Contribution | Specific Tasks Handled |
|---|:---:|:---:|---|
| **Backend & Architecture** | `[Shaktheesh / Gayathri]` | `____%` | FastAPI setup, MongoDB integration, ReportLab PDF generator |
| **NLP & ML Pipelines** | `[Shaktheesh / Gayathri]` | `____%` | Preprocessing, TF-IDF vectorization, Logistic Regression, TextRank |
| **Cyber Intelligence Modules**| `[Shaktheesh / Gayathri]` | `____%` | IoC extraction regex, MITRE ATT&CK storyline, Threat scoring |
| **Frontend & Visualization** | `[Shaktheesh / Gayathri]` | `____%` | Vanilla JS client, Chart.js, Vis-network knowledge graph, CSS styling |
| **Evaluation & Benchmarking** | `[Shaktheesh / Gayathri]` | `____%` | Synthetic dataset generation, 5-fold CV, Independent benchmark curation |
| **Report Writing** | Both | 50% / 50% | Methodology documentation, literature survey, empirical analysis |

### Question 4: Provenance of the 18 Independent Benchmark Samples
*Confirm the origin of the 18 test incidents used in `backend/evaluate_models.py`:*
- [ ] Option A: Curated and written by Shaktheesh & Gayathri based on real-world CERT-In, CISA, and NIST cybersecurity incident reports.
- [ ] Option B: Extracted from publicly disclosed breach writeups (e.g., The Hacker News, BleepingComputer, MITRE ATT&CK case studies).
- [ ] Option C: Adapted from an academic cybersecurity incident dataset.
- *Notes on benchmark labeling:* `[PLEASE CLARIFY: e.g., Ground-truth severity labels were assigned by the authors based on business impact criteria.]`

### Question 5: Code Repository & Project Deliverables
- **GitHub / GitLab Repository URL:** `[PLEASE FILL: e.g., https://github.com/username/cyber-incident-intel-platform]`
- **Repository Visibility:** `[Public / Private with Reviewer Access]`
- **Demonstration Video Link:** `[PLEASE FILL: YouTube Unlisted / Google Drive Link]`
- **Running Port Confirmation:** Backend confirmed on `8000`, Frontend confirmed on `5500`.

### Question 6: Academic Integrity & AI Usage Disclosure
*VIT requires a formal disclosure regarding AI assistance in project development and documentation:*
- **Declaration Statement:**  
  *"We hereby declare that CIRIP was designed and developed by Shaktheesh and Gayathri for CSI4001. AI coding tools (such as Anthropic Claude API for optional narrative enrichment, and Antigravity AI pair programming assistant for code scaffolding and QA testing audit) were utilized in compliance with academic guidelines. All core algorithms, architecture, and empirical evaluation data were verified directly on our local deployment."*
- [ ] Confirmed by Shaktheesh
- [ ] Confirmed by Gayathri
