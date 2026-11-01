# CIRIP Implementation & Evaluation Verification Report
**Document Title:** Fact-Based Implementation and Empirical Evaluation Audit for IEEE Paper Correction  
**Project Name:** Cyber Incident Report Intelligence Platform (CIRIP)  
**Audit Date:** October 2026  
**Auditor Roles:** Senior Python Developer, Cybersecurity Researcher, and Software Quality Assurance Engineer  
**Audit Modality:** Read-Only Static Code Analysis & Deterministic Test Execution (No Project Modifications)

---

## A. Executive Summary

This independent audit rigorously verified the implementation status and quantitative evaluation claims of the Cyber Incident Report Intelligence Platform (CIRIP) codebase. The audit was conducted strictly adhering to read-only safety constraints: no source files, configuration files, trained model binaries, or evaluation artifacts were altered.

### Key Audit Findings:

1. **Implementation Coverage:**
   - **All 15 distinct functional components** referenced in the IEEE research paper (and Table I) are genuinely implemented in the Python backend (`backend/app/`) and fully accessible through the FastAPI application workflow (`backend/app/main.py`) and frontend dashboard (`frontend/`).
   - The platform encompasses a complete defensive cybersecurity workflow: multilingual text ingestion, regex/gazetteer entity and IoC extraction, TF-IDF + Logistic Regression triage, explainable feature attribution, deterministic threat risk scoring, MITRE ATT&CK tactic progression mapping, cross-incident indicator correlation, graph-based campaign clustering, NetworkX knowledge graph synthesis, and professional multi-page ReportLab PDF generation.

2. **Empirical Evaluation Reality vs. Methodological Scope:**
   - **Only two machine learning tasks were quantitatively evaluated**: (1) Incident-Type Classification and (2) Severity Prediction. Both employ a TF-IDF vectorizer coupled with multiclass Logistic Regression.
   - **No other algorithm was evaluated:** Claims that Logistic Regression outperforms algorithms such as Naive Bayes, Linear Support Vector Machines (SVM), Random Forest, Decision Trees, K-Nearest Neighbors, Gradient Boosting, Multi-Layer Perceptrons, or BERT/Transformer architectures are **empirically unverified in this codebase**. As documented in `backend/app/main.py` (lines 756–810) and the frontend evaluation view, these algorithms are explicitly marked `"Not evaluated"`. Logistic Regression was selected solely for its operational simplicity, linear coefficient interpretability, and low computational overhead.
   - **All rule-based and heuristic modules** (IoC extraction, entity extraction, TextRank summarization, MITRE ATT&CK stage mapping, threat scoring, cross-incident correlation, campaign detection, mitigation guidance, and knowledge graph construction) **lack labeled ground-truth evaluation datasets and quantitative performance metrics** (such as Precision, Recall, F1-score, ROUGE scores, or clustering Adjusted Rand Index). They are verified at the source-code and functional levels only.

3. **Machine Learning Metrics Verification:**
   - **Synthetic In-Distribution Holdout (80/20 split & 5-fold CV):** Both incident classification and severity prediction achieve **100.00% accuracy and 1.0000 Macro F1**. However, this result is heavily conditioned by the dataset construction: the 180-sample training dataset (`training_data.csv`) was synthetically generated from only 12 rigid templates (2 per incident type) with slot-filled entity permutations, resulting in 30 exact duplicates and high lexical homogeneity.
   - **Independent Out-of-Distribution Benchmark (18 realistic, unseen incident narratives):**
     - **Incident Classification:** Exactly reproduces **72.22% Accuracy (13/18)** and **0.71 Macro F1**.
     - **Severity Prediction:** Exactly reproduces **33.33% Accuracy (6/18)** and **0.20 Macro F1**.
     - **Root Cause of Severity Drop:** Severity labels in the synthetic dataset were generated using naive keyword heuristics (`infer_severity()` in `generate_training_data.py`), with "Medium" comprising 43.3% of the training distribution. On realistic unseen text, the model predicted "Medium" for 15 out of 18 samples, achieving 0.00 Precision and 0.00 Recall on both "High" and "Low" severity levels.

4. **Security, Privacy & Architectural Disclosures:**
   - **External Transmission of Incident Text:** Despite claims of local/offline processing, non-English incident reports trigger `deep_translator.GoogleTranslator` (`backend/app/language_utils.py`), which transmits incident text over the public internet to Google Translate endpoints. Furthermore, enabling optional LLM enrichment transmits incident text to Anthropic's Claude API.
   - **Data Leakage in Training Script:** In `backend/app/ml_pipeline.py` (lines 34–38), `TfidfVectorizer.fit_transform()` is executed on the entire dataset *prior* to `train_test_split()`, leaking vocabulary and IDF weights across train/test boundaries. In contrast, the evaluation script (`backend/evaluate_models.py`) correctly encapsulates vectorization within a scikit-learn `Pipeline` fitted strictly on training folds.

---

## B. Project Files Inspected

The audit inspected all functional and configuration files across the repository structure:

| File Path | Description / Role in CIRIP | Lines Audited |
|---|---|---|
| [`backend/app/main.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/main.py) | Primary FastAPI application, REST endpoints, workflow orchestration, evaluation payloads | Lines 1–819 |
| [`backend/app/ml_pipeline.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/ml_pipeline.py) | ML pipeline class (`TfidfLogRegPipeline`), vectorization, training, inference, feature explainability | Lines 1–98 |
| [`backend/app/language_utils.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/language_utils.py) | Language detection (`langdetect`) and translation (`deep-translator` via Google Translate) | Lines 1–82 |
| [`backend/app/preprocessing.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/preprocessing.py) | Regex text cleaning, tokenization preserving IoC punctuation, custom stopword filtering | Lines 1–31 |
| [`backend/app/ioc_extraction.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/ioc_extraction.py) | Regex-based indicator extraction (IPv4, IPv6, domains, URLs, emails, MD5/SHA1/SHA256, CVEs) | Lines 1–72 |
| [`backend/app/ner_entities.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/ner_entities.py) | Gazetteer substring lookup (malware, attack keywords) and regex heuristics (users, orgs, CVEs) | Lines 1–50 |
| [`backend/app/summarizer.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/summarizer.py) | Extractive summarization using sentence-level TF-IDF cosine similarity and NetworkX TextRank | Lines 1–42 |
| [`backend/app/storyline_generator.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/storyline_generator.py) | MITRE ATT&CK tactic progression mapping (TA0001–TA0040) based on keyword matching | Lines 1–285 |
| [`backend/app/threat_scoring.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/threat_scoring.py) | Deterministic 0–100 threat scoring engine based on additive rule weights | Lines 1–160 |
| [`backend/app/threat_correlation.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/threat_correlation.py) | Cross-incident correlation engine comparing shared IoCs, entities, and TF-IDF text similarity | Lines 1–201 |
| [`backend/app/campaign_detection.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/campaign_detection.py) | Graph-based clustering via Union-Find disjoint sets to identify multi-incident threat campaigns | Lines 1–221 |
| [`backend/app/mitigation.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/mitigation.py) | Rule-based recommendation engine keyed by incident type and severity level | Lines 1–127 |
| [`backend/app/knowledge_graph.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/knowledge_graph.py) | Per-incident star-topology graph and cross-incident graph merging via NetworkX | Lines 1–116 |
| [`backend/app/report_generator.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/report_generator.py) | Multi-page professional threat intelligence PDF generator built with ReportLab Platypus | Lines 1–903 |
| [`backend/app/llm_integration.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/llm_integration.py) | Optional integration with Anthropic Claude API (`claude-sonnet-4-6`) | Lines 1–59 |
| [`backend/app/db.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/db.py) | Storage abstraction: PyMongo MongoDB connection with transparent JSON fallback store | Lines 1–97 |
| [`backend/app/schemas.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/schemas.py) | Pydantic request models (`AnalyzeRequest`) | Lines 1–9 |
| [`backend/evaluate_models.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/evaluate_models.py) | Standalone evaluation script executing holdout, 5-fold CV, and independent benchmark tests | Lines 1–202 |
| [`backend/train_models.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/train_models.py) | Script to train and serialize classifier and severity joblib models | Lines 1–47 |
| [`backend/data/generate_training_data.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/data/generate_training_data.py) | Synthetic template-based generator creating `training_data.csv` (180 samples) | Lines 1–142 |
| [`backend/data/training_data.csv`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/data/training_data.csv) | CSV dataset containing 180 labeled incident records | 181 rows |
| [`backend/data/campaigns_store.json`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/data/campaigns_store.json) | Local JSON store tracking identified multi-incident threat campaigns | JSON data |
| [`backend/requirements.txt`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/requirements.txt) | Python dependencies specifying exact pinned package versions | 15 lines |
| [`frontend/index.html`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/frontend/index.html) | Single-page HTML application interface and view containers | Lines 1–1371 |
| [`frontend/app.js`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/frontend/app.js) | Frontend client logic, state management, REST consumption, and DOM rendering | Lines 1–1979 |
| [`frontend/style.css`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/frontend/style.css) | Custom styling, CSS custom properties, and dashboard layouts | Lines 1–1900 |

---

## C. Implementation Verification Table

This table maps every candidate component from the IEEE paper against its exact source code realization, workflow reachability, and implementation status.

| # | Component | Implementation Status | Source File & Function / Class | Empirical & Structural Evidence | Remaining Limitations |
|---|---|---|---|---|---|
| 1 | **Language detection and translation** | Implemented and verified | [`backend/app/language_utils.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/language_utils.py): `detect_and_translate()` (L30–81) | Invoked in [`main.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/main.py#L132-L137) at the start of `/api/analyze`. Translates non-English incident text before feeding to ML models. | Relies on `langdetect` heuristics; translation uses `deep_translator.GoogleTranslator`, which transmits incident text to public Google endpoints over the internet. |
| 2 | **Text preprocessing** | Implemented and verified | [`backend/app/preprocessing.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/preprocessing.py): `clean_text()`, `tokenize()`, `normalize_for_model()` (L14–30) | Invoked in [`ml_pipeline.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/ml_pipeline.py#L33), [`main.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/main.py#L234), and [`evaluate_models.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/evaluate_models.py#L47). | Regex token pattern `[A-Za-z0-9\-\.]+` is English-specific; hardcoded 128-word stopword list; does not perform lemmatization or stemming. |
| 3 | **Incident-type classification** | Implemented and verified | [`backend/app/ml_pipeline.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/ml_pipeline.py): `TfidfLogRegPipeline.predict()` (L49–57) | Invoked in [`main.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/main.py#L139). Loads `incident_classifier.joblib` from `backend/app/models_store/`. Produces label, confidence, and class probabilities. | Trained on synthetic template data; vocabulary limited to 3,000 n-grams; independent benchmark accuracy drops from 100% to 72.22%. |
| 4 | **Severity prediction** | Implemented and verified | [`backend/app/ml_pipeline.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/ml_pipeline.py): `TfidfLogRegPipeline.predict()` (L49–57) | Invoked in [`main.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/main.py#L143). Loads `severity_model.joblib`. Returns predicted severity (Low/Medium/High/Critical). | Ground-truth labels in training data were generated via simple keyword rules, not SOC analysts. Independent benchmark accuracy is only 33.33% (Macro F1: 0.20). |
| 5 | **Model feature contributions / explainability** | Implemented and verified | [`backend/app/ml_pipeline.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/ml_pipeline.py): `TfidfLogRegPipeline.explain()` (L59–79) | Invoked in [`main.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/main.py#L140,L144). Computes $W_i \times C_{k,i}$ (TF-IDF weight multiplied by logistic regression coefficient). | Linear attribution only; ignores feature interactions; lacks quantitative faithfulness/SHAP comparative validation. |
| 6 | **IoC extraction** | Implemented and verified | [`backend/app/ioc_extraction.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/ioc_extraction.py): `extract_iocs()` (L37–71) | Invoked in [`main.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/main.py#L147). Extracts IPv4, IPv6, domains, URLs, emails, CVEs, and MD5/SHA1/SHA256 hashes. | Rule-based regex only. Cannot parse defanged indicators (`hxxp[:]//`, `example[.]com`); limited to 15 hardcoded top-level domains. |
| 7 | **Entity extraction** | Implemented and verified | [`backend/app/ner_entities.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/ner_entities.py): `extract_entities()` (L33–49) | Invoked in [`main.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/main.py#L150). Matches malware names, attack keywords, users, orgs, CVEs. | Gazetteer list contains only 21 malware families and 18 attack terms; user extraction requires literal prefix `"user "`; no statistical or transformer NER model. |
| 8 | **Extractive summarization** | Implemented and verified | [`backend/app/summarizer.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/summarizer.py): `extractive_summary()` (L21–41) | Invoked in [`main.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/main.py#L153) as the default offline summarizer. Builds NetworkX graph of sentence TF-IDF cosine similarities and runs PageRank. | For texts with $\le 3$ sentences, returns unmodified input. No quantitative ROUGE benchmark against human reference summaries. |
| 9 | **MITRE ATT&CK-inspired stage mapping** | Implemented and verified | [`backend/app/storyline_generator.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/storyline_generator.py): `generate_storyline()` (L143–285) | Invoked in [`main.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/main.py#L212) and exposed via `GET /api/storyline/{id}`. Maps incident context to 9 ATT&CK tactics (TA0001–TA0040). | Keyword-based tactic mapping only; does not identify fine-grained ATT&CK *Techniques* (e.g., T1566) or sub-techniques. |
| 10 | **Mitigation guidance** | Implemented and verified | [`backend/app/mitigation.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/mitigation.py): `get_recommendations()` (L120–126) | Invoked in [`main.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/main.py#L163). Returns structured dictionary (immediate response, containment, recovery, prevention). | Static lookup table keyed solely by predicted incident type (6 fixed playbooks). No dynamic parameter tailoring to specific network infrastructure. |
| 11 | **Threat score** | Implemented and verified | [`backend/app/threat_scoring.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/threat_scoring.py): `calculate_threat_score()` (L32–151) | Invoked in [`main.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/main.py#L218,L250) and exposed via `GET /api/threat-score/{id}`. Outputs 0–100 score and risk tier. | Deterministic additive scoring model using author-defined heuristic weights; weights are not statistically calibrated or fitted against external loss data. |
| 12 | **Cross-incident correlation and campaign detection** | Implemented and verified | [`backend/app/threat_correlation.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/threat_correlation.py): `correlate_incident()` (L59–200); [`backend/app/campaign_detection.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/campaign_detection.py): `detect_campaigns()` (L95–210) | Invoked in [`main.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/main.py#L240,L267). Exposed via `GET /api/correlations/{id}` and `GET /api/campaigns`. Clusters related incidents via Union-Find. | Indicator weights and 40% confidence threshold are heuristic choices; no evaluation against labeled multi-stage APT attack datasets. |
| 13 | **Knowledge graph** | Implemented and verified | [`backend/app/knowledge_graph.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/knowledge_graph.py): `build_incident_graph()`, `merge_graphs()` (L13–116) | Invoked in [`main.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/main.py#L175,L415). Generates NetworkX node-link JSON consumed by vis-network in frontend. | Star-topology bipartite graph (Incident $\leftrightarrow$ Indicator/Entity); no typed ontology (e.g. STIX 2.1/OWL); no graph embedding or link prediction. |
| 14 | **PDF report generation** | Implemented and verified | [`backend/app/report_generator.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/report_generator.py): `generate_pdf()` (L503–903) | Exposed via `GET /api/report/{incident_id}/pdf` in [`main.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/main.py#L595–683). Dynamically compiles a 12-section PDF document. | Document compilation module; evaluated by manual visual layout verification. |
| 15 | **Optional LLM summary/narrative** | Implemented and verified | [`backend/app/llm_integration.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/llm_integration.py): `generate_llm_summary()`, `generate_llm_recommendation()` (L41–58) | Conditionally triggered in [`main.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/main.py#L155–171) only when `req.use_llm` is true and `ANTHROPIC_API_KEY` is set. | Requires third-party cloud API key; transmits sensitive incident text to Anthropic servers; excluded from quantitative evaluation. |

---

## D. Quantitative Evaluation Verification Table

This table details the empirical evaluation status of every platform component, distinguishing between true quantitative benchmarking and functional demonstration.

| Component / Model | Evaluation Status | Empirical Metrics Available | Evaluation Method | Dataset / Sample Count | Reproducibility Status | Key Limitations |
|---|---|---|---|---|---|---|
| **Incident-Type Classifier** | Quantitatively evaluated | • Holdout Acc: 100.00%<br>• Holdout Macro F1: 1.00<br>• 5-Fold CV Acc: 100.00%<br>• Benchmark Acc: 72.22%<br>• Benchmark Macro F1: 0.71 | Stratified 80/20 train/test split, 5-Fold Stratified CV, and out-of-distribution benchmark | • Synthetic: 180 samples (144 train / 36 test)<br>• Benchmark: 18 realistic unseen reports | **Fully reproduced** via `backend/evaluate_models.py` | 100% holdout score is inflated by template-based data generation. Benchmark dataset is small ($N=18$). No comparisons against SVM or Random Forest. |
| **Severity Predictor** | Quantitatively evaluated | • Holdout Acc: 100.00%<br>• Holdout Macro F1: 1.00<br>• 5-Fold CV Acc: 100.00%<br>• Benchmark Acc: 33.33%<br>• Benchmark Macro F1: 0.20 | Stratified 80/20 train/test split, 5-Fold Stratified CV, and out-of-distribution benchmark | • Synthetic: 180 samples (144 train / 36 test)<br>• Benchmark: 18 realistic unseen reports | **Fully reproduced** via `backend/evaluate_models.py` | Training labels based on naive string rules (`infer_severity()`). Fails completely on unseen High and Low severities (0.00 F1). |
| **Comparative Baseline Models** (Naive Bayes, SVM, RF, Decision Tree, KNN, Gradient Boosting, Neural Net, BERT) | **Not evaluated** | None (`"Not evaluated"` returned by API) | None (explicitly listed as future work in `backend/app/main.py` lines 756–810) | None | **Confirmed absent** | The paper cannot claim that Logistic Regression is superior to these algorithms. |
| **Language Detection & Translation** | Tested functionally only | None (no WER / BLEU score) | Illustrative manual test | None | Functional verification only | External API call to Google Translate is not benchmarked for latency or translation fidelity. |
| **IoC Extraction** | Tested functionally only | None (no Precision, Recall, or F1) | Static code & regex inspection | None (no annotated IoC corpus like CASIE or CySecNER) | Functional verification only | Accuracy across defanged or obfuscated IoCs is unquantified. |
| **Entity Extraction** | Tested functionally only | None (no Precision, Recall, or F1) | Substring & regex inspection | None (no labeled cybersecurity NER dataset) | Functional verification only | Substring gazetteer matching prone to ambiguity and false positives. |
| **Extractive Summarizer** | Tested functionally only | None (no ROUGE-1, ROUGE-2, ROUGE-L) | TextRank graph inspection | None (no human reference summary corpus) | Functional verification only | Compression ratio and summary informativeness are unmeasured. |
| **MITRE ATT&CK Mapping** | Tested functionally only | None (no Precision/Recall per tactic) | Keyword dictionary inspection | None (no MITRE-mapped ground truth incident dataset) | Functional verification only | Keyword matching may infer attack stages without true causal evidence. |
| **Threat Score** | Tested functionally only | None (no correlation with financial loss or CVSS) | Deterministic score formula check | None (no calibrated threat scoring benchmark) | Functional verification only | Score is an uncalibrated heuristic sum of points. |
| **Correlation & Campaign Detection** | Tested functionally only | None (no Adjusted Rand Index or F-measure) | Union-Find graph algorithm inspection | None (no multi-incident campaign ground truth) | Functional verification only | Clustering threshold ($\ge 40$ confidence) is empirically unvalidated. |
| **Mitigation Guidance** | Tested functionally only | None (no expert acceptance rating) | Static dictionary inspection | None | Functional verification only | Recommends identical fixed text blocks for any incident of the same category. |
| **Knowledge Graph** | Tested functionally only | None (no link prediction / graph metrics) | NetworkX graph structure inspection | None | Functional verification only | Evaluated only via visual node-link rendering in UI. |
| **PDF Report Generation** | Tested functionally only | None (visual rendering inspection) | ReportLab document generation | None | Functional verification only | Visual inspection confirms correct 12-section layout compilation. |
| **Optional LLM Summary** | Demonstrated with illustrative example | None (no quantitative human preference score) | Conditional API call inspection | None | Excluded from offline quantitative evaluation | Dependent on external Anthropic API availability and user opt-in. |

---

## E. Machine-Learning Results Verification

### 1. Dataset & Class Distribution
The dataset file [`backend/data/training_data.csv`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/data/training_data.csv) contains **180 records** generated by [`backend/data/generate_training_data.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/data/generate_training_data.py).

- **Incident-Type Distribution:** Perfectly balanced across 6 classes (30 records / 16.7% per class):
  - Phishing: 30
  - Malware: 30
  - Ransomware: 30
  - DDoS: 30
  - Insider Threat: 30
  - Data Breach: 30
- **Severity Distribution:** Imbalanced across 4 severity tiers:
  - Medium: 78 (43.3%)
  - Critical: 41 (22.8%)
  - High: 31 (17.2%)
  - Low: 30 (16.7%)
- **Template Diversity & Duplicates:**
  - The dataset is derived from only **12 templates** (2 per incident type).
  - Out of 180 records, there are **150 unique text strings** and **30 exact duplicates** (16.7% duplicate rate).
  - Even non-duplicate rows differ only by random slot substitutions (5 organization names, 5 user names, 6 IPs, 4 domains, 3 file hashes, 5 CVEs, 10 malware family names).

### 2. Model & Vectorizer Configuration
- **Preprocessing:** Normalization in `backend/app/preprocessing.py` performs lowercasing, whitespace trimming, regex tokenization (`[A-Za-z0-9\-\.]+`), and removes 128 English stopwords.
- **TF-IDF Vectorizer:** `TfidfVectorizer(max_features=3000, ngram_range=(1, 2), min_df=1)`.
- **Classifier:** `LogisticRegression(max_iter=2000, C=2.0, multi_class="auto")`.
- **Train/Test Split:** Stratified 80/20 train/test split ($N_{\text{train}} = 144$, $N_{\text{test}} = 36$), random seed = 42.

### 3. Data Leakage Finding
In [`backend/app/ml_pipeline.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/ml_pipeline.py#L34-L38):
```python
self.vectorizer = TfidfVectorizer(max_features=3000, ngram_range=(1, 2), min_df=1)
X = self.vectorizer.fit_transform(cleaned)
X_train, X_test, y_train, y_test = train_test_split(
    X, labels, test_size=test_size, random_state=random_state, stratify=labels
)
```
Fitting the vectorizer on the combined corpus prior to splitting causes **information leakage**: vocabulary inclusion and inverse document frequencies from the test fold influence the feature representation of the training fold. In `backend/evaluate_models.py`, this is resolved by using an explicit scikit-learn `Pipeline` where `fit()` is invoked only on `X_train`.

### 4. Empirical Test Execution & Results
Executing `backend/evaluate_models.py` via Python 3.12 within `backend/venv` yielded the following verified metrics:

#### Incident-Type Classifier:
- **Training Accuracy:** 100.00%
- **Holdout Test Accuracy (80/20):** 100.00%
- **Holdout Macro Precision, Recall, F1:** 1.0000, 1.0000, 1.0000
- **5-Fold Stratified Cross-Validation:** Folds = `[1.0, 1.0, 1.0, 1.0, 1.0]`, Mean = 1.0000 ($\pm 0.0000$)
- **Holdout Confusion Matrix ($6 \times 6$):**
  $$\begin{bmatrix} 6 & 0 & 0 & 0 & 0 & 0 \\ 0 & 6 & 0 & 0 & 0 & 0 \\ 0 & 0 & 6 & 0 & 0 & 0 \\ 0 & 0 & 0 & 6 & 0 & 0 \\ 0 & 0 & 0 & 0 & 6 & 0 \\ 0 & 0 & 0 & 0 & 0 & 6 \end{bmatrix}$$
  *(Classes: DDoS, Data Breach, Insider Threat, Malware, Phishing, Ransomware)*

#### Severity Predictor:
- **Training Accuracy:** 100.00%
- **Holdout Test Accuracy (80/20):** 100.00%
- **Holdout Macro Precision, Recall, F1:** 1.0000, 1.0000, 1.0000
- **5-Fold Stratified Cross-Validation:** Folds = `[1.0, 1.0, 1.0, 1.0, 1.0]`, Mean = 1.0000 ($\pm 0.0000$)
- **Holdout Confusion Matrix ($4 \times 4$):**
  $$\begin{bmatrix} 8 & 0 & 0 & 0 \\ 0 & 6 & 0 & 0 \\ 0 & 0 & 6 & 0 \\ 0 & 0 & 0 & 16 \end{bmatrix}$$
  *(Classes: Critical, High, Low, Medium)*

### 5. Independent Out-of-Distribution Benchmark Verification
The independent benchmark in [`backend/evaluate_models.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/evaluate_models.py#L137-L167) consists of **18 hand-crafted, realistic incident narratives** exhibiting varied vocabulary and terminology not found in the training templates.

#### Incident Classification Performance on Independent Benchmark:
- **Accuracy:** **72.22%** (13/18 correctly classified)
- **Macro Precision:** 0.78
- **Macro Recall:** 0.72
- **Macro F1-Score:** **0.71**
- **Weighted F1-Score:** 0.71

| Incident Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| **DDoS** | 0.67 | 0.67 | 0.67 | 3 |
| **Data Breach** | 0.50 | 1.00 | 0.67 | 3 |
| **Insider Threat** | 1.00 | 0.33 | 0.50 | 3 |
| **Malware** | 0.50 | 0.33 | 0.40 | 3 |
| **Phishing** | 1.00 | 1.00 | 1.00 | 3 |
| **Ransomware** | 1.00 | 1.00 | 1.00 | 3 |
| **Macro Average** | **0.78** | **0.72** | **0.71** | **18** |

- **Independent Benchmark Confusion Matrix (Incident Type):**
  $$\begin{bmatrix} 2 & 1 & 0 & 0 & 0 & 0 \\ 0 & 3 & 0 & 0 & 0 & 0 \\ 0 & 1 & 1 & 1 & 0 & 0 \\ 1 & 1 & 0 & 1 & 0 & 0 \\ 0 & 0 & 0 & 0 & 3 & 0 \\ 0 & 0 & 0 & 0 & 0 & 3 \end{bmatrix}$$
  *(Order: DDoS, Data Breach, Insider Threat, Malware, Phishing, Ransomware)*

#### Severity Prediction Performance on Independent Benchmark:
- **Accuracy:** **33.33%** (6/18 correctly classified)
- **Macro Precision:** 0.33
- **Macro Recall:** 0.26
- **Macro F1-Score:** **0.20**
- **Weighted F1-Score:** 0.24

| Severity Class | Precision | Recall | F1-Score | Support |
|---|---|---|---|---|
| **Critical** | 1.00 | 0.20 | 0.33 | 5 |
| **High** | 0.00 | 0.00 | 0.00 | 6 |
| **Low** | 0.00 | 0.00 | 0.00 | 1 |
| **Medium** | 0.31 | 0.83 | 0.45 | 6 |
| **Macro Average** | **0.33** | **0.26** | **0.20** | **18** |

- **Independent Benchmark Confusion Matrix (Severity):**
  $$\begin{bmatrix} 1 & 0 & 0 & 4 \\ 0 & 0 & 0 & 6 \\ 0 & 0 & 0 & 1 \\ 0 & 1 & 0 & 5 \end{bmatrix}$$
  *(Order: Critical, High, Low, Medium)*

**Confirmation:** The reported figures of **72.22% accuracy / 0.71 Macro F1** for incident classification and **33.33% accuracy / 0.20 Macro F1** for severity prediction are **100% exact and mathematically verified**.

---

## F. Rule-Based Module Verification

Every rule-based component was examined to determine whether genuine evaluation scripts or labeled ground-truth datasets exist:

| Module | Source Code Implementation | Functional Test Evidence | Ground Truth Corpus Available | Quantitative Performance Metrics |
|---|---|---|---|---|
| **IoC Extraction** | [`backend/app/ioc_extraction.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/ioc_extraction.py) (L37–71) | Verified via API execution and live payload tests | **None** (no labeled test corpus) | **None** (no Precision, Recall, or F1 measured) |
| **Entity Extraction** | [`backend/app/ner_entities.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/ner_entities.py) (L33–49) | Verified via API execution and live payload tests | **None** (no labeled test corpus) | **None** (no Precision, Recall, or F1 measured) |
| **Summarization** | [`backend/app/summarizer.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/summarizer.py) (L21–41) | Verified via TextRank graph ranking | **None** (no human reference summaries) | **None** (no ROUGE-1/2/L or BLEU scores) |
| **ATT&CK Mapping** | [`backend/app/storyline_generator.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/storyline_generator.py) (L143–285) | Verified via storyline graph generation | **None** (no MITRE ground truth annotations) | **None** (no tactic/technique classification metrics) |
| **Threat Scoring** | [`backend/app/threat_scoring.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/threat_scoring.py) (L32–151) | Verified via deterministic point summation | **None** (no expert risk validation) | **None** (weights are uncalibrated heuristics) |
| **Correlation & Campaigns** | [`backend/app/threat_correlation.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/threat_correlation.py) & [`campaign_detection.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/campaign_detection.py) | Verified via Union-Find connected components | **None** (no labeled multi-incident campaigns) | **None** (no clustering purity or ARI evaluated) |
| **Knowledge Graph** | [`backend/app/knowledge_graph.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/knowledge_graph.py) (L13–116) | Verified via NetworkX node-link conversion | **None** | **None** (no link prediction or graph metrics) |
| **Mitigation Engine** | [`backend/app/mitigation.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/mitigation.py) (L120–126) | Verified via static table retrieval | **None** (no expert evaluation) | **None** |
| **PDF Reporting** | [`backend/app/report_generator.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/report_generator.py) (L503–903) | Verified via ReportLab compilation | N/A | **None** (visual layout inspection only) |

**Conclusion:** The IEEE paper must explicitly state that rule-based modules are verified for functional correctness and operational integrity, but have **not been quantitatively evaluated against annotated benchmark corpora**.

---

## G. Discrepancies Between the IEEE Paper and Actual Code

The following discrepancies must be resolved to align the paper with the codebase:

1. **Algorithm Comparison & Superiority Claims:**
   - *Paper Claim:* Logistic Regression was shown to outperform alternative models (such as Naive Bayes, Linear SVM, Random Forest, or Decision Trees).
   - *Code Reality:* **No comparative experiments were performed.** `backend/app/main.py` lines 756–810 and the frontend comparison table explicitly mark all eight alternative classifiers as `"Not evaluated"`. Logistic Regression was chosen for low computational overhead, lack of GPU requirements, and linear coefficient interpretability.

2. **Holdout Evaluation Generalizability:**
   - *Paper Claim:* Logistic Regression achieves 100% accuracy on cyber incident classification and severity triage.
   - *Code Reality:* The 100% holdout accuracy is solely an artifact of the synthetic, template-based dataset (180 samples generated from 12 static templates with 30 exact duplicates). On realistic out-of-distribution text, incident classification accuracy drops to **72.22% (Macro F1: 0.71)** and severity prediction accuracy collapses to **33.33% (Macro F1: 0.20)**.

3. **MITRE ATT&CK Mapping Granularity:**
   - *Paper Claim:* The platform maps incident behaviors to MITRE ATT&CK techniques.
   - *Code Reality:* The implementation in `storyline_generator.py` maps solely to **9 high-level Tactics** (`TA0001` Initial Access through `TA0040` Impact). It does not classify granular MITRE ATT&CK *Techniques* (e.g., T1566 Phishing) or *Sub-techniques*.

4. **Threat Score Formulation:**
   - *Paper Claim:* Threat scores represent calibrated risk probabilities or statistical estimations.
   - *Code Reality:* The threat score is an **uncalibrated heuristic sum** (0–100) combining fixed point bonuses: severity (up to 25 pts), malware families (+5 pts each, max 15), CVEs (+5 pts each, max 10), IoC diversity (+5 pts per category, max 20), keyword density (up to 10 pts), incident correlation (up to 15 pts), and risky category bonus (5 pts).

5. **Local Processing & Data Privacy:**
   - *Paper Claim:* CIRIP operates completely offline and ensures zero external data leakage.
   - *Code Reality:* 
     - Non-English incident narratives are passed to `deep_translator.GoogleTranslator` (`language_utils.py`), which transmits raw report text over the public internet to Google Translate web servers.
     - Optional LLM enrichment transmits raw incident text to Anthropic's Claude API.
     - Offline operation is strictly true **only** when the incident text is in English and LLM enrichment is disabled.

6. **Scope of Quantitative Benchmarking:**
   - *Paper Claim:* Suggests or implies that IoC extraction, NER, TextRank summarization, and campaign correlation were quantitatively validated with precision/recall figures.
   - *Code Reality:* No labeled ground-truth datasets or evaluation scripts exist for any rule-based or graph components.

---

## H. Exact Recommended Corrections to IEEE Table I

To ensure full scientific integrity and pass technical review, the paper's summary table (Table I) must be updated to clearly separate **Implementation Status** from **Evaluation Status**, and accurately state the underlying method and verified evidence.

### Recommended Replacement Table for IEEE Table I:

| Component | Method | Implementation Status | Evaluation Status | Exact Source File & Function | Empirical Evidence & Limitations |
|---|---|---|---|---|---|
| **Language Detection & Translation** | `langdetect` + `deep-translator` (Google Translate API) | Implemented and verified | Tested functionally only | [`backend/app/language_utils.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/language_utils.py): `detect_and_translate()` | Functional verification via API; external HTTP call transmits text to Google Translate if non-English. |
| **Text Preprocessing** | Regex tokenization, custom English stopwords, IoC-preserving filter | Implemented and verified | Tested functionally only | [`backend/app/preprocessing.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/preprocessing.py): `normalize_for_model()` | Normalizes incident text before vectorization; no formal tokenizer ablation study. |
| **Incident-Type Classification** | TF-IDF (1–2 n-grams, 3k features) + Logistic Regression | Implemented and verified | Quantitatively evaluated | [`backend/app/ml_pipeline.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/ml_pipeline.py): `TfidfLogRegPipeline` | 100% synthetic holdout acc; **72.22% acc / 0.71 Macro F1** on 18-sample independent benchmark. |
| **Severity Prediction** | TF-IDF (1–2 n-grams, 3k features) + Logistic Regression | Implemented and verified | Quantitatively evaluated | [`backend/app/ml_pipeline.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/ml_pipeline.py): `TfidfLogRegPipeline` | 100% synthetic holdout acc; **33.33% acc / 0.20 Macro F1** on 18-sample independent benchmark (heavily biased to Medium). |
| **Model Feature Contributions (XAI)** | Local linear attribution ($W_i \times C_{k,i}$) | Implemented and verified | Tested functionally only | [`backend/app/ml_pipeline.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/ml_pipeline.py): `explain()` | Ranks top-8 contributing features; linear attribution only; no quantitative fidelity/SHAP benchmark. |
| **IoC Extraction** | Compiled regular expressions with contextual deduplication | Implemented and verified | Tested functionally only | [`backend/app/ioc_extraction.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/ioc_extraction.py): `extract_iocs()` | Extracts IPv4, IPv6, domains, URLs, emails, hashes, CVEs; does not handle defanged indicators. |
| **Entity Extraction** | 21-malware gazetteer, 18 attack keywords, regex heuristics | Implemented and verified | Tested functionally only | [`backend/app/ner_entities.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/ner_entities.py): `extract_entities()` | Functional string matching; not a machine-learned NER model; no Precision/Recall measured. |
| **Extractive Summarization** | TextRank (sentence TF-IDF cosine similarity + NetworkX PageRank) | Implemented and verified | Tested functionally only | [`backend/app/summarizer.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/summarizer.py): `extractive_summary()` | Selects top-3 sentences; defaults to full text if $\le 3$ sentences; no ROUGE score evaluation. |
| **MITRE ATT&CK Mapping** | Keyword matching + incident-type heuristics | Implemented and verified | Tested functionally only | [`backend/app/storyline_generator.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/storyline_generator.py): `generate_storyline()` | Maps to 9 high-level Tactics (`TA0001`–`TA0040`), not fine-grained Techniques; no annotated evaluation. |
| **Mitigation Guidance** | Static rule-based lookup table by incident category & severity | Implemented and verified | Tested functionally only | [`backend/app/mitigation.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/mitigation.py): `get_recommendations()` | Fixed playbooks across 4 incident phases; no automated dynamic customization. |
| **Threat Intelligence Score** | Deterministic additive heuristic point weighting (0–100) | Implemented and verified | Tested functionally only | [`backend/app/threat_scoring.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/threat_scoring.py): `calculate_threat_score()` | Provides transparent point breakdown; point weights are manually assigned heuristics, not calibrated. |
| **Cross-Incident Correlation & Campaigns** | Weighted IoC matching + Union-Find connected components | Implemented and verified | Tested functionally only | [`backend/app/threat_correlation.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/threat_correlation.py) & [`campaign_detection.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/campaign_detection.py) | Groups incidents sharing indicators into named campaigns ($\ge 40\%$ confidence); uncalibrated threshold. |
| **Knowledge Graph** | NetworkX bipartite star-topology graph & graph composition | Implemented and verified | Tested functionally only | [`backend/app/knowledge_graph.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/knowledge_graph.py): `build_incident_graph()` | Exports node-link JSON for vis-network; no formal semantic ontology or graph metrics. |
| **PDF Intelligence Report** | ReportLab Platypus multi-page styled layout engine | Implemented and verified | Tested functionally only | [`backend/app/report_generator.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/report_generator.py): `generate_pdf()` | Produces 12-section threat intelligence PDF document; verified via visual rendering. |
| **Optional LLM Narrative** | Anthropic Claude API (`claude-sonnet-4-6`) REST integration | Implemented and verified | Demonstrated with illustrative example | [`backend/app/llm_integration.py`](file:///d:/cyber-incident-intel-platform/cyber-incident-intel-platform/backend/app/llm_integration.py): `generate_llm_summary()` | Opt-in via API key; transmits text externally; excluded from ML benchmark experiments. |

---

## I. Unverified Claims Requiring Author Confirmation

Before finalizing the IEEE paper, the authors must confirm or adjust the following items:

1. **Comparative Algorithm Claims:** Confirm that any mention of SVM, Naive Bayes, Random Forest, or Decision Tree superiority has been removed, as no comparative code exists in CIRIP.
2. **Benchmark Construction:** Clarify in Section IV of the paper that the 18-sample independent benchmark was author-constructed from representative real-world incident formats to evaluate out-of-distribution transferability, rather than an external public benchmark (e.g., CASIE, CERT-SEI, or Kaggle).
3. **Dual Metric Reporting:** Ensure both the synthetic holdout metrics (100% / 100%) and independent benchmark metrics (72.22% / 33.33%) are reported side-by-side with an honest discussion of synthetic data limitations.
4. **Offline Deployment Boundaries:** Disclose that strict offline deployment requires (1) keeping LLM enrichment disabled and (2) disabling or replacing Google Translate with an offline library (e.g., MarianMT / Argos Translate).
5. **Mitigation Scope:** Confirm that mitigation guidance is presented as an automated baseline checklist rather than an adaptive, AI-synthesized remediation plan.

---

## J. Tests Performed, Commands Used, and Results

All checks performed during this audit were strictly read-only and deterministic:

### 1. Environment & Dependency Check
- **Command:** `powershell -Command "Test-Path backend\venv\Scripts\python.exe"`
- **Result:** Success (`True`). Verified Python virtual environment with scikit-learn 1.5.2, pandas 2.2.2, numpy 1.26.4, networkx 3.3, reportlab 4.2.5, langdetect 1.0.9, deep-translator 1.11.4.

### 2. Machine Learning Pipeline Execution
- **Command:** `backend\venv\Scripts\python.exe backend\evaluate_models.py`
- **Result:** Executed cleanly to completion. Produced:
  - Total dataset size: 180 samples.
  - Incident Type holdout accuracy: 1.0000 (100.00%), 5-Fold CV: 1.0000.
  - Severity holdout accuracy: 1.0000 (100.00%), 5-Fold CV: 1.0000.
  - Independent benchmark Incident Type accuracy: 0.7222 (72.22%), Macro F1: 0.71.
  - Independent benchmark Severity accuracy: 0.3333 (33.33%), Macro F1: 0.20.

### 3. Training Dataset Structural Analysis
- **Command:** `backend\venv\Scripts\python.exe -c "import pandas as pd; df = pd.read_csv('backend/data/training_data.csv'); print('Total rows:', len(df)); print('Unique texts:', df['text'].nunique()); print('Duplicate texts:', len(df) - df['text'].nunique())"`
- **Result:**
  - Total rows: 180
  - Unique texts: 150
  - Duplicate texts: 30 (16.7% exact duplicate rate).

### 4. Static Code and AST Verification
- Inspected regex patterns in `ioc_extraction.py` and `ner_entities.py`.
- Verified linear attribution logic in `ml_pipeline.py` line 67: `contributions = x_dense * coefs`.
- Verified Union-Find disjoint set clustering in `campaign_detection.py` lines 129–157.
- Verified 12-section layout compilation in `report_generator.py`.
- Verified non-English HTTP request triggers in `language_utils.py` lines 57–58.

---

## K. Security and Privacy Concerns Requiring Attention

The following security and privacy considerations should be noted or addressed in the paper's discussion / limitations section:

1. **Third-Party Data Exfiltration Risk:**
   - `language_utils.py` uses `deep-translator` which defaults to Google's public translation endpoint (`GoogleTranslator(source='auto', target='en')`). Passing confidential corporate incident reports containing proprietary server names, internal IP addresses, or executive identities sends sensitive unencrypted data to external servers.
   - *Recommendation:* Document this privacy trade-off and recommend offline neural machine translation (e.g., HuggingFace MarianMT or Argos Translate) for air-gapped SOC environments.

2. **Unauthenticated API Endpoints & CORS Wildcard:**
   - In `backend/app/main.py` lines 80–87, `CORSMiddleware` is configured with `allow_origins=["*"]`, allowing any domain to execute cross-origin requests against the platform.
   - None of the endpoints enforce authentication (e.g., JWT, OAuth2, or API tokens) or role-based access control (RBAC).

3. **Denial-of-Service (DoS) and ReDoS Exposure:**
   - The PDF generation endpoint (`GET /api/report/{id}/pdf`) performs intensive ReportLab rendering on-demand without rate limiting or caching. Concurrent requests could exhaust host memory and CPU resources.
   - Several complex regular expressions in `ioc_extraction.py` (e.g., `DOMAIN_RE`, `IPV4_RE`) have not been hardened against catastrophic backtracking under adversarial input.

4. **Multi-Worker Database Concurrency:**
   - In `backend/app/db.py`, the `JsonFallbackStore` uses a Python `threading.Lock()` to serialize writes. This lock is effective only within a single OS process. If Uvicorn is spawned with multiple worker processes (`--workers > 1`), concurrent writes to `incidents_store.json` and `campaigns_store.json` could cause race conditions and JSON corruption.

---

## L. Final Checklist for Revising the IEEE Paper

Use this actionable checklist when prompting Claude or editing the LaTeX manuscript:

- [ ] **Revise IEEE Table I:** Replace Table I with the audited table from Section H of this report, distinguishing implementation from evaluation.
- [ ] **Correct Machine Learning Claims:** 
  - [ ] Explicitly state that the 100% holdout accuracy was achieved on a synthetic dataset generated from 12 templates ($N=180$).
  - [ ] Report the independent out-of-distribution benchmark results: **72.22% accuracy (0.71 Macro F1)** for Incident Classification and **33.33% accuracy (0.20 Macro F1)** for Severity Prediction.
  - [ ] Explain that severity prediction struggles on unseen data because training labels were derived from simple heuristics, leading to a strong bias toward "Medium" severity.
- [ ] **Remove Comparative Superiority Claims:** Delete claims that Logistic Regression outperformed Naive Bayes, Linear SVM, Random Forest, or Decision Trees on this platform. Clarify that Logistic Regression was selected for low computational complexity, lack of GPU requirement, and direct linear coefficient explainability.
- [ ] **Accurately Describe MITRE ATT&CK Mapping:** State that CIRIP maps incident narratives to **9 high-level ATT&CK Tactics** (`TA0001`–`TA0040`) via keyword matching and incident-type heuristics, not fine-grained *Techniques*.
- [ ] **Clarify Rule-Based Modules:** State that IoC extraction, NER, TextRank summarization, threat scoring, mitigation guidance, and campaign clustering are rule-based/heuristic and evaluated for functional correctness rather than benchmarked on annotated corpora.
- [ ] **Disclose Threat Score Heuristics:** Acknowledge that the 0–100 threat intelligence score is an uncalibrated deterministic additive point model.
- [ ] **Disclose Privacy & Translation Dependencies:** Clarify that completely offline operation is limited to English text unless an offline translation engine is deployed.
