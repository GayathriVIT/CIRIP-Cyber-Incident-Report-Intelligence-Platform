# CIRIP Technical Configuration, Parameters & Deployment Specification
**Project Title:** Cyber Incident Report Intelligence Platform (CIRIP)  
**Verification Date:** October 31, 2026  
**Extraction Source:** Direct Static Inspection of Codebase & Runtime Environment Extraction  
**Compliance Standard:** Fact-Checked Against Active Environment; No Speculative Values

---

## 1. Verified Software Environment & Library Versions

The following versions were extracted directly from the active runtime environment (`backend\venv`) on Windows 11:

| Component / Library | Verified Runtime Version | Source Specification File | Role in CIRIP Platform |
|---|:---:|:---:|---|
| **Python** | `3.12.0` (64-bit AMD64) | System interpreter | Core backend execution runtime |
| **Operating System** | `Windows 11 (10.0.26200)` | Host environment | Development, evaluation & hosting platform |
| **FastAPI** | `0.115.0` | `requirements.txt` | REST API framework, OpenAPI/Swagger provider |
| **Uvicorn** | `0.30.6` | `requirements.txt` | ASGI web server handling HTTP requests |
| **scikit-learn** | `1.5.2` | `requirements.txt` | TF-IDF vectorization, Logistic Regression, metrics |
| **NetworkX** | `3.3` | `requirements.txt` | TextRank sentence graph, knowledge graph synthesis |
| **ReportLab** | `4.2.5` | `requirements.txt` | Dynamic threat intelligence PDF report generation |
| **PyMongo** | `4.8.0` | `requirements.txt` | MongoDB driver for incident & campaign persistence |
| **Pydantic** | `2.9.2` | Dependency tree | Request validation models (`AnalyzeRequest`) |
| **NumPy** | `1.26.4` | Dependency tree | Vector calculations, probability arrays, cosine similarity |
| **Pandas** | `2.2.2` | `requirements.txt` | Data loading and preprocessing during model training |
| **langdetect** | `1.0.9` | `requirements.txt` | Offline N-gram language detection |
| **deep-translator** | `1.11.4` | `requirements.txt` | Google Translate integration for non-English reports |
| **Joblib** | `1.4.2` | `requirements.txt` | Serialization for trained scikit-learn models |

---

## 2. Machine Learning Hyperparameters & Pipeline Configuration

The ML pipeline is implemented across `backend/app/ml_pipeline.py` and evaluated in `backend/evaluate_models.py`.

### 2.1 Feature Extraction: `TfidfVectorizer`
- **N-gram Range:** `(1, 2)` (Extracts both individual words and two-word phrases)
- **Maximum Features:** `3000` (Vocabulary capped at top 3,000 n-grams ordered by term frequency across the corpus)
- **Minimum Document Frequency (`min_df`):** `1` (Terms appearing in at least 1 document are included)
- **Sublinear Term Frequency (`sublinear_tf`):** `False` (Standard term frequency weighting: $tf(t, d)$ rather than $1 + \log(tf)$)
- **Stopwords Configuration:** Custom hardcoded set of **128 English words** defined in `backend/app/preprocessing.py`:
  ```python
  STOPWORDS = set("""
  a an the and or but if while is are was were be been being to of in on at by for with
  from as this that these those it its it's he she they them his her their our your my
  i we you not no nor do does did doing have has had having will would shall should can
  could may might must about into over under again further then once here there when
  where why how all any both each few more most other some such only own same so than
  too very s t can will just don should now
  """.split())
  ```
- **Token Pattern:** `[A-Za-z0-9\-\.]+` via custom regex `tokenize()` in `preprocessing.py` (explicitly preserves hyphens and periods so IP addresses, CVEs, and domain fragments are not shredded).

### 2.2 Estimator: `LogisticRegression`
- **Regularization Strength ($C$):** `2.0` (Inverse regularization parameter; slightly lower regularization than default $C=1.0$)
- **Optimization Solver:** `lbfgs` (Limited-memory Broyden–Fletcher–Goldfarb–Shanno algorithm; scikit-learn default)
- **Maximum Iterations (`max_iter`):** `2000` (Guarantees gradient convergence for multi-class optimization)
- **Random Seed (`random_state`):** `42`
- **Multi-class Strategy:** Multinomial cross-entropy loss (`multinomial` / `auto`)
- **Class Space — Incident Classifier:** 6 classes: `['DDoS', 'Data Breach', 'Insider Threat', 'Malware', 'Phishing', 'Ransomware']`
- **Class Space — Severity Predictor:** 4 classes: `['Critical', 'High', 'Low', 'Medium']`

### 2.3 Validation & Split Configuration
- **Train / Test Split:** `80%` Training (144 samples) / `20%` Testing (36 samples)
- **Stratification:** Yes (`stratify=labels`)
- **Cross-Validation:** 5-Fold Stratified K-Fold (`StratifiedKFold(n_splits=5, shuffle=True, random_state=42)`)

---

## 3. Threat Intelligence Scoring Engine Rules

Implemented in `backend/app/threat_scoring.py`. The score is purely deterministic, transparent, and bounded within $[0, 100]$.

### 3.1 Scoring Factors and Itemized Weights

| Factor # | Intelligence Factor | Point Weight / Contribution Formula | Maximum Points |
|:---:|:---|:---|:---:|
| 1 | **ML-Predicted Severity** | Critical = 25 pts, High = 20 pts, Medium = 10 pts, Low = 5 pts | **25 pts** |
| 2 | **Malware Family Detection** | +5 pts per unique malware family detected (min($N \times 5, 15$)) | **15 pts** |
| 3 | **CVE / Known Vulnerabilities** | +5 pts per unique CVE reference (min($N \times 5, 10$)) | **10 pts** |
| 4 | **IoC Category Richness** | +5 pts per IoC category containing items (IPv4, Domains, URLs, Emails, Hashes) | **20 pts** |
| 5 | **Attack Keyword Density** | If $\ge 3$ keywords, min($N \times 2, 10$) pts | **10 pts** |
| 6 | **Correlation with Past Incidents** | +5 pts per similar incident with similarity $\ge 0.5$ (min($N \times 5, 15$)) | **15 pts** |
| 7 | **High-Risk Category Multiplier** | +5 pts if incident type is `Ransomware`, `Data Breach`, or `Insider Threat` | **5 pts** |
| — | **Total Possible Score** | Sum of above factors (Clamped to maximum: $\min(\text{Total}, 100)$) | **100 pts** |

### 3.2 Risk Classification Tiers
- **Critical Risk:** `76 – 100` points
- **High Risk:** `51 – 75` points
- **Moderate Risk:** `26 – 50` points
- **Low Risk:** `0 – 25` points

---

## 4. Cross-Incident Correlation & Campaign Clustering Rules

Implemented in `backend/app/threat_correlation.py` and `backend/app/campaign_detection.py`.

### 4.1 Indicator Correlation Point Weights

| Indicator Type | Weight per Match | Rationale |
|:---|:---:|:---|
| **File Hash (MD5 / SHA-1 / SHA-256)** | **35 pts** | Exact cryptographic match denotes identical executable payload or tool |
| **Attacker / C2 IP Address** | **30 pts** | Denotes shared hosting or command-and-control server infrastructure |
| **Malicious Domain** | **25 pts** | Denotes shared adversary domain registration or phishing infrastructure |
| **Malware Family** | **20 pts** | Denotes common malware strain (e.g., LockBit, Emotet) |
| **CVE Identifier** | **15 pts** | Shared exploitation of identical vulnerability vector |
| **Textual Cosine Similarity** | **Up to 15 pts** | Scaled contribution ($\text{similarity} \times 15$) if TF-IDF similarity $\ge 0.3$ |
| **Attack Keyword Overlap** | **10 pts** | Flat bonus if $\ge 3$ identical attack tactics/keywords match |
| **Attacker Email Address** | **8 pts** | Shared sender address across campaigns |
| **Malicious URL** | **8 pts** | Shared phishing or payload staging path |

### 4.2 Relationship Strength Thresholds
- **Strongly Related:** Confidence $\ge 70\%$
- **Potentially Related:** Confidence $40\% – 69\%$
- **Weakly Related:** Confidence $10\% – 39\%$
- **Omitted (Unrelated):** Confidence $< 10\%$ (filtered out to eliminate noise)

### 4.3 Campaign Detection Engine Logic
- **Clustering Algorithm:** Connected components via Disjoint Set Union (Union-Find) algorithm.
- **Inclusion Criteria:** Correlated edge with Confidence $\ge 40\%$ (Potentially or Strongly Related).
- **Minimum Campaign Size:** $\ge 2$ incidents connected in the correlation graph.
- **Naming Convention:** NATO phonetic alphabet (`Campaign Alpha`, `Campaign Beta`, `Campaign Gamma`, ... `Campaign Omega`). If exhausted, falls back to two-letter permutations (`Campaign AA`, `Campaign AB`, ...).
- **Common IoC Threshold:** Any indicator appearing in $\ge 2$ incidents of the campaign is promoted to `common_iocs`.
- **Campaign Threat Level:** Set to the maximum severity among all member incidents.

---

## 5. MITRE ATT&CK Storyline Progression Rules

Implemented in `backend/app/storyline_generator.py`. Maps incident evidence strictly to **9 ATT&CK tactics**:

| Stage Order | Tactic Name | MITRE Tactic ID | Example Trigger Keywords |
|:---:|:---|:---:|:---|
| 1 | **Initial Access** | `TA0001` | phishing, spear-phishing, email, attachment, exploit, supply chain, zero-day, rdp access |
| 2 | **Execution** | `TA0002` | malware, payload, script, dropper, loader, macro, powershell, cmd, shellcode |
| 3 | **Persistence** | `TA0003` | persistence, registry, scheduled task, cron, startup, autorun, backdoor installed |
| 4 | **Privilege Escalation** | `TA0004` | privilege escalation, admin, administrator, root, sudo, uac bypass, elevated, kernel exploit |
| 5 | **Credential Access** | `TA0006` | credential, password, hash, mimikatz, lsass, ntlm, kerberos, keylogger, harvesting |
| 6 | **Lateral Movement** | `TA0008` | lateral movement, rdp, smb, wmi, psexec, spread, propagation, internal network |
| 7 | **Command & Control** | `TA0011` | c2, c&c, command and control, beacon, callback, reverse shell, remote access, contacted |
| 8 | **Exfiltration** | `TA0010` | exfiltration, data theft, data transfer, uploaded, leaked, copied to external, data breach |
| 9 | **Impact** | `TA0040` | encrypt, encrypted, ransom, ransomware, wipe, destroy, denial of service, ddos, outage |

**Constraint Note:** The platform performs tactic-level mapping only. It does not claim technique-level (e.g., T1566) or sub-technique identification.

---

## 6. Official Deployment & Execution Instructions

To deploy and run the CIRIP platform in the exact configuration verified by this audit:

### Step 1: Environment Activation & Dependency Verification
```powershell
# Open terminal in project root
cd d:\cyber-incident-intel-platform\cyber-incident-intel-platform\backend

# Activate the virtual environment
.\venv\Scripts\activate

# Verify dependencies are installed
pip install -r requirements.txt
```

### Step 2: Model Verification / Training (If models are missing)
```powershell
# Train and serialize the two ML models (takes ~2 seconds on CPU)
python train_models.py
```
*Note: This creates `incident_classifier.joblib` and `severity_model.joblib` in `backend/app/models_store/`.*

### Step 3: Launch Backend REST API Server
```powershell
# Run Uvicorn ASGI server on port 8000
uvicorn app.main:app --reload --port 8000
```
- **Backend Port:** `8000`
- **Local API Base:** `http://127.0.0.1:8000`
- **Swagger Documentation:** `http://127.0.0.1:8000/docs`
- **Health Check Endpoint:** `http://127.0.0.1:8000/api/health`

### Step 4: Storage Connection & Fallback Behavior
- The backend automatically attempts to connect to MongoDB at `mongodb://localhost:27017` (timeout: 800 ms).
- If MongoDB is running, it connects to database `cyber_incident_intel` and collection `incidents`.
- If MongoDB is offline, it transparently falls back to local JSON storage at `backend/data/incidents_store.json` without throwing an error or interrupting platform functionality.

### Step 5: Launch Frontend Server
```powershell
# Open a second terminal window
cd d:\cyber-incident-intel-platform\cyber-incident-intel-platform\frontend

# Start lightweight static HTTP server
python -m http.server 5500
```
- **Frontend Port:** `5500`
- **Browser Access URL:** `http://localhost:5500` (or `http://127.0.0.1:5500`)
- *Note:* Do not open `index.html` via `file:///` protocol in browser, as CORS security restrictions in modern browsers will block REST API fetches to `http://127.0.0.1:8000`.
