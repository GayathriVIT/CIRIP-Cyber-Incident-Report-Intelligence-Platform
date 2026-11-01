# CIRIP Screenshot Evidence Checklist & Report Figure Mapping
**Project Title:** Cyber Incident Report Intelligence Platform (CIRIP)  
**Academic Target:** VIT CSI4001 Project-Only Final Report  
**Verification Date:** October 31, 2026  
**Auditor:** Senior Software QA Engineer & Academic Project Evaluator  

---

## 1. Existing Repository Screenshot Audit

A recursive filesystem scan across the entire project repository (`d:\cyber-incident-intel-platform\cyber-incident-intel-platform`) was performed:
```powershell
Get-ChildItem -Path . -Recurse -Include *.png,*.jpg,*.jpeg,*.webp -File
```
**Findings:**
- **Zero project-specific screenshot files** currently exist in the repository.
- Only vendor unit-test assets exist deep inside `backend/venv/Lib/site-packages/` (e.g., `sklearn/datasets/images/china.jpg`).
- **Conclusion:** All UI and evidence figures required for the VIT CSI4001 project report must be freshly captured from the live application.

---

## 2. Screenshot Evidence Checklist for VIT CSI4001 Report

To achieve full marks in the system implementation, testing, and evaluation sections of the VIT Project-Only report, the authors must capture the following **15 distinct screenshots**:

| Figure # | Target Report Section | Recommended Caption / Title | Description / Content to Capture | Capture Status |
|:---:|:---|:---|:---|:---:|
| **Fig. 1** | Section 3.1 / 4.1 (System Interface) | *Threat Command Center & Ingestion Interface* | The primary Analyze view showing the incident text entry area, title input, LLM enrichment toggle, and "Analyze Incident" action button. | **Missing — To Be Captured** |
| **Fig. 2** | Section 4.1 (Workflow Execution) | *Real-Time Pipeline Execution Trace* | The visual execution stepper lighting up sequentially: `Ingest` $\rightarrow$ `Language` $\rightarrow$ `Preprocess` $\rightarrow$ `ML Triage` $\rightarrow$ `IoC Regex` $\rightarrow$ `NER Gazetteer` $\rightarrow$ `TextRank` $\rightarrow$ `ATT&CK Storyline` $\rightarrow$ `Threat Score` $\rightarrow$ `Graph Build`. | **Missing — To Be Captured** |
| **Fig. 3** | Section 4.2 / 5.1 (ML Classification) | *Incident Classification & Severity Prediction Panel* | Result card displaying predicted Incident Type (e.g. `Ransomware`), confidence percentage badge, predicted Severity (e.g. `Critical`), and complete class probability distribution bars. | **Missing — To Be Captured** |
| **Fig. 4** | Section 4.3 / 5.3 (Explainable AI) | *Model Explainability & Feature Contribution Breakdown* | Horizontal bar chart or ranked table showing top positive and negative $W_i \times C_{k,i}$ feature weights (TF-IDF weight $\times$ Logistic Regression coefficient) for both type and severity. | **Missing — To Be Captured** |
| **Fig. 5** | Section 4.2 (IoC Extraction) | *Extracted Indicators of Compromise (IoCs)* | Categorized tables and badges displaying parsed IPv4 addresses, IPv6, domains, URLs, email addresses, cryptographic hashes (MD5, SHA-1, SHA-256), and CVE IDs. | **Missing — To Be Captured** |
| **Fig. 6** | Section 4.2 (Entity Extraction) | *Extracted Threat Entities & Attack Keywords* | Entity badges showing gazetteer-matched malware families (e.g., `LockBit`, `Cobalt Strike`), detected attack keywords, extracted user accounts, and organizations. | **Missing — To Be Captured** |
| **Fig. 7** | Section 4.4 / 5.2 (Threat Scoring) | *Deterministic Threat Intelligence Score & Risk Gauge* | Radial score gauge widget showing the calculated 0–100 threat score (e.g., `85/100`), assigned risk tier (`Critical Risk`), and the transparent additive point breakdown. | **Missing — To Be Captured** |
| **Fig. 8** | Section 4.5 (Kill Chain Mapping) | *MITRE ATT&CK Attack Storyline Flowchart* | Interactive chronological progression showing detected attack stages (TA0001 through TA0040) with evidence badges (confirmed, inferred) and stage narrative. | **Missing — To Be Captured** |
| **Fig. 9** | Section 4.6 / 5.4 (Knowledge Graph) | *Interactive Incident Knowledge Graph* | Vis-network canvas displaying the central incident node connected via colored edges to surrounding entity and IoC nodes (star topology). | **Missing — To Be Captured** |
| **Fig. 10** | Section 4.7 (Threat Correlation) | *Cross-Incident Correlation & Similar Incidents View* | List of correlated past incidents showing relationship strength badges (`Strongly Related`, `Potentially Related`), confidence scores, and specific shared-indicator reasons. | **Missing — To Be Captured** |
| **Fig. 11** | Section 4.8 (Campaign Clustering) | *Threat Campaign Detection & Clustering Matrix* | Active campaign cards showing NATO designations (`Campaign Alpha`, `Campaign Beta`), total member incidents, combined threat level, and common IoCs. | **Missing — To Be Captured** |
| **Fig. 12** | Section 4.9 (Incident Management) | *Historical Incident Records & Audit Log Table* | Sortable table displaying all past analyzed incidents with timestamps, incident titles, predicted classifications, severities, and threat score badges. | **Missing — To Be Captured** |
| **Fig. 13** | Section 4.10 / 5.1 (Executive Dashboard) | *Aggregated Threat Intelligence Dashboard* | Executive KPI cards (Total Incidents, Active Campaigns, High-Risk IoCs, Avg Threat Score), donut charts for type/severity distribution, and incident volume timeline. | **Missing — To Be Captured** |
| **Fig. 14** | Section 5.5 (Performance Benchmarking) | *Model Performance & Comparative Evaluation Matrix* | The Evaluation tab showing Holdout vs Independent Benchmark comparison cards (72.22% vs 100% accuracy) and the 10-algorithm comparison table. | **Missing — To Be Captured** |
| **Fig. 15** | Section 4.11 / Appendix (Reporting) | *Downloadable Multi-Page PDF Threat Intelligence Report* | Preview of the generated ReportLab PDF showing cover page, classification vector charts, IoC matrices, MITRE flowchart, and 4-phase mitigation playbooks. | **Missing — To Be Captured** |

---

## 3. Step-by-Step Guide for Capturing Genuine Screenshots

The authors (Shaktheesh and Gayathri) should capture genuine screenshots directly from the running application by following these instructions:

### Prerequisites:
1. Ensure MongoDB is running locally (`mongod` on port 27017).
2. Start the backend:
   ```powershell
   cd d:\cyber-incident-intel-platform\cyber-incident-intel-platform\backend
   .\venv\Scripts\activate
   uvicorn app.main:app --reload --port 8000
   ```
3. Start the frontend in a second terminal:
   ```powershell
   cd d:\cyber-incident-intel-platform\cyber-incident-intel-platform\frontend
   python -m http.server 5500
   ```
4. Open Google Chrome or Microsoft Edge at `http://localhost:5500`.

### Recommended Standard Test Narrative for Captures:
Use this realistic incident report to produce rich, complete visual output across all tabs:

```text
At 02:45 UTC on October 31, 2026, security operations detected a severe ransomware attack across internal virtualization clusters. 
Investigation revealed user jsmith received a spear-phishing email from invoice-verify@malicious-payroll.xyz containing an HTML attachment. 
The attachment initiated a dropper macro that executed an obfuscated PowerShell script downloading Cobalt Strike beacon from https://cdn-update-service.com/payload.bin. 
Threat actors exploited privilege escalation vulnerability CVE-2023-34362 to compromise domain controller 10.0.4.15. 
Lateral movement was executed via SMB, and LockBit ransomware payload (SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855) was deployed across SAN storage arrays. 
External C2 communications were observed to 194.26.29.11. All healthcare records were encrypted with a .locked extension and a ransom notice README_RESTORE.txt was left on workstations.
```

### Capture Instructions:
1. **For Figs 1–9:** Paste the narrative into the **Analyze Threat** tab. Click **Analyze Incident**. Capture each result section as it populates.
2. **For Fig 10:** Scroll to the **Correlations & Similar Incidents** card on the analysis result page.
3. **For Fig 11:** Navigate to the **Threat Campaigns** tab via the sidebar.
4. **For Fig 12:** Navigate to the **Incident History** tab via the sidebar.
5. **For Fig 13:** Navigate to the **Intelligence Dashboard** tab via the sidebar.
6. **For Fig 14:** Navigate to the **Model Performance & Evaluation** tab via the sidebar.
7. **For Fig 15:** Click **Export PDF Report** at the top-right of the incident analysis page, open the downloaded PDF in Acrobat Reader or Edge, and capture the first 2 pages side-by-side.

### Formatting Guidelines for Report Submission:
- Resolution: Minimum 1920×1080 display capture; zoom browser to 100% or 110%.
- Crop cleanly around the relevant container cards (avoid capturing browser bookmarks bar or Windows taskbar).
- Save images in `.png` format inside a new folder: `docs/screenshots/`.
