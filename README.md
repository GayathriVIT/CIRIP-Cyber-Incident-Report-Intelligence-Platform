# Cyber Incident Report Intelligence Platform

A defensive cybersecurity NLP/ML platform: paste an incident report, get incident
classification, severity prediction, extracted IoCs/entities, an auto-generated
summary, mitigation recommendations, an explainable-AI breakdown, and an
interactive knowledge graph — with history and a trend dashboard.

Built as a **student final-year project**: lightweight, runnable on a normal
laptop, no GPU or paid API required to run the full pipeline end-to-end.

## What's ML, what's rules, what's LLM (important distinction)

The spec asks for this to be explicit, so every result in the UI is tagged:

| Component | Method | Tag |
|---|---|---|
| Incident type classification | TF-IDF + Logistic Regression (trained model) | `ML` |
| Severity prediction | TF-IDF + Logistic Regression (trained model) | `ML` |
| IoC extraction (IPs, domains, hashes, CVEs, URLs, emails) | Regex, rule-based | `Rule-based` |
| Entity extraction (malware families, users, orgs, attack keywords) | Gazetteer + regex heuristics | `Rule-based` |
| Incident summary (default) | Extractive TF-IDF + TextRank (no external API) | `Extractive` |
| Incident summary (optional) | Anthropic Claude API, only if `ANTHROPIC_API_KEY` is set and "Use LLM enrichment" is checked | `LLM-generated` |
| Mitigation recommendations (default) | Rule-based lookup table by incident type + severity | `Rule-based` |
| Mitigation narrative (optional) | Anthropic Claude API rephrasing, same opt-in as above | `LLM-generated` |
| Explainable AI | Top TF-IDF × logistic-regression-coefficient features for the predicted class | — |

No component claims to detect real-world attacks with guaranteed accuracy — this
is a demo/academic pipeline trained on a small synthetic dataset (see below).

## Project layout

```
cyber-incident-intel-platform/
├── backend/
│   ├── app/
│   │   ├── main.py              FastAPI app (all API endpoints)
│   │   ├── ml_pipeline.py       TF-IDF + LogisticRegression train/predict/explain
│   │   ├── ioc_extraction.py    Regex-based IoC extraction
│   │   ├── ner_entities.py      Lightweight entity extraction
│   │   ├── preprocessing.py     Text cleaning / tokenization / stopword removal
│   │   ├── summarizer.py        Extractive summarization (TextRank)
│   │   ├── mitigation.py        Rule-based recommendation engine
│   │   ├── knowledge_graph.py   Builds per-incident graph (networkx)
│   │   ├── llm_integration.py   Optional Anthropic API calls
│   │   ├── db.py                MongoDB, with automatic JSON-file fallback
│   │   ├── schemas.py           Pydantic request schema
│   │   └── models_store/        Saved trained models (created by train_models.py)
│   ├── data/
│   │   ├── generate_training_data.py   Synthetic dataset generator
│   │   └── training_data.csv           Generated labeled dataset (180 rows)
│   ├── train_models.py          Trains + saves both ML models
│   └── requirements.txt
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── app.js                   Vanilla JS, no build step needed
└── README.md
```

## About the training data

`backend/data/generate_training_data.py` generates a **synthetic, template-based**
labeled dataset (180 incident reports across 6 types × severities) so the project
trains and runs without needing to download an external dataset. This is enough
to demonstrate a working, honest ML pipeline, but it is not real-world data —
the model will look "too accurate" on this synthetic set because the templates
are quite distinct from each other.

**To get closer to real-world performance:** replace `training_data.csv` with
labeled real incident report text (e.g., from CERT advisories, MITRE ATT&CK
write-ups, or a labeled Kaggle dataset), keeping the same CSV columns:
`text,incident_type,severity`. Then re-run `python train_models.py`.

## Setup & run

### 1. Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Generate synthetic training data + train both ML models (takes a few seconds)
python train_models.py

# Start the API server
uvicorn app.main:app --reload --port 8000
```

The API is now live at `http://localhost:8000` (interactive docs at
`http://localhost:8000/docs`).

**Storage:** the app tries to connect to a local MongoDB instance
(`mongodb://localhost:27017`) automatically. If MongoDB isn't installed/running,
it transparently falls back to a JSON file
(`backend/data/incidents_store.json`) with the same interface — the app still
works fully, it just isn't using Mongo. To use real MongoDB: install MongoDB
Community Server, make sure it's running, then just start the backend — it'll
detect and use it automatically. You can also point at a different URI:

```bash
export MONGO_URI="mongodb://localhost:27017"
export MONGO_DB="cyber_incident_intel"
```

**Optional LLM enrichment:** to enable the "Use LLM enrichment" checkbox in the
UI, set an Anthropic API key before starting the server:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

Without this set, the platform still works completely — it just uses the
rule-based/extractive summarizer and mitigation engine instead of the LLM.

### 2. Frontend

The frontend is plain HTML/CSS/JS with no build step. Simplest way to run it:

```bash
cd frontend
python3 -m http.server 5500
```

Then open `http://localhost:5500` in your browser (keep the backend running in
another terminal). If you open `index.html` directly via `file://`, some
browsers block the API requests — using a local static server avoids that.

> The frontend calls the backend at `http://localhost:8000` by default. If you
> run the backend on a different host/port, update `API_BASE` at the top of
> `frontend/app.js`.

## Using the app

1. Go to the **Analyze** tab, paste an incident report, click **Analyze
   Incident**.
2. Watch the pipeline trace light up through each stage.
3. Review: incident type, severity, confidence, extracted IoCs, entities,
   summary, mitigation, explainable-AI feature weights, the incident's
   knowledge graph, and similar past incidents.
4. Go to **History** to revisit any past analysis and reopen its full report
   (`GET /api/report/{id}` returns the "Final Incident Intelligence Report"
   view used for a written report).
5. Go to **Dashboard** for aggregate incident-type/severity trends and a
   combined cross-incident knowledge graph.

## API reference (quick)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Backend/model/storage status |
| POST | `/api/analyze` | Run the full pipeline on a new report, save it |
| GET | `/api/history` | List all saved incidents |
| GET | `/api/incident/{id}` | Full saved record |
| GET | `/api/report/{id}` | Formatted "Final Incident Intelligence Report" |
| GET | `/api/similar/{id}` | TF-IDF cosine-similarity search over past incidents |
| GET | `/api/dashboard` | Aggregate stats + combined knowledge graph |

Full interactive docs: `http://localhost:8000/docs` (auto-generated by FastAPI).

## Design decisions & honesty notes

- **No guaranteed detection claims.** This system predicts labels from text
  patterns learned on a small dataset — it is a decision-support / triage aid,
  not a certified detection system.
- **Lightweight by default.** TF-IDF + Logistic Regression instead of
  BERT/RoBERTa/Llama, so it trains in seconds and needs no GPU. The code is
  structured (`ml_pipeline.py`) so swapping in a transformer classifier later
  is a contained change if you want to extend the project.
- **Every output is labeled by method** (ML / rule-based / LLM-generated) in
  both the API response and the UI, per the project brief.
