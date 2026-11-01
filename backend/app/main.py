"""
CIRIP — AI-Powered Cyber Threat Fusion & Intelligence Platform
FastAPI backend (v2.0)

All existing endpoints are preserved.  New endpoints added:
  GET  /api/campaigns
  GET  /api/campaign/{campaign_id}
  GET  /api/threat-score/{incident_id}
  GET  /api/storyline/{incident_id}
  GET  /api/correlations/{incident_id}
  GET  /api/report/{incident_id}/pdf

New fields added to /api/analyze response:
  threat_score, attack_storyline, correlations, campaign_id, campaign_name
"""

from collections import Counter
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from .schemas import AnalyzeRequest
from .ml_pipeline import TfidfLogRegPipeline
from .ioc_extraction import extract_iocs
from .ner_entities import extract_entities
from .summarizer import extractive_summary
from .mitigation import get_recommendations
from .knowledge_graph import build_incident_graph, merge_graphs
from . import db
from . import llm_integration

# ── New innovation modules ─────────────────────────────────────────────────────
from .threat_scoring import calculate_threat_score
from .threat_correlation import correlate_incident
from .campaign_detection import (
    detect_campaigns,
    find_incident_campaign,
)
from .storyline_generator import generate_storyline
from .report_generator import generate_pdf

# ── Campaign store path ────────────────────────────────────────────────────────
import os, json
from threading import Lock

_CAMP_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "campaigns_store.json"
)
_camp_lock = Lock()


def _read_campaigns() -> list:
    if not os.path.exists(_CAMP_PATH):
        return []
    try:
        with open(_CAMP_PATH) as f:
            return json.load(f)
    except Exception:
        return []


def _write_campaigns(data: list):
    os.makedirs(os.path.dirname(_CAMP_PATH), exist_ok=True)
    with open(_CAMP_PATH, "w") as f:
        json.dump(data, f, indent=2, default=str)


# ── FastAPI app ────────────────────────────────────────────────────────────────
app = FastAPI(
    title="CIRIP — AI-Powered Cyber Threat Fusion & Intelligence Platform",
    description=(
        "Defensive cybersecurity NLP/ML platform for analyzing incident reports. "
        "Academic/demo project — not a substitute for a production SOC toolchain."
    ),
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

# ── Load models & storage once at startup ─────────────────────────────────────
classifier    = TfidfLogRegPipeline("incident_classifier")
severity_model = TfidfLogRegPipeline("severity_model")
STORE, BACKEND_NAME = db.get_store()


@app.on_event("startup")
def load_models():
    global classifier, severity_model
    try:
        classifier.load()
        severity_model.load()
    except FileNotFoundError as e:
        print(f"[WARN] {e}")


# ══════════════════════════════════════════════════════════════════════════════
# EXISTING ENDPOINTS (unchanged signatures, extended responses)
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "storage_backend": BACKEND_NAME,
        "models_loaded": classifier.model is not None and severity_model.model is not None,
        "llm_available": llm_integration.llm_available(),
        "version": "2.0.0",
    }


@app.post("/api/analyze")
def analyze_incident(req: AnalyzeRequest):
    if classifier.model is None or severity_model.model is None:
        raise HTTPException(
            status_code=503,
            detail="Models not trained yet. Run `python train_models.py` in the backend folder, then restart the server.",
        )
    text = req.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Incident text must not be empty.")

    # ── NEW: Language Detection & Translation ─────────────────────────────
    from .language_utils import detect_and_translate
    lang_info = detect_and_translate(text)
    
    # Use translated text for all downstream NLP and ML tasks
    process_text = lang_info["translated_text"] if lang_info["translated_text"] else lang_info["original_text"]

    # ── 1. ML: incident classification ────────────────────────────────────
    itype_label, itype_conf, itype_probs, itype_X = classifier.predict(process_text)
    itype_explanation = classifier.explain(itype_X, itype_label)

    # ── 2. ML: severity prediction ────────────────────────────────────────
    sev_label, sev_conf, sev_probs, sev_X = severity_model.predict(process_text)
    sev_explanation = severity_model.explain(sev_X, sev_label)

    # ── 3. Rule-based IoC extraction ──────────────────────────────────────
    iocs = extract_iocs(process_text)

    # ── 4. Lightweight entity extraction ──────────────────────────────────
    entities = extract_entities(process_text)

    # ── 5. Summarization ──────────────────────────────────────────────────
    summary_text = extractive_summary(process_text, num_sentences=3)
    summary_source = "extractive (TF-IDF + TextRank)"
    if req.use_llm and llm_integration.llm_available():
        try:
            summary_text = llm_integration.generate_llm_summary(process_text)
            summary_source = "llm_generated"
        except Exception as e:
            summary_source = f"extractive (LLM call failed: {e})"

    # ── 6. Mitigation recommendation ──────────────────────────────────────
    recommendations = get_recommendations(itype_label, sev_label)
    llm_recommendation_text = None
    if req.use_llm and llm_integration.llm_available():
        try:
            llm_recommendation_text = llm_integration.generate_llm_recommendation(
                itype_label, sev_label, summary_text
            )
        except Exception as e:
            llm_recommendation_text = f"(LLM recommendation unavailable: {e})"

    # ── 7. Knowledge graph ────────────────────────────────────────────────
    incident_id = db.new_id()
    graph = build_incident_graph(incident_id, itype_label, entities, iocs)

    # ── 8. Build base record (existing fields) ────────────────────────────
    record = {
        "_id": incident_id,
        "title": req.title or f"{itype_label} incident",
        "created_at": db.now_iso(),
        "text": text,
        "language_info": lang_info,
        "incident_type": {
            "label": itype_label,
            "confidence": round(itype_conf, 4),
            "class_probabilities": {k: round(v, 4) for k, v in itype_probs.items()},
            "source": "ML prediction (TF-IDF + Logistic Regression)",
        },
        "severity": {
            "label": sev_label,
            "confidence": round(sev_conf, 4),
            "class_probabilities": {k: round(v, 4) for k, v in sev_probs.items()},
            "source": "ML prediction (TF-IDF + Logistic Regression)",
        },
        "iocs": iocs,
        "entities": entities,
        "summary": {"text": summary_text, "source": summary_source},
        "mitigation": {
            "rule_based": recommendations,
            "llm_narrative": llm_recommendation_text,
        },
        "explainable_ai": {
            "incident_type_top_features": itype_explanation,
            "severity_top_features": sev_explanation,
            "note": "Top contributing words = TF-IDF weight x logistic-regression coefficient for the predicted class.",
        },
        "knowledge_graph": graph,
    }

    # ── 9. NEW: Attack Storyline ───────────────────────────────────────────
    storyline = generate_storyline(record)
    record["attack_storyline"] = storyline

    # ── 10. NEW: Threat Score ─────────────────────────────────────────────
    # (compute after saving so we can pass similar incidents — but we compute
    #  without similar first, then update after saving)
    threat_score = calculate_threat_score(record, similar_incidents=None)
    record["threat_score"] = threat_score

    # ── 11. Save record ───────────────────────────────────────────────────
    STORE.insert_one(record)

    # ── 12. NEW: Cross-incident correlation ───────────────────────────────
    all_records = STORE.find()
    candidates = [r for r in all_records if r.get("_id") != incident_id]

    # Build text similarity map using classifier vectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    from .preprocessing import normalize_for_model

    text_sims: dict[str, float] = {}
    if candidates and classifier.model is not None:
        target_X = classifier.vectorizer.transform([normalize_for_model(process_text)])
        corpus_texts = [normalize_for_model(r["text"]) for r in candidates]
        corpus_X = classifier.vectorizer.transform(corpus_texts)
        sims = cosine_similarity(target_X, corpus_X)[0]
        text_sims = {r["_id"]: float(s) for r, s in zip(candidates, sims)}

    correlations = correlate_incident(record, candidates, text_similarities=text_sims)
    record["correlations"] = correlations

    # ── 13. NEW: Threat score refined with similar incidents ───────────────
    high_sim = [
        {"similarity_score": text_sims.get(r["_id"], 0), **r}
        for r in candidates
        if text_sims.get(r["_id"], 0) >= 0.5
    ]
    if high_sim:
        threat_score = calculate_threat_score(record, similar_incidents=high_sim)
        record["threat_score"] = threat_score

    # ── 14. NEW: Campaign detection ───────────────────────────────────────
    with _camp_lock:
        existing_campaigns = _read_campaigns()

        # Build correlations_map for all incidents
        corr_map: dict[str, list] = {incident_id: correlations}
        # Also load stored correlations for other incidents so we can
        # re-cluster globally
        for r in candidates:
            stored_corrs = r.get("correlations", [])
            if stored_corrs:
                corr_map[r["_id"]] = stored_corrs

        all_records_full = STORE.find()
        new_campaigns = detect_campaigns(
            all_incidents=list(all_records_full),
            correlations_map=corr_map,
            existing_campaigns=existing_campaigns,
        )
        _write_campaigns(new_campaigns)

    # Find if this incident belongs to a campaign
    campaign = find_incident_campaign(incident_id, new_campaigns)
    record["campaign_id"]   = campaign["campaign_id"] if campaign else None
    record["campaign_name"] = campaign["name"]        if campaign else None

    # Persist updated record (with correlations + campaign fields)
    # JSON store: rewrite file with updated record
    _update_stored_record(incident_id, {
        "correlations":    correlations,
        "threat_score":    record["threat_score"],
        "attack_storyline": storyline,
        "campaign_id":     record["campaign_id"],
        "campaign_name":   record["campaign_name"],
    })

    return record


def _update_stored_record(incident_id: str, updates: dict):
    """Best-effort update of a stored record with new fields."""
    try:
        if isinstance(STORE, db.JsonFallbackStore):
            with STORE._lock:
                data = STORE._read()
                for rec in data:
                    if rec.get("_id") == incident_id:
                        rec.update(updates)
                        break
                STORE._write(data)
        else:
            # MongoDB
            STORE.collection.update_one(
                {"_id": incident_id},
                {"$set": updates},
            )
    except Exception as e:
        print(f"[WARN] Could not update record {incident_id}: {e}")


# ── EXISTING: History ──────────────────────────────────────────────────────────
@app.get("/api/history")
def get_history():
    records = STORE.find()
    return [
        {
            "id":            r["_id"],
            "title":         r.get("title"),
            "created_at":    r.get("created_at"),
            "incident_type": r.get("incident_type", {}).get("label"),
            "severity":      r.get("severity", {}).get("label"),
            "confidence":    r.get("incident_type", {}).get("confidence"),
            "threat_score":  r.get("threat_score", {}).get("score") if r.get("threat_score") else None,
            "campaign_name": r.get("campaign_name"),
        }
        for r in records
    ]


# ── EXISTING: Incident detail ──────────────────────────────────────────────────
@app.get("/api/incident/{incident_id}")
def get_incident(incident_id: str):
    record = STORE.find_one(incident_id)
    if not record:
        raise HTTPException(status_code=404, detail="Incident not found")
    return record


# ── EXISTING: Final report ─────────────────────────────────────────────────────
@app.get("/api/report/{incident_id}")
def get_final_report(incident_id: str):
    r = STORE.find_one(incident_id)
    if not r:
        raise HTTPException(status_code=404, detail="Incident not found")

    root_cause_hints = []
    if r.get("entities", {}).get("attack_keywords"):
        root_cause_hints.append(
            f"Detected attack-related terms: {', '.join(r['entities']['attack_keywords'])}"
        )
    if r.get("iocs", {}).get("cves"):
        root_cause_hints.append(
            f"Referenced vulnerabilities (possible initial access vector): {', '.join(r['iocs']['cves'])}"
        )
    if not root_cause_hints:
        root_cause_hints.append("No explicit root-cause indicators (e.g. CVEs) found in the report text.")

    return {
        "incident_id":          incident_id,
        "title":                r.get("title"),
        "created_at":           r.get("created_at"),
        "incident_type":        r["incident_type"],
        "severity":             r["severity"],
        "summary":              r["summary"],
        "iocs":                 r["iocs"],
        "entities":             r["entities"],
        "root_cause_hints":     root_cause_hints,
        "mitigation":           r["mitigation"],
        "explainable_ai":       r["explainable_ai"],
        # New fields (graceful fallback for old records)
        "threat_score":         r.get("threat_score"),
        "attack_storyline":     r.get("attack_storyline"),
        "correlations":         r.get("correlations", []),
        "campaign_id":          r.get("campaign_id"),
        "campaign_name":        r.get("campaign_name"),
        "language_info":        r.get("language_info"),
    }


# ── EXISTING: Dashboard ────────────────────────────────────────────────────────
@app.get("/api/dashboard")
def get_dashboard():
    records = STORE.find()
    records = list(records)

    type_counts     = Counter(r.get("incident_type", {}).get("label", "Unknown") for r in records)
    severity_counts = Counter(r.get("severity", {}).get("label", "Unknown") for r in records)

    # Threat score distribution
    score_dist = {"Low Risk": 0, "Moderate Risk": 0, "High Risk": 0, "Critical Risk": 0}
    for r in records:
        cls = (r.get("threat_score") or {}).get("classification")
        if cls and cls in score_dist:
            score_dist[cls] += 1

    timeline = sorted(
        [
            {
                "created_at":    r.get("created_at"),
                "incident_type": r.get("incident_type", {}).get("label"),
                "severity":      r.get("severity", {}).get("label"),
                "threat_score":  (r.get("threat_score") or {}).get("score"),
                "campaign_name": r.get("campaign_name"),
                "title":         r.get("title"),
                "_id":           r.get("_id"),
            }
            for r in records
        ],
        key=lambda x: x["created_at"] or "",
    )

    graphs   = [r["knowledge_graph"] for r in records if r.get("knowledge_graph")]
    combined = merge_graphs(graphs) if graphs else {"nodes": [], "links": []}

    # Active campaigns
    campaigns      = _read_campaigns()
    active_camps   = len(campaigns)

    # High-risk IoC count
    high_risk_iocs = 0
    for r in records:
        iocs = r.get("iocs") or {}
        high_risk_iocs += len(iocs.get("ipv4_addresses", []))
        high_risk_iocs += len(iocs.get("domains", []))
        high_risk_iocs += sum(len(v) for v in (iocs.get("file_hashes") or {}).values() if isinstance(v, list))

    # Critical incidents
    critical_count = sum(
        1 for r in records
        if (r.get("severity") or {}).get("label") == "Critical"
        or (r.get("threat_score") or {}).get("classification") == "Critical Risk"
    )

    # Avg threat score
    scores = [
        (r.get("threat_score") or {}).get("score")
        for r in records
        if (r.get("threat_score") or {}).get("score") is not None
    ]
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0

    return {
        "total_incidents":           len(records),
        "incident_type_distribution": dict(type_counts),
        "severity_distribution":     dict(severity_counts),
        "threat_score_distribution": score_dist,
        "timeline":                  timeline,
        "combined_knowledge_graph":  combined,
        "active_campaigns":          active_camps,
        "high_risk_iocs":            high_risk_iocs,
        "critical_incidents":        critical_count,
        "avg_threat_score":          avg_score,
    }


# ── EXISTING: Similar incidents ────────────────────────────────────────────────
@app.get("/api/similar/{incident_id}")
def find_similar_incidents(incident_id: str, top_k: int = 5):
    from sklearn.metrics.pairwise import cosine_similarity
    from .preprocessing import normalize_for_model

    target = STORE.find_one(incident_id)
    if not target:
        raise HTTPException(status_code=404, detail="Incident not found")

    records = [r for r in STORE.find() if r["_id"] != incident_id]
    if not records:
        return {"incident_id": incident_id, "similar_incidents": []}

    vec     = classifier.vectorizer
    target_X = vec.transform([normalize_for_model(target["text"])])
    corpus_X = vec.transform([normalize_for_model(r["text"]) for r in records])
    sims    = cosine_similarity(target_X, corpus_X)[0]

    ranked = sorted(zip(records, sims), key=lambda x: -x[1])[:top_k]

    # Enhanced: also pull correlation reasons if available
    corr_map = {
        c["incident_id"]: c
        for c in (target.get("correlations") or [])
    }

    return {
        "incident_id": incident_id,
        "similar_incidents": [
            {
                "id":               r["_id"],
                "title":            r.get("title"),
                "incident_type":    r.get("incident_type", {}).get("label"),
                "severity":         r.get("severity", {}).get("label"),
                "similarity_score": round(float(score), 4),
                # Enhanced fields
                "relationship_strength": corr_map.get(r["_id"], {}).get("relationship_strength"),
                "correlation_confidence": corr_map.get(r["_id"], {}).get("confidence"),
                "reasons":          corr_map.get(r["_id"], {}).get("reasons", []),
            }
            for r, score in ranked
            if score > 0
        ],
    }


# ══════════════════════════════════════════════════════════════════════════════
# NEW ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/threat-score/{incident_id}")
def get_threat_score(incident_id: str):
    """Return the threat intelligence score for a specific incident."""
    r = STORE.find_one(incident_id)
    if not r:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Return stored score or recalculate if missing (old records)
    if r.get("threat_score"):
        return r["threat_score"]

    score = calculate_threat_score(r)
    return score


@app.get("/api/storyline/{incident_id}")
def get_storyline(incident_id: str):
    """Return the attack storyline for a specific incident."""
    r = STORE.find_one(incident_id)
    if not r:
        raise HTTPException(status_code=404, detail="Incident not found")

    if r.get("attack_storyline"):
        return r["attack_storyline"]

    return generate_storyline(r)


@app.get("/api/correlations/{incident_id}")
def get_correlations(incident_id: str):
    """Return cross-incident correlations for a specific incident."""
    r = STORE.find_one(incident_id)
    if not r:
        raise HTTPException(status_code=404, detail="Incident not found")

    if r.get("correlations") is not None:
        return {"incident_id": incident_id, "correlations": r["correlations"]}

    # Recalculate for old records
    from sklearn.metrics.pairwise import cosine_similarity
    from .preprocessing import normalize_for_model

    candidates = [rec for rec in STORE.find() if rec["_id"] != incident_id]
    text_sims: dict[str, float] = {}
    if candidates and classifier.model is not None:
        tX = classifier.vectorizer.transform([normalize_for_model(r["text"])])
        cX = classifier.vectorizer.transform([normalize_for_model(rec["text"]) for rec in candidates])
        sims = cosine_similarity(tX, cX)[0]
        text_sims = {rec["_id"]: float(s) for rec, s in zip(candidates, sims)}

    correlations = correlate_incident(r, candidates, text_similarities=text_sims)
    return {"incident_id": incident_id, "correlations": correlations}


@app.get("/api/campaigns")
def get_campaigns():
    """Return all detected threat campaigns."""
    campaigns = _read_campaigns()
    return {"campaigns": campaigns, "total": len(campaigns)}


@app.get("/api/campaign/{campaign_id}")
def get_campaign(campaign_id: str):
    """Return details of a specific threat campaign including member incidents."""
    campaigns = _read_campaigns()
    campaign  = next((c for c in campaigns if c.get("campaign_id") == campaign_id), None)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    # Attach member incident summaries
    members = []
    for inc_id in campaign.get("incident_ids", []):
        r = STORE.find_one(inc_id)
        if r:
            members.append({
                "id":            r["_id"],
                "title":         r.get("title"),
                "created_at":    r.get("created_at"),
                "incident_type": (r.get("incident_type") or {}).get("label"),
                "severity":      (r.get("severity") or {}).get("label"),
                "threat_score":  (r.get("threat_score") or {}).get("score"),
            })

    return {**campaign, "members": members}


@app.get("/api/report/{incident_id}/pdf")
def download_pdf_report(incident_id: str):
    """Generate and download a professional PDF intelligence report."""
    r = STORE.find_one(incident_id)
    if not r:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Ensure language_info exists for legacy records
    if not r.get("language_info"):
        try:
            from .language_utils import detect_and_translate
            r["language_info"] = detect_and_translate(r.get("text", ""))
        except Exception:
            r["language_info"] = {
                "detected_language_code": "en",
                "detected_language_name": "English",
                "original_text": r.get("text", ""),
                "translated_text": None,
            }

    # Gather all data for the PDF
    report_data = None
    try:
        root_cause_hints = []
        if r.get("entities", {}).get("attack_keywords"):
            root_cause_hints.append(
                f"Detected attack-related terms: {', '.join(r['entities']['attack_keywords'])}"
            )
        if r.get("iocs", {}).get("cves"):
            root_cause_hints.append(
                f"Referenced vulnerabilities: {', '.join(r['iocs']['cves'])}"
            )
        report_data = {"root_cause_hints": root_cause_hints}
    except Exception:
        pass

    # Similar incidents
    similar: list = []
    try:
        from sklearn.metrics.pairwise import cosine_similarity
        from .preprocessing import normalize_for_model
        candidates = [rec for rec in STORE.find() if rec["_id"] != incident_id]
        if candidates and classifier.model is not None:
            tX = classifier.vectorizer.transform([normalize_for_model(r["text"])])
            cX = classifier.vectorizer.transform([normalize_for_model(rec["text"]) for rec in candidates])
            sims = cosine_similarity(tX, cX)[0]
            ranked = sorted(zip(candidates, sims), key=lambda x: -x[1])[:5]
            similar = [
                {
                    "title": rec.get("title", "—"),
                    "incident_type": (rec.get("incident_type") or {}).get("label", "—"),
                    "severity": (rec.get("severity") or {}).get("label", "—"),
                    "similarity_score": round(float(s), 4),
                }
                for rec, s in ranked
                if s > 0
            ]
    except Exception:
        pass

    # Campaign
    campaigns = _read_campaigns()
    campaign  = find_incident_campaign(incident_id, campaigns)

    # Storyline
    storyline = r.get("attack_storyline") or generate_storyline(r)

    # Threat score
    threat_score = r.get("threat_score") or calculate_threat_score(r)

    try:
        pdf_bytes = generate_pdf(
            record=r,
            report_data=report_data,
            similar_incidents=similar,
            campaign=campaign,
            storyline=storyline,
            threat_score=threat_score,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

    filename = f"CIRIP_Report_{incident_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ══════════════════════════════════════════════════════════════════════════════
# MODEL PERFORMANCE & EVALUATION ENDPOINT
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/api/model-evaluation")
def get_model_evaluation():
    """
    Returns empirical evaluation results and comparison matrix for models.
    Preserves backward compatibility; does not modify any existing models or datasets.
    """
    return {
        "summary_cards": [
            {
                "title": "Incident Classification — Holdout Accuracy",
                "value": "100%",
                "type": "Holdout",
                "task": "Incident Classification",
                "sub": "In-distribution 80/20 test split (synthetic templates)",
            },
            {
                "title": "Incident Classification — Independent Accuracy",
                "value": "72.22%",
                "type": "Independent",
                "task": "Incident Classification",
                "sub": "Out-of-distribution benchmark (18 realistic reports)",
            },
            {
                "title": "Severity Prediction — Holdout Accuracy",
                "value": "100%",
                "type": "Holdout",
                "task": "Severity Prediction",
                "sub": "In-distribution 80/20 test split (synthetic templates)",
            },
            {
                "title": "Severity Prediction — Independent Accuracy",
                "value": "33.33%",
                "type": "Independent",
                "task": "Severity Prediction",
                "sub": "Out-of-distribution benchmark (18 realistic reports)",
            },
            {
                "title": "Incident Classification — Independent Macro F1",
                "value": "0.71",
                "type": "Independent",
                "task": "Incident Classification",
                "sub": "Unweighted mean F1 across 6 incident classes",
            },
            {
                "title": "Severity Prediction — Independent Macro F1",
                "value": "0.20",
                "type": "Independent",
                "task": "Severity Prediction",
                "sub": "Unweighted mean F1 across 4 severity levels",
            },
        ],
        "comparison_table": [
            {
                "model_task": "Logistic Regression — Incident Classification",
                "holdout_accuracy": "100%",
                "independent_accuracy": "72.22%",
                "independent_macro_f1": "0.71",
                "status": "Evaluated (Active)",
            },
            {
                "model_task": "Logistic Regression — Severity Prediction",
                "holdout_accuracy": "100%",
                "independent_accuracy": "33.33%",
                "independent_macro_f1": "0.20",
                "status": "Evaluated (Active)",
            },
            {
                "model_task": "Naive Bayes",
                "holdout_accuracy": "Not evaluated",
                "independent_accuracy": "Not evaluated",
                "independent_macro_f1": "Not evaluated",
                "status": "Not evaluated",
            },
            {
                "model_task": "Linear SVM",
                "holdout_accuracy": "Not evaluated",
                "independent_accuracy": "Not evaluated",
                "independent_macro_f1": "Not evaluated",
                "status": "Not evaluated",
            },
            {
                "model_task": "Random Forest",
                "holdout_accuracy": "Not evaluated",
                "independent_accuracy": "Not evaluated",
                "independent_macro_f1": "Not evaluated",
                "status": "Not evaluated",
            },
            {
                "model_task": "Decision Tree",
                "holdout_accuracy": "Not evaluated",
                "independent_accuracy": "Not evaluated",
                "independent_macro_f1": "Not evaluated",
                "status": "Not evaluated",
            },
            {
                "model_task": "K-Nearest Neighbors",
                "holdout_accuracy": "Not evaluated",
                "independent_accuracy": "Not evaluated",
                "independent_macro_f1": "Not evaluated",
                "status": "Not evaluated",
            },
            {
                "model_task": "Gradient Boosting",
                "holdout_accuracy": "Not evaluated",
                "independent_accuracy": "Not evaluated",
                "independent_macro_f1": "Not evaluated",
                "status": "Not evaluated",
            },
            {
                "model_task": "Neural Network",
                "holdout_accuracy": "Not evaluated",
                "independent_accuracy": "Not evaluated",
                "independent_macro_f1": "Not evaluated",
                "status": "Not evaluated",
            },
            {
                "model_task": "Transformer / BERT",
                "holdout_accuracy": "Not evaluated",
                "independent_accuracy": "Not evaluated",
                "independent_macro_f1": "Not evaluated",
                "status": "Not evaluated",
            },
        ],
        "notes": {
            "benchmark_size": 18,
            "synthetic_template_caveat": "The 100% holdout scores are affected by repeated synthetic sentence templates in the generated training dataset and should not be interpreted as real-world accuracy.",
            "selection_rationale": "Logistic Regression was selected for CIRIP because it is lightweight, fast, interpretable via linear coefficients (driving Explainable AI), and suitable for sparse TF-IDF text features without requiring GPU acceleration. It is not claimed to outperform all other algorithms because they have not yet been benchmarked on this platform.",
        },
    }

