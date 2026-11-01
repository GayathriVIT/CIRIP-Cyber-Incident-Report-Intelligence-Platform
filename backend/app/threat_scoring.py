"""
Threat Intelligence Scoring Engine.

Calculates a deterministic 0-100 Threat Intelligence Score from incident data.
Every point contribution is transparent and explainable — the score breakdown
is returned alongside the final score so the frontend can display 'Why this score?'.

Score is DETERMINISTIC (no randomness): same input always produces same score.
Score is labeled as 'calculated' (not ML-predicted) in the API response.
"""

from typing import Any

# Score classification thresholds
CLASSIFICATIONS = [
    (76, 100, "Critical Risk"),
    (51, 75,  "High Risk"),
    (26, 50,  "Moderate Risk"),
    (0,  25,  "Low Risk"),
]

SEVERITY_SCORES = {
    "Critical": 25,
    "High": 20,
    "Medium": 10,
    "Low": 5,
}

ATTACK_KEYWORD_THRESHOLD = 3  # keywords needed for bonus points


def calculate_threat_score(record: dict, similar_incidents: list | None = None) -> dict:
    """
    Calculate a 0-100 Threat Intelligence Score from a stored incident record.

    Parameters
    ----------
    record : dict
        The full stored incident record (as returned by /api/analyze).
    similar_incidents : list | None
        Optional list of similar incident dicts (from /api/similar).

    Returns
    -------
    dict with keys:
        score          : int   (0-100)
        classification : str   (Low Risk / Moderate Risk / High Risk / Critical Risk)
        breakdown      : list  of {reason, points, category}
        explanation    : str   (human-readable summary)
    """
    breakdown = []
    total = 0

    def add(reason: str, points: int, category: str):
        nonlocal total
        if points > 0:
            breakdown.append({"reason": reason, "points": points, "category": category})
            total += points

    # ── 1. Severity (up to 25 pts) ─────────────────────────────────────────
    sev_label = (record.get("severity") or {}).get("label", "")
    sev_pts = SEVERITY_SCORES.get(sev_label, 0)
    if sev_pts:
        add(f"{sev_label} severity detected", sev_pts, "severity")

    # ── 2. Malware (up to 15 pts, +5 per unique family, max 3) ────────────
    malware = (record.get("entities") or {}).get("malware_families", [])
    malware_pts = min(len(malware) * 5, 15)
    if malware_pts:
        add(f"Malware detected: {', '.join(malware[:3])}", malware_pts, "malware")

    # ── 3. CVEs (up to 10 pts, +5 per CVE, max 2) ─────────────────────────
    iocs = record.get("iocs") or {}
    cves_from_iocs = iocs.get("cves", [])
    cves_from_ent = (record.get("entities") or {}).get("cves", [])
    all_cves = list(set(cves_from_iocs + cves_from_ent))
    cve_pts = min(len(all_cves) * 5, 10)
    if cve_pts:
        add(f"Known vulnerabilities referenced: {', '.join(all_cves[:2])}", cve_pts, "cve")

    # ── 4. IoC richness (up to 20 pts, +5 per IoC category with items) ────
    ioc_categories: list[tuple[str, Any]] = [
        ("IPv4 addresses", iocs.get("ipv4_addresses", [])),
        ("Domains",        iocs.get("domains", [])),
        ("URLs",           iocs.get("urls", [])),
        ("Email addresses",iocs.get("emails", [])),
        ("File hashes",    _all_hashes(iocs.get("file_hashes", {}))),
    ]
    ioc_hit_categories = [name for name, items in ioc_categories if items]
    ioc_pts = min(len(ioc_hit_categories) * 5, 20)
    if ioc_pts:
        add(
            f"Multiple IoC types detected: {', '.join(ioc_hit_categories)}",
            ioc_pts,
            "ioc",
        )

    # ── 5. Attack keyword density (up to 10 pts) ──────────────────────────
    attack_kws = (record.get("entities") or {}).get("attack_keywords", [])
    if len(attack_kws) >= ATTACK_KEYWORD_THRESHOLD:
        kw_pts = min(len(attack_kws) * 2, 10)
        add(
            f"High attack keyword density ({len(attack_kws)} terms detected)",
            kw_pts,
            "keywords",
        )

    # ── 6. Similar past incidents (up to 15 pts) ──────────────────────────
    if similar_incidents:
        high_sim = [s for s in similar_incidents if s.get("similarity_score", 0) >= 0.5]
        if high_sim:
            sim_pts = min(len(high_sim) * 5, 15)
            add(
                f"Similar to {len(high_sim)} past incident(s) — potential repeat attack pattern",
                sim_pts,
                "correlation",
            )

    # ── 7. Incident type risk multiplier (up to 5 pts) ────────────────────
    RISKY_TYPES = {"Ransomware", "Data Breach", "Insider Threat"}
    itype = (record.get("incident_type") or {}).get("label", "")
    if itype in RISKY_TYPES:
        add(f"High-risk incident type: {itype}", 5, "type")

    # ── Clamp to 100 ──────────────────────────────────────────────────────
    score = min(total, 100)

    # ── Classification ────────────────────────────────────────────────────
    classification = "Low Risk"
    for low, high, label in CLASSIFICATIONS:
        if low <= score <= high:
            classification = label
            break

    # ── Human-readable explanation ─────────────────────────────────────────
    top_reasons = [b["reason"] for b in breakdown[:3]]
    if top_reasons:
        explanation = (
            f"Score of {score}/100 ({classification}). "
            f"Primary factors: {'; '.join(top_reasons)}."
        )
    else:
        explanation = f"Score of {score}/100 ({classification}). No significant risk indicators detected."

    return {
        "score": score,
        "classification": classification,
        "breakdown": breakdown,
        "explanation": explanation,
        "source": "deterministic scoring engine",
    }


def _all_hashes(file_hashes: dict) -> list:
    out = []
    for v in file_hashes.values():
        if isinstance(v, list):
            out.extend(v)
    return out
