"""
Cross-Incident Threat Correlation Engine.

Compares a target incident against all stored incidents to identify shared
Indicators of Compromise, malware families, CVEs, and textual similarity.

Output labels are deliberately conservative:
  - Strongly Related   (confidence >= 70)
  - Potentially Related (confidence 40-69)
  - Weakly Related     (confidence 10-39)

No correlation below 10% confidence is reported.

All weights and thresholds are documented inline for academic transparency.
"""

from __future__ import annotations
from typing import Any

# ── Shared-indicator point weights ─────────────────────────────────────────
WEIGHTS = {
    "file_hash":  35,   # Exact hash match = near-certainty of same tool/payload
    "ip_address": 30,   # Same C2/attacker IP
    "domain":     25,   # Same malicious domain
    "malware":    20,   # Same malware family
    "cve":        15,   # Same CVE exploited
    "text_sim":   15,   # High TF-IDF cosine similarity (scaled 0→15)
    "attack_kw":  10,   # ≥3 identical attack keywords
    "email":       8,   # Same attacker email
    "url":         8,   # Same malicious URL
}

STRENGTH_THRESHOLDS = [
    (70, "Strongly Related"),
    (40, "Potentially Related"),
    (10, "Weakly Related"),
]


def _normalize_list(items: Any) -> set[str]:
    """Return a lowercase set from list-or-None."""
    if not items:
        return set()
    return {str(i).lower().strip() for i in items if i}


def _all_hashes(fh: dict) -> set[str]:
    out: set[str] = set()
    for v in fh.values():
        if isinstance(v, list):
            out.update(h.lower() for h in v)
    return out


def _shared(a: set, b: set) -> list[str]:
    return sorted(a & b)


def correlate_incident(
    target: dict,
    candidates: list[dict],
    text_similarities: dict[str, float] | None = None,
) -> list[dict]:
    """
    Compare `target` incident against `candidates`.

    Parameters
    ----------
    target : dict
        Full incident record (the one just analyzed or looked up).
    candidates : list[dict]
        All other stored incident records.
    text_similarities : dict | None
        Mapping of candidate _id → cosine similarity score (from classifier vectorizer).
        If None, text similarity contribution is skipped.

    Returns
    -------
    list of correlation dicts (only those with confidence >= 10), sorted by confidence desc.
    """
    if not candidates:
        return []

    t_iocs = target.get("iocs") or {}
    t_ent  = target.get("entities") or {}

    t_ips     = _normalize_list(t_iocs.get("ipv4_addresses"))
    t_domains = _normalize_list(t_iocs.get("domains"))
    t_emails  = _normalize_list(t_iocs.get("emails"))
    t_urls    = _normalize_list(t_iocs.get("urls"))
    t_hashes  = _all_hashes(t_iocs.get("file_hashes") or {})
    t_cves    = _normalize_list(t_iocs.get("cves")) | _normalize_list((t_ent.get("cves")))
    t_malware = _normalize_list(t_ent.get("malware_families"))
    t_kws     = _normalize_list(t_ent.get("attack_keywords"))

    results: list[dict] = []

    for cand in candidates:
        if cand.get("_id") == target.get("_id"):
            continue  # skip self

        c_iocs = cand.get("iocs") or {}
        c_ent  = cand.get("entities") or {}

        c_ips     = _normalize_list(c_iocs.get("ipv4_addresses"))
        c_domains = _normalize_list(c_iocs.get("domains"))
        c_emails  = _normalize_list(c_iocs.get("emails"))
        c_urls    = _normalize_list(c_iocs.get("urls"))
        c_hashes  = _all_hashes(c_iocs.get("file_hashes") or {})
        c_cves    = _normalize_list(c_iocs.get("cves")) | _normalize_list(c_ent.get("cves"))
        c_malware = _normalize_list(c_ent.get("malware_families"))
        c_kws     = _normalize_list(c_ent.get("attack_keywords"))

        raw_score = 0
        reasons: list[str] = []

        # File hashes
        sh = _shared(t_hashes, c_hashes)
        if sh:
            raw_score += WEIGHTS["file_hash"] * len(sh)
            reasons.append(f"Identical file hash(es): {', '.join(sh[:2])}")

        # IPs
        si = _shared(t_ips, c_ips)
        if si:
            raw_score += WEIGHTS["ip_address"] * len(si)
            reasons.append(f"Same IP address(es): {', '.join(si[:2])}")

        # Domains
        sd = _shared(t_domains, c_domains)
        if sd:
            raw_score += WEIGHTS["domain"] * len(sd)
            reasons.append(f"Same domain(s): {', '.join(sd[:2])}")

        # Malware
        sm = _shared(t_malware, c_malware)
        if sm:
            raw_score += WEIGHTS["malware"] * len(sm)
            reasons.append(f"Same malware family: {', '.join(sm[:2])}")

        # CVEs
        sc = _shared(t_cves, c_cves)
        if sc:
            raw_score += WEIGHTS["cve"] * len(sc)
            reasons.append(f"Same CVE(s): {', '.join(sc[:2])}")

        # Attack keywords
        sk = _shared(t_kws, c_kws)
        if len(sk) >= 3:
            raw_score += WEIGHTS["attack_kw"]
            reasons.append(f"Similar attack behavior ({len(sk)} common keywords)")

        # Emails
        se = _shared(t_emails, c_emails)
        if se:
            raw_score += WEIGHTS["email"] * len(se)
            reasons.append(f"Same email(s): {', '.join(se[:2])}")

        # URLs
        su = _shared(t_urls, c_urls)
        if su:
            raw_score += WEIGHTS["url"] * len(su)
            reasons.append(f"Same URL(s): {', '.join(su[:2])}")

        # Text similarity (TF-IDF cosine)
        if text_similarities and cand.get("_id") in text_similarities:
            sim = float(text_similarities[cand["_id"]])
            if sim >= 0.3:
                ts_pts = int(sim * WEIGHTS["text_sim"])
                raw_score += ts_pts
                reasons.append(f"High textual similarity ({sim * 100:.0f}%)")

        # Clamp confidence to 0–100
        confidence = min(raw_score, 100)

        if confidence < 10:
            continue

        # Determine relationship strength
        strength = "Weakly Related"
        for threshold, label in STRENGTH_THRESHOLDS:
            if confidence >= threshold:
                strength = label
                break

        results.append({
            "incident_id":         cand["_id"],
            "incident_title":      cand.get("title", "Untitled"),
            "incident_type":       (cand.get("incident_type") or {}).get("label", "Unknown"),
            "severity":            (cand.get("severity") or {}).get("label", "Unknown"),
            "created_at":          cand.get("created_at"),
            "relationship_strength": strength,
            "confidence":          confidence,
            "reasons":             reasons,
            "source":              "rule-based IoC/entity correlation engine",
        })

    # Sort by confidence descending
    results.sort(key=lambda x: -x["confidence"])
    return results
