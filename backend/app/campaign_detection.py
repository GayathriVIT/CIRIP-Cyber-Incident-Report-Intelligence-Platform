"""
Threat Campaign Detection Engine.

Groups correlated incidents into named "threat campaigns" when two or more
incidents share strong/potential relationships (confidence >= 40).

Campaigns are stored as a separate list in the JSON store (or a second
MongoDB collection). This module is purely logic — storage calls are handled
in main.py.

Naming convention: Campaign Alpha, Campaign Beta, Campaign Gamma, …
(26 names, then Campaign AA, Campaign AB, …)
"""

from __future__ import annotations
import itertools
import string
from typing import Any


# ── Campaign naming ──────────────────────────────────────────────────────────

_NATO_NAMES = [
    "Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta", "Eta", "Theta",
    "Iota", "Kappa", "Lambda", "Mu", "Nu", "Xi", "Omicron", "Pi", "Rho",
    "Sigma", "Tau", "Upsilon", "Phi", "Chi", "Psi", "Omega",
]


def _campaign_name(index: int) -> str:
    if index < len(_NATO_NAMES):
        return f"Campaign {_NATO_NAMES[index]}"
    # Fallback: Campaign AA, Campaign AB …
    letters = list(string.ascii_uppercase)
    combo = list(itertools.product(letters, letters))
    ci = index - len(_NATO_NAMES)
    return f"Campaign {''.join(combo[ci % len(combo)])}"


# ── Helpers ──────────────────────────────────────────────────────────────────

def _all_hashes(fh: dict) -> list[str]:
    out = []
    for v in fh.values():
        if isinstance(v, list):
            out.extend(v)
    return out


def _common_iocs(incidents: list[dict]) -> dict:
    """Return IoC values that appear in ≥2 of the incidents."""
    from collections import Counter

    def gather(key: str) -> list[str]:
        all_vals = []
        for inc in incidents:
            iocs = inc.get("iocs") or {}
            if key == "file_hashes":
                all_vals.extend(_all_hashes(iocs.get("file_hashes") or {}))
            else:
                all_vals.extend(iocs.get(key, []))
        counts = Counter(v.lower() for v in all_vals)
        return [v for v, c in counts.items() if c >= 2]

    def gather_entity(key: str) -> list[str]:
        all_vals = []
        for inc in incidents:
            ent = inc.get("entities") or {}
            all_vals.extend(ent.get(key, []))
        counts = Counter(v.lower() for v in all_vals)
        return [v for v, c in counts.items() if c >= 2]

    return {
        "domains":         gather("domains"),
        "ip_addresses":    gather("ipv4_addresses"),
        "urls":            gather("urls"),
        "file_hashes":     gather("file_hashes"),
        "cves":            gather("cves"),
        "malware_families": gather_entity("malware_families"),
    }


def _threat_level(incidents: list[dict]) -> str:
    """Derive overall campaign threat level from member severities."""
    sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    max_sev = 0
    for inc in incidents:
        sev = (inc.get("severity") or {}).get("label", "")
        max_sev = max(max_sev, sev_rank.get(sev, 0))
    return {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}.get(max_sev, "Unknown")


# ── Main public function ─────────────────────────────────────────────────────

def detect_campaigns(
    all_incidents: list[dict],
    correlations_map: dict[str, list[dict]],
    existing_campaigns: list[dict] | None = None,
) -> list[dict]:
    """
    Build or update the list of threat campaigns.

    Parameters
    ----------
    all_incidents : list[dict]
        All stored incident records (full objects).
    correlations_map : dict[str, list[dict]]
        Mapping of incident_id → list of correlation results for that incident.
        Only correlations with confidence >= 40 are considered.
    existing_campaigns : list[dict] | None
        Previously detected campaigns (to avoid renaming/duplicating).

    Returns
    -------
    list[dict] — updated list of campaign objects.
    """
    MIN_CONFIDENCE = 40

    # Build adjacency: incident_id → set of strongly/potentially related incident_ids
    adjacency: dict[str, set[str]] = {}
    incident_by_id: dict[str, dict] = {inc["_id"]: inc for inc in all_incidents if inc.get("_id")}

    for inc_id, corr_list in correlations_map.items():
        for corr in corr_list:
            if corr.get("confidence", 0) >= MIN_CONFIDENCE:
                adjacency.setdefault(inc_id, set()).add(corr["incident_id"])
                adjacency.setdefault(corr["incident_id"], set()).add(inc_id)

    # Find connected components (clusters) via union-find
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        if parent.get(x, x) != x:
            parent[x] = find(parent[x])
        return parent.get(x, x)

    def union(a: str, b: str):
        pa, pb = find(a), find(b)
        if pa != pb:
            parent[pa] = pb

    for node, neighbors in adjacency.items():
        for neighbor in neighbors:
            union(node, neighbor)

    # Group by root
    clusters: dict[str, set[str]] = {}
    for node in adjacency:
        root = find(node)
        clusters.setdefault(root, set()).add(node)

    # Only clusters with ≥2 incidents qualify as a campaign
    valid_clusters = [
        sorted(members)
        for members in clusters.values()
        if len(members) >= 2
    ]

    if not valid_clusters:
        return existing_campaigns or []

    # Match clusters to existing campaigns (by incident set overlap)
    existing = {frozenset(c.get("incident_ids", [])): c for c in (existing_campaigns or [])}
    next_index = len(existing)
    campaigns: list[dict] = []

    for cluster in valid_clusters:
        cluster_set = frozenset(cluster)

        # Check if this cluster matches an existing campaign
        matched = None
        for existing_set, camp in existing.items():
            # Overlap ≥ 50%
            overlap = len(cluster_set & existing_set) / max(len(cluster_set), len(existing_set))
            if overlap >= 0.5:
                matched = camp
                break

        incidents_in_cluster = [incident_by_id[i] for i in cluster if i in incident_by_id]
        common_iocs = _common_iocs(incidents_in_cluster)
        threat_level = _threat_level(incidents_in_cluster)

        dates = sorted(
            inc.get("created_at", "") for inc in incidents_in_cluster if inc.get("created_at")
        )

        if matched:
            # Update existing campaign
            updated = dict(matched)
            updated["incident_ids"]    = cluster
            updated["common_iocs"]     = common_iocs
            updated["threat_level"]    = threat_level
            updated["incident_count"]  = len(cluster)
            updated["last_activity"]   = dates[-1] if dates else updated.get("last_activity")
            campaigns.append(updated)
        else:
            # Create new campaign
            campaigns.append({
                "campaign_id":    f"camp-{len(campaigns) + next_index:03d}",
                "name":           _campaign_name(len(campaigns) + next_index),
                "threat_level":   threat_level,
                "incident_ids":   cluster,
                "incident_count": len(cluster),
                "common_iocs":    common_iocs,
                "first_detected": dates[0] if dates else None,
                "last_activity":  dates[-1] if dates else None,
                "source":         "campaign detection engine (IoC correlation clustering)",
            })

    return campaigns


def find_incident_campaign(
    incident_id: str, campaigns: list[dict]
) -> dict | None:
    """Return the campaign a given incident belongs to, or None."""
    for camp in campaigns:
        if incident_id in camp.get("incident_ids", []):
            return camp
    return None
