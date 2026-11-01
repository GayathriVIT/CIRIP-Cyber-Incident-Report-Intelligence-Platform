"""
Attack Storyline Generator.

Maps incident data (incident type, entities, IoCs, attack keywords) to
MITRE ATT&CK-inspired attack stages to produce a visual attack journey.

IMPORTANT HONESTY LABELS:
  - "confirmed"  : stage directly evidenced by extracted IoCs or entities
  - "inferred"   : stage inferred from textual keywords (ML/rule prediction)
  - "possible"   : stage plausible given incident type but no direct evidence

Only stages with at least one piece of evidence are included in the output.
Empty stages are never fabricated.
"""

from __future__ import annotations
import re

# ── Stage definitions ──────────────────────────────────────────────────────
# Each stage: (stage_id, name, mitre_tactic, keywords, weight)
# weight = importance in attack chain ordering

STAGES = [
    (
        "initial_access",
        "Initial Access",
        "TA0001",
        [
            "phishing", "spear-phishing", "spearphishing", "email", "attachment",
            "exploit", "supply chain", "zero-day", "zeroday", "watering hole",
            "drive-by", "external facing", "vpn", "remote desktop", "rdp access",
            "brute force login", "credential stuffing", "social engineering",
        ],
        1,
    ),
    (
        "execution",
        "Execution",
        "TA0002",
        [
            "malware", "payload", "script", "execute", "ran", "running",
            "launched", "dropper", "loader", "macro", "powershell",
            "cmd", "wscript", "mshta", "command executed", "shellcode",
            "ransomware deployed", "trojan", "worm", "virus",
        ],
        2,
    ),
    (
        "persistence",
        "Persistence",
        "TA0003",
        [
            "persistence", "registry", "scheduled task", "cron", "startup",
            "autorun", "service created", "backdoor installed", "boot",
            "logon script", "init script",
        ],
        3,
    ),
    (
        "privilege_escalation",
        "Privilege Escalation",
        "TA0004",
        [
            "privilege escalation", "privilege", "escalation", "admin",
            "administrator", "root", "sudo", "uac bypass", "elevated",
            "token impersonation", "kernel exploit",
        ],
        4,
    ),
    (
        "credential_access",
        "Credential Access",
        "TA0006",
        [
            "credential", "credentials", "password", "passwords", "hash",
            "mimikatz", "lsass", "ntlm", "kerberos", "ticket", "dump",
            "keylogger", "credential theft", "harvesting", "stolen",
            "account compromise",
        ],
        5,
    ),
    (
        "lateral_movement",
        "Lateral Movement",
        "TA0008",
        [
            "lateral movement", "lateral", "rdp", "smb", "wmi", "psexec",
            "remote exec", "spread", "propagation", "moved to",
            "accessed other", "internal network",
        ],
        6,
    ),
    (
        "command_control",
        "Command & Control",
        "TA0011",
        [
            "c2", "c&c", "command and control", "command & control",
            "beacon", "beaconing", "callback", "reverse shell",
            "remote access", "rat ", "remote administration",
            "communication with", "contacted", "connected to",
        ],
        7,
    ),
    (
        "exfiltration",
        "Exfiltration",
        "TA0010",
        [
            "exfil", "exfiltration", "data theft", "data transfer",
            "uploaded", "leaked", "sent to", "copied to external",
            "stolen data", "data breach", "exfiltrated",
        ],
        8,
    ),
    (
        "impact",
        "Impact",
        "TA0040",
        [
            "encrypt", "encrypted", "ransom", "ransomware", "wipe",
            "wiped", "destroy", "destroyed", "denial of service",
            "ddos", "disruption", "service down", "outage",
            "data deleted", "defaced",
        ],
        9,
    ),
]


# ── IoC → stage mapping ────────────────────────────────────────────────────

INCIDENT_TYPE_STAGE_HINTS: dict[str, list[str]] = {
    "Phishing":      ["initial_access"],
    "Malware":       ["execution"],
    "Ransomware":    ["impact"],
    "DDoS":          ["impact"],
    "Data Breach":   ["exfiltration"],
    "Insider Threat": ["credential_access", "exfiltration"],
}


def generate_storyline(record: dict) -> dict:
    """
    Generate an attack storyline from a stored incident record.

    Returns
    -------
    dict with keys:
        stages         : list of stage dicts (in attack chain order)
        total_stages   : int
        confidence     : int (0-100, overall story confidence)
        summary        : str
        source         : str
    """
    text = (record.get("text") or "").lower()
    iocs = record.get("iocs") or {}
    entities = record.get("entities") or {}
    incident_type = (record.get("incident_type") or {}).get("label", "")

    attack_kws = {k.lower() for k in entities.get("attack_keywords", [])}
    malware = entities.get("malware_families", [])
    domains = iocs.get("domains", [])
    ips = iocs.get("ipv4_addresses", [])
    emails = iocs.get("emails", [])
    cves = iocs.get("cves", []) + entities.get("cves", [])
    all_hashes = []
    for v in (iocs.get("file_hashes") or {}).values():
        if isinstance(v, list):
            all_hashes.extend(v)

    # ── Hint stages from incident type ────────────────────────────────────
    hinted_stages = set(INCIDENT_TYPE_STAGE_HINTS.get(incident_type, []))

    active_stages: list[dict] = []

    for stage_id, name, mitre, keywords, weight in STAGES:
        # Find keyword matches in text
        matched_keywords = [kw for kw in keywords if kw in text]
        matched_attack_kws = [kw for kw in attack_kws if any(kw in k or k in kw for k in keywords)]
        all_matched = list(dict.fromkeys(matched_keywords + matched_attack_kws))

        if not all_matched and stage_id not in hinted_stages:
            continue  # skip stages with no evidence

        # Attach IoCs relevant to this stage
        stage_iocs: list[str] = []
        evidence_items: list[str] = []

        if stage_id == "initial_access":
            stage_iocs.extend(emails[:3])
            if cves:
                stage_iocs.extend(cves[:2])
                evidence_items.append(f"CVE referenced: {', '.join(cves[:2])}")

        elif stage_id == "execution":
            stage_iocs.extend(malware[:3])
            stage_iocs.extend(all_hashes[:2])
            if malware:
                evidence_items.append(f"Malware: {', '.join(malware[:2])}")

        elif stage_id == "command_control":
            stage_iocs.extend(domains[:3])
            stage_iocs.extend(ips[:2])
            if domains:
                evidence_items.append(f"C2 domains: {', '.join(domains[:2])}")
            if ips:
                evidence_items.append(f"C2 IPs: {', '.join(ips[:2])}")

        elif stage_id == "exfiltration":
            stage_iocs.extend(ips[:2])
            stage_iocs.extend(domains[:2])

        elif stage_id == "impact":
            stage_iocs.extend(all_hashes[:2])

        # Evidence list
        for kw in all_matched[:4]:
            evidence_items.append(f'Keyword detected: "{kw}"')

        # Determine confidence and label
        if all_matched:
            kw_conf = min(len(all_matched) * 20, 70)
        else:
            kw_conf = 0

        if stage_id in hinted_stages and not all_matched:
            # Hinted from incident type, no direct keyword evidence
            confidence = 40
            evidence_label = "possible"
            note = f"Possible stage based on incident type: {incident_type}."
        elif all_matched:
            confidence = min(kw_conf + (20 if stage_iocs else 0), 95)
            evidence_label = "confirmed" if stage_iocs else "inferred"
            note = None
        else:
            continue

        active_stages.append({
            "stage_id":       stage_id,
            "name":           name,
            "mitre_tactic":   mitre,
            "evidence_label": evidence_label,   # confirmed / inferred / possible
            "confidence":     confidence,
            "evidence":       evidence_items[:5],
            "iocs":           list(dict.fromkeys(stage_iocs))[:5],
            "note":           note,
            "order":          weight,
        })

    # Sort by attack chain order
    active_stages.sort(key=lambda s: s["order"])

    # Overall confidence = average of stage confidences (if any stages)
    if active_stages:
        overall_conf = int(sum(s["confidence"] for s in active_stages) / len(active_stages))
    else:
        overall_conf = 0

    # Summary text
    if active_stages:
        stage_names = [s["name"] for s in active_stages]
        if len(stage_names) == 1:
            summary = f"Single attack stage identified: {stage_names[0]}."
        else:
            summary = (
                f"Attack chain spanning {len(active_stages)} stages detected: "
                + " → ".join(stage_names)
                + "."
            )
    else:
        summary = "Insufficient evidence to construct a detailed attack storyline from this report."

    return {
        "stages":        active_stages,
        "total_stages":  len(active_stages),
        "confidence":    overall_conf,
        "summary":       summary,
        "source":        "rule-based MITRE ATT&CK keyword mapping",
        "note": (
            "Stages labeled 'inferred' or 'possible' are based on keyword analysis. "
            "Only 'confirmed' stages have direct IoC evidence."
        ),
    }
