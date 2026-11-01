"""
Lightweight Named Entity Recognition for cyber incident text.

By design this uses a small gazetteer + regex heuristics instead of a large
transformer NER model, so the project stays runnable on a normal laptop with
no large model downloads required.

OPTIONAL UPGRADE PATH (documented in README): swap this module for spaCy's
en_core_web_sm (or a fine-tuned cyber-NER model) for better organization/person
recognition, without changing the API contract (extract_entities(text) -> dict).
"""
import re

# Small, extensible gazetteer of common malware / threat-actor / tool names.
MALWARE_GAZETTEER = [
    "Emotet", "TrickBot", "LockBit", "Ryuk", "Conti", "AgentTesla", "Cobalt Strike",
    "Mimikatz", "Zeus", "njRAT", "WannaCry", "NotPetya", "Qakbot", "REvil", "BlackCat",
    "DarkSide", "Sodinokibi", "IcedID", "Dridex", "Gootloader", "Raccoon Stealer",
]

ATTACK_KEYWORDS = [
    "phishing", "spear-phishing", "ransomware", "malware", "trojan", "exploit",
    "brute force", "credential stuffing", "lateral movement", "exfiltration",
    "denial-of-service", "ddos", "sql injection", "privilege escalation",
    "man-in-the-middle", "supply chain attack", "zero-day", "backdoor",
]

USER_RE = re.compile(r"\buser\s+([A-Za-z][A-Za-z0-9._-]{2,20})\b", re.IGNORECASE)
ORG_RE = re.compile(r"\b(?:[A-Z][a-zA-Z&]+\s){0,3}(?:Department|Corp|Corporation|Inc|LLC|Center|Team|Bank|Hospital|University)\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def extract_entities(text: str) -> dict:
    text_l = text.lower()

    malware = [m for m in MALWARE_GAZETTEER if m.lower() in text_l]
    attack_types = [k for k in ATTACK_KEYWORDS if k in text_l]
    users = list(dict.fromkeys(USER_RE.findall(text)))
    orgs = list(dict.fromkeys(ORG_RE.findall(text)))
    cves = list(dict.fromkeys([c.upper() for c in CVE_RE.findall(text)]))

    return {
        "malware_families": malware,
        "attack_keywords": attack_types,
        "users": users,
        "organizations": orgs,
        "cves": cves,
        "extraction_method": "gazetteer + regex heuristics (lightweight NER)",
    }
