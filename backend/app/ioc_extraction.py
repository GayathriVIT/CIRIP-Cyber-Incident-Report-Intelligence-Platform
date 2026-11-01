"""
Rule-based Indicator of Compromise (IoC) extraction.

This is deliberately RULE-BASED (regex), not ML-based, and is labeled as such
in the API response so the frontend can clearly distinguish:
  - Rule-based IoC extraction (this module)
  - ML-based incident classification / severity prediction (classifier.py, severity.py)
  - LLM-generated summary / recommendation (llm_integration.py, used optionally)
"""
import re

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")
URL_RE = re.compile(r"\bhttps?://[^\s,)\]\"']+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|info|xyz|biz|io|co|ru|cn|top|club|online|site)\b",
    re.IGNORECASE,
)
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _dedupe(items):
    seen, out = set(), []
    for i in items:
        key = i.lower()
        if key not in seen:
            seen.add(key)
            out.append(i)
    return out


def extract_iocs(text: str) -> dict:
    urls = _dedupe(URL_RE.findall(text))
    emails = _dedupe(EMAIL_RE.findall(text))
    ipv4 = _dedupe(IPV4_RE.findall(text))
    ipv6 = _dedupe([m for m in IPV6_RE.findall(text) if m.count(":") >= 2])
    cves = _dedupe([c.upper() for c in CVE_RE.findall(text)])
    sha256 = _dedupe(SHA256_RE.findall(text))
    sha1 = _dedupe([h for h in SHA1_RE.findall(text) if h not in sha256])
    md5 = _dedupe([h for h in MD5_RE.findall(text) if h not in sha1 and h not in sha256])

    # domains: strip out ones that are actually part of an email or URL already captured
    raw_domains = DOMAIN_RE.findall(text)
    domains = []
    for d in raw_domains:
        if any(d.lower() in e.lower() for e in emails):
            continue
        if any(d.lower() in u.lower() for u in urls):
            continue
        domains.append(d)
    domains = _dedupe(domains)

    return {
        "ipv4_addresses": ipv4,
        "ipv6_addresses": ipv6,
        "domains": domains,
        "urls": urls,
        "emails": emails,
        "cves": cves,
        "file_hashes": {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
        },
        "extraction_method": "rule-based (regex)",
    }
