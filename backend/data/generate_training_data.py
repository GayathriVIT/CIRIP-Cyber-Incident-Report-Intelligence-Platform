"""
Generates a synthetic (template-based) labeled dataset of cyber incident report
texts for demo/training purposes.

IMPORTANT (student project note):
This data is SYNTHETIC and template-generated so the project is runnable without
external dataset downloads. It is good enough to demonstrate a working ML pipeline
(TF-IDF + Logistic Regression) but is NOT a substitute for real-world labeled data.
For higher real-world accuracy, replace this with actual incident reports from
sources such as CERT advisories, MITRE/CVE data, or a labeled Kaggle dataset, kept
in the same CSV format: text,incident_type,severity
"""
import csv
import random
import os

random.seed(42)

INCIDENT_TYPES = ["Phishing", "Malware", "Ransomware", "DDoS", "Insider Threat", "Data Breach"]
SEVERITIES = ["Low", "Medium", "High", "Critical"]

IPS = ["203.0.113.45", "198.51.100.23", "192.0.2.77", "45.33.32.156", "185.220.101.5", "91.219.237.244"]
DOMAINS = ["secure-login-update.com", "paypal-verify-account.net", "office365-reset.info", "cloudstorage-share.xyz"]
HASHES = ["d41d8cd98f00b204e9800998ecf8427e", "5f4dcc3b5aa765d61d8327deb882cf99",
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
CVES = ["CVE-2023-23397", "CVE-2021-44228", "CVE-2022-30190", "CVE-2020-1472", "CVE-2019-0708"]
MALWARE = ["Emotet", "TrickBot", "LockBit", "Ryuk", "Conti", "AgentTesla", "Cobalt Strike", "Mimikatz", "Zeus", "njRAT"]
ORGS = ["Finance Department", "HR Department", "IT Operations", "Acme Corp", "Regional Data Center"]
USERS = ["jsmith", "amehta", "rgarcia", "kwong", "tpatel"]

TEMPLATES = {
    "Phishing": [
        "An employee in the {org} reported receiving a suspicious email from {domain} requesting login credentials. "
        "The email impersonated IT support and included a link to a fake login page hosted at {domain}. "
        "User {user} clicked the link but did not enter credentials. No further compromise detected.",

        "Multiple users including {user} received phishing emails referencing an urgent password reset from {domain}. "
        "The sender spoofed an internal address. One user entered credentials before recognizing the scam. "
        "SOC blocked the sending domain and reset the affected account.",
    ],
    "Malware": [
        "Endpoint detection flagged {malware} activity on a workstation in the {org}. The malware attempted to contact "
        "command-and-control infrastructure at {ip}. The file hash was identified as {hash}. The host was isolated from "
        "the network for further investigation.",

        "Antivirus alerts indicate the {malware} trojan was executed on a host used by {user}. Outbound connections to "
        "{ip} were observed. The infected binary matched hash {hash}. Remediation is in progress.",
    ],
    "Ransomware": [
        "Systems in the {org} were encrypted by {malware} ransomware. A ransom note was left demanding payment. "
        "Lateral movement was traced back to a compromised account belonging to {user}, and outbound traffic to {ip} "
        "was recorded prior to encryption. Backups are being used for recovery.",

        "The {org} experienced a ransomware outbreak attributed to {malware}. Encrypted files with a new extension "
        "were found on multiple servers. Exploitation of {cve} is suspected as the initial access vector. "
        "Incident response has contained the spread.",
    ],
    "DDoS": [
        "A distributed denial-of-service attack targeted public-facing services, generating abnormal traffic volumes "
        "from IP ranges including {ip}. Service availability for the {org} was degraded for approximately two hours "
        "before mitigation via traffic scrubbing was applied.",

        "Network monitoring detected a volumetric DDoS attack against the web application, originating from multiple "
        "sources including {ip}. Latency increased significantly and some requests timed out. Rate limiting and "
        "upstream filtering restored normal service.",
    ],
    "Insider Threat": [
        "Unusual data access patterns were observed for user {user} in the {org}, including bulk downloads of sensitive "
        "files outside normal working hours. The activity does not match the user's typical role and is under "
        "investigation for potential data exfiltration.",

        "A former employee's credentials, belonging to {user}, were used to access internal systems in the {org} after "
        "their termination date. Account access has been revoked and an internal investigation has been opened.",
    ],
    "Data Breach": [
        "Unauthorized access to a database containing customer records was discovered. Logs show access from external "
        "IP {ip} exploiting {cve}. Approximately several thousand records may have been exposed. Notification "
        "procedures are being initiated for the {org}.",

        "A misconfigured cloud storage bucket used by the {org} was found publicly accessible, exposing sensitive "
        "documents. The exposure was linked to an account associated with {user}. The bucket has since been secured.",
    ],
}

SEVERITY_HINTS = {
    "Low": ["No further compromise detected.", "did not enter credentials", "was contained quickly with minimal impact"],
    "Medium": ["under investigation", "Remediation is in progress", "degraded for approximately two hours"],
    "High": ["Lateral movement was traced", "multiple servers", "may have been exposed"],
    "Critical": ["ransomware outbreak", "encrypted", "publicly accessible", "customer records"],
}


def infer_severity(incident_type: str, text: str) -> str:
    """Lightweight heuristic used ONLY to label synthetic training data
    (a real project would use analyst-labeled ground truth)."""
    base = {
        "Phishing": "Low",
        "Malware": "Medium",
        "DDoS": "Medium",
        "Insider Threat": "Medium",
        "Ransomware": "Critical",
        "Data Breach": "High",
    }[incident_type]
    text_l = text.lower()
    if "did not enter credentials" in text_l or "no further compromise" in text_l:
        return "Low"
    if "ransom" in text_l or "encrypted" in text_l or "publicly accessible" in text_l:
        return "Critical"
    if "exfiltrat" in text_l or "unauthorized access" in text_l or "exposed" in text_l:
        return "High"
    return base


def generate(n_per_type=25):
    rows = []
    for itype, templates in TEMPLATES.items():
        for i in range(n_per_type):
            template = random.choice(templates)
            text = template.format(
                org=random.choice(ORGS),
                domain=random.choice(DOMAINS),
                user=random.choice(USERS),
                malware=random.choice(MALWARE),
                ip=random.choice(IPS),
                hash=random.choice(HASHES),
                cve=random.choice(CVES),
            )
            severity = infer_severity(itype, text)
            rows.append({"text": text, "incident_type": itype, "severity": severity})
    random.shuffle(rows)
    return rows


if __name__ == "__main__":
    rows = generate(n_per_type=30)
    out_path = os.path.join(os.path.dirname(__file__), "training_data.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "incident_type", "severity"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to {out_path}")
