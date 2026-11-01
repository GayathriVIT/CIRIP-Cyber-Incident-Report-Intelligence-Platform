"""
Rule-based mitigation recommendation engine, mapping incident type + severity to
standard response guidance. This is intentionally RULE-BASED (not ML/LLM) as the
authoritative baseline; an LLM can optionally rephrase/expand this into a more
tailored narrative (see llm_integration.py), but always clearly labeled.
"""

BASE_RECOMMENDATIONS = {
    "Phishing": {
        "immediate_response": [
            "Isolate any host where a user entered credentials or ran an attachment.",
            "Force a password reset for the targeted account(s).",
        ],
        "containment": [
            "Block the sender domain/address and reported phishing URL at the email gateway and web proxy.",
            "Search mailbox logs for other recipients of the same message.",
        ],
        "recovery": [
            "Re-enable the account after reset and monitor for anomalous sign-ins.",
        ],
        "prevention": [
            "Enable MFA on all accounts if not already enforced.",
            "Run targeted phishing-awareness training for affected teams.",
        ],
    },
    "Malware": {
        "immediate_response": [
            "Isolate the infected endpoint from the network.",
            "Preserve volatile evidence (memory, running processes) before remediation if forensics is required.",
        ],
        "containment": [
            "Block associated C2 IPs/domains and file hashes at firewall/EDR.",
            "Scan adjacent hosts for the same indicators of compromise.",
        ],
        "recovery": [
            "Reimage the affected host from a known-good image where feasible.",
            "Restore affected files/services from clean backups.",
        ],
        "prevention": [
            "Ensure EDR/antivirus signatures and detection rules are updated with the new IoCs.",
            "Review and patch the initial infection vector (e.g., email attachment policy, USB restrictions).",
        ],
    },
    "Ransomware": {
        "immediate_response": [
            "Immediately isolate affected systems and disable shared network drives to stop encryption spread.",
            "Notify incident response leadership; do not pay ransom without legal/executive guidance.",
        ],
        "containment": [
            "Disable compromised accounts used for lateral movement.",
            "Block identified C2 infrastructure and known ransomware file hashes network-wide.",
        ],
        "recovery": [
            "Restore systems from offline/immutable backups after confirming they are clean.",
            "Rebuild encrypted systems from trusted images rather than decrypting where possible.",
        ],
        "prevention": [
            "Patch the exploited vulnerability (if any) and enforce network segmentation.",
            "Test backup restoration procedures regularly and keep offline backup copies.",
        ],
    },
    "DDoS": {
        "immediate_response": [
            "Engage upstream ISP / CDN / DDoS scrubbing service.",
            "Enable rate limiting and geo/IP-based filtering on affected services.",
        ],
        "containment": [
            "Blackhole or filter traffic from confirmed malicious source ranges.",
        ],
        "recovery": [
            "Gradually restore normal traffic routing and monitor for renewed attack activity.",
        ],
        "prevention": [
            "Adopt a DDoS protection / traffic scrubbing service for critical public-facing assets.",
            "Set up auto-scaling and load-balancing for public services.",
        ],
    },
    "Insider Threat": {
        "immediate_response": [
            "Suspend or restrict the involved account's access pending investigation.",
            "Preserve relevant access and data-transfer logs.",
        ],
        "containment": [
            "Review and revoke unnecessary privileged access for the account.",
        ],
        "recovery": [
            "Coordinate with HR/Legal on next steps once investigation concludes.",
        ],
        "prevention": [
            "Implement least-privilege access and periodic access reviews.",
            "Deploy data loss prevention (DLP) monitoring for sensitive repositories.",
        ],
    },
    "Data Breach": {
        "immediate_response": [
            "Contain the exposed system/database (revoke public access, rotate credentials/keys).",
            "Determine scope: what data, how many records, and time window of exposure.",
        ],
        "containment": [
            "Patch or reconfigure the vulnerability/misconfiguration that caused exposure.",
        ],
        "recovery": [
            "Prepare breach notification per applicable regulatory requirements (e.g., GDPR/local law).",
        ],
        "prevention": [
            "Add automated cloud configuration/security posture scanning.",
            "Encrypt sensitive data at rest and enforce least-privilege database access.",
        ],
    },
}

SEVERITY_NOTES = {
    "Low": "Handle via standard operating procedures; document and close out after verification.",
    "Medium": "Escalate to on-call security analyst; monitor closely for escalation.",
    "High": "Escalate to incident response team immediately; consider stakeholder notification.",
    "Critical": "Activate full incident response plan; notify leadership and, if applicable, legal/regulatory contacts immediately.",
}


def get_recommendations(incident_type: str, severity: str) -> dict:
    rec = BASE_RECOMMENDATIONS.get(incident_type, BASE_RECOMMENDATIONS["Malware"])
    return {
        **rec,
        "severity_guidance": SEVERITY_NOTES.get(severity, SEVERITY_NOTES["Medium"]),
        "source": "rule-based mitigation engine",
    }
