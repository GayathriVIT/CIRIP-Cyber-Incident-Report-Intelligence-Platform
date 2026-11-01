"""
OPTIONAL LLM integration layer.

The platform runs fully offline/locally WITHOUT this (using the rule-based /
extractive summarizer and rule-based mitigation engine as defaults). If you set
an ANTHROPIC_API_KEY environment variable, main.py will additionally call this
module to produce an LLM-generated abstractive summary and a more natural-language
mitigation narrative -- always clearly labeled "llm_generated": true in the API
response so it's never confused with the trained ML classifier's output.
"""
import os
import json
import requests

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-4-6"


def llm_available() -> bool:
    return bool(ANTHROPIC_API_KEY)


def _call_claude(prompt: str, max_tokens: int = 500) -> str:
    headers = {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body = {
        "model": MODEL,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    resp = requests.post(ANTHROPIC_URL, headers=headers, json=body, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return "".join(block.get("text", "") for block in data.get("content", []) if block.get("type") == "text")


def generate_llm_summary(incident_text: str) -> str:
    prompt = (
        "You are assisting a SOC analyst. Summarize the following cyber incident report "
        "in 2-3 concise, factual sentences. Do not invent details not present in the text.\n\n"
        f"Incident report:\n{incident_text}"
    )
    return _call_claude(prompt, max_tokens=250).strip()


def generate_llm_recommendation(incident_type: str, severity: str, summary: str) -> str:
    prompt = (
        f"A cyber incident of type '{incident_type}' with severity '{severity}' occurred. "
        f"Summary: {summary}\n\n"
        "Write a short (4-6 sentence) practical mitigation and response narrative for a SOC "
        "analyst, grounded in standard incident response practice (identify, contain, eradicate, "
        "recover, lessons learned). Do not fabricate specific IoCs not mentioned above."
    )
    return _call_claude(prompt, max_tokens=400).strip()
