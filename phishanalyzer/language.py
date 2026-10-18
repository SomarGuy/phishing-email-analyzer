"""Wording heuristics: urgency, credential and payment lures, gift-card scams, BEC phrasing, QR lures, generic greetings."""
from __future__ import annotations

import re
from typing import Dict, List

from .models import Finding

# language category -> indicator id
CATEGORY_IDS = [
    ("urgency", "urgency_language"),
    ("credential", "credential_lure"),
    ("payment", "payment_lure"),
    ("gift_card", "gift_card_scam"),
    ("bec", "bec_wording"),
    ("qr", "qr_lure"),
    ("enable_content", "enable_content_lure"),
    ("greeting", "generic_greeting"),
]

def scan(text: str, cfg: dict) -> Dict[str, List[str]]:
    """category -> list of distinct matched phrases (one per pattern)."""
    out: Dict[str, List[str]] = {}
    for cat, pats in cfg["language"].items():
        hits = []
        for p in pats:
            m = re.search(p, text, re.I | re.M)
            if m:
                hits.append(re.sub(r"\s+", " ", m.group(0)).strip()[:60])
        out[cat] = hits
    return out


def analyze_language(subject: str, text: str, html_text: str, has_images: bool, cfg: dict) -> (List[Finding], dict):
    combined = "\n".join(x for x in (subject, text, html_text) if x)
    hits = scan(combined, cfg)
    minm = cfg["thresholds"].get("min_matches", {})
    findings: List[Finding] = []
    for cat, ind in CATEGORY_IDS:
        h = hits.get(cat, [])
        if len(h) < minm.get(cat, 1):
            continue
        if cat == "qr" and not has_images:
            continue
        label = {"urgency": "Pressure/urgency wording", "credential": "Credential-harvesting wording", "payment": "Payment/invoice wording",
                 "gift_card": "Gift-card request wording", "bec": "Business-email-compromise phrasing", "qr": "QR-code instruction with an image", "enable_content": "Enable-content/macro instruction",
                 "greeting": "Generic greeting"}[cat]
        findings.append(Finding(ind, f"{label}: " + ", ".join(f"'{x}'" for x in h[:3]), [f"\"{x}\"" for x in h[:4]]))
    return findings, hits
