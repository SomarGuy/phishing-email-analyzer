"""Orchestrates one message: parse -> headers/auth/urls/attachments/language -> weighted score -> verdict."""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional

from . import __version__
from .attachments import analyze_attachments
from .auth import analyze_auth
from .headers import basic_info, header_findings
from .iocs import extract_iocs
from .language import analyze_language
from .mime import parse_bytes
from .models import Finding
from .textutil import analyze_html, defang_text

IDENTITY_IDS = ("display_name_exec_spoof", "display_name_brand_spoof", "display_name_email_spoof", "sender_domain_lookalike", "freemail_display_spoof")
DECEPTIVE_LINK_IDS = ("url_text_mismatch", "url_lookalike_domain", "url_idn_homograph", "url_userinfo", "url_ip_host", "url_brand_in_domain", "url_brand_in_subdomain", "url_script_scheme")
LURE_IDS = ("credential_lure", "payment_lure", "urgency_language")
MONEY_IDS = ("payment_lure", "bec_wording", "gift_card_scam")


def verdict_for(score: int, cfg: dict) -> str:
    th = cfg["thresholds"]
    return "likely_phishing" if score >= th["phishing"] else ("suspicious" if score >= th["suspicious"] else "benign")


def _combo_findings(ids: set) -> List[Finding]:
    out = []
    lure = [i for i in LURE_IDS if i in ids]
    link = [i for i in DECEPTIVE_LINK_IDS if i in ids]
    if lure and link:
        out.append(Finding("combo_lure_deceptive_link", "Persuasion wording plus a deceptive link", lure + link))
    ident = [i for i in IDENTITY_IDS if i in ids]
    money = [i for i in MONEY_IDS if i in ids]
    if ident and money:
        out.append(Finding("combo_exec_payment", "Impersonated sender combined with a money request", ident + money))
    if ident and ("dmarc_fail" in ids or "spf_fail" in ids):
        out.append(Finding("combo_unauth_spoof", "Impersonated sender that also fails authentication", ident + [i for i in ("dmarc_fail", "spf_fail") if i in ids]))
    return out


def analyze_message(raw: bytes, cfg: dict, dns: Optional[dict] = None, label: str = "") -> dict:
    pe = parse_bytes(raw)
    info = basic_info(pe, cfg)
    auth, auth_findings, aligned = analyze_auth(pe, info, cfg, dns)
    hdr_findings = header_findings(pe, info, auth, aligned, cfg)

    html = analyze_html(pe.html) if pe.html else {"text": "", "links": [], "images": [], "form": False, "password_input": False}
    sender_domains = [d for d in ((info["from"] or {}).get("domain"), (info["reply_to"] or {}).get("domain"), (info["return_path"] or {}).get("domain")) if d]
    from .urls import analyze_urls
    links, url_findings = analyze_urls(pe, cfg, sender_domains[:1])
    atts, att_findings = analyze_attachments(pe, cfg, html["text"])
    has_images = bool(html["images"]) or any(a["detected_type"] in ("png", "jpg", "gif") for a in atts)
    lang_findings, lang_hits = analyze_language(info["subject"], pe.text, html["text"], has_images, cfg)

    findings = hdr_findings + auth_findings + url_findings + att_findings + lang_findings
    findings += _combo_findings({f.id for f in findings})
    by_id = cfg["_by_id"]
    caps = cfg["category_caps"]
    th = cfg["thresholds"]

    indicators = []
    for f in findings:
        ind = by_id[f.id]
        indicators.append({"id": f.id, "category": ind["category"], "title": ind["title"], "severity": ind["severity"], "weight": ind["weight"],
                           "points": ind["weight"], "detail": f.detail, "evidence": [defang_text(e) for e in f.evidence[:th["max_evidence"]]],
                           "mitre": list(ind["mitre"]), "description": ind["description"]})
    breakdown = {}
    for cat in ("header", "auth", "url", "attachment", "language", "combo"):
        items = [i for i in indicators if i["category"] == cat]
        raw_sum = sum(i["weight"] for i in items)
        capped = min(raw_sum, caps[cat])
        if raw_sum > caps[cat] and raw_sum:
            # scale each indicator's displayed points so the bars add up to the capped value
            run = 0
            for i in sorted(items, key=lambda x: -x["weight"]):
                give = min(i["weight"], capped - run)
                i["points"] = max(give, 0)
                run += i["points"]
        breakdown[cat] = {"raw": raw_sum, "capped": capped, "cap": caps[cat]}
    subtotal = sum(b["capped"] for b in breakdown.values())

    ids = {i["id"] for i in indicators}
    mitigations = []
    has_identity = any(i in ids for i in IDENTITY_IDS)
    if aligned and not has_identity and "dmarc_fail" not in ids and subtotal > 0:
        m = by_id["authenticated_aligned"]
        mitigations.append({"id": m["id"], "category": "mitigation", "title": m["title"], "severity": m["severity"], "weight": m["weight"], "points": m["weight"],
                            "detail": "SPF or DKIM passed for a domain aligned with the From domain", "evidence": [], "mitre": [], "description": m["description"]})
    if aligned and not has_identity and info["list_unsubscribe"] and subtotal > 0:
        m = by_id["list_unsubscribe"]
        mitigations.append({"id": m["id"], "category": "mitigation", "title": m["title"], "severity": m["severity"], "weight": m["weight"], "points": m["weight"],
                            "detail": "List-Unsubscribe header present on authenticated mail", "evidence": [], "mitre": [], "description": m["description"]})
    mit_total = max(sum(m["points"] for m in mitigations), -th["mitigation_cap"])
    score = max(0, min(100, subtotal + mit_total))
    verdict = verdict_for(score, cfg)

    indicators.sort(key=lambda i: (-i["points"], -i["weight"], i["id"]))
    mitre_ids: List[str] = []
    for i in indicators:
        if i["points"] > 0:
            for t in i["mitre"]:
                if t not in mitre_ids:
                    mitre_ids.append(t)
    if verdict != "benign" and not any(t.startswith("T1566") for t in mitre_ids):
        if any(a["flags"] for a in atts):
            mitre_ids.insert(0, "T1566.001")
        elif any(u["flags"] for u in links):
            mitre_ids.insert(0, "T1566.002")
    mitre = [{"id": t, "name": cfg["mitre"].get(t, t)} for t in mitre_ids]

    response: List[str] = []
    for i in indicators:
        if i["points"] > 0:
            for s in by_id[i["id"]]["response"]:
                if s not in response:
                    response.append(s)
    response = response[:6] + [s for s in cfg["generic_response"][verdict] if s not in response]

    frm = info["from"]
    result = {
        "id": label or hashlib.sha1(raw).hexdigest()[:12],
        "label": label,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "subject": info["subject"],
        "from": frm, "reply_to": info["reply_to"], "return_path": info["return_path"], "to": info["to"],
        "date": info["date"], "date_text": info["date_text"], "message_id": info["message_id"],
        "score": score, "verdict": verdict,
        "breakdown": breakdown, "subtotal": subtotal, "mitigation_total": mit_total,
        "indicators": indicators, "mitigations": mitigations,
        "mitre": mitre, "response": response,
        "hops": info["hops"], "origin_ip": info["origin_ip"],
        "auth": auth,
        "urls": links, "attachments": atts,
        "language": {k: v for k, v in lang_hits.items() if v},
        "parse_defects": pe.defects,
        "synthetic": pe.get("X-Synthetic-Sample").strip().lower() == "yes",
        "engine": __version__,
    }
    for h in result["hops"]:
        h.pop("raw", None)
    result["iocs"] = extract_iocs(result) if verdict != "benign" else []
    return result
