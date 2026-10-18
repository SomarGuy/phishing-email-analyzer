"""Indicator-of-compromise extraction and export. Every value is also given in defanged form for safe sharing."""
from __future__ import annotations

import csv
import io
import json
from typing import Dict, List

from .textutil import defang_email, defang_host, defang_url, is_ipv4, is_ipv6

CSV_FIELDS = ["message_id", "type", "value", "defanged", "context", "verdict", "score"]


def extract_iocs(res: dict) -> List[dict]:
    """IOCs worth blocking or hunting for from an analysed message (called only for non-benign verdicts)."""
    out: List[dict] = []
    seen = set()

    def add(t: str, value: str, defanged: str, context: str) -> None:
        if not value or (t, value) in seen:
            return
        seen.add((t, value))
        out.append({"type": t, "value": value, "defanged": defanged, "context": context})

    frm = res.get("from")
    if frm:
        add("email", frm["addr"], defang_email(frm["addr"]), "From address")
        add("domain", frm["domain"], defang_host(frm["domain"]), "Sender domain")
    for key, label in (("reply_to", "Reply-To address"), ("return_path", "Return-Path address")):
        a = res.get(key)
        if a and (not frm or a["addr"] != frm["addr"]):
            add("email", a["addr"], defang_email(a["addr"]), label)
            if not frm or a["domain"] != frm["domain"]:
                add("domain", a["domain"], defang_host(a["domain"]), label.replace("address", "domain"))
    if res.get("origin_ip"):
        add("ip", res["origin_ip"], defang_host(res["origin_ip"]), "Origin of the Received chain")
    for u in res.get("urls", []):
        if u["flags"]:
            add("url", u["url"], u["defanged"], "; ".join(f["id"] for f in u["flags"][:3]))
            if u["domain"]:
                add("domain", u["domain"], defang_host(u["domain"]), "Domain of a flagged URL")
            elif u["host"] and (is_ipv4(u["host"]) or is_ipv6(u["host"])):
                add("ip", u["host"], defang_host(u["host"]), "IP host of a flagged URL")
    for a in res.get("attachments", []):
        if a["flags"]:
            add("sha256", a["sha256"], a["sha256"], f"Attachment {a['display_name']}: " + ", ".join(f["id"] for f in a["flags"][:3]))
            add("filename", a["display_name"], a["display_name"], "Flagged attachment name")
    return out


def to_json(results: List[dict]) -> str:
    rows = []
    for r in results:
        for i in r["iocs"]:
            rows.append({"message_id": r["id"], **i, "verdict": r["verdict"], "score": r["score"]})
    return json.dumps({"tool": "phishanalyzer", "note": "Values are defanged in the 'defanged' field. Synthetic corpus: none of these are real indicators.", "iocs": rows}, indent=2, ensure_ascii=False) + "\n"


def safe_cell(value) -> str:
    """Neutralise spreadsheet formula injection: attacker-controlled text (a file name, a display value) must not
    start with = + - @ or a control character when the CSV is opened in Excel/Sheets."""
    v = str(value)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def to_csv(results: List[dict]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\n")
    w.writeheader()
    for r in results:
        for i in r["iocs"]:
            row = {"message_id": r["id"], **i, "verdict": r["verdict"], "score": r["score"]}
            w.writerow({k: safe_cell(v) for k, v in row.items()})
    return buf.getvalue()
