"""Reports: analysis.json, analysis.md, one incident report per message (with a copy-ready ticket note), IOC exports."""
from __future__ import annotations

import json
import os
from typing import Dict, List

from . import TOOL_NAME, __version__
from .iocs import to_csv, to_json
from .textutil import defang_email, defang_host, defang_known, defang_text

VERDICT_TEXT = {"benign": "BENIGN", "suspicious": "SUSPICIOUS", "likely_phishing": "LIKELY PHISHING"}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _addr(a: dict) -> str:
    if not a:
        return "(none)"
    disp = f'"{a["display"]}" ' if a.get("display") else ""
    return f"{disp}<{defang_email(a['addr'])}>"


def auth_line(r: dict) -> str:
    a = r["auth"]
    spf = a["spf"]["result"] if a["spf"] else "none"
    dkim = ", ".join(sorted({d["result"] for d in a["dkim"]})) if a["dkim"] else "none"
    dmarc = a["dmarc"]["result"] if a["dmarc"] else "none"
    return f"SPF {spf} | DKIM {dkim} | DMARC {dmarc}"


def top_reasons(r: dict, n: int = 5) -> List[dict]:
    return [i for i in r["indicators"] if i["points"] > 0 and i["category"] != "combo"][:n]


def _hosts(r: dict) -> List[str]:
    return [i["value"] for i in r.get("iocs", []) if i["type"] in ("domain", "ip")]


def ticket_note(r: dict) -> str:
    """Plain-text note to paste into a ticket. URLs, domains, IPs and addresses are defanged."""
    lines = [f"PHISHING TRIAGE - {VERDICT_TEXT[r['verdict']]} (risk {r['score']}/100)",
             f"Subject: {defang_text(r['subject'])}",
             f"From: {_addr(r['from'])}"]
    if r.get("reply_to") and (not r["from"] or r["reply_to"]["addr"] != r["from"]["addr"]):
        lines.append(f"Reply-To: {_addr(r['reply_to'])}")
    if r.get("return_path") and (not r["from"] or r["return_path"]["addr"] != r["from"]["addr"]):
        lines.append(f"Return-Path: {_addr(r['return_path'])}")
    lines.append(f"Sent: {r['date_text'] or 'unknown'} | Origin IP: {defang_host(r['origin_ip']) if r['origin_ip'] else 'not determined'}")
    lines.append(f"Authentication: {auth_line(r)}")
    reasons = top_reasons(r)
    if reasons:
        lines.append("Why it was flagged:")
        for k, i in enumerate(reasons, 1):
            lines.append(f"  {k}. {defang_text(i['title'])} (+{i['points']}) - {defang_text(i['detail'])}")
    else:
        lines.append("Why: no suspicious indicators fired.")
    urls = [u for u in r["urls"] if u["flags"]]
    if urls:
        lines.append("Suspicious links: " + "; ".join(u["defanged"] for u in urls[:4]))
    atts = r["attachments"]
    if atts:
        lines.append("Attachments: " + "; ".join(f"{a['display_name']} (sha256 {a['sha256'][:16]}...)" + (" [FLAGGED]" if a["flags"] else "") for a in atts[:4]))
    if r["mitre"]:
        lines.append("ATT&CK: " + ", ".join(m["id"] for m in r["mitre"]))
    lines.append("Recommended actions:")
    for s in r["response"][:6]:
        lines.append(f"  [ ] {s}")
    lines.append("User impact: UNKNOWN - ask the recipient whether they clicked a link, opened an attachment, entered credentials or replied.")
    lines.append(f"Method: {TOOL_NAME} {__version__} static analysis (nothing was opened, executed or fetched).")
    return defang_known("\n".join(lines), _hosts(r))


def _tbl(headers: List[str], rows: List[List[str]]) -> str:
    esc = lambda x: str(x).replace("|", "\\|").replace("\n", " ")
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(esc(c) for c in row) + " |" for row in rows]
    return "\n".join(out)


def incident_md(r: dict) -> str:
    L: List[str] = []
    if r.get("synthetic"):
        L.append("> **SYNTHETIC SAMPLE.** This message was written for testing; the people, organisations, domains and IPs are fictional or reserved.\n")
    L.append(f"# Incident report: {defang_text(r['subject']) or '(no subject)'}\n")
    L.append(_tbl(["Field", "Value"], [
        ["Verdict", f"**{VERDICT_TEXT[r['verdict']]}** (risk score {r['score']}/100)"],
        ["Message", r["id"]],
        ["From", _addr(r["from"])],
        ["Reply-To / Return-Path", f"{_addr(r['reply_to'])} / {_addr(r['return_path'])}"],
        ["Date / origin IP", f"{r['date_text'] or 'unknown'} / {defang_host(r['origin_ip']) if r['origin_ip'] else 'n/a'}"],
        ["Authentication", auth_line(r)],
        ["ATT&CK", ", ".join(f"{m['id']} {m['name']}" for m in r["mitre"]) or "none"],
    ]))
    L.append("\n## Why\n")
    reasons = [i for i in r["indicators"] if i["points"] > 0]
    if reasons:
        L.append(_tbl(["Pts", "Sev", "Indicator", "Detail"], [[f"+{i['points']}", i["severity"], i["title"], defang_known(defang_text(i["detail"]), _hosts(r))] for i in reasons[:8]]))
        if len(reasons) > 8:
            L.append(f"\n_{len(reasons) - 8} lower-weight indicator(s) omitted; see analysis.json._")
    else:
        L.append("No indicator fired.")
    for m in r["mitigations"]:
        L.append(f"\nMitigation applied: **{m['title']}** ({m['points']}): {m['detail']}.")
    L.append("\n## Recommended response\n")
    L += [f"- [ ] {s}" for s in r["response"]]
    if r["iocs"]:
        L.append("\n## Indicators (defanged)\n")
        L.append(_tbl(["Type", "Value", "Context"], [[i["type"], i["defanged"], i["context"]] for i in r["iocs"]]))
    L.append("\n## Ticket note (copy-ready)\n")
    L.append("```text\n" + r["ticket_note"] + "\n```\n")
    L.append(f"_Generated by {TOOL_NAME} {__version__}. Static analysis only: nothing was opened, executed or fetched._\n")
    return "\n".join(L)


def build_analysis(results: List[dict], cfg: dict, source: str) -> dict:
    for r in results:
        r["ticket_note"] = ticket_note(r)
    counts = {"benign": 0, "suspicious": 0, "likely_phishing": 0}
    for r in results:
        counts[r["verdict"]] += 1
    return {
        "tool": TOOL_NAME, "version": __version__, "source": source,
        "synthetic": all(r.get("synthetic") for r in results) if results else False,
        "thresholds": {"suspicious": cfg["thresholds"]["suspicious"], "likely_phishing": cfg["thresholds"]["phishing"]},
        "summary": {"messages": len(results), **counts, "iocs": sum(len(r["iocs"]) for r in results)},
        "messages": results,
    }


def summary_md(analysis: dict) -> str:
    s = analysis["summary"]
    L = [f"# Phishing analysis summary\n",
         f"Source: `{analysis['source']}` | messages: {s['messages']} | benign {s['benign']} | suspicious {s['suspicious']} | likely phishing {s['likely_phishing']} | IOCs {s['iocs']}\n"]
    if analysis["synthetic"]:
        L.append("> All messages are SYNTHETIC test data.\n")
    rows = []
    for r in sorted(analysis["messages"], key=lambda x: (-x["score"], x["id"])):
        top = ", ".join(i["id"] for i in top_reasons(r, 3)) or "-"
        rows.append([r["id"], str(r["score"]), VERDICT_TEXT[r["verdict"]], defang_text(r["subject"])[:60], top])
    L.append(_tbl(["Message", "Score", "Verdict", "Subject", "Top indicators"], rows))
    return "\n".join(L) + "\n"


def write_reports(analysis: dict, outdir: str) -> List[str]:
    os.makedirs(os.path.join(outdir, "incidents"), exist_ok=True)
    written = []

    def put(name: str, text: str) -> None:
        path = os.path.join(outdir, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        written.append(path)

    put("analysis.json", json.dumps(analysis, indent=1, ensure_ascii=False) + "\n")
    put("analysis.md", summary_md(analysis))
    for r in analysis["messages"]:
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in r["id"])
        put(os.path.join("incidents", f"{safe}.md"), incident_md(r))
    put("iocs.csv", to_csv(analysis["messages"]))
    put("iocs.json", to_json(analysis["messages"]))
    return written
