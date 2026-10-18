import csv
import io
import json

import pytest

from phishanalyzer.iocs import extract_iocs, safe_cell, to_csv, to_json
from phishanalyzer.report import auth_line, build_analysis, incident_md, summary_md, ticket_note, top_reasons, write_reports
from phishanalyzer.synthbuild import Att, exe_stub
from .conftest import STD, ids, run


def phish(cfg):
    return run(cfg, [("From", '"IT Help Desk" <helpdesk@northwind-analytlcs.example>'), ("Reply-To", "it@freemail.example"), ("Subject", "Password expires today - verify your account"),
                     ("Date", "Mon, 02 Mar 2026 10:00:00 +0000"), ("Message-ID", "<x@northwind-analytlcs.example>"), ("Return-Path", "<bounce@other.test>"),
                     ("Received", "from mail.bad.test (unknown [198.51.100.9]) by mx.example.net with ESMTP; Mon, 02 Mar 2026 10:00:05 +0000"),
                     ("Authentication-Results", "mx; spf=fail smtp.mailfrom=other.test; dmarc=fail header.from=northwind-analytlcs.example")],
               text="Please verify your account: http://203.0.113.5/login now. https://paypa1.test/x\n", atts=[Att("Invoice.pdf.exe", exe_stub("z"))])


def test_extract_iocs_for_a_phish(cfg):
    r = phish(cfg)
    got = {(i["type"], i["value"]) for i in r["iocs"]}
    assert ("email", "helpdesk@northwind-analytlcs.example") in got and ("domain", "northwind-analytlcs.example") in got
    assert ("email", "it@freemail.example") in got and ("domain", "freemail.example") in got and ("email", "bounce@other.test") in got and ("domain", "other.test") in got
    assert ("ip", "198.51.100.9") in got and ("ip", "203.0.113.5") in got and ("domain", "paypa1.test") in got
    assert any(t == "url" and v.startswith("http://203.0.113.5") for t, v in got)
    assert any(t == "sha256" for t, _ in got) and ("filename", "Invoice.pdf.exe") in got
    assert len(got) == len(r["iocs"])                    # no duplicates
    for i in r["iocs"]:
        assert i["defanged"] != i["value"] or i["type"] in ("sha256", "filename")


def test_benign_messages_yield_no_iocs(cfg):
    assert run(cfg)["iocs"] == []


def test_extract_iocs_handles_sparse_results():
    assert extract_iocs({}) == []
    assert extract_iocs({"from": None, "urls": [{"flags": [{"id": "x"}], "url": "http://h.test/", "defanged": "hxxp://h[.]test/", "domain": "", "host": "h.test"}]})[0]["type"] == "url"


def test_csv_and_json_exports_round_trip(cfg):
    r = phish(cfg)
    rows = list(csv.DictReader(io.StringIO(to_csv([r]))))
    assert rows and set(rows[0]) == {"message_id", "type", "value", "defanged", "context", "verdict", "score"}
    assert {x["type"] for x in rows} >= {"email", "domain", "ip", "url", "sha256", "filename"}
    js = json.loads(to_json([r]))
    assert js["tool"] == "phishanalyzer" and len(js["iocs"]) == len(rows) and "Synthetic" in js["note"]
    assert all(x["verdict"] == r["verdict"] for x in js["iocs"])


@pytest.mark.parametrize("value,safe", [("=1+1", "'=1+1"), ("+cmd", "'+cmd"), ("-2", "'-2"), ("@SUM(A1)", "'@SUM(A1)"), ("\tx", "'\tx"), ("normal", "normal"), ("", ""), (5, "5")])
def test_csv_cells_are_neutralised_against_formula_injection(value, safe):
    assert safe_cell(value) == safe


def test_hostile_filename_cannot_become_a_formula(cfg):
    r = run(cfg, text="x\n", atts=[Att("=HYPERLINK(x).exe", exe_stub("q"))])
    r["iocs"] = extract_iocs(r)
    text = to_csv([r])
    assert "'=HYPERLINK" in text
    for row in csv.DictReader(io.StringIO(text)):
        assert not row["value"].startswith("=") and not row["context"].startswith("=")


# ------------------------------------------------------------------------------------------------ report
def test_ticket_note_is_copy_ready_and_defanged(cfg):
    r = phish(cfg)
    note = ticket_note(r)
    assert note.startswith("PHISHING TRIAGE - LIKELY PHISHING (risk ") and "Recommended actions:" in note and "User impact: UNKNOWN" in note
    assert "Why it was flagged:" in note and "ATT&CK:" in note and "Method: phishanalyzer" in note and "[ ] " in note
    assert "http://" not in note and "https://" not in note and "@northwind-analytlcs.example" not in note
    for bare in ("northwind-analytlcs.example", "freemail.example", "other.test", "paypa1.test", "198.51.100.9", "203.0.113.5"):
        assert bare not in note, bare           # every IOC domain/IP is defanged even in free text, so chat and ticket tools cannot auto-link it
    assert "Reply-To:" in note and "Return-Path:" in note and "SPF fail | DKIM none | DMARC fail" in note
    assert "hxxp" in note and "Attachments: Invoice.pdf.exe" in note and "[FLAGGED]" in note
    assert len(note.splitlines()) < 40


def test_ticket_note_for_a_clean_message(cfg):
    r = run(cfg, [("From", "a@example.com"), ("Date", "Mon, 02 Mar 2026 10:00:00 +0000"), ("Message-ID", "<1@example.com>"), ("Subject", "Lunch"),
                  ("Received", "from mail.example.com (mail.example.com [198.51.100.7]) by mx.example.net with ESMTP; Mon, 02 Mar 2026 10:00:03 +0000"),
                  ("Authentication-Results", "mx; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com")], text="Lunch at noon.\n")
    note = ticket_note(r)
    assert "BENIGN" in note and "no suspicious indicators fired" in note and "\nReply-To:" not in note and "Origin IP: 198[.]51[.]100[.]7" in note


def test_auth_line_variants(cfg):
    r = run(cfg, [("From", "a@example.com"), ("Date", "Mon, 02 Mar 2026 10:00:00 +0000"), ("Authentication-Results", "mx; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dkim=fail header.d=x.test; dmarc=pass header.from=example.com")])
    assert auth_line(r) == "SPF pass | DKIM fail, pass | DMARC pass"
    assert auth_line(run(cfg)) == "SPF none | DKIM none | DMARC none"


def test_incident_report_one_page(cfg):
    r = build_analysis([phish(cfg)], cfg, "x")["messages"][0]
    md = incident_md(r)
    for h in ("# Incident report", "| Verdict | **LIKELY PHISHING**", "## Why", "## Recommended response", "## Indicators (defanged)", "## Ticket note (copy-ready)", "```text", "Static analysis only"):
        assert h in md, h
    assert "http://" not in md and "https://" not in md
    assert md.count("\n") < 120


def test_build_analysis_summary_and_files(cfg, tmp_path, results):
    a = build_analysis(list(results.values()), cfg, "unit")
    s = a["summary"]
    assert s["messages"] == 36 and s["benign"] + s["suspicious"] + s["likely_phishing"] == 36 and s["iocs"] == sum(len(m["iocs"]) for m in a["messages"])
    assert a["synthetic"] is True and a["thresholds"]["likely_phishing"] == 55 and a["source"] == "unit"
    md = summary_md(a)
    assert "| Message |" in md or "Message" in md
    written = write_reports(a, str(tmp_path / "out"))
    assert any(p.endswith("analysis.json") for p in written) and any(p.endswith("iocs.csv") for p in written)
    assert len(list((tmp_path / "out" / "incidents").glob("*.md"))) == 36
    assert [x["id"] for x in top_reasons(results["P05-invoice-double-extension-exe"], 3)] and len(top_reasons(results["P05-invoice-double-extension-exe"], 2)) == 2


def test_not_synthetic_when_unlabelled(cfg):
    a = build_analysis([run(cfg)], cfg, "x")
    assert a["synthetic"] is False
