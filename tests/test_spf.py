import json
import shutil
import subprocess

import pytest

from phishanalyzer.spf import evaluate_spf

DNS = {
    "a.example": {"TXT": ["v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all"]},
    "soft.example": {"TXT": ["v=spf1 ~all"]},
    "neutral.example": {"TXT": ["v=spf1 ?all"]},
    "plus.example": {"TXT": ["v=spf1 +all"]},
    "noall.example": {"TXT": ["v=spf1 ip4:192.0.2.1"]},
    "mech.example": {"TXT": ["v=spf1 a mx:mail.example -all"], "A": ["192.0.2.50"]},
    "mail.example": {"MX": ["mx1.mail.example"]},
    "mx1.mail.example": {"A": ["198.51.100.4"], "AAAA": ["2001:db8:1::4"]},
    "amask.example": {"TXT": ["v=spf1 a:host.example/24 -all"]},
    "host.example": {"A": ["203.0.113.9"]},
    "inc.example": {"TXT": ["v=spf1 include:a.example -all"]},
    "incnone.example": {"TXT": ["v=spf1 include:missing.example -all"]},
    "incfail.example": {"TXT": ["v=spf1 include:soft.example ip4:192.0.2.99 -all"]},
    "red.example": {"TXT": ["v=spf1 redirect=a.example"]},
    "rednone.example": {"TXT": ["v=spf1 redirect=missing.example"]},
    "ex.example": {"TXT": ["v=spf1 exists:ok.example -all"]},
    "ok.example": {"A": ["127.0.0.2"]},
    "dup.example": {"TXT": ["v=spf1 -all", "v=spf1 +all"]},
    "macro.example": {"TXT": ["v=spf1 exists:%{i}.example -all"]},
    "ptr.example": {"TXT": ["v=spf1 ptr -all"]},
    "weird.example": {"TXT": ["v=spf1 bogus:thing -all"]},
    "badamx.example": {"TXT": ["v=spf1 a:x:y/zz -all"]},
    "badcidr.example": {"TXT": ["v=spf1 ip4:not-a-net -all"]},
    "mod.example": {"TXT": ["v=spf1 exp=txt.example ip4:192.0.2.7 -all"]},
    "loop.example": {"TXT": ["v=spf1 include:loop.example -all"]},
    "many.example": {"TXT": ["v=spf1 " + " ".join(f"exists:n{i}.example" for i in range(12)) + " -all"]},
    "manymx.example": {"TXT": ["v=spf1 mx:big.example -all"]},
    "big.example": {"MX": [f"m{i}.example" for i in range(12)]},
    "tenA.example": {"TXT": ["v=spf1 " + " ".join("a:h%d.example" % i for i in range(11)) + " -all"]},
    "tenRed.example": {"TXT": ["v=spf1 " + " ".join(f"exists:n{i}.example" for i in range(10)) + " redirect=a.example"]},
    "txtonly.example": {"TXT": ["hello world"]},
}


@pytest.mark.parametrize("ip,dom,want", [
    ("192.0.2.5", "a.example", "pass"), ("198.51.100.1", "a.example", "fail"), ("2001:db8::9", "a.example", "pass"), ("2001:dead::1", "a.example", "fail"),
    ("1.2.3.4", "soft.example", "softfail"), ("1.2.3.4", "neutral.example", "neutral"), ("1.2.3.4", "plus.example", "pass"), ("9.9.9.9", "noall.example", "neutral"), ("192.0.2.1", "noall.example", "pass"),
    ("192.0.2.50", "mech.example", "pass"), ("198.51.100.4", "mech.example", "pass"), ("2001:db8:1::4", "mech.example", "pass"), ("8.8.8.8", "mech.example", "fail"),
    ("203.0.113.200", "amask.example", "pass"), ("203.0.114.1", "amask.example", "fail"),
    ("192.0.2.3", "inc.example", "pass"), ("1.1.1.1", "inc.example", "fail"), ("1.1.1.1", "incnone.example", "permerror"), ("192.0.2.99", "incfail.example", "pass"), ("1.1.1.1", "incfail.example", "fail"),
    ("192.0.2.3", "red.example", "pass"), ("1.1.1.1", "rednone.example", "permerror"),
    ("1.1.1.1", "ex.example", "pass"), ("1.1.1.1", "dup.example", "permerror"), ("1.1.1.1", "macro.example", "permerror"), ("1.1.1.1", "ptr.example", "permerror"),
    ("1.1.1.1", "weird.example", "permerror"), ("1.1.1.1", "badamx.example", "permerror"), ("1.1.1.1", "badcidr.example", "fail"), ("192.0.2.7", "mod.example", "pass"),
    ("1.1.1.1", "loop.example", "permerror"), ("1.1.1.1", "many.example", "permerror"), ("1.1.1.1", "manymx.example", "permerror"),
    ("1.1.1.1", "tenA.example", "permerror"), ("1.1.1.1", "tenRed.example", "permerror"), ("1.1.1.1", "nothing.example", "none"), ("1.1.1.1", "txtonly.example", "none"), ("not-an-ip", "a.example", "none"),
])
def test_spf_results(ip, dom, want):
    assert evaluate_spf(ip, dom, DNS)["result"] == want, evaluate_spf(ip, dom, DNS)


def test_case_and_trailing_dot_and_lookup_count():
    r = evaluate_spf("192.0.2.5", "A.Example.", DNS)
    assert r["result"] == "pass" and r["lookups"] == 0 and "detail" in r
    assert evaluate_spf("198.51.100.4", "mech.example", DNS)["lookups"] >= 2


def test_empty_dns_is_none():
    assert evaluate_spf("192.0.2.5", "a.example", {})["result"] == "none"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_browser_spf_evaluator_agrees_with_python():
    from .conftest import ROOT
    cases = [("192.0.2.5", "a.example"), ("2001:db8::9", "a.example"), ("198.51.100.4", "mech.example"), ("2001:db8:1::4", "mech.example"), ("203.0.113.200", "amask.example"),
             ("203.0.114.1", "amask.example"), ("192.0.2.3", "inc.example"), ("1.1.1.1", "incnone.example"), ("1.1.1.1", "red.example"), ("1.1.1.1", "ex.example"),
             ("1.1.1.1", "dup.example"), ("1.1.1.1", "macro.example"), ("1.1.1.1", "ptr.example"), ("1.1.1.1", "weird.example"), ("1.1.1.1", "many.example"),
             ("1.1.1.1", "manymx.example"), ("1.1.1.1", "tenA.example"), ("1.1.1.1", "nothing.example"), ("192.0.2.7", "mod.example"), ("1.1.1.1", "soft.example"),
             ("1.1.1.1", "neutral.example"), ("9.9.9.9", "noall.example"), ("1.1.1.1", "badcidr.example"), ("1.1.1.1", "loop.example")]
    job = {"spf": cases, "spf_dns": DNS}
    p = subprocess.run(["node", str(ROOT / "scripts" / "parity_dump.js")], input=json.dumps(job), capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    for (ip, dom), js in zip(cases, json.loads(p.stdout)):
        py = evaluate_spf(ip, dom, DNS)
        assert (js["result"], js["detail"]) == (py["result"], py["detail"]), (ip, dom, js, py)
