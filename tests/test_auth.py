import pytest

from phishanalyzer.auth import parse_authentication_results, parse_received_spf
from .conftest import STD, ids, run

FROM_EX = [("From", "Sam <sam@example.com>"), ("To", "you@example.net"), ("Subject", "hi"), ("Date", "Mon, 02 Mar 2026 10:00:00 +0000"), ("Message-ID", "<1@example.com>")]


def hdrs(*extra):
    return FROM_EX + list(extra)


def test_parse_authentication_results():
    ar = parse_authentication_results('mx.example.net; spf=pass smtp.mailfrom=Bounce@Example.COM; dkim=pass header.d=example.com header.s=sel1; '
                                      'dkim=fail header.i=@other.example; dmarc=pass header.from=example.com; arc=pass; junk')
    assert ar["authserv"] == "mx.example.net"
    assert ar["spf"] == {"result": "pass", "domain": "example.com", "source": "Authentication-Results"}
    assert [(d["result"], d["domain"], d["selector"]) for d in ar["dkim"]] == [("pass", "example.com", "sel1"), ("fail", "other.example", "")]
    assert ar["dmarc"]["result"] == "pass" and ar["dmarc"]["from"] == "example.com"
    assert parse_authentication_results("")["authserv"] == ""
    assert parse_authentication_results("mx; spf=none smtp.helo=h.example")["spf"]["domain"] == "h.example"


def test_parse_received_spf():
    assert parse_received_spf("pass (example.net: ok) client-ip=192.0.2.1; envelope-from=\"<bob@Example.com>\";") == {"result": "pass", "domain": "example.com", "source": "Received-SPF"}
    assert parse_received_spf("softfail")["domain"] == ""
    assert parse_received_spf("garbage here") is None


def auth_of(cfg, *extra, dns=None):
    return run(cfg, hdrs(*extra), dns=dns)["auth"]


def test_all_pass_aligned_gets_mitigation(cfg):
    r = run(cfg, hdrs(("Authentication-Results", "mx.example.net; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com")),
            text="Urgent: verify your password\n")
    assert r["auth"]["spf_aligned"] and r["auth"]["dkim_aligned"] and r["auth"]["dmarc"]["result"] == "pass"
    assert not ({"spf_fail", "dkim_fail", "dmarc_fail", "auth_absent"} & ids(r))


def test_spf_fail_and_softfail_and_dkim_fail_and_dmarc_fail(cfg):
    r = run(cfg, hdrs(("Authentication-Results", "mx; spf=fail smtp.mailfrom=example.com; dkim=fail header.d=example.com; dmarc=fail header.from=example.com")))
    assert {"spf_fail", "dkim_fail", "dmarc_fail"} <= ids(r)
    r = run(cfg, hdrs(("Authentication-Results", "mx; spf=softfail smtp.mailfrom=example.com")))
    assert "spf_softfail" in ids(r) and "spf_fail" not in ids(r)
    r = run(cfg, hdrs(("Authentication-Results", "mx; spf=softfail smtp.mailfrom=example.com; dkim=pass header.d=example.com")))
    assert "dkim_fail" not in ids(r)


def test_dkim_pass_for_another_domain_is_misaligned(cfg):
    r = run(cfg, hdrs(("Authentication-Results", "mx; dkim=pass header.d=mailer.example.net")))
    assert "dkim_misaligned" in ids(r) and r["auth"]["dkim_aligned"] is False


def test_received_spf_header_used_when_no_authentication_results(cfg):
    r = run(cfg, hdrs(("Received-SPF", "fail (x) envelope-from=sam@example.com")))
    assert r["auth"]["spf"]["source"] == "Received-SPF" and "spf_fail" in ids(r)
    assert r["auth"]["dmarc"]["result"] == "fail" and r["auth"]["dmarc"]["source"].startswith("computed")


def test_dkim_signature_without_verification_is_unverified(cfg):
    r = run(cfg, hdrs(("DKIM-Signature", "v=1; a=rsa-sha256; d=Example.com; s=sel; b=abc"), ("DKIM-Signature", "v=1; s=nodomain")))
    d = r["auth"]["dkim"]
    assert len(d) == 1 and d[0]["result"] == "unverified" and d[0]["domain"] == "example.com" and "not verified" in d[0]["source"]
    assert r["auth"]["present"] is True and r["auth"]["dmarc"]["result"] == "none" and "auth_absent" not in ids(r)


def test_no_auth_headers_is_absent_and_dmarc_none(cfg):
    r = run(cfg, hdrs())
    assert "auth_absent" in ids(r) and r["auth"]["present"] is False and r["auth"]["dmarc"]["source"] == "no data"


def test_dmarc_computed_pass_from_dkim_alignment(cfg):
    r = run(cfg, hdrs(("Authentication-Results", "mx; dkim=pass header.d=example.com")))
    assert r["auth"]["dmarc"] == {"result": "pass", "from": "example.com", "source": "computed from SPF/DKIM alignment"}


def test_offline_spf_uses_fixture_records_and_origin_ip(cfg):
    dns = {"example.com": {"TXT": ["v=spf1 ip4:203.0.113.0/24 -all"]}}
    recv = ("Received", "from mail.example.org (mail.example.org [%s]) by mx.example.com with ESMTP id 1; Mon, 02 Mar 2026 10:00:01 +0000")
    ok = run(cfg, hdrs((recv[0], recv[1] % "203.0.113.9")), dns=dns)["auth"]
    assert ok["spf"]["result"] == "pass" and ok["spf"]["source"].startswith("offline") and ok["spf_aligned"] is True
    bad = run(cfg, hdrs((recv[0], recv[1] % "198.51.100.9")), dns=dns)
    assert bad["auth"]["spf"]["result"] == "fail" and "spf_fail" in ids(bad)
    none = run(cfg, hdrs((recv[0], recv[1] % "198.51.100.9")), dns={"unrelated.example": {"TXT": ["v=spf1 -all"]}})
    assert none["auth"]["spf"] is None and "auth_absent" in ids(none)
    no_dns = run(cfg, hdrs((recv[0], recv[1] % "198.51.100.9")))
    assert no_dns["auth"]["spf"] is None
    hdr_wins = run(cfg, hdrs((recv[0], recv[1] % "198.51.100.9"), ("Authentication-Results", "mx; spf=pass smtp.mailfrom=example.com")), dns=dns)
    assert hdr_wins["auth"]["spf"]["source"] == "Authentication-Results"
