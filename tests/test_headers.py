import pytest

from phishanalyzer.headers import brand_matches, parse_received
from .conftest import ids, run

DATE = "Mon, 02 Mar 2026 10:00:00 +0000"


def msg(cfg, frm="Sam <sam@example.com>", extra=(), text="hello\n", date=DATE, mid="<1@example.com>", dns=None, rcv=True):
    h = [("From", frm), ("To", "you@example.net"), ("Subject", "hi")]
    if date is not None:
        h.append(("Date", date))
    if mid is not None:
        h.append(("Message-ID", mid))
    h += list(extra)
    if rcv:
        h.append(("Received", "from mail.example.com (mail.example.com [198.51.100.7]) by mx.example.net with ESMTP id 1; Mon, 02 Mar 2026 10:00:03 +0000"))
    return run(cfg, h, text=text, dns=dns)


def test_parse_received_variants():
    r = parse_received("from mail.Example.org (mail.example.org [198.51.100.7]) by MX.example.net with ESMTPS id 1; Mon, 02 Mar 2026 10:00:03 +0000")
    assert (r["from_helo"], r["rdns"], r["ip"], r["ip_scope"], r["by"], r["with"], r["time"]) == ("mail.example.org", "mail.example.org", "198.51.100.7", "documentation", "mx.example.net", "ESMTPS", 1772445603)
    r = parse_received("from [192.0.2.9] (unknown [192.0.2.9]) by mx.example.net; Mon, 02 Mar 2026 10:00:03 +0000")
    assert r["from_helo"] == "192.0.2.9" and r["rdns"] == "unknown" and r["ip"] == "192.0.2.9"
    r = parse_received("from h.example (HELO h.example [2001:db8::5]) by m.example with ESMTP; Mon, 02 Mar 2026 10:00:03 +0000")
    assert r["ip"] == "2001:db8::5" and r["ip_scope"] == "documentation" and r["rdns"] == "h.example"
    r = parse_received("from h.example (IPv6:2001:db8::1) by m.example with ESMTP")
    assert r["ip"] == "" and r["time"] is None and r["time_text"] == ""
    r = parse_received("by only.example with LMTP; Mon, 02 Mar 2026 10:00:03 +0000")
    assert r["from_helo"] == "" and r["by"] == "only.example" and r["ip"] == ""
    r = parse_received("from a.example (postfix authenticated) by m.example")
    assert r["rdns"] == ""
    r = parse_received("from a.example ([10.1.2.3]) by m.example")
    assert r["ip"] == "10.1.2.3" and r["ip_scope"] == "private"
    assert parse_received("")["from_helo"] == ""


def test_reply_to_and_return_path_mismatch(cfg):
    r = msg(cfg, extra=[("Reply-To", "x@other.example")])
    assert "reply_to_mismatch" in ids(r)
    r = msg(cfg, extra=[("Reply-To", "x@other.example"), ("List-Id", "<list.example.com>")])
    assert "reply_to_mismatch" not in ids(r)
    r = msg(cfg, extra=[("Reply-To", "x@news.example.com")])
    assert "reply_to_mismatch" not in ids(r)
    r = msg(cfg, extra=[("Return-Path", "<bounce@other.example>")])
    assert "return_path_mismatch" in ids(r)
    r = msg(cfg, extra=[("Return-Path", "<bounce@other.example>"), ("Authentication-Results", "mx; dkim=pass header.d=example.com")])
    assert "return_path_mismatch" not in ids(r)
    r = msg(cfg, extra=[("Return-Path", "<>")])
    assert r["return_path"] is None and "return_path_mismatch" not in ids(r)


def test_display_name_email_spoof(cfg):
    r = msg(cfg, frm='"ceo@northwind-analytics.example" <attacker@evil.test>')
    assert "display_name_email_spoof" in ids(r)
    r = msg(cfg, frm='"sam@example.com" <sam@example.com>')
    assert "display_name_email_spoof" not in ids(r)


def test_display_name_brand_exec_and_freemail(cfg):
    r = msg(cfg, frm='"PayPal Support" <help@evil.test>')
    assert "display_name_brand_spoof" in ids(r) and "freemail_display_spoof" not in ids(r)
    r = msg(cfg, frm='"PayPal Support" <help@freemail.example>')
    assert {"display_name_brand_spoof", "freemail_display_spoof"} <= ids(r)
    r = msg(cfg, frm='"PayPal Support" <help@paypal.com>')
    assert "display_name_brand_spoof" not in ids(r)
    r = msg(cfg, frm='"Priya Raman (CEO)" <priya@freemail.example>')
    assert {"display_name_exec_spoof", "freemail_display_spoof"} <= ids(r)
    r = msg(cfg, frm='"Priya Raman" <priya.raman@northwind-analytics.example>')
    assert "display_name_exec_spoof" not in ids(r)
    r = msg(cfg, frm='"Priyanka Ramana" <p@evil.test>')
    assert "display_name_exec_spoof" not in ids(r)
    r = msg(cfg, frm="<bare@example.com>")
    assert not ({"display_name_brand_spoof", "display_name_exec_spoof"} & ids(r))


def test_sender_domain_lookalike_from_reply_to_and_return_path(cfg):
    assert "sender_domain_lookalike" in ids(msg(cfg, frm="PayPal <a@paypa1.test>"))
    assert "sender_domain_lookalike" in ids(msg(cfg, extra=[("Reply-To", "x@micr0soft-support.test")]))
    assert "sender_domain_lookalike" in ids(msg(cfg, extra=[("Return-Path", "<x@rnicrosoft.test>")]))
    assert "sender_domain_lookalike" not in ids(msg(cfg, frm="PayPal <a@paypal.com>"))
    assert "sender_domain_lookalike" not in ids(msg(cfg, frm="Sam <a@example.com>", extra=[("Reply-To", "b@example.com")]))


@pytest.mark.parametrize("host,kind,where", [
    ("paypal.test", "same name, different domain", "domain"),
    ("paypa1.test", "look-alike characters", "domain"),
    ("paypall.test", "typo of the brand name", "domain"),
    ("secure-paypal-login.test", "brand name inside the domain", "domain-token"),
    ("paypal-login.test", "brand name inside the domain", "domain-token"),
    ("secure-paypa1-login.test", "brand name inside the domain", "domain-token"),
    ("secure-paypall-login.test", "typo of the brand name inside the domain", "domain-token"),
    ("paypal.com.evil.test", "brand domain used as a subdomain", "subdomain"),
    ("microsoft.evil.test", "brand domain used as a subdomain", "subdomain"),
    ("xn--micrsoft-6gb.test", None, None),
])
def test_brand_matches_kinds(cfg, host, kind, where):
    got = brand_matches(host, cfg)
    if kind is None:
        return
    assert got and (got[0]["kind"], got[0]["where"]) == (kind, where), got


def test_brand_matches_negatives_and_unicode(cfg):
    assert brand_matches("paypal.com", cfg) == [] and brand_matches("www.paypal.com", cfg) == [] and brand_matches("example.com", cfg) == []
    assert brand_matches("amazon.ca", cfg) == [] and brand_matches("rbc.com", cfg) == []
    assert brand_matches("mail.example.co.uk", cfg) == []
    got = brand_matches("xn--pypal-4ve.test", cfg)     # pаypal with a Cyrillic а
    assert got and got[0]["brand"] == "PayPal"
    org = brand_matches("northwind-analytlcs.example", cfg)
    assert org and org[0]["org"] is True
    assert brand_matches("northwind-analytics.example", cfg) == []
    assert brand_matches("dhl.test", cfg)[0]["kind"] == "same name, different domain"
    assert brand_matches("dhi.test", cfg) == []       # short labels are exempt from fuzzy matching


def test_message_id_findings(cfg):
    assert "message_id_missing" in ids(msg(cfg, mid=None))
    assert "message_id_malformed" in ids(msg(cfg, mid="not-an-id"))
    assert "message_id_malformed" in ids(msg(cfg, mid="<abc@localhost.localdomain>"))
    assert "message_id_domain_mismatch" in ids(msg(cfg, mid="<abc@somewhere.test>"))
    assert not ({"message_id_missing", "message_id_malformed", "message_id_domain_mismatch"} & ids(msg(cfg, mid="<abc@mail.example.com>")))
    assert "message_id_domain_mismatch" not in ids(msg(cfg, mid="<abc@esp.example.net>", extra=[("Return-Path", "<b@esp.example.net>")]))
    assert "message_id_domain_mismatch" not in ids(msg(cfg, mid="<abc@somewhere.test>", extra=[("Authentication-Results", "mx; dkim=pass header.d=example.com")]))


def rcv(by, t, frm="mail.example.org (mail.example.org [198.51.100.%d])", n=1):
    return ("Received", f"from {frm % n if '%d' in frm else frm} by {by} with ESMTP id {n}; {t}")


def test_received_chain_anomalies(cfg):
    r = run(cfg, [("From", "a@example.com"), ("Date", DATE), ("Message-ID", "<1@example.com>"),
                  rcv("c.example", "Mon, 02 Mar 2026 09:00:00 +0000", n=3), rcv("b.example", "Mon, 02 Mar 2026 10:00:00 +0000", n=2), rcv("a.example", "Mon, 02 Mar 2026 09:30:00 +0000", n=1)], text="x\n")
    assert "received_time_anomaly" in ids(r)
    assert [h["delta_s"] for h in r["hops"]] == [None, 1800, -3600]
    long = run(cfg, [("From", "a@example.com"), ("Date", DATE), ("Message-ID", "<1@example.com>"),
                     rcv("b.example", "Mon, 02 Mar 2026 22:30:00 +0000", n=2), rcv("a.example", "Mon, 02 Mar 2026 09:00:00 +0000", n=1)], text="x\n")
    assert any("delay" in a for h in long["hops"] for a in h["anomalies"])
    many = run(cfg, [("From", "a@example.com"), ("Date", DATE), ("Message-ID", "<1@example.com>")] + [rcv(f"h{i}.example", "Mon, 02 Mar 2026 10:00:00 +0000", n=i + 1) for i in range(12)], text="x\n")
    assert "received_many_hops" in ids(many)
    assert "received_missing" in ids(msg(cfg, rcv=False))
    untimed = run(cfg, [("From", "a@example.com"), ("Date", DATE), ("Message-ID", "<1@example.com>"), ("Received", "from a.example (a.example [198.51.100.1]) by b.example"),
                        ("Received", "from z.example (z.example [198.51.100.2]) by a.example; Mon, 02 Mar 2026 10:00:00 +0000")], text="x\n")
    assert "received_time_anomaly" not in ids(untimed)


def test_helo_vs_rdns(cfg):
    ok = msg(cfg)
    assert "received_helo_mismatch" not in ids(ok)
    bad = run(cfg, [("From", "a@example.com"), ("Date", DATE), ("Message-ID", "<1@example.com>"),
                    ("Received", "from mail.good.example (unknown [198.51.100.9]) by mx.example.net; Mon, 02 Mar 2026 10:00:00 +0000")], text="x\n")
    assert "received_helo_mismatch" in ids(bad)
    other = run(cfg, [("From", "a@example.com"), ("Date", DATE), ("Message-ID", "<1@example.com>"),
                      ("Received", "from mail.good.example (mail.other.test [198.51.100.9]) by mx.example.net; Mon, 02 Mar 2026 10:00:00 +0000")], text="x\n")
    assert "received_helo_mismatch" in ids(other)
    internal = run(cfg, [("From", "a@example.com"), ("Date", DATE), ("Message-ID", "<1@example.com>"),
                         ("Received", "from mail.good.example (unknown [10.0.0.5]) by mx.example.net; Mon, 02 Mar 2026 10:00:00 +0000")], text="x\n")
    assert "received_helo_mismatch" not in ids(internal)


def test_date_checks(cfg):
    assert "date_invalid" in ids(msg(cfg, date=None))
    assert "date_invalid" in ids(msg(cfg, date="sometime last week"))
    assert "date_future" in ids(msg(cfg, date="Wed, 04 Mar 2026 10:00:00 +0000"))
    assert "date_stale" in ids(msg(cfg, date="Sat, 10 Jan 2026 10:00:00 +0000"))
    assert not ({"date_invalid", "date_future", "date_stale"} & ids(msg(cfg)))
    assert not ({"date_future", "date_stale"} & ids(msg(cfg, rcv=False)))


def test_missing_from_does_not_crash(cfg):
    r = run(cfg, [("To", "you@example.net"), ("Subject", "x"), ("Date", DATE)], text="hi\n")
    assert r["from"] is None and "message_id_missing" in ids(r)
