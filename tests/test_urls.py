import pytest

from phishanalyzer.mime import parse_bytes
from phishanalyzer.urls import MAX_LINKS, analyze_link, analyze_urls, collect_links, is_idn_homograph
from .conftest import STD, build, ids, run

SENDERS = ["example.com"]


def link(cfg, url, text="", source="html link", senders=SENDERS):
    rec = analyze_link({"url": url, "text": text, "source": source}, cfg, senders)
    return rec, {f["id"] for f in rec["flags"]}


def test_collect_links_orders_and_dedupes():
    raw = build(STD, "plain https://a.example/x and www.b.example/y\n", '<p>See <a href="https://c.example/z">https://c.example/z</a> https://d.example/t</p><a href="https://c.example/z">again</a><a href="">empty</a>')
    got = collect_links(parse_bytes(raw))
    assert [(g["url"], g["source"]) for g in got] == [("https://c.example/z", "html link"), ("https://d.example/t", "html text"), ("https://a.example/x", "plain text"), ("http://www.b.example/y", "plain text")]
    assert got[0]["text"] == "https://c.example/z"


def test_collect_links_caps_the_list():
    text = " ".join(f"https://h{i}.example/p" for i in range(MAX_LINKS + 20)) + "\n"
    assert len(collect_links(parse_bytes(build(STD, text)))) == MAX_LINKS


def test_idn_homograph_reasons():
    assert is_idn_homograph("xn--pypal-4ve.test") == "label 'p\u0430ypal' mixes scripts (cyrillic, latin)"
    assert is_idn_homograph("xn--80ak6aa92e.test") == "label '\u0430\u0440\u0440\u04cf\u0435' is cyrillic lookalike of 'apple'"     # whole-script confusable
    assert is_idn_homograph("xn--mnchen-3ya.example") is None            # m\u00fcnchen: Latin only
    assert is_idn_homograph("xn--e1afmkfd.example") is None              # \u043f\u0440\u0438\u043c\u0435\u0440: genuine Cyrillic word, not an ASCII look-alike
    assert is_idn_homograph("example.com") is None


def test_ip_hosts_and_obfuscation(cfg):
    rec, f = link(cfg, "http://192.0.2.9/login")
    assert {"url_ip_host"} <= f and rec["domain"] == ""
    rec, f = link(cfg, "http://3405803853/x")
    assert {"url_ip_host", "url_obfuscated"} <= f
    rec, f = link(cfg, "http://[2001:db8::1]/x")
    assert "url_ip_host" in f
    rec, f = link(cfg, "https://203.0.113.5/a", text="www.example.com/login")
    assert "url_text_mismatch" in f


def test_scheme_handling(cfg):
    assert link(cfg, "javascript:alert(1)")[1] == {"url_script_scheme"}
    assert link(cfg, "data:text/html;base64,AAAA")[1] == {"url_script_scheme"}
    assert link(cfg, "mailto:a@example.com")[1] == set()
    assert link(cfg, "tel:+15550100")[1] == set()
    assert link(cfg, "https:///nohost")[1] == set()


def test_lookalike_and_brand_placement(cfg):
    assert "url_lookalike_domain" in link(cfg, "https://paypa1.test/")[1]
    assert "url_lookalike_domain" in link(cfg, "https://paypall.test/")[1]
    assert "url_brand_in_domain" in link(cfg, "https://secure-paypal-login.test/")[1]
    assert "url_brand_in_subdomain" in link(cfg, "https://paypal.com.evil.test/")[1]
    assert not any(i.startswith("url_brand") or i == "url_lookalike_domain" for i in link(cfg, "https://www.paypal.com/signin")[1])
    f = link(cfg, "https://schemas.microsoft.com/office/2004")[1]
    assert not any(i.startswith("url_brand") for i in f)
    rec, f = link(cfg, "https://xn--pypal-4ve.test/")
    assert "url_idn_homograph" in f and rec["host_unicode"].endswith(".test")
    rec, f = link(cfg, "https://xn--mnchen-3ya.example/")
    assert "url_idn_homograph" not in f


def test_shorteners_tlds_depth_and_length(cfg):
    assert "url_shortener" in link(cfg, "https://bit.ly/abc")[1]
    assert "url_suspicious_tld" in link(cfg, "https://cheap-deals.xyz/")[1]
    assert "url_obfuscated" in link(cfg, "https://a.b.c.d.e.example.test/")[1]
    assert "url_obfuscated" in link(cfg, "https://x.example.test/" + "a" * 230)[1]
    rec, f = link(cfg, "https://ex%61mple.test/")
    assert "url_obfuscated" in f


def test_userinfo_trick(cfg):
    rec, f = link(cfg, "https://paypal.com@evil.test/login")
    assert "url_userinfo" in f and rec["host"] == "evil.test"
    assert "url_userinfo" not in link(cfg, "https://evil.test/@x")[1]


def test_display_text_mismatch(cfg):
    assert "url_text_mismatch" in link(cfg, "https://evil.test/x", text="https://www.paypal.com/signin")[1]
    assert "url_text_mismatch" in link(cfg, "https://evil.test/x", text="Sign in at paypal.com now")[1]
    assert "url_text_mismatch" not in link(cfg, "https://www.paypal.com/x", text="paypal.com")[1]
    assert "url_text_mismatch" not in link(cfg, "https://evil.test/x", text="Click here")[1]
    assert "url_text_mismatch" not in link(cfg, "https://evil.test/x", text="paypal.com", source="plain text")[1]
    assert "url_text_mismatch" in link(cfg, "https://evil.test/x", text="https://xn--mnchen-3ya.example/")[1]


def test_redirect_params(cfg):
    assert "url_redirect_param" in link(cfg, "https://good.test/r?next=https%3A%2F%2Fevil.test%2Fx")[1]
    assert "url_redirect_param" in link(cfg, "https://good.test/r?a=1&url=https://evil.test/")[1]
    assert "url_redirect_param" not in link(cfg, "https://good.test/r?next=/home")[1]
    assert "url_redirect_param" not in link(cfg, "https://good.test/r?next=https://good.test/home")[1]
    assert "url_redirect_param" not in link(cfg, "https://good.test/r?color=https://evil.test/")[1]
    assert "url_redirect_param" not in link(cfg, "https://example.com/r?next=https://evil.test/")[1]          # sender's own domain
    assert "url_redirect_param" not in link(cfg, "https://good.test/r?next=https://example.com/home")[1]       # back to the sender


def test_login_keywords(cfg):
    rec, f = link(cfg, "https://evil.test/secure/login?verify=1")
    assert "url_login_keywords" in f and "secure" in rec["flags"][-1]["detail"]
    assert "url_login_keywords" not in link(cfg, "https://example.com/login")[1]
    assert "url_login_keywords" not in link(cfg, "https://evil.test/news")[1]
    assert "url_login_keywords" not in link(cfg, "https://schemas.microsoft.com/account")[1]


def test_analyze_urls_aggregates_evidence(cfg):
    raw = build(STD, None, '<a href="https://bit.ly/a">x</a><a href="https://bit.ly/b">y</a>')
    links, findings = analyze_urls(parse_bytes(raw), cfg, SENDERS)
    f = next(x for x in findings if x.id == "url_shortener")
    assert len(f.evidence) == 2 and "(+1 more link(s))" in f.detail and f.evidence[0].startswith("hxxps://bit[.]ly/a")
    assert len(links) == 2


def test_urls_end_to_end_in_a_message(cfg):
    r = run(cfg, text=None, html='<p><a href="https://paypa1.test/signin?next=https://x.test/">https://www.paypal.com/signin</a></p>')
    assert {"url_lookalike_domain", "url_text_mismatch", "url_redirect_param", "url_login_keywords"} <= ids(r)
    assert r["urls"][0]["defanged"].startswith("hxxps://paypa1[.]test")
