"""Unit tests for the hand-rolled primitives, plus a check that the JavaScript copies behave identically."""
import json
import shutil
import subprocess

import pytest

from phishanalyzer import textutil as T
from .conftest import ROOT

MULTI = ("co.uk", "com.au", "org.uk")


def test_unfold_and_decode_words():
    assert T.unfold("a\r\n  b\n\tc") == "a b c"
    assert T.unfold(None) == ""
    assert T.decode_words("plain") == "plain" and T.decode_words(None) == ""
    assert T.decode_words("=?utf-8?B?Q2Fmw6k=?=") == "Café"
    assert T.decode_words("=?utf-8?Q?caf=C3=A9_au_lait?=") == "café au lait"
    assert T.decode_words("=?no-such-charset?Q?abc?=") == "abc"
    assert T.decode_words("a =? b") == "a =? b"
    assert T.decode_words("=?utf-8?B?!!!?=") in ("", "=?utf-8?B?!!!?=")


def test_decode_words_survives_a_parser_failure(monkeypatch):
    def boom(value):
        raise ValueError("broken")
    monkeypatch.setattr(T, "decode_header", boom)
    assert T.decode_words("=?utf-8?B?Q2Fm?= tail") == "=?utf-8?B?Q2Fm?= tail"


def test_parse_address_forms():
    a = T.parse_address('"Doe, Jane" <Jane.Doe@Example.COM>')
    assert (a.display, a.addr, a.domain, a.local) == ("Doe, Jane", "jane.doe@example.com", "example.com", "jane.doe")
    assert T.parse_address("Bob <bob@example.org>").display == "Bob"
    assert T.parse_address("bob@example.org").addr == "bob@example.org"
    assert T.parse_address("'Q' <q@example.org>").display == "Q"
    assert T.parse_address('"A \\"B\\"" <q@example.org>').display == 'A "B"'
    assert T.parse_address("=?utf-8?B?Q2Fmw6k=?= <c@example.org>").display == "Café"
    assert T.parse_address("") is None and T.parse_address("no address here") is None and T.parse_address(None) is None
    assert T.parse_address("a@b.example.").domain == "b.example"
    assert T.parse_address("x <>").addr == ""
    assert T.parse_address("x <a@b.example>").as_dict() == {"display": "x", "addr": "a@b.example", "domain": "b.example"}


def test_parse_addresses_splits_on_commas_outside_quotes():
    got = T.parse_addresses('"Doe, J" <j@example.com>, k@example.org, junk')
    assert [x.addr for x in got] == ["j@example.com", "k@example.org"]
    assert T.parse_addresses("") == []


DATES = [
    ("Mon, 02 Mar 2026 10:00:00 +0000", 1772445600), ("2 Mar 2026 10:00 GMT", 1772445600), ("Mon, 02 Mar 2026 10:00:00 -0500", 1772445600 + 18000),
    ("Mon, 02 Mar 2026 10:00:00 +0530", 1772445600 - 19800), ("Mon, 02 Mar 2026 10:00:00 EST", 1772445600 + 18000), ("Mon, 02 Mar 26 10:00:00 PDT", 1772445600 + 25200),
    ("Mon, 02 Mar 99 10:00:00 UT", 920368800), ("02 Mar 126 10:00:00 Z", 1772445600 + 0),
    ("garbage", None), ("", None), (None, None), ("32 Mar 2026 10:00:00", None), ("02 Foo 2026 10:00:00", None), ("02 Mar 2026 25:00:00", None), ("02 Mar 2026 10:00:00 XYZ", 1772445600),
]


@pytest.mark.parametrize("text,want", DATES)
def test_parse_date(text, want):
    assert T.parse_date(text) == want


def test_format_epoch_round_trip():
    assert T.format_epoch(None) == ""
    assert T.format_epoch(1772445600) == "2026-03-02 10:00:00Z"
    assert T.format_epoch(0) == "1970-01-01 00:00:00Z"
    assert T.format_epoch(951782400) == "2000-02-29 00:00:00Z"
    assert T.format_epoch(-86400) == "1969-12-31 00:00:00Z"
    import datetime
    for ts in (1, 86399, 86400, 1709164800, 4102444800):
        dt = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
        assert T.parse_date(dt.strftime("%a, %d %b %Y %H:%M:%S +0000")) == ts
        assert T.format_epoch(ts) == dt.strftime("%Y-%m-%d %H:%M:%SZ")


def test_decode_entities_and_attrs():
    assert T.decode_entities("a &amp; b &lt;c&gt; &#65;&#x42; &nbsp;&bogus; &#0; &#x110000; &#xZZ;") == "a & b <c> AB  &bogus; &#0; &#x110000; &#xZZ;"
    attrs = T.parse_attrs('HREF="http://x.example/?a=1&amp;b=2" class=big data-x=\'q\' hidden href="dup"')
    assert attrs == {"href": "http://x.example/?a=1&b=2", "class": "big", "data-x": "q", "hidden": ""}
    assert T.parse_attrs("") == {} and T.parse_attrs(None) == {}


def test_analyze_html_extracts_text_links_images_and_forms():
    html = ('<html><style>.x{color:red}</style><!-- hidden --><script>alert(1)</script><p>Hello <b>there</b></p>'
            '<a href="https://a.example/x">Click <img src="i.png" alt="here"> now</a><a href="https://b.example/y">B</a>'
            '<a name="anchor">no href</a><a href="https://c.example/z">Unclosed <a href="https://d.example/">nested</a>'
            '<img src="p.gif"><form action="/x"><input type="PASSWORD"><input type=text></form>tail &amp; text')
    r = T.analyze_html(html)
    assert "alert" not in r["text"] and "color" not in r["text"] and "hidden" not in r["text"]
    assert "Hello there" in r["text"] and r["text"].endswith("tail & text")
    assert [(l["href"], l["text"]) for l in r["links"]] == [("https://a.example/x", "Click here now"), ("https://b.example/y", "B"), ("https://c.example/z", "Unclosed"), ("https://d.example/", "nested")]
    assert r["images"] == [{"src": "i.png", "alt": "here"}, {"src": "p.gif", "alt": ""}]
    assert r["form"] is True and r["password_input"] is True
    assert T.analyze_html("")["text"] == "" and T.analyze_html(None)["links"] == []
    tail = T.analyze_html('<a href="https://z.example/">dangling text')
    assert tail["links"] == [{"href": "https://z.example/", "text": "dangling text"}]


def test_extract_urls_and_refang():
    text = "See https://a.example/x?y=1, hxxps://b[.]example/p). Also www.c.example/z; ftp://d.example/f and ftp://x"
    assert T.extract_urls(text) == ["https://a.example/x?y=1", "https://b.example/p", "http://www.c.example/z", "ftp://d.example/f"]
    assert T.refang("hxxp://a[.]b(.)c[:]80") == "http://a.b.c:80"
    assert T.extract_urls("") == [] and T.extract_urls(None) == []


URLS = ["https://user:pw@Example.COM:8443/a/b?x=1&y=2#frag", "http://[2001:db8::1]:8080/p", "http://[2001:db8::1/p", "mailto:a@b.example", "no scheme", "https://host.example.", "https://h.example:/p",
        "https://h.example:abc/p", "https://paypal.com@evil.test/x", "javascript:alert(1)", "https://h.example?q=1", "https://h.example#f", "HTTP://UP.example/PATH", ""]


@pytest.mark.parametrize("u", URLS)
def test_parse_url_never_raises_and_round_trips_host(u):
    r = T.parse_url(u)
    assert r["host"] == r["host"].lower() and set(r) >= {"scheme", "userinfo", "host", "port", "path", "query", "fragment"}


def test_parse_url_details():
    r = T.parse_url(URLS[0])
    assert (r["scheme"], r["userinfo"], r["host"], r["port"], r["path"], r["query"], r["fragment"]) == ("https", "user:pw", "example.com", "8443", "/a/b", "x=1&y=2", "frag")
    assert T.parse_url("http://[2001:db8::1]:8080/p")["host"] == "2001:db8::1" and T.parse_url("http://[2001:db8::1]:8080/p")["port"] == "8080"
    assert T.parse_url("mailto:a@b.example")["path"] == "a@b.example"
    assert T.parse_url("https://paypal.com@evil.test/x")["host"] == "evil.test"
    assert T.parse_url("https://host.example.")["host"] == "host.example"
    assert T.parse_url("no scheme")["host"] == "" and T.parse_url(None)["url"] == ""


def test_percent_decode_and_query_pairs():
    assert T.percent_decode("a%20b%e2%82%ac") == "a b€" and T.percent_decode("plain") == "plain"
    assert T.query_pairs("A=1&b=x+y&c&&d=%41") == [("a", "1"), ("b", "x y"), ("c", ""), ("d", "A")]
    assert T.query_pairs("") == [] and T.query_pairs(None) == []


def test_ip_helpers():
    assert T.is_ipv4("192.0.2.1") and not T.is_ipv4("256.0.0.1") and not T.is_ipv4("1.2.3") and not T.is_ipv4("1.2.3.4444")
    assert T.is_ipv6("2001:db8::1") and T.is_ipv6("::1") and not T.is_ipv6("abc") and not T.is_ipv6("g::1")
    assert T.obfuscated_ipv4("3405803853") == "203.0.113.77" and T.obfuscated_ipv4("0xCB00714D") == "203.0.113.77"
    assert T.obfuscated_ipv4("0313.0.0161.0115") == "203.0.113.77" and T.obfuscated_ipv4("0xcb.0x0.0x71.0x4d") == "203.0.113.77"
    assert T.obfuscated_ipv4("99999999999") is None and T.obfuscated_ipv4("example.com") is None and T.obfuscated_ipv4("192.0.2.1") is None
    assert T.obfuscated_ipv4("0400.0.0.1") is None and T.obfuscated_ipv4("0x1.09.0.1") is None and T.obfuscated_ipv4("09.0.0.1") is None and T.obfuscated_ipv4("4294967296") is None
    for ip, want in (("10.1.2.3", "private"), ("172.16.0.1", "private"), ("172.32.0.1", "public"), ("192.168.1.1", "private"), ("169.254.1.1", "private"), ("127.0.0.1", "loopback"),
                     ("192.0.2.9", "documentation"), ("198.51.100.9", "documentation"), ("203.0.113.9", "documentation"), ("8.8.8.8", "public"),
                     ("::1", "loopback"), ("::", "loopback"), ("fd00::1", "private"), ("fe80::1", "private"), ("2001:db8::5", "documentation"), ("2606:4700::1", "public")):
        assert T.ip_scope(ip) == want, ip


def test_domain_helpers():
    assert T.registered_domain("a.b.example.com", MULTI) == "example.com" and T.registered_domain("example.com", MULTI) == "example.com" and T.registered_domain("localhost", MULTI) == "localhost"
    assert T.registered_domain("shop.example.co.uk", MULTI) == "example.co.uk" and T.registered_domain("example.co.uk", MULTI) == "example.co.uk"
    assert T.split_registered("login.secure.example.co.uk", MULTI) == (["login", "secure"], "example", "example.co.uk")
    assert T.split_registered("a.example.com", MULTI) == (["a"], "example", "example.com")
    assert T.split_registered("example.com", MULTI) == ([], "example", "example.com")
    assert T.split_registered("localhost", MULTI) == ([], "localhost", "localhost")
    assert T.same_org("a.example.com", "b.example.com", MULTI) and not T.same_org("a.example.com", "a.example.net", MULTI) and not T.same_org("", "a.example.com", MULTI)


def test_punycode_and_scripts():
    assert T.host_unicode("xn--mnchen-3ya.example") == "münchen.example"
    assert T.host_unicode("xn--e1afmkfd.example") == "пример.example"
    assert T.host_unicode("xn--!!!.example") == "xn--!!!.example"
    assert T.host_unicode("xn--99999999999999999999.example") == "xn--99999999999999999999.example"
    assert T.host_unicode("plain.example") == "plain.example"
    assert T.host_unicode("xn--n3h.example") == "☃.example" and T.host_unicode("XN--MNCHEN-3YA.example") == "MüNCHEN.example"
    assert T.host_unicode("xn--zz99z.example") == "xn--zz99z.example"      # code point beyond U+10FFFF stays encoded
    assert T.script_of("a") == "latin" and T.script_of("é") == "latin" and T.script_of("а") == "cyrillic" and T.script_of("α") == "greek" and T.script_of("1") == "common"
    assert T.script_of("-") == "common" and T.script_of("中") == "cjk" and T.script_of("ա") == "armenian" and T.script_of("ع") == "arabic" and T.script_of("🙂") == "other"
    assert T.scripts_in("раураl") == ["cyrillic", "latin"] and T.scripts_in("abc-123") == ["latin"] and T.scripts_in("") == []


def test_confusables_and_edit_distance():
    assert T.normalize_confusables("раураl") == "paypal"
    assert T.normalize_confusables("rnicrosoft") == "microsoft" and T.normalize_confusables("vvork") == "work" and T.normalize_confusables("micr0soft") == "microsoft"
    assert T.normalize_confusables("café") == "cafe"
    assert T.edit_distance("", "") == 0 and T.edit_distance("abc", "abc") == 0 and T.edit_distance("abc", "") == 3 and T.edit_distance("", "ab") == 2
    assert T.edit_distance("paypal", "paypa1") == 1 and T.edit_distance("paypal", "pyapal") == 1 and T.edit_distance("kitten", "sitting") == 3 and T.edit_distance("ca", "abc") == 3


def test_defanging():
    assert T.defang_host("a.b.example") == "a[.]b[.]example"
    assert T.defang_url("http://a.example/p.html?x=a.b") == "hxxp://a[.]example/p.html?x=a.b"
    assert T.defang_url("HTTPS://A.example") == "hxxpS://A[.]example" or T.defang_url("HTTPS://A.example").lower() == "hxxps://a[.]example"
    assert T.defang_url("not a url.example") == "not a url[.]example"
    assert T.defang_email("a.b@c.example") == "a[.]b[@]c[.]example"
    out = T.defang_text("Visit https://a.example/x and mail me@b.example or ftp://c.example.")
    assert "hxxps://a[.]example/x" in out and "me[@]b[.]example" in out and "ftp://c[.]example[.]" in out


def test_defang_known_hosts_including_subdomains():
    txt = "Seen evil.test and sso.login.evil.test, also EVIL.TEST. IP 203.0.113.9 not 1203.0.113.99 or evil.testing.example"
    out = T.defang_known(txt, ["evil.test", "203.0.113.9", ""])
    assert out == "Seen evil[.]test and sso[.]login[.]evil[.]test, also EVIL[.]TEST. IP 203[.]0[.]113[.]9 not 1203.0.113.99 or evil.testing.example"
    assert T.defang_known("a.b.test and b.test", ["b.test", "a.b.test"]) == "a[.]b[.]test and b[.]test"
    assert T.defang_known("nothing here", ["x.test"]) == "nothing here" and T.defang_known("x", []) == "x"


def test_b64decode_lenient():
    assert T.b64decode_lenient("aGVsbG8") == b"hello" and T.b64decode_lenient("aGVs\nbG8=") == b"hello" and T.b64decode_lenient("a") == b"" and T.b64decode_lenient("") == b""


# ------------------------------------------------------------------------ browser copies agree
PRIMS = [("unfold", ["a\r\n  b\n\tc"]), ("decodeWords", ["=?utf-8?B?Q2Fmw6k=?= x"]), ("decodeWords", ["=?utf-8?Q?caf=C3=A9_au_lait?="]),
         ("parseDate", ["Mon, 02 Mar 2026 10:00:00 -0500"]), ("parseDate", ["2 Mar 2026 10:00 GMT"]), ("parseDate", ["Mon, 02 Mar 99 10:00:00 UT"]), ("parseDate", ["garbage"]), ("parseDate", ["32 Mar 2026 10:00:00"]),
         ("formatEpoch", [1772445600]), ("formatEpoch", [951782400]), ("formatEpoch", [-86400])]
PRIMS += [("parseUrl", [u]) for u in URLS if u]
PRIMS += [("extractUrls", ["See https://a.example/x?y=1, hxxps://b[.]example/p). Also www.c.example/z; ftp://d.example/f and ftp://x"]),
          ("percentDecode", ["a%20b%e2%82%ac"]), ("queryPairs", ["A=1&b=x+y&c&&d=%41"]),
          ("obfuscatedIPv4", ["3405803853"]), ("obfuscatedIPv4", ["0xCB00714D"]), ("obfuscatedIPv4", ["0313.0.0161.0115"]), ("obfuscatedIPv4", ["0xcb.0x0.0x71.0x4d"]), ("obfuscatedIPv4", ["example.com"]), ("obfuscatedIPv4", ["0400.0.0.1"]),
          ("ipScope", ["172.16.0.1"]), ("ipScope", ["2001:db8::5"]), ("ipScope", ["fd00::1"]), ("ipScope", ["8.8.8.8"]),
          ("hostUnicode", ["xn--mnchen-3ya.example"]), ("hostUnicode", ["xn--e1afmkfd.example"]), ("hostUnicode", ["xn--!!!.example"]), ("hostUnicode", ["xn--zz99z.example"]), ("hostUnicode", ["xn--n3h.example"]), ("decodeWords", ["a =? b"]),
          ("scriptsIn", ["раураl"]), ("normalizeConfusables", ["rnicrosoft"]), ("normalizeConfusables", ["café"]), ("normalizeConfusables", ["раураl"]),
          ("editDistance", ["paypal", "pyapal"]), ("editDistance", ["kitten", "sitting"]), ("editDistance", ["ca", "abc"]),
          ("defangUrl", ["http://a.example/p.html?x=a.b"]), ("defangEmail", ["a.b@c.example"]), ("defangKnown", ["Seen evil.test and sso.login.evil.test, also EVIL.TEST. IP 203.0.113.9 not 1203.0.113.99 or evil.testing.example", ["evil.test", "203.0.113.9", ""]]), ("defangKnown", ["a.b.test and b.test", ["b.test", "a.b.test"]]), ("defangText", ["Visit https://a.example/x and mail me@b.example or ftp://c.example."]),
          ("registeredDomain", ["shop.example.co.uk", ["co.uk"]]), ("splitRegistered", ["login.secure.example.co.uk", ["co.uk"]])]


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_javascript_primitives_match_python():
    p = subprocess.run(["node", str(ROOT / "scripts" / "parity_dump.js")], input=json.dumps({"prims": PRIMS}), capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    js = json.loads(p.stdout)
    py_fn = {"unfold": T.unfold, "decodeWords": T.decode_words, "parseDate": T.parse_date, "formatEpoch": T.format_epoch, "extractUrls": T.extract_urls, "percentDecode": T.percent_decode,
             "queryPairs": lambda q: [list(x) for x in T.query_pairs(q)], "obfuscatedIPv4": T.obfuscated_ipv4, "ipScope": T.ip_scope, "hostUnicode": T.host_unicode, "scriptsIn": T.scripts_in,
             "normalizeConfusables": T.normalize_confusables, "editDistance": T.edit_distance, "defangUrl": T.defang_url, "defangEmail": T.defang_email, "defangKnown": T.defang_known, "defangText": T.defang_text,
             "registeredDomain": T.registered_domain, "splitRegistered": lambda h, m: list(T.split_registered(h, m)), "parseUrl": T.parse_url}
    for (fn, args), got in zip(PRIMS, js):
        want = py_fn[fn](*args)
        if fn == "parseUrl":
            got = {k: got[k] for k in want} if isinstance(got, dict) else got
        assert got == want, (fn, args, got, want)
