import hashlib
import struct

import pytest

from phishanalyzer.attachments import _PW_HINT, analyze_attachment, analyze_attachments, analyze_html_payload, sniff, split_name
from phishanalyzer.mime import Part, parse_bytes
from phishanalyzer.synthbuild import Att, build_eml, exe_stub, make_ooxml, make_zip, pdf_clean, png_tiny, zipcrypto_zip
from .conftest import STD, ids, run

OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64


def flags(cfg, name, data, ctype="application/octet-stream", body=""):
    rec = analyze_attachment(Part(name, ctype, "attachment", data), cfg, body)
    return {f["id"] for f in rec["flags"]}, rec


@pytest.mark.parametrize("data,want", [
    (b"MZ\x90\x00", "pe"), (b"%PDF-1.7\n", "pdf"), (b"PK\x03\x04xxxx", "zip"), (b"PK\x05\x06xxxx", "zip"), (OLE, "ole"), (b"Rar!\x1a\x07\x00", "rar"),
    (b"7z\xbc\xaf\x27\x1c\x00\x04", "7z"), (b"\x7fELF\x02\x01", "elf"), (b"\x4c\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 8, "lnk"), (png_tiny(), "png"),
    (b"\xff\xd8\xff\xe0", "jpg"), (b"GIF89a", "gif"), (b"{\\rtf1\\ansi", "rtf"), (b"\x00" * 0x8001 + b"CD001" + b"\x00" * 10, "iso"),
    (b"<!DOCTYPE html><html>", "html"), (b"  \n<HTML><body>", "html"), (b"\xef\xbb\xbf<script>x</script>", "html"), (b"<svg xmlns='http://www.w3.org/2000/svg'/>", "svg"),
    (b"<?xml version='1.0'?><svg></svg>", "svg"), (b"<?xml version='1.0'?><note/>", "text"), (b"#!/bin/sh\necho hi\n", "script"), (b"plain text\n", "text"), (b"caf\xc3\xa9", "text"),
    (b"\x00\x01\x02binary", "unknown"), (b"", "unknown"),
])
def test_sniff(data, want):
    assert sniff(data) == want


def test_split_name():
    assert split_name("invoice.pdf.exe") == ("invoice.pdf.exe", ["pdf", "exe"], False)
    assert split_name("C:\\dir\\a.docm") == ("a.docm", ["docm"], False)
    assert split_name("/tmp/x/readme") == ("readme", [], False)
    base, exts, had = split_name("report\u202efdp.exe")
    assert base == "reportfdp.exe" and exts == ["exe"] and had is True
    assert split_name("trailing.")[1] == [] and split_name(".hidden")[1] == ["hidden"] and split_name("A.PDF")[1] == ["pdf"]


def test_executable_and_double_extension_and_known_bad(cfg):
    f, rec = flags(cfg, "Invoice.pdf.exe", exe_stub("P05"))
    assert {"attachment_executable", "attachment_double_extension", "attachment_known_bad"} <= f
    assert rec["sha256"] == hashlib.sha256(exe_stub("P05")).hexdigest() and rec["detected_type"] == "pe"
    f, _ = flags(cfg, "Invoice.pdf.exe", exe_stub("other"))
    assert "attachment_known_bad" not in f and "attachment_double_extension" in f
    f, _ = flags(cfg, "photo.jpg.scr", exe_stub("x"))
    assert "attachment_double_extension" in f
    f, _ = flags(cfg, "doc.pdf.html", b"<html>hi</html>")
    assert "attachment_double_extension" in f and "html_attachment" in f
    f, _ = flags(cfg, "notes.txt.docm", make_ooxml("word", True))
    assert "attachment_double_extension" in f and "attachment_macro" in f
    f, _ = flags(cfg, "release.notes.pdf", pdf_clean())
    assert f == set()


def test_magic_mismatch(cfg):
    f, rec = flags(cfg, "invoice.pdf", exe_stub("x"))
    assert "attachment_magic_mismatch" in f and "attachment_executable" in f
    assert "content is pe" in next(x["detail"] for x in rec["flags"] if x["id"] == "attachment_magic_mismatch")
    f, _ = flags(cfg, "photo.png", pdf_clean())
    assert "attachment_magic_mismatch" in f
    f, _ = flags(cfg, "notes.txt", b"<html><script>x</script></html>")
    assert "attachment_magic_mismatch" in f
    f, _ = flags(cfg, "notes.csv", b"#!/bin/sh\nrm -rf x\n")
    assert "attachment_magic_mismatch" in f and "attachment_executable" in f
    f, _ = flags(cfg, "readme", b"MZ\x90\x00")
    assert "attachment_magic_mismatch" in f
    f, _ = flags(cfg, "ok.pdf", pdf_clean())
    assert "attachment_magic_mismatch" not in f
    f, _ = flags(cfg, "unknown.pdf", b"\x00\x01\x02\x03")
    assert "attachment_magic_mismatch" not in f
    f, _ = flags(cfg, "setup.exe", exe_stub("x"))
    assert "attachment_magic_mismatch" not in f


def test_rtl_override(cfg):
    f, rec = flags(cfg, "report\u202efdp.exe", exe_stub("x"))
    assert "attachment_rtl_override" in f and rec["display_name"] == "reportfdp.exe"


def test_macro_variants(cfg):
    for name in ("a.docm", "b.xlsm", "c.pptm"):
        assert "attachment_macro" in flags(cfg, name, make_ooxml("word", True))[0]
    f, _ = flags(cfg, "old.doc", OLE + b"xx_VBA_PROJECTxx")
    assert "attachment_macro" in f
    f, _ = flags(cfg, "old.xls", OLE + b"Attribute VB_Name = x")
    assert "attachment_macro" in f
    f, _ = flags(cfg, "old.doc", OLE + b"nothing")
    assert "attachment_macro" not in f
    f, rec = flags(cfg, "renamed.docx", make_ooxml("word", True))
    assert "attachment_macro" in f and "vbaProject" in next(x["detail"] for x in rec["flags"] if x["id"] == "attachment_macro")
    f, _ = flags(cfg, "clean.docx", make_ooxml("word", False))
    assert f == set()


def test_archives(cfg):
    f, rec = flags(cfg, "scan.zip", make_zip([("readme.txt", b"hi"), ("scan.pdf.scr", exe_stub("a"))]))
    assert "archive_contains_executable" in f and rec["archive"]["count"] == 2 and rec["archive"]["encrypted"] is False
    f, rec = flags(cfg, "secret.zip", zipcrypto_zip([("a.exe", exe_stub("a"))], "pw"))
    assert "archive_encrypted" in f and rec["archive"]["encrypted"] is True
    f, _ = flags(cfg, "many.zip", make_zip([(f"f{i}.txt", b"x") for i in range(30)] + [("z.js", b"x"), ("y.bat", b"x"), ("w.vbs", b"x"), ("v.exe", b"x")]))
    assert "archive_contains_executable" in f
    f, _ = flags(cfg, "fake.zip", b"PK\x03\x04not really a zip")
    assert f == set() or "archive_encrypted" not in f
    f, rec = flags(cfg, "a.rar", b"Rar!\x1a\x07\x00data")
    assert rec["notes"] and "not inspected" in rec["notes"][0] and rec["archive"] is None
    f, rec = flags(cfg, "a.7z", b"7z\xbc\xaf\x27\x1c\x00\x04")
    assert "not inspected" in rec["notes"][0]
    f, _ = flags(cfg, "named.zip", pdf_clean())
    assert "attachment_magic_mismatch" in f
    f, rec = flags(cfg, "truncated.zip", make_zip([("a.txt", b"x")])[:30])
    assert rec["archive"] is None
    # an Office package is not an 'archive that contains an executable'
    f, rec = flags(cfg, "d.docx", make_ooxml("word", False))
    assert "archive_contains_executable" not in f and rec["archive"]["format"] == "zip"


def test_html_and_svg(cfg):
    smug = b"<html><script>var b=new Blob([atob('QUJD')]);var u=URL.createObjectURL(b);a.download='x.iso';a.click();</script></html>"
    f, rec = flags(cfg, "remit.html", smug)
    assert {"html_attachment", "html_smuggling"} <= f and len(rec["html"]["smuggling"]) >= 4
    f, rec = flags(cfg, "form.htm", b"<html><form action='https://evil.example.test/p'><input type=password></form></html>")
    assert "html_credential_form" in f and rec["html"]["form_hosts"] == ["evil.example.test"]
    f, _ = flags(cfg, "form.html", b"<html><form><input type='password'></form></html>")
    assert "html_credential_form" in f
    f, _ = flags(cfg, "plain.html", b"<html><p>hello</p></html>")
    assert f == {"html_attachment"}
    f, _ = flags(cfg, "img.svg", b"<svg xmlns='x'><script>alert(1)</script></svg>")
    assert f == {"svg_script"}
    f, _ = flags(cfg, "img.svg", b"<svg xmlns='x' onload='go()'></svg>")
    assert f == {"svg_script"}
    f, _ = flags(cfg, "img.svg", b"<svg xmlns='x'><a href='javascript:x'>t</a></svg>")
    assert f == {"svg_script"}
    f, _ = flags(cfg, "safe.svg", b"<svg xmlns='x'><circle r='1'/></svg>")
    assert f == set()
    p = analyze_html_payload("eval(unescape('x')); " + "A" * 450)
    assert any("base64 blob" in s for s in p["smuggling"]) and any("obfuscation" in s for s in p["smuggling"])
    p = analyze_html_payload("msSaveOrOpenBlob(x)")
    assert p["smuggling"] == ["saves it via createObjectURL / msSaveOrOpenBlob"] and p["password_form"] is False


def test_pdf_active_content(cfg):
    f, rec = flags(cfg, "a.pdf", b"%PDF-1.4\n1 0 obj<</OpenAction 2 0 R/JS (app.alert(1))>>endobj\n")
    assert "pdf_active_content" in f and "/OpenAction" in rec["flags"][-1]["detail"]
    assert flags(cfg, "a.pdf", b"%PDF-1.4\n<</JavaScriptX 1>>")[0] == set()


def test_unnamed_part_and_script(cfg):
    f, rec = flags(cfg, "unnamed.octet-stream", b"#!/bin/bash\nid\n")
    assert "attachment_executable" in f and rec["detected_type"] == "script"


def test_password_hint_and_aggregation(cfg):
    zipped = Att("docs.zip", make_zip([("a.txt", b"x")]), "application/zip")
    res = run(cfg, text="The password is: records2026\n", atts=[zipped])
    assert "archive_password_hint" in ids(res)
    res = run(cfg, text="Password to open: abc123\n", atts=[zipped])
    assert "archive_password_hint" in ids(res)
    res = run(cfg, text="Please see the attached.\n", atts=[zipped])
    assert "archive_password_hint" not in ids(res)
    res = run(cfg, text="The password is: records2026\n", atts=[Att("a.pdf", pdf_clean(), "application/pdf")])
    assert "archive_password_hint" not in ids(res)
    res = run(cfg, text="passcode = zq81x\n", atts=[Att("a.rar", b"Rar!\x1a\x07\x00", "application/x-rar")])
    assert "archive_password_hint" in ids(res)
    assert _PW_HINT.search("the password is ab") is None
    two = run(cfg, text="x\n", atts=[Att("a.exe", exe_stub("1")), Att("b.exe", exe_stub("2"))])
    ev = next(i for i in two["indicators"] if i["id"] == "attachment_executable")
    assert len(ev["evidence"]) == 2 and "(+1 more)" in ev["detail"]


def test_never_reads_entries_only_central_directory(cfg, monkeypatch):
    import zipfile
    def forbidden(*a, **k):
        raise AssertionError("archive entry data must never be read")
    monkeypatch.setattr(zipfile.ZipFile, "read", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "open", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", forbidden)
    f, _ = flags(cfg, "x.zip", zipcrypto_zip([("a.exe", exe_stub("a"))], "pw"))
    assert "archive_encrypted" in f


def test_inline_images_are_attachments_without_flags(cfg):
    raw = build_eml(STD, "see image\n", None, [Att("logo.png", png_tiny(), "image/png", inline_cid="logo1")])
    pe = parse_bytes(raw)
    recs, findings = analyze_attachments(pe, cfg)
    assert recs[0]["detected_type"] == "png" and findings == []
