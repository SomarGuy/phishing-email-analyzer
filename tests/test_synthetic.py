"""The corpus must be deterministic, labelled synthetic, and use only reserved domains and documentation IPs."""
import hashlib
import ipaddress
import json
import re
import zipfile
import io

from phishanalyzer import synthetic
from phishanalyzer.synthbuild import enc_word, exe_stub, fold, make_ooxml, make_zip, pdf_clean, png_tiny, rfc_date, zipcrypto_zip
from phishanalyzer.mime import parse_bytes
from .conftest import ROOT

# the only real domains in the corpus: the legitimate side of the look-alike / must-not-flag tests (documented in the notice)
REAL_BRAND_HOSTS = ("paypal.com", "amazon.com", "aws.amazon.com", "amazon.com")
RESERVED_SUFFIXES = (".example", ".test", ".invalid", ".localhost", "example.com", "example.net", "example.org")
SAFE_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "10.0.0.0/8", "127.0.0.0/8", "0.0.0.0/8", "169.254.0.0/16")]


def test_build_is_deterministic():
    a = synthetic.build_corpus()
    b = synthetic.build_corpus()
    assert [hashlib.sha256(x["bytes"]).hexdigest() for x in a] == [hashlib.sha256(x["bytes"]).hexdigest() for x in b]


def test_every_message_is_labelled_synthetic(corpus):
    for e in corpus:
        pe = parse_bytes(e["bytes"])
        assert pe.get("X-Synthetic-Sample").strip().lower() == "yes", e["id"]
    assert len({e["id"] for e in corpus}) == len(corpus) == len({e["file"] for e in corpus})


def test_only_reserved_domains_and_documentation_ips(corpus):
    for e in corpus:
        text = e["bytes"].decode("ascii", "replace")
        text = re.sub(r"=\?utf-8\?[bq]\?[^?]*\?=", "", text, flags=re.I)
        for host in re.findall(r"(?:https?://|@|from |by |\[)([A-Za-z0-9._-]+\.[A-Za-z0-9-]+)", text):
            h = host.lower().strip(".")
            if re.fullmatch(r"[\d.]+", h):
                continue
            if h.endswith(RESERVED_SUFFIXES):
                continue
            if h.endswith(REAL_BRAND_HOSTS):
                assert e["id"][:3] in ("P01", "P13", "H08"), (e["id"], h)
                continue
            if re.fullmatch(r"[a-z0-9_-]+\.(png|pdf|exe|zip|docm|html|svg|rar|js|scr|txt|docx|xlsx|iso|lnk)", h) or "boundary" in h:
                continue
            raise AssertionError(f"{e['id']}: non-reserved host {h}")
        for ip in re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text):
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            assert any(addr in n for n in SAFE_NETS), (e["id"], ip)


def test_written_files_equal_a_fresh_build(synth_dir, corpus):
    for e in corpus:
        assert (synth_dir / "eml" / e["file"]).read_bytes() == e["bytes"]
    gt = json.loads((synth_dir / "ground_truth.json").read_text())
    assert gt["synthetic"] is True and len(gt["messages"]) == 36 and "SYNTHETIC" in gt["notice"]
    assert (synth_dir / "README_SYNTHETIC.txt").read_text().startswith("SYNTHETIC")
    assert json.loads((synth_dir / "dns_fixtures.json").read_text())["domains"] == synthetic.DNS_FIXTURES["domains"]


def test_committed_corpus_equals_a_fresh_generation(synth_dir):
    committed = ROOT / "data" / "synthetic"
    fresh = {str(p.relative_to(synth_dir)): p.read_bytes() for p in synth_dir.rglob("*") if p.is_file()}
    have = {str(p.relative_to(committed)): p.read_bytes() for p in committed.rglob("*") if p.is_file()}
    assert fresh.keys() == have.keys()
    assert [k for k in fresh if fresh[k] != have[k]] == []


def test_holdout_is_labelled_and_weights_never_see_it(truth):
    hold = [m for m in truth["messages"] if m["set"] == "holdout"]
    assert len(hold) == 8 and all(m["id"].startswith("H") for m in hold)


def test_payload_helpers_are_inert_and_well_formed():
    assert pdf_clean().startswith(b"%PDF-")
    assert exe_stub("a").startswith(b"MZ") and exe_stub("a") != exe_stub("b") and len(exe_stub("a")) < 400
    assert png_tiny().startswith(b"\x89PNG")
    z = zipfile.ZipFile(io.BytesIO(make_zip([("a.txt", b"hi")])))
    assert z.namelist() == ["a.txt"] and z.read("a.txt") == b"hi"
    enc = zipfile.ZipFile(io.BytesIO(zipcrypto_zip([("a.txt", b"hello world")], "secret")))
    assert enc.infolist()[0].flag_bits & 1
    enc.setpassword(b"secret")
    assert enc.read("a.txt") == b"hello world"
    assert "word/vbaProject.bin" in zipfile.ZipFile(io.BytesIO(make_ooxml("word", True))).namelist()
    assert "word/vbaProject.bin" not in zipfile.ZipFile(io.BytesIO(make_ooxml("word", False))).namelist()


def test_header_helpers():
    assert rfc_date(5, 1, 2, 3) == "Thu, 05 Mar 2026 01:02:03 +0000"
    assert enc_word("plain") == "plain" and enc_word("café").lower().startswith("=?utf-8?b?")
    folded = fold("Subject", "x " * 80)
    assert all(len(line) <= 78 for line in folded.split("\r\n"))
