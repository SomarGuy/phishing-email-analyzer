import pytest

from phishanalyzer.language import analyze_language, scan
from .conftest import STD, build, ids, run


def lang(cfg, subject="", text="", html="", images=False):
    f, hits = analyze_language(subject, text, html, images, cfg)
    return {x.id for x in f}, hits, f


@pytest.mark.parametrize("text,indicator", [
    ("This is URGENT, act now", "urgency_language"), ("Your account will be closed within 24 hours", "urgency_language"),
    ("Please verify your account", "credential_lure"), ("Confirm your password to continue", "credential_lure"),
    ("Invoice attached for your review", "payment_lure"), ("Payment is overdue", "payment_lure"), ("Invoice 55120 is overdue", "payment_lure"),
    ("Scan the QR code below to continue", "qr_lure"), ("Dear customer,\nyour parcel", "generic_greeting"),
    ("Please click enable content to view", "enable_content_lure"), ("Enable editing to see the document", "enable_content_lure"),
])
def test_single_match_categories(cfg, text, indicator):
    got, _, _ = lang(cfg, text=text, images=True)
    assert indicator in got


def test_gift_card_and_bec_need_two_matches(cfg):
    assert "gift_card_scam" not in lang(cfg, text="Thanks for the gift card!")[0]
    assert "gift_card_scam" in lang(cfg, text="Buy gift cards and scratch off the back")[0]
    assert "bec_wording" not in lang(cfg, text="Are you available?")[0]
    assert "bec_wording" in lang(cfg, text="Are you available? I need a quick favor. Keep this confidential.")[0]


def test_qr_wording_needs_an_image(cfg):
    assert "qr_lure" not in lang(cfg, text="Scan the QR code", images=False)[0]
    assert "qr_lure" in lang(cfg, text="Scan the QR code", images=True)[0]


def test_subject_and_html_text_are_scanned_and_evidence_is_quoted(cfg):
    got, hits, f = lang(cfg, subject="Urgent: verify your password", html="Dear customer")
    assert {"urgency_language", "credential_lure", "generic_greeting"} <= got
    cred = next(x for x in f if x.id == "credential_lure")
    assert cred.evidence == ['"verify your password"'] and "Credential-harvesting wording" in cred.detail
    assert hits["credential"] == ["verify your password"]


def test_benign_text_is_quiet(cfg):
    got, hits, _ = lang(cfg, subject="Team lunch", text="Lunch is at noon on Friday. Bring your own mug.")
    assert got == set() and all(v == [] for v in hits.values())


def test_scan_is_case_insensitive_and_bounds_evidence(cfg):
    assert scan("VERIFY YOUR ACCOUNT", cfg)["credential"] == ["VERIFY YOUR ACCOUNT"]
    long = scan("scratch off " + "x" * 100, cfg)
    assert all(len(v) <= 60 for vals in long.values() for v in vals)
    assert scan("", cfg)["urgency"] == []


def test_language_end_to_end_in_a_message(cfg):
    r = run(cfg, text="Dear customer, verify your password within 24 hours.\n")
    assert {"generic_greeting", "credential_lure", "urgency_language"} <= ids(r)
    assert set(r["language"]) >= {"credential", "urgency", "greeting"}
