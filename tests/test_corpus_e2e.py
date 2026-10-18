"""End-to-end: every synthetic message must produce its labelled verdict (except the two documented misses) and indicators."""
import json

import pytest

from phishanalyzer.evaluate import evaluate
from .conftest import ids

KNOWN_WRONG = {"B12-secops-awareness-quoted-phish": "suspicious", "H07-unauth-rar-password": "benign"}
LABEL = {"benign": "benign", "suspicious": "suspicious", "phishing": "likely_phishing"}


def test_corpus_size_and_label_mix(corpus):
    assert len(corpus) == 36
    labels = [e["label"] for e in corpus]
    assert labels.count("benign") >= 14 and labels.count("phishing") >= 15 and labels.count("suspicious") == 4
    assert {e["set"] for e in corpus} == {"tuning", "holdout"}
    assert sum(1 for e in corpus if e["set"] == "holdout") == 8


@pytest.mark.parametrize("eid", [e["id"] for e in __import__("phishanalyzer.synthetic", fromlist=["x"]).ENTRIES])
def test_each_message_matches_ground_truth(eid, corpus, results):
    e = next(x for x in corpus if x["id"] == eid)
    r = results[eid]
    fired = ids(r)
    assert [x for x in e["expect"] if x not in fired] == []
    assert [x for x in e["forbid"] if x in ids(r, points_only=True)] == []
    want = KNOWN_WRONG.get(eid, LABEL[e["label"]])
    assert r["verdict"] == want, (eid, r["score"])


def test_known_misses_are_the_only_misses(results, corpus):
    wrong = {e["id"] for e in corpus if results[e["id"]]["verdict"] != LABEL[e["label"]]}
    assert wrong == set(KNOWN_WRONG)


def test_evaluation_numbers(results, truth):
    ev = evaluate(list(results.values()), truth)
    o = ev["overall"]
    assert (o["messages"], o["exact"]) == (36, 34)
    f = o["flagged_vs_benign"]
    assert (f["tp"], f["fp"], f["fn"], f["tn"]) == (20, 1, 1, 14)
    assert o["expected_indicators"]["hit"] == o["expected_indicators"]["of"] == 64
    assert o["forbidden_indicator_violations"] == 0
    assert ev["by_set"]["tuning"]["exact"] == 27 and ev["by_set"]["holdout"]["exact"] == 7
    assert {r["id"] for r in ev["errors"]} == set(KNOWN_WRONG)


def test_scores_are_bounded_and_explained(results, cfg):
    for r in results.values():
        assert 0 <= r["score"] <= 100
        assert r["synthetic"] is True
        total = sum(b["capped"] for b in r["breakdown"].values()) + r["mitigation_total"]
        assert r["score"] == max(0, min(100, total))
        for i in r["indicators"]:
            assert i["detail"] and i["id"] in cfg["_by_id"]
        thr = cfg["thresholds"]
        want = "likely_phishing" if r["score"] >= thr["phishing"] else "suspicious" if r["score"] >= thr["suspicious"] else "benign"
        assert r["verdict"] == want


def test_category_caps_are_respected(results):
    for r in results.values():
        for cat, b in r["breakdown"].items():
            assert b["capped"] <= b["cap"]
            pts = sum(i["points"] for i in r["indicators"] if i["category"] == cat)
            assert abs(pts - b["capped"]) <= len([1 for i in r["indicators"] if i["category"] == cat])   # rounding of scaled points


def test_high_and_critical_indicators_have_attack_mapping(results):
    for r in results.values():
        for i in r["indicators"]:
            if i["severity"] in ("high", "critical"):
                assert i["mitre"], i["id"]


def test_specific_scenarios(results):
    p = results
    assert "url_idn_homograph" in ids(p["P02-microsoft-idn-homograph"])
    assert "html_smuggling" in " ".join(ids(p["P04-remittance-html-smuggling"])) or "attachment_html_smuggling" in ids(p["P04-remittance-html-smuggling"])
    assert "attachment_known_bad" in ids(p["P05-invoice-double-extension-exe"])
    assert "spf_fail" in ids(p["P10-cfo-vendor-bank-change-lookalike"])
    assert any(h["anomalies"] for h in p["P10-cfo-vendor-bank-change-lookalike"]["hops"])
    assert p["B07-events-idn-muenchen"]["verdict"] == "benign"
    assert p["B06-monitoring-alert-no-msgid"]["verdict"] == "benign"


def test_benign_messages_with_weird_traits_are_not_flagged(results):
    for k in ("B01", "B02", "B03", "B04", "B05", "B06", "B07", "B08", "B09", "B10"):
        r = next(v for i, v in results.items() if i.startswith(k))
        assert r["verdict"] == "benign", (k, r["score"])


def test_iocs_are_defanged(results):
    for r in results.values():
        for i in r["iocs"]:
            if i["type"] in ("url",):
                assert i["defanged"].startswith(("hxxp://", "hxxps://")), i
            if i["type"] in ("domain", "ip"):
                assert "[.]" in i["defanged"] and "." not in i["defanged"].replace("[.]", "")
            if i["type"] == "email":
                assert "[@]" in i["defanged"]


def test_analysis_is_deterministic(corpus, cfg, dns):
    a = [json.dumps(__import__("phishanalyzer.analyzer", fromlist=["x"]).analyze_message(e["bytes"], cfg, dns, e["id"]), sort_keys=True) for e in corpus[:12]]
    b = [json.dumps(__import__("phishanalyzer.analyzer", fromlist=["x"]).analyze_message(e["bytes"], cfg, dns, e["id"]), sort_keys=True) for e in corpus[:12]]
    assert a == b
