import copy
import json
import os

import pytest

from phishanalyzer.analyzer import analyze_message, verdict_for
from phishanalyzer.config import CATEGORIES, ConfigError, load_config, validate
from phishanalyzer.evaluate import evaluate, evaluation_md
from phishanalyzer.inputs import collect, is_mbox
from phishanalyzer.mime import iter_mbox, parse_bytes
from phishanalyzer.models import Finding
from phishanalyzer.synthbuild import Att, build_eml, make_zip
from .conftest import ROOT, STD, build, ids, run


# ------------------------------------------------------------------------------------------------ config
def fresh(cfg):
    return copy.deepcopy({k: v for k, v in cfg.items() if not k.startswith("_")})


def test_shipped_config_is_valid_and_complete(cfg):
    validate(fresh(cfg))
    assert len(cfg["indicators"]) == 63 and len(cfg["_by_id"]) == 63
    cats = {i["category"] for i in cfg["indicators"]}
    assert cats == set(CATEGORIES)
    assert all(i["weight"] < 0 for i in cfg["indicators"] if i["category"] == "mitigation")
    from phishanalyzer.analyzer import IDENTITY_IDS
    assert set(IDENTITY_IDS) <= set(cfg["_by_id"])


def test_every_finding_id_the_code_can_emit_is_configured(cfg):
    import re
    emitted = set()
    for f in ("attachments", "auth", "headers", "urls", "language", "analyzer"):
        src = open(os.path.join(ROOT, "phishanalyzer", f + ".py"), encoding="utf-8").read()
        emitted |= set(re.findall(r'Finding\(\s*"([a-z0-9_]+)"', src)) | set(re.findall(r'flag\(\s*"([a-z0-9_]+)"', src)) | set(re.findall(r'\("[a-z_]+", "([a-z_]+)"\)', src if f == "language" else ""))
    assert emitted and emitted <= set(cfg["_by_id"]), emitted - set(cfg["_by_id"])


@pytest.mark.parametrize("mutate,message", [
    (lambda c: c.pop("thresholds"), "missing config key: thresholds"),
    (lambda c: c.pop("indicators"), "missing config key: indicators"),
    (lambda c: c["thresholds"].update(suspicious=60, phishing=55), "thresholds"),
    (lambda c: c["thresholds"].update(suspicious=0), "thresholds"),
    (lambda c: c["thresholds"].update(phishing=101), "thresholds"),
    (lambda c: c["indicators"][0].pop("title"), "lacks 'title'"),
    (lambda c: c["indicators"].append(dict(c["indicators"][0])), "duplicate indicator"),
    (lambda c: c["indicators"][0].update(category="nonsense"), "unknown category"),
    (lambda c: c["indicators"][0].update(severity="apocalyptic"), "unknown severity"),
    (lambda c: c["indicators"][0].update(weight=-5), "only mitigations"),
    (lambda c: next(i for i in c["indicators"] if i["category"] == "mitigation").update(weight=5), "only mitigations"),
    (lambda c: c["indicators"][0].update(mitre=["T12"]), "bad ATT&CK id"),
    (lambda c: c["indicators"][0].update(mitre=["T9999"]), "has no name"),
    (lambda c: c["category_caps"].pop("url"), "no cap for category url"),
    (lambda c: c["lists"]["brands"].append({"name": "X"}), "brand lacks"),
    (lambda c: c["language"]["urgency"].append("(unclosed"), "bad language regex"),
])
def test_validate_rejects_bad_configs(cfg, mutate, message):
    c = fresh(cfg)
    mutate(c)
    with pytest.raises(ConfigError) as e:
        validate(c)
    assert message in str(e.value)


def test_load_config_adds_index_and_reads_custom_paths(cfg, tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps(fresh(cfg)))
    c = load_config(str(p))
    assert c["_by_id"]["spf_fail"]["weight"] == cfg["_by_id"]["spf_fail"]["weight"]
    with pytest.raises(FileNotFoundError):
        load_config(str(tmp_path / "nope.json"))


def test_verdict_thresholds(cfg):
    assert [verdict_for(s, cfg) for s in (0, 24, 25, 54, 55, 100)] == ["benign", "benign", "suspicious", "suspicious", "likely_phishing", "likely_phishing"]


def test_changing_a_weight_changes_the_score(cfg):
    base = run(cfg, [("From", "a@example.com"), ("Date", "Mon, 02 Mar 2026 10:00:00 +0000")], text="x\n")
    c = copy.deepcopy(cfg)
    c["_by_id"]["received_missing"]["weight"] += 10
    bumped = run(c, [("From", "a@example.com"), ("Date", "Mon, 02 Mar 2026 10:00:00 +0000")], text="x\n")
    assert bumped["score"] > base["score"]


def test_category_cap_limits_the_total_and_scales_displayed_points(cfg):
    c = copy.deepcopy(cfg)
    c["category_caps"]["header"] = 5
    r = run(c, [("From", '"IT Help Desk" <x@evil.test>'), ("Reply-To", "y@other.test"), ("Subject", "x")], text="x\n")
    assert r["breakdown"]["header"]["capped"] == 5 and r["breakdown"]["header"]["raw"] > 5
    assert sum(i["points"] for i in r["indicators"] if i["category"] == "header") <= 5 + len(r["indicators"])


def test_mitigations_only_apply_to_authenticated_mail(cfg):
    base = [("From", "News <n@example.com>"), ("Subject", "Weekly"), ("Date", "Mon, 02 Mar 2026 10:00:00 +0000"), ("Message-ID", "<1@example.com>"),
            ("Return-Path", "<b@example.com>"), ("Authentication-Results", "mx; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com")]
    r = run(cfg, base + [("List-Unsubscribe", "<mailto:u@example.com>")], text="Urgent: act within 24 hours\n")
    assert {m["id"] for m in r["mitigations"]} == {"authenticated_aligned", "list_unsubscribe"} and r["mitigation_total"] == -17
    spoofed = [h for h in base if h[0] != "From"] + [("From", '"PayPal" <n@example.com>')]
    r2 = run(cfg, spoofed, text="Urgent: act within 24 hours\n")
    assert r2["mitigations"] == []
    rcv = ("Received", "from mail.example.com (mail.example.com [198.51.100.7]) by mx.example.net with ESMTP; Mon, 02 Mar 2026 10:00:03 +0000")
    assert run(cfg, base + [rcv], text="plain\n")["mitigations"] == []            # nothing to mitigate: score is already 0


def test_t1566_fallback_when_only_unmapped_findings_push_the_score_up(cfg):
    c = copy.deepcopy(cfg)
    for k in ("attachment_magic_mismatch",):
        c["_by_id"][k]["mitre"] = []
        c["_by_id"][k]["weight"] = 40
    r = run(c, text="x\n", atts=[Att("a.png", b"%PDF-1.4 stub")])
    assert r["verdict"] != "benign" and r["mitre"][0]["id"] == "T1566.001"
    c2 = copy.deepcopy(cfg)
    c2["_by_id"]["url_shortener"]["mitre"] = []
    c2["_by_id"]["url_shortener"]["weight"] = 40
    r2 = run(c2, text="open https://bit.ly/abc now\n")
    assert r2["verdict"] != "benign" and r2["mitre"][0]["id"] == "T1566.002"


def test_finding_dataclass_defaults():
    assert Finding("x", "d").evidence == []


# ------------------------------------------------------------------------------------------------ evaluation
def truth_for(*rows):
    return {"notice": "n", "messages": [{"id": i, "label": l, "category": "c", "set": s, "description": "d", "expect": e, "forbid": f} for i, l, s, e, f in rows]}


def res(i, verdict, score, inds=()):
    return {"id": i, "verdict": verdict, "score": score, "indicators": [{"id": x, "points": p} for x, p in inds]}


def test_evaluate_counts_and_errors():
    truth = truth_for(("a", "phishing", "tuning", ["spf_fail"], []), ("b", "benign", "tuning", [], ["url_shortener"]), ("c", "benign", "holdout", [], []),
                      ("d", "suspicious", "holdout", ["x"], []), ("e", "phishing", "tuning", [], []), ("gone", "benign", "tuning", [], []))
    results = [res("a", "likely_phishing", 80, [("spf_fail", 10)]), res("b", "suspicious", 30, [("url_shortener", 5)]), res("c", "benign", 0),
               res("d", "benign", 10), res("e", "suspicious", 30)]
    ev = evaluate(results, truth)
    assert ev["unmatched"] == ["gone"] and ev["messages_in_truth"] == 6
    o = ev["overall"]
    f = o["flagged_vs_benign"]
    assert (o["messages"], o["exact"]) == (5, 2) and (f["tp"], f["fp"], f["fn"], f["tn"]) == (2, 1, 1, 1)
    assert f["precision"] == round(2 / 3, 4) and f["recall"] == round(2 / 3, 4) and f["false_positive_rate"] == 0.5
    assert o["confusion"]["benign"]["suspicious"] == 1 and o["confusion"]["suspicious"]["benign"] == 1
    assert o["phishing_caught_as_likely_phishing"] == {"caught": 1, "of": 2}
    assert o["expected_indicators"] == {"hit": 1, "of": 2, "rate": 0.5} and o["forbidden_indicator_violations"] == 1
    assert set(ev["by_set"]) == {"tuning", "holdout"}
    assert {r["id"] for r in ev["errors"]} == {"b", "d", "e"}
    md = evaluation_md(ev)
    assert "Caveat" in md and "| holdout |" in md and "## Misses and surprises" in md
    assert "expected indicators not fired: x" in md and "forbidden indicators fired: url_shortener" in md and "expected likely_phishing" in md


def test_evaluate_zero_division_and_clean_run():
    ev = evaluate([], truth_for())
    assert ev["overall"]["exact_accuracy"] is None and ev["overall"]["flagged_vs_benign"]["precision"] is None
    ev = evaluate([res("a", "benign", 0)], truth_for(("a", "benign", "tuning", [], [])))
    assert ev["errors"] == [] and "Misses and surprises" not in evaluation_md(ev)
    assert ev["overall"]["flagged_vs_benign"]["recall"] is None


def test_forbidden_only_counts_scoring_indicators():
    ev = evaluate([res("a", "benign", 0, [("url_shortener", 0)])], truth_for(("a", "benign", "tuning", [], ["url_shortener"])))
    assert ev["overall"]["forbidden_indicator_violations"] == 0


# ------------------------------------------------------------------------------------------------ inputs and mime
def test_collect_handles_files_dirs_and_mbox(tmp_path, synth_dir):
    one = tmp_path / "one.eml"
    one.write_bytes(build(STD, "a\n"))
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "two.EML").write_bytes(build(STD, "b\n"))
    (sub / "ignore.txt").write_text("not mail")
    (sub / "box.mbox").write_bytes((synth_dir / "corpus.mbox").read_bytes())
    got = collect([str(tmp_path)])
    labels = [l for l, _ in got]
    assert labels[0] == "one" and "two" in labels and sum(l.startswith("box.mbox#") for l in labels) == 36 and "ignore" not in labels
    assert [l for l, _ in collect([str(one), str(sub / "two.EML")])] == ["one", "two"]
    assert len(collect([str(synth_dir / "corpus.mbox")])) == 36
    with pytest.raises(FileNotFoundError):
        collect([str(tmp_path / "missing.eml")])


def test_is_mbox_detection(tmp_path):
    a = tmp_path / "x.dat"
    a.write_bytes(b"From someone Mon Mar  2 00:00:00 2026\nSubject: x\n\nbody\n")
    assert is_mbox(str(a)) is True
    b = tmp_path / "y.eml"
    b.write_bytes(b"Subject: x\n\nbody\n")
    assert is_mbox(str(b)) is False
    assert is_mbox(str(tmp_path / "z.MBOX")) is True
    assert is_mbox(str(tmp_path / "does-not-exist")) is False


def test_iter_mbox_labels_and_roundtrip(tmp_path):
    p = tmp_path / "m.mbox"
    p.write_bytes(b"From a@example.com Mon Mar  2 00:00:00 2026\nSubject: one\n\nbody1\n\nFrom b@example.com Mon Mar  2 00:00:00 2026\nSubject: two\n\nbody2\n")
    got = list(iter_mbox(str(p)))
    assert [l for l, _ in got] == ["m.mbox#1", "m.mbox#2"] and b"Subject: two" in got[1][1]


def test_parse_bytes_structure():
    raw = build(STD, "plain body\n", "<p>html body</p>", [Att("a.zip", make_zip([("x.txt", b"hi")]), "application/zip"), Att("logo.png", b"\x89PNG\r\n\x1a\n", "image/png", inline_cid="cid1")])
    pe = parse_bytes(raw)
    assert pe.get("subject") == "hi" and pe.get("SUBJECT") == "hi" and pe.get("Nope", "dflt") == "dflt" and pe.get_all("received") == []
    assert "plain body" in pe.text and "html body" in pe.html and pe.size == len(raw) and pe.raw == raw
    assert [(a.filename, a.disposition, a.content_id) for a in pe.attachments] == [("a.zip", "attachment", ""), ("logo.png", "inline", "cid1")]


def test_parse_bytes_unnamed_parts_bad_charsets_and_defects():
    raw = (b"From: a@example.com\r\nSubject: =?utf-8?B?Q2Fmw6k=?=\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain; charset=no-such-charset\r\n\r\nhello caf\xe9\r\n"
           b"--B\r\nContent-Type: application/x-weird+json\r\n\r\n{}\r\n--B\r\nContent-Type: application\r\n\r\nzzz\r\n--B--\r\n")
    pe = parse_bytes(raw)
    assert "hello caf" in pe.text
    assert [a.filename for a in pe.attachments] == ["unnamed.x-weird"]
    broken = parse_bytes(b"this is not an email at all")
    assert broken.headers == [] and broken.attachments == []


def test_empty_and_garbage_inputs_do_not_crash(cfg):
    for raw in (b"", b"\x00\x01\x02", b"Subject:\n\n", b"From: <>\n\n", b"X" * 5000):
        r = analyze_message(raw, cfg, None, "g")
        assert 0 <= r["score"] <= 100 and r["verdict"] in ("benign", "suspicious", "likely_phishing")
