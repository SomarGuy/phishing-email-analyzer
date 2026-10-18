"""The committed reports, dashboard data, README and indicator table must agree with what the code produces today."""
import json
import re
import subprocess
import sys

from phishanalyzer import __version__
from phishanalyzer.analyzer import analyze_message
from phishanalyzer.cli import run_analysis
from phishanalyzer.evaluate import evaluate
from phishanalyzer.report import build_analysis
from .conftest import ROOT

README = (ROOT / "README.md").read_text(encoding="utf-8")
SECTIONS = ["The problem", "Architecture", "How to run it", "Sample output", "Indicators", "Evaluation against ground truth", "What I learned", "Limitations"]


def test_reports_equal_a_fresh_run(synth_dir, cfg):
    analysis = run_analysis([str(synth_dir / "eml")], cfg, json.loads((synth_dir / "dns_fixtures.json").read_text())["domains"])
    analysis["source"] = "data/synthetic/eml"
    committed = json.loads((ROOT / "reports" / "analysis.json").read_text())
    assert analysis == committed
    ev = evaluate(analysis["messages"], json.loads((synth_dir / "ground_truth.json").read_text()))
    assert ev == json.loads((ROOT / "reports" / "evaluation.json").read_text())
    assert json.loads((ROOT / "dashboard" / "data" / "evaluation.json").read_text()) == ev
    assert json.loads((ROOT / "dashboard" / "data" / "analysis.json").read_text()) == committed


def test_dashboard_config_matches_the_shipped_config(cfg):
    pub = json.loads((ROOT / "dashboard" / "data" / "config.json").read_text())
    assert pub == {k: v for k, v in cfg.items() if not k.startswith("_")}


def test_dashboard_embedded_samples_are_the_corpus(corpus):
    emls = json.loads((ROOT / "dashboard" / "data" / "emls.json").read_text())
    assert set(emls) == {e["id"] for e in corpus}
    assert all(emls[e["id"]].encode("ascii") == e["bytes"] for e in corpus)


def test_committed_incident_reports_and_ioc_files_match(results, cfg):
    analysis = build_analysis(list(results.values()), cfg, "data/synthetic/eml")
    inc = ROOT / "reports" / "incidents"
    assert len(list(inc.glob("*.md"))) == 36
    text = (inc / "P11-helpdesk-password-reset-spoof.md").read_text()
    assert analysis["messages"][[m["id"] for m in analysis["messages"]].index("P11-helpdesk-password-reset-spoof")]["ticket_note"] in text
    rows = json.loads((ROOT / "reports" / "iocs.json").read_text())["iocs"]
    assert len(rows) == analysis["summary"]["iocs"] == 101
    assert (ROOT / "reports" / "iocs.csv").read_text().count("\n") == 102


def test_reports_contain_no_local_paths_or_live_links():
    for p in (ROOT / "reports").rglob("*"):
        if p.is_file():
            t = p.read_text(encoding="utf-8")
            assert "/workspace/" not in t and "/home/" not in t, p
            if p.suffix == ".md":
                assert not re.search(r"https?://", t), p        # human-readable reports (incident reports, ticket notes) are defanged everywhere


# ------------------------------------------------------------------------------------------------ README
def test_readme_sections_are_in_the_required_order():
    heads = [h for h in re.findall(r"^## (.+)$", README, re.M)]
    pos = []
    for want in SECTIONS:
        idx = next((i for i, h in enumerate(heads) if h.startswith(want)), None)
        assert idx is not None, want
        pos.append(idx)
    assert pos == sorted(pos)
    assert "```mermaid" in README and "https://github.com/SomarGuy/phishing-email-analyzer" in README and "<your-repo-url>" not in README and "https://phishing-email-analyzer" in README


def test_readme_numbers_match_the_evaluation_and_corpus():
    ev = json.loads((ROOT / "reports" / "evaluation.json").read_text())
    o = ev["overall"]
    f = o["flagged_vs_benign"]
    assert f"{o['exact']}/{o['messages']}" in README
    assert f"{ev['by_set']['tuning']['exact']}/{ev['by_set']['tuning']['messages']}" in README and f"{ev['by_set']['holdout']['exact']}/{ev['by_set']['holdout']['messages']}" in README
    assert str(f["precision"]) in README and str(f["recall"]) in README
    for m in ("B12", "H07", "holdout", "self-graded", "SYNTHETIC"):
        assert m in README, m
    an = json.loads((ROOT / "reports" / "analysis.json").read_text())["summary"]
    assert f"{an['messages']} synthetic" in README.lower() or f"{an['messages']} messages" in README.lower()
    cfg = json.loads((ROOT / "config" / "phish_config.json").read_text())
    assert f"{len(cfg['indicators'])} indicators" in README


def test_readme_indicator_table_lists_every_indicator_with_its_weight():
    cfg = json.loads((ROOT / "config" / "phish_config.json").read_text())
    for i in cfg["indicators"]:
        row = re.search(r"^\| `%s` \|(.*)$" % re.escape(i["id"]), README, re.M)
        assert row, i["id"]
        assert f"| {i['weight']} |" in row.group(0) or f"| {i['weight']:+d} |" in row.group(0), (i["id"], row.group(0))


def test_readme_test_count_matches_the_suite():
    m = re.search(r"\*\*(\d+) pytest tests\*\*", README)
    assert m, "README must state '**N pytest tests**'"
    out = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider", "--no-cov"], cwd=ROOT, capture_output=True, text=True).stdout
    # addopts already carries -q, so the extra -q yields per-file counts ("tests/x.py: 12")
    per_file = [int(n) for n in re.findall(r"^tests/\S+\.py: (\d+)$", out, re.M)]
    summary = re.search(r"(\d+) tests? collected", out)
    total = sum(per_file) if per_file else (int(summary.group(1)) if summary else -1)
    assert total == int(m.group(1))


def test_readme_screenshots_exist_and_commands_are_real():
    for ref in re.findall(r"\]\((screenshots/[^)]+)\)", README):
        assert (ROOT / ref).exists(), ref
    for cmd in ("python -m phishanalyzer demo", "python -m phishanalyzer analyze", "python -m phishanalyzer explain", "pytest"):
        assert cmd in README
    assert __version__ == "1.0.0"
    assert (ROOT / "LICENSE").exists() and (ROOT / "Makefile").exists() and (ROOT / "portfolio_blurb.txt").exists()


def test_every_synthetic_message_is_in_the_readme_corpus_table(corpus):
    for e in corpus:
        assert e["id"].split("-")[0] in README


def test_mitre_renumbering_note_is_documented():
    assert "T1684.001" in README and "T1656" in README and "T1672" in README
