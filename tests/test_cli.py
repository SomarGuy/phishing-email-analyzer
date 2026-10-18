import io
import json
from pathlib import Path

import pytest

from phishanalyzer.cli import build_parser, load_dns, main
from .conftest import ROOT, STD, build


def run(argv):
    out = io.StringIO()
    code = main(argv, out)
    return code, out.getvalue()


@pytest.fixture(scope="module")
def eml_dir(synth_dir):
    return str(synth_dir / "eml")


@pytest.fixture(scope="module")
def dns_path(synth_dir):
    return str(synth_dir / "dns_fixtures.json")


def test_analyze_table_exit_zero(eml_dir, dns_path):
    code, out = run(["analyze", eml_dir, "--dns", dns_path])
    assert code == 0 and "36 message(s): 15 benign, 4 suspicious, 17 likely phishing" in out
    assert "P05-invoice-double-extension-exe" in out


def test_fail_on_levels(eml_dir, dns_path, synth_dir):
    assert run(["analyze", eml_dir, "--dns", dns_path, "--fail-on", "phishing"])[0] == 2
    assert run(["analyze", eml_dir, "--fail-on", "suspicious"])[0] == 2
    benign = str(synth_dir / "eml" / "B01-newsletter-harbour-gazette.eml")
    assert run(["analyze", benign, "--fail-on", "suspicious"])[0] == 0
    sus = str(synth_dir / "eml" / "S01-partner-encrypted-zip.eml")
    assert run(["analyze", sus, "--fail-on", "phishing"])[0] == 0
    assert run(["analyze", sus, "--fail-on", "suspicious"])[0] == 2


def test_json_and_out_directory(eml_dir, dns_path, tmp_path):
    code, out = run(["analyze", eml_dir, "--dns", dns_path, "--json", "--out", str(tmp_path / "o")])
    assert code == 0
    data = json.loads(out)
    assert data["summary"]["messages"] == 36 and data["synthetic"] is True
    o = tmp_path / "o"
    for name in ("analysis.json", "analysis.md", "iocs.csv", "iocs.json"):
        assert (o / name).exists(), name
    assert len(list((o / "incidents").glob("*.md"))) == 36


def test_explain_prints_incident_report(synth_dir, dns_path):
    code, out = run(["explain", str(synth_dir / "eml" / "P11-helpdesk-password-reset-spoof.eml"), "--dns", dns_path])
    assert code == 0 and "Copy-ready ticket note" in out and "hxxp" in out.lower() or "[.]" in out


def test_explain_needs_one_message(synth_dir):
    code, out = run(["explain", str(synth_dir / "corpus.mbox")])
    assert code == 1 and "exactly one" in out


def test_evaluate_command(eml_dir, dns_path, synth_dir):
    code, out = run(["evaluate", eml_dir, "--truth", str(synth_dir / "ground_truth.json"), "--dns", dns_path])
    assert code == 0 and "| all | 36 | 34/36 |" in out and "Caveat" in out


def test_mbox_equals_eml_directory(synth_dir, dns_path):
    _, a = run(["analyze", str(synth_dir / "eml"), "--dns", dns_path, "--json"])
    _, b = run(["analyze", str(synth_dir / "corpus.mbox"), "--dns", dns_path, "--json"])
    ra, rb = json.loads(a)["messages"], json.loads(b)["messages"]
    assert len(ra) == len(rb) == 36
    key = lambda m: (str(m["message_id"]), m["subject"], m["from"]["addr"])
    sig = lambda ms: {key(m): (m["score"], m["verdict"], tuple(i["id"] for i in m["indicators"])) for m in ms}
    assert sig(ra) == sig(rb) and len(sig(ra)) == 36


def test_list_indicators_and_validate():
    code, out = run(["list-indicators"])
    assert code == 0 and out.count("\n") == 63 and "attachment_double_extension" in out
    assert run(["validate-config"])[0] == 0


def test_errors_exit_one(tmp_path):
    assert run(["analyze", str(tmp_path / "missing.eml")])[0] == 1
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert run(["validate-config", str(bad)])[0] == 1
    cfg = json.loads((ROOT / "config" / "phish_config.json").read_text())
    del cfg["thresholds"]
    bad.write_text(json.dumps(cfg))
    assert run(["validate-config", str(bad)])[0] == 1
    assert run(["analyze", str(tmp_path / "x.eml"), "--config", str(bad)])[0] == 1


def test_usage_error_exits_two():
    with pytest.raises(SystemExit) as e:
        main(["analyze", "x", "--fail-on", "nonsense"], io.StringIO())
    assert e.value.code == 2
    with pytest.raises(SystemExit) as e:
        main([], io.StringIO())
    assert e.value.code == 2


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"], io.StringIO())
    assert e.value.code == 0 and "phishanalyzer 1.0.0" in capsys.readouterr().out


def test_load_dns_unwraps_domains_key(dns_path, tmp_path):
    assert "vendor-pay.example" in load_dns(dns_path)
    p = tmp_path / "d.json"
    p.write_text('{"a.example": {"TXT": []}}')
    assert load_dns(str(p)) == {"a.example": {"TXT": []}}
    assert load_dns(None) is None


def test_analyze_single_eml_from_stdin_style_path(tmp_path):
    p = tmp_path / "one.eml"
    p.write_bytes(build(STD, "hello\n"))
    code, out = run(["analyze", str(p)])
    assert code == 0 and "one" in out and "1 message(s)" in out


def test_generate_and_demo(tmp_path):
    code, out = run(["generate", "--out", str(tmp_path / "g")])
    assert code == 0 and "36 SYNTHETIC" in out
    root = tmp_path / "root"
    (root / "config").mkdir(parents=True)
    (root / "config" / "phish_config.json").write_text((ROOT / "config" / "phish_config.json").read_text())
    code, out = run(["demo", "--root", str(root)])
    assert code == 0 and "exact verdict 34/36" in out
    for p in ("reports/analysis.json", "reports/evaluation.md", "dashboard/data/emls.json", "dashboard/data/dns_fixtures.json", "data/synthetic/corpus.mbox"):
        assert (root / p).exists(), p


def test_parser_has_all_commands():
    names = set(build_parser()._subparsers._group_actions[0].choices)
    assert names == {"analyze", "explain", "evaluate", "list-indicators", "validate-config", "generate", "demo"}


def test_module_entrypoint_runs():
    import subprocess
    import sys
    r = subprocess.run([sys.executable, "-m", "phishanalyzer", "--version"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0 and "1.0.0" in r.stdout
