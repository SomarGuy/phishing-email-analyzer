"""Command line interface. Exit status: 0 ok, 1 error (bad input/config), 2 --fail-on threshold reached or usage error."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import TOOL_NAME, __version__
from .analyzer import analyze_message
from .config import ConfigError, DEFAULT_PATH, load_config
from .evaluate import evaluate, evaluation_md
from .inputs import collect
from .report import VERDICT_TEXT, build_analysis, incident_md, top_reasons, write_reports

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LEVELS = {"suspicious": ("suspicious", "likely_phishing"), "phishing": ("likely_phishing",)}


def load_dns(path: Optional[str]) -> Optional[dict]:
    if not path:
        return None
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("domains", data)


def run_analysis(paths: List[str], cfg: dict, dns: Optional[dict]) -> dict:
    msgs = collect(paths)
    results = [analyze_message(raw, cfg, dns, label) for label, raw in msgs]
    return build_analysis(results, cfg, ", ".join(os.path.basename(p.rstrip("/")) or p for p in paths))


def write_dashboard_data(analysis: dict, ev: Optional[dict], cfg: dict, raw_by_id: dict, dns_fixtures: dict, outdir: str) -> None:
    os.makedirs(outdir, exist_ok=True)
    pub_cfg = {k: v for k, v in cfg.items() if not k.startswith("_")}
    files = {"analysis.json": analysis, "config.json": pub_cfg, "emls.json": raw_by_id, "dns_fixtures.json": dns_fixtures}
    if ev is not None:
        files["evaluation.json"] = ev
    for name, obj in files.items():
        with open(os.path.join(outdir, name), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(obj, fh, indent=None if name == "emls.json" else 1, ensure_ascii=False)
            fh.write("\n")


def _print_table(analysis: dict, out) -> None:
    out.write(f"{'MESSAGE':44s} {'SCORE':>5s}  {'VERDICT':16s} TOP INDICATORS\n")
    for r in analysis["messages"]:
        top = ", ".join(i["id"] for i in top_reasons(r, 3)) or "-"
        out.write(f"{r['id'][:44]:44s} {r['score']:5d}  {VERDICT_TEXT[r['verdict']]:16s} {top}\n")
    s = analysis["summary"]
    out.write(f"\n{s['messages']} message(s): {s['benign']} benign, {s['suspicious']} suspicious, {s['likely_phishing']} likely phishing; {s['iocs']} IOC(s)\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=TOOL_NAME, description="Static phishing e-mail analyser (reads .eml/mbox, never opens, executes or fetches anything).")
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyse .eml files, directories or mbox files")
    a.add_argument("paths", nargs="+")
    a.add_argument("--config", default=DEFAULT_PATH)
    a.add_argument("--dns", help="JSON file of synthetic DNS records for the offline SPF evaluator")
    a.add_argument("--out", help="write analysis.json/.md, incidents/*.md, iocs.csv/json into this directory")
    a.add_argument("--json", action="store_true", help="print the full analysis as JSON instead of a table")
    a.add_argument("--fail-on", choices=sorted(LEVELS), help="exit 2 if any message reaches this verdict (suspicious or phishing)")
    e = sub.add_parser("explain", help="print the incident report for one message")
    e.add_argument("path")
    e.add_argument("--config", default=DEFAULT_PATH)
    e.add_argument("--dns")
    ev = sub.add_parser("evaluate", help="score a directory/mbox against a ground_truth.json")
    ev.add_argument("paths", nargs="+")
    ev.add_argument("--truth", required=True)
    ev.add_argument("--config", default=DEFAULT_PATH)
    ev.add_argument("--dns")
    sub.add_parser("list-indicators", help="print every indicator with weight and ATT&CK mapping").add_argument("--config", default=DEFAULT_PATH)
    sub.add_parser("validate-config", help="check a configuration file").add_argument("path", nargs="?", default=DEFAULT_PATH)
    g = sub.add_parser("generate", help="write the SYNTHETIC corpus (eml files, mbox, DNS fixtures, ground truth)")
    g.add_argument("--out", default=os.path.join(ROOT, "data", "synthetic"))
    d = sub.add_parser("demo", help="generate the corpus, analyse it, evaluate it and refresh reports and dashboard data")
    d.add_argument("--root", default=ROOT)
    return p


def cmd_demo(root: str, out) -> int:
    from .synthetic import write_corpus
    cfg = load_config(os.path.join(root, "config", "phish_config.json"))
    syn_dir = os.path.join(root, "data", "synthetic")
    write_corpus(syn_dir)
    dns = load_dns(os.path.join(syn_dir, "dns_fixtures.json"))
    analysis = run_analysis([os.path.join(syn_dir, "eml")], cfg, dns)
    analysis["source"] = "data/synthetic/eml"
    with open(os.path.join(syn_dir, "ground_truth.json"), encoding="utf-8") as fh:
        truth = json.load(fh)
    ev = evaluate(analysis["messages"], truth)
    reports = os.path.join(root, "reports")
    write_reports(analysis, reports)
    with open(os.path.join(reports, "evaluation.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(ev, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    with open(os.path.join(reports, "evaluation.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(evaluation_md(ev))
    raw = {}
    for label, data in collect([os.path.join(syn_dir, "eml")]):
        raw[label] = data.decode("ascii")
    with open(os.path.join(syn_dir, "dns_fixtures.json"), encoding="utf-8") as fh:
        dns_raw = json.load(fh)
    write_dashboard_data(analysis, ev, cfg, raw, dns_raw, os.path.join(root, "dashboard", "data"))
    _print_table(analysis, out)
    o = ev["overall"]
    out.write(f"Evaluation vs ground truth (synthetic, self-authored): exact verdict {o['exact']}/{o['messages']}, "
              f"flagged-vs-benign precision {o['flagged_vs_benign']['precision']} recall {o['flagged_vs_benign']['recall']}\n")
    return 0


def main(argv: Optional[List[str]] = None, out=None) -> int:
    out = out or sys.stdout
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "validate-config":
            load_config(args.path)
            out.write(f"{args.path}: OK\n")
            return 0
        if args.cmd == "generate":
            from .synthetic import write_corpus
            gt = write_corpus(args.out)
            out.write(f"wrote {len(gt['messages'])} SYNTHETIC messages to {args.out}\n")
            return 0
        if args.cmd == "demo":
            return cmd_demo(args.root, out)
        cfg = load_config(args.config)
        if args.cmd == "list-indicators":
            for i in sorted(cfg["indicators"], key=lambda x: (x["category"], -x["weight"], x["id"])):
                out.write(f"{i['category']:10s} {i['id']:32s} {i['weight']:4d}  {i['severity']:8s} {','.join(i['mitre']) or '-'}\n")
            return 0
        dns = load_dns(getattr(args, "dns", None))
        if args.cmd == "explain":
            analysis = run_analysis([args.path], cfg, dns)
            if len(analysis["messages"]) != 1:
                out.write("explain needs exactly one message\n")
                return 1
            out.write(incident_md(analysis["messages"][0]))
            return 0
        analysis = run_analysis(args.paths, cfg, dns)
        if args.cmd == "evaluate":
            with open(args.truth, encoding="utf-8") as fh:
                truth = json.load(fh)
            ev = evaluate(analysis["messages"], truth)
            out.write(evaluation_md(ev))
            return 0
        if args.out:
            write_reports(analysis, args.out)
        if args.json:
            out.write(json.dumps(analysis, indent=1, ensure_ascii=False) + "\n")
        else:
            _print_table(analysis, out)
        if args.fail_on and any(r["verdict"] in LEVELS[args.fail_on] for r in analysis["messages"]):
            return 2
        return 0
    except (ConfigError, FileNotFoundError, json.JSONDecodeError, OSError) as e:
        sys.stderr.write(f"error: {e}\n")
        return 1
