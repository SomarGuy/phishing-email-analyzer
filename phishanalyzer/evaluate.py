"""Compare analysis results with ground_truth.json. The labels were written by the same author as the corpus: see README caveat."""
from __future__ import annotations

from typing import Dict, List, Optional

LABEL_TO_VERDICT = {"benign": "benign", "suspicious": "suspicious", "phishing": "likely_phishing"}
VERDICTS = ["benign", "suspicious", "likely_phishing"]


def _ratio(a: int, b: int) -> Optional[float]:
    return round(a / b, 4) if b else None


def _score_set(rows: List[dict]) -> dict:
    cm = {t: {p: 0 for p in VERDICTS} for t in VERDICTS}
    for r in rows:
        cm[r["truth"]][r["verdict"]] += 1
    n = len(rows)
    exact = sum(1 for r in rows if r["truth"] == r["verdict"])
    tp = sum(1 for r in rows if r["truth"] != "benign" and r["verdict"] != "benign")
    fn = sum(1 for r in rows if r["truth"] != "benign" and r["verdict"] == "benign")
    fp = sum(1 for r in rows if r["truth"] == "benign" and r["verdict"] != "benign")
    tn = sum(1 for r in rows if r["truth"] == "benign" and r["verdict"] == "benign")
    phish = [r for r in rows if r["truth"] == "likely_phishing"]
    exp_total = sum(len(r["expected"]) for r in rows)
    exp_hit = sum(len(r["expected"]) - len(r["missing"]) for r in rows)
    return {"messages": n, "exact_accuracy": _ratio(exact, n), "exact": exact, "confusion": cm,
            "flagged_vs_benign": {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": _ratio(tp, tp + fp), "recall": _ratio(tp, tp + fn), "false_positive_rate": _ratio(fp, fp + tn)},
            "phishing_caught_as_likely_phishing": {"caught": sum(1 for r in phish if r["verdict"] == "likely_phishing"), "of": len(phish)},
            "expected_indicators": {"hit": exp_hit, "of": exp_total, "rate": _ratio(exp_hit, exp_total)},
            "forbidden_indicator_violations": sum(len(r["violations"]) for r in rows)}


def evaluate(results: List[dict], truth: dict) -> dict:
    by_id = {r["id"]: r for r in results}
    rows: List[dict] = []
    unmatched = []
    for m in truth["messages"]:
        r = by_id.get(m["id"])
        if r is None:
            unmatched.append(m["id"])
            continue
        ids = {i["id"] for i in r["indicators"] if i["points"] > 0}
        fired_any = {i["id"] for i in r["indicators"]}
        rows.append({"id": m["id"], "set": m.get("set", "tuning"), "category": m["category"], "truth": LABEL_TO_VERDICT[m["label"]], "verdict": r["verdict"], "score": r["score"],
                     "expected": m["expect"], "missing": [x for x in m["expect"] if x not in fired_any], "violations": [x for x in m["forbid"] if x in ids],
                     "correct": LABEL_TO_VERDICT[m["label"]] == r["verdict"], "description": m["description"]})
    sets = sorted({r["set"] for r in rows})
    out = {"synthetic": True, "ground_truth_notice": truth.get("notice", ""), "messages_in_truth": len(truth["messages"]), "unmatched": unmatched,
           "overall": _score_set(rows), "by_set": {s: _score_set([r for r in rows if r["set"] == s]) for s in sets},
           "rows": rows, "errors": [r for r in rows if not r["correct"] or r["missing"] or r["violations"]]}
    return out


def evaluation_md(ev: dict) -> str:
    def line(name: str, s: dict) -> str:
        f = s["flagged_vs_benign"]
        return (f"| {name} | {s['messages']} | {s['exact']}/{s['messages']} | {f['tp']} | {f['fp']} | {f['fn']} | {f['tn']} | "
                f"{f['precision']} | {f['recall']} | {s['expected_indicators']['hit']}/{s['expected_indicators']['of']} | {s['forbidden_indicator_violations']} |")
    L = ["# Evaluation against ground_truth.json", "", "**Caveat:** the corpus and its labels were written by the same person who wrote the detector. This measures regressions and whether the heuristics do what they claim, not real-world accuracy.", "",
         "| Set | Messages | Exact verdict | TP | FP | FN | TN | Precision | Recall | Expected indicators | Forbidden hits |", "|---|---|---|---|---|---|---|---|---|---|---|"]
    for name, s in ev["by_set"].items():
        L.append(line(name, s))
    L.append(line("all", ev["overall"]))
    L.append("")
    if ev["errors"]:
        L.append("## Misses and surprises")
        L.append("")
        for r in ev["errors"]:
            bits = []
            if not r["correct"]:
                bits.append(f"verdict {r['verdict']} (score {r['score']}), expected {r['truth']}")
            if r["missing"]:
                bits.append("expected indicators not fired: " + ", ".join(r["missing"]))
            if r["violations"]:
                bits.append("forbidden indicators fired: " + ", ".join(r["violations"]))
            L.append(f"- `{r['id']}` ({r['category']}): " + "; ".join(bits))
    return "\n".join(L) + "\n"
