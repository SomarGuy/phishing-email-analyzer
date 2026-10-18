"""Load and validate the indicator/weight configuration."""
from __future__ import annotations

import json
import os
import re
from typing import Dict

DEFAULT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "phish_config.json")
CATEGORIES = ("header", "auth", "url", "attachment", "language", "combo", "mitigation")
SEVERITIES = ("info", "low", "medium", "high", "critical")
REQUIRED_TOP = ("organisation", "thresholds", "category_caps", "multi_label_suffixes", "lists", "language", "known_bad_sha256", "mitre", "generic_response", "indicators")
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class ConfigError(ValueError):
    pass


def load_config(path: str = DEFAULT_PATH) -> dict:
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    validate(cfg)
    cfg["_by_id"] = {i["id"]: i for i in cfg["indicators"]}
    return cfg


def validate(cfg: dict) -> None:
    for k in REQUIRED_TOP:
        if k not in cfg:
            raise ConfigError(f"missing config key: {k}")
    th = cfg["thresholds"]
    if not (0 < th["suspicious"] < th["phishing"] <= 100):
        raise ConfigError("thresholds must satisfy 0 < suspicious < phishing <= 100")
    seen: Dict[str, bool] = {}
    for ind in cfg["indicators"]:
        for f in ("id", "category", "weight", "severity", "mitre", "title", "description", "response"):
            if f not in ind:
                raise ConfigError(f"indicator {ind.get('id', '?')} lacks '{f}'")
        if ind["id"] in seen:
            raise ConfigError(f"duplicate indicator id {ind['id']}")
        seen[ind["id"]] = True
        if ind["category"] not in CATEGORIES:
            raise ConfigError(f"{ind['id']}: unknown category {ind['category']}")
        if ind["severity"] not in SEVERITIES:
            raise ConfigError(f"{ind['id']}: unknown severity {ind['severity']}")
        if (ind["category"] == "mitigation") != (ind["weight"] < 0):
            raise ConfigError(f"{ind['id']}: only mitigations may have a negative weight")
        for t in ind["mitre"]:
            if not MITRE_RE.match(t):
                raise ConfigError(f"{ind['id']}: bad ATT&CK id {t}")
            if t not in cfg["mitre"]:
                raise ConfigError(f"{ind['id']}: ATT&CK id {t} has no name in config.mitre")
    for cat in CATEGORIES:
        if cat not in ("mitigation",) and cat not in cfg["category_caps"]:
            raise ConfigError(f"no cap for category {cat}")
    for b in cfg["lists"]["brands"]:
        for f in ("name", "label", "domains"):
            if f not in b:
                raise ConfigError(f"brand lacks {f}")
    for v in cfg["language"].values():
        for p in v:
            try:
                re.compile(p)
            except re.error as e:
                raise ConfigError(f"bad language regex {p!r}: {e}")
