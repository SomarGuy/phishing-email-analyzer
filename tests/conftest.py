import json
from pathlib import Path

import pytest

from phishanalyzer import synthetic
from phishanalyzer.analyzer import analyze_message
from phishanalyzer.config import load_config

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def cfg():
    return load_config()


@pytest.fixture(scope="session")
def dns():
    return synthetic.DNS_FIXTURES["domains"]


@pytest.fixture(scope="session")
def corpus():
    return synthetic.build_corpus()


@pytest.fixture(scope="session")
def truth(corpus):
    return synthetic.ground_truth(corpus)


@pytest.fixture(scope="session")
def results(corpus, cfg, dns):
    return {e["id"]: analyze_message(e["bytes"], cfg, dns, e["id"]) for e in corpus}


@pytest.fixture(scope="session")
def synth_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("synth") / "synthetic"
    synthetic.write_corpus(str(d))
    return d


def build(headers, text=None, html=None, atts=()):
    """Tiny helper for unit tests: assemble an .eml from (name, value) pairs."""
    from phishanalyzer.synthbuild import build_eml
    return build_eml(headers, text, html, atts)


def ids(res, points_only=False):
    return {i["id"] for i in res["indicators"] if (i["points"] > 0 or not points_only)}


STD = [("From", "Sam <sam@example.com>"), ("To", "you@example.net"), ("Subject", "hi"), ("Date", "Mon, 02 Mar 2026 10:00:00 +0000"), ("Message-ID", "<1@example.com>")]


def run(cfg, headers=None, text="hello\n", html=None, atts=(), dns=None):
    h = list(headers if headers is not None else STD)
    return analyze_message(build(h, text, html, atts), cfg, dns, "t")
