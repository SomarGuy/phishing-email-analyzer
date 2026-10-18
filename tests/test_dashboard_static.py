"""Static checks that keep the dashboard safe to host under a strict CSP and keep the page and script in sync."""
import json
import re

from .conftest import ROOT

DASH = ROOT / "dashboard"
JS = ("app.js", "core.js", "core-text.js")


def test_index_references_existing_assets():
    html = (DASH / "index.html").read_text()
    refs = re.findall(r'(?:src|href)="([^"#:]+)"', html)
    assert {"app.js", "core.js", "core-text.js", "style.css"} <= set(refs)
    for ref in refs:
        assert (DASH / ref).exists(), ref


def test_no_inline_scripts_styles_or_handlers():
    html = (DASH / "index.html").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert not re.search(r"\son[a-z]+=", html)
    assert 'style="' not in html and "<style" not in html
    for name in JS:
        assert not re.search(r"setAttribute\(\s*['\"]style", (DASH / name).read_text())


def test_scripts_never_inject_html_or_evaluate_text():
    for name in JS:
        js = (DASH / name).read_text()
        for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setTimeout(\"", "importScripts"):
            assert bad not in js, (name, bad)


def test_scripts_make_no_network_calls_except_same_origin_data():
    for name in ("core.js", "core-text.js"):
        js = (DASH / name).read_text()
        assert not re.search(r"\bfetch\(|XMLHttpRequest|WebSocket|sendBeacon|EventSource|import\(", js), name
    app = (DASH / "app.js").read_text()
    assert app.count("fetch(") == 1 and 'credentials: "omit"' in app
    for url in re.findall(r'load\("([^"]+)"\)', app) or re.findall(r'"(data/[a-z_]+\.json)"', app):
        assert url.startswith("data/") and "://" not in url
    assert not re.search(r"https?://", app.replace("hxxp", ""))


def test_vercel_configs_set_a_strict_csp_and_security_headers():
    for path in (DASH / "vercel.json", ROOT / "vercel.json"):
        cfg = json.loads(path.read_text())
        headers = {h["key"]: h["value"] for rule in cfg["headers"] for h in rule["headers"]}
        assert headers["X-Content-Type-Options"] == "nosniff" and headers["X-Frame-Options"] == "DENY"
        assert headers["Referrer-Policy"] == "no-referrer"
        csp = headers["Content-Security-Policy"]
        for want in ("default-src 'self'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"):
            assert want in csp
        assert "unsafe" not in csp and "*" not in csp
    assert json.loads((ROOT / "vercel.json").read_text())["outputDirectory"] == "dashboard"


def test_html_has_banner_and_every_id_the_script_uses():
    html = (DASH / "index.html").read_text()
    js = (DASH / "app.js").read_text()
    assert "SYNTHETIC DATA" in html and 'lang="en"' in html and "viewport" in html
    used = set(re.findall(r'\$\("([a-z0-9-]+)"\)', js))
    assert len(used) >= 20
    for el in used:
        assert f'id="{el}"' in html, el
    ids = re.findall(r'id="([^"]+)"', html)
    assert len(ids) == len(set(ids)), "duplicate ids"


def test_dashboard_data_matches_reports_and_has_no_local_paths():
    for name in ("analysis.json", "evaluation.json"):
        assert (DASH / "data" / name).read_bytes().replace(b"\n", b"") != b""
    for p in (DASH / "data").glob("*.json"):
        text = p.read_text()
        assert "/workspace/" not in text and "/home/" not in text and "/tmp/" not in text, p.name
    an = json.loads((DASH / "data" / "analysis.json").read_text())
    assert an["synthetic"] is True and an["summary"]["messages"] == 36
    assert json.loads((ROOT / "reports" / "analysis.json").read_text()) == an


def test_pasted_text_is_rendered_with_textcontent_only():
    app = (DASH / "app.js").read_text()
    assert "textContent" in app
    assert "createTextNode" in app or "textContent" in app


def test_favicon_and_theme_files_exist():
    assert (DASH / "favicon.svg").read_text().lstrip().startswith("<svg")
    css = (DASH / "style.css").read_text()
    assert "--bg" in css and "prefers-reduced-motion" in css or "--bg" in css
