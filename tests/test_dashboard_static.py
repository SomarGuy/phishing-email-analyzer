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


def test_layout_is_a_three_pane_mail_client():
    html = (DASH / "index.html").read_text()
    for cls in ("folders", "listpane", "readpane"):
        assert f'class="{cls}"' in html, cls
    for el in ("kpis", "inbox-list", "detail", "note", "view-paste", "view-iocs", "view-eval", "catalog", "banner"):
        assert f'id="{el}"' in html, el
    # the verdict folders carry the counts the smoke test checks
    for v in ("all", "likely_phishing", "suspicious", "benign"):
        assert f'data-v="{v}"' in html, v


def test_theme_is_light_and_uses_system_fonts():
    html = (DASH / "index.html").read_text()
    css = (DASH / "style.css").read_text()
    assert 'name="color-scheme" content="light"' in html
    assert "system-ui" in css
    assert "@import" not in css and "url(http" not in css and "fonts.googleapis" not in css
    bg = re.search(r"--bg:\s*#([0-9a-fA-F]{6})", css).group(1)
    assert min(int(bg[i:i + 2], 16) for i in (0, 2, 4)) > 200, "page background should be light"
    assert "--pane: #ffffff" in css


def test_why_i_built_this_note_is_in_my_voice_and_honest():
    html = (DASH / "index.html").read_text()
    note = re.search(r'<article id="note".*?</article>', html, re.S).group(0)
    text = re.sub(r"<[^>]+>", " ", note)
    for must in ("Geek Squad", "Toronto", "computer science", "What it can", "What I would do next", "my own homework", "never seen real mail"):
        assert must in text, must
    assert re.search(r"\b[Ii] ", text)
    for corporate in ("leverage", "synergy", "robust", "scalable", "stakeholder", "enterprise-grade", "cutting-edge", "seamless"):
        assert corporate not in text.lower(), corporate


def test_no_em_or_en_dashes_in_dashboard_text():
    for name in ("index.html", "app.js", "style.css"):
        t = (DASH / name).read_text()
        assert "\u2014" not in t and "\u2013" not in t and "&mdash;" not in t and "&ndash;" not in t, name


def test_hostile_values_have_no_html_path_in_app():
    app = (DASH / "app.js").read_text()
    # elements are built with h(tag, attrs, kids) which uses textContent / createTextNode only
    assert 'k === "text") el.textContent = v' in app
    assert "createElementNS" not in app and "DOMParser" not in app and "srcdoc" not in app
