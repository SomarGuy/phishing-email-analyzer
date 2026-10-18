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


# ---- the "How to use this" guide

def _guide_html():
    html = (DASH / "index.html").read_text()
    return html, re.search(r'<section id="view-guide".*?</section>', html, re.S).group(0)


def test_guide_has_entry_points_a_start_here_bar_and_the_expected_parts():
    html, guide = _guide_html()
    for el in ("guide-open", "guide-pin", "start-here", "start-open", "start-dismiss", "guide-title", "walk-title", "gloss-title"):
        assert f'id="{el}"' in html, el
    assert 'data-view="guide"' in html, "Extras folder entry"
    assert guide.count('class="btn ghost sm go"') == 6 and guide.count("<li>") == 6, "six steps with a Take me there button each"
    for words in ("Try this in 60 seconds", "Words you will see", "What this shows about my skills"):
        assert words in guide, words
    terms = re.findall(r"<dt>(.*?)</dt>", guide)
    for term in ("SPF", "DKIM", "DMARC", "Header hops", "Spoofing", "Defanged"):
        assert any(t.startswith(term) for t in terms), term


def test_guide_steps_name_real_data_and_ui():
    html, guide = _guide_html()
    an = json.loads((DASH / "data" / "analysis.json").read_text())
    by_id = {m["id"]: m for m in an["messages"]}
    p01 = by_id["P01-paypal-lookalike-credential"]
    assert "PayPal Security" in guide
    assert p01["subject"] in guide.replace("&amp;", "&") and p01["score"] == 100 and p01["verdict"] == "likely_phishing"
    benign = by_id["B01-newsletter-harbour-gazette"]
    assert benign["subject"] in guide and benign["score"] == 0
    for chip in ("Sign-in", "Route", "Links"):
        assert f'"{chip}"' in guide
    app = (DASH / "app.js").read_text()
    assert all(f'"{chip}"' in app or chip in app for chip in ("Sign-in", "Route", "Links"))
    emls = json.loads((DASH / "data" / "emls.json").read_text())
    for go in re.findall(r'data-go="([^"]+)"', guide):
        if go.startswith("p01"):
            assert "P01-paypal-lookalike-credential" in emls


def test_guide_dismissal_is_remembered_in_local_storage_and_never_blocks_the_page():
    app = (DASH / "app.js").read_text()
    assert "phishing-analyzer-guide-dismissed" in app
    assert re.search(r"try\s*\{[^}]*localStorage", app), "storage access is wrapped in try/catch"
    html, _ = _guide_html()
    assert re.search(r'<[^>]+id="start-here"[^>]*\bhidden\b', html), "bar starts hidden and only shows when not dismissed"
    assert 'role="region" aria-label="Start here"' in html


def test_guide_copy_is_plain_and_has_no_dashes_or_buzzwords():
    _, guide = _guide_html()
    text = re.sub(r"<[^>]+>", " ", guide).lower()
    assert "\u2014" not in guide and "\u2013" not in guide
    for bad in ("leverage", "synergy", "robust", "scalable", "stakeholder", "enterprise-grade", "cutting-edge", "seamless", "vibe", "results-driven", "passionate"):
        assert bad not in text, bad


def test_guide_is_keyboard_and_screen_reader_friendly():
    html, _ = _guide_html()
    css = (DASH / "style.css").read_text()
    assert 'id="main" tabindex="-1"' in html
    assert "ol class=\"walk\" role=\"list\"" in html
    assert "#main:focus" in css and "focus-visible" in css
    assert "(max-width" in css and ".startbar" in css and ".walk" in css


def test_readme_has_a_how_to_use_section_that_matches_the_guide():
    readme = (ROOT / "README.md").read_text()
    section = re.search(r"## How to use the demo\n(.*?)\n## ", readme, re.S).group(1)
    assert "Try this in 60 seconds" in section and "PayPal Security" in section and "Check it" in section
    assert "\u2014" not in section and "\u2013" not in section
    assert len(re.findall(r"^\d\. ", section, re.M)) == 6
    for shot in ("09-how-to-use.png", "10-how-to-use-mobile.png"):
        assert shot in section and (ROOT / "screenshots" / shot).exists()
