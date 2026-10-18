"""Static attachment analysis. Content is hashed and inspected as bytes only: never executed, opened or extracted."""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from typing import Dict, List, Optional

from .models import Finding
from .textutil import analyze_html

RLO = "\u202e"
_BIDI = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"

EXPECTED = {
    "pdf": {"pdf"}, "docx": {"zip"}, "xlsx": {"zip"}, "pptx": {"zip"}, "docm": {"zip"}, "xlsm": {"zip"}, "pptm": {"zip"}, "zip": {"zip"},
    "doc": {"ole", "rtf"}, "xls": {"ole"}, "ppt": {"ole"}, "rtf": {"rtf"}, "png": {"png"}, "jpg": {"jpg"}, "jpeg": {"jpg"}, "gif": {"gif"},
    "rar": {"rar"}, "7z": {"7z"}, "txt": {"text"}, "csv": {"text"}, "exe": {"pe"}, "dll": {"pe"},
}
BINARY_DANGEROUS = ("pe", "elf", "lnk")


def sniff(data: bytes) -> str:
    """Detect a coarse file type from magic bytes."""
    h = data[:16]
    if h[:2] == b"MZ":
        return "pe"
    if h[:5] == b"%PDF-":
        return "pdf"
    if h[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if h[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if h[:4] == b"Rar!":
        return "rar"
    if h[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if h[:4] == b"\x7fELF":
        return "elf"
    if h[:4] == b"\x4c\x00\x00\x00" and data[4:8] == b"\x01\x14\x02\x00":
        return "lnk"
    if h[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if h[:3] == b"\xff\xd8\xff":
        return "jpg"
    if h[:4] == b"GIF8":
        return "gif"
    if h[:5] == b"{\\rtf":
        return "rtf"
    if len(data) > 0x8005 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    head = data[:2048].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if head.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<script", b"<meta", b"<form", b"<a ", b"<div")):
        return "html"
    if head.startswith((b"<svg", b"<?xml")) and b"<svg" in data[:4096].lower():
        return "svg"
    if head.startswith(b"#!"):
        return "script"
    if data and all(b in (9, 10, 13) or 32 <= b < 127 or b >= 128 for b in data[:512]) and b"\x00" not in data[:512]:
        return "text"
    return "unknown"


def split_name(name: str):
    """(clean name without bidi controls, [extensions], had_bidi)."""
    had = any(c in name for c in _BIDI)
    clean = "".join(c for c in name if c not in _BIDI)
    base = clean.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    parts = base.split(".")
    exts = [p.lower() for p in parts[1:] if p] if len(parts) > 1 else []
    return base, exts, had


def _zip_info(data: bytes) -> Optional[dict]:
    """Central directory only. Entry bytes are never read or decompressed."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except (zipfile.BadZipFile, ValueError, OSError):
        return None
    entries = [{"name": i.filename, "size": i.file_size, "encrypted": bool(i.flag_bits & 0x1)} for i in infos[:500]]
    return {"entries": entries, "count": len(infos), "encrypted": any(e["encrypted"] for e in entries)}


def _ole_has_vba(data: bytes) -> bool:
    return b"_VBA_PROJECT" in data or b"V\x00B\x00A\x00" in data or b"Attribut\x00e VB_Name" in data or b"Attribute VB_Name" in data


def analyze_html_payload(text: str) -> dict:
    low = text.lower()
    smug = []
    if re.search(r"new\s+blob\s*\(", low):
        smug.append("builds a Blob in the browser")
    if "createobjecturl" in low or "mssaveoropenblob" in low or "mssaveblob" in low:
        smug.append("saves it via createObjectURL / msSaveOrOpenBlob")
    if re.search(r"\batob\s*\(", low) or "uint8array" in low:
        smug.append("decodes embedded base64 (atob / Uint8Array)")
    if re.search(r"\.download\s*=|download\s*=\s*[\"']", low):
        smug.append("sets a download file name")
    if re.search(r"\.click\s*\(", low):
        smug.append("clicks it programmatically")
    big_b64 = bool(re.search(r"[A-Za-z0-9+/=]{400,}", text))
    if big_b64:
        smug.append("contains a large base64 blob")
    if re.search(r"\beval\s*\(|\bunescape\s*\(|fromcharcode", low):
        smug.append("uses eval/unescape/fromCharCode obfuscation")
    h = analyze_html(text)
    form_hosts = [m.group(1).lower() for m in re.finditer(r"<form[^>]*\baction\s*=\s*[\"']?https?://([^/\"'\s>:]+)", low)]
    return {"smuggling": smug, "password_form": bool(h["password_input"]), "form_hosts": form_hosts}


def analyze_attachment(part, cfg: dict, body_text: str) -> dict:
    lists = cfg["lists"]
    data = part.data
    base, exts, had_bidi = split_name(part.filename)
    ext = exts[-1] if exts else ""
    kind = sniff(data)
    flags: List[dict] = []

    def flag(i: str, detail: str) -> None:
        flags.append({"id": i, "detail": detail})

    sha256 = hashlib.sha256(data).hexdigest()
    rec = {"filename": part.filename, "display_name": base, "content_type": part.content_type, "size": len(data), "extension": ext,
           "detected_type": kind, "md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(), "sha256": sha256,
           "flags": flags, "archive": None, "notes": []}
    exe_exts = set(lists["executable_exts"])
    if ext in exe_exts or kind in BINARY_DANGEROUS or kind == "script":
        flag("attachment_executable", f"{base} is a {'file of type .' + ext if ext in exe_exts else 'detected ' + kind + ' file'} that can run code")
    if had_bidi:
        flag("attachment_rtl_override", f"File name contains a right-to-left override; it is displayed differently from its real name '{base}'")
    # extension vs content
    expect = EXPECTED.get(ext)
    mism = ""
    if kind in BINARY_DANGEROUS and ext not in exe_exts:
        mism = f"content is {kind} but name ends in .{ext or '(none)'}"
    elif expect is not None and kind != "unknown" and kind not in expect and not (ext in ("txt", "csv") and kind in ("html", "script", "svg")):
        mism = f"name says .{ext} but the content is {kind}"
    elif ext in ("txt", "csv") and kind in ("html", "script", "svg"):
        mism = f"name says .{ext} but the content is {kind}"
    if mism:
        flag("attachment_magic_mismatch", mism)
    if len(exts) >= 2 and exts[-2] in set(lists["decoy_exts"]) and (exts[-1] in exe_exts or exts[-1] in set(lists["html_exts"]) or exts[-1] in set(lists["macro_exts"])):
        flag("attachment_double_extension", f"'{base}' pretends to be .{exts[-2]} but really ends in .{exts[-1]}")
    # macros
    if ext in set(lists["macro_exts"]):
        flag("attachment_macro", f".{ext} is a macro-enabled Office format")
    elif kind == "ole" and ext in set(lists["ole_exts"]) and _ole_has_vba(data):
        flag("attachment_macro", "Legacy Office file contains a VBA project")
    elif kind == "zip":
        zi = _zip_info(data)
        if zi and any(e["name"].lower().endswith("vbaproject.bin") for e in zi["entries"]):
            flag("attachment_macro", "Office Open XML package contains vbaProject.bin")
    # archives
    if kind == "zip" or ext in ("zip",):
        zi = _zip_info(data) if kind == "zip" else None
        if zi:
            rec["archive"] = {"format": "zip", "count": zi["count"], "encrypted": zi["encrypted"], "entries": zi["entries"][:20]}
            office = any(e["name"] in ("[Content_Types].xml",) for e in zi["entries"])
            if not office:
                bad = []
                for e in zi["entries"]:
                    n, es, _ = split_name(e["name"])
                    if es and (es[-1] in exe_exts or es[-1] in set(lists["macro_exts"])):
                        bad.append(e["name"])
                if bad:
                    flag("archive_contains_executable", f"Archive contains {', '.join(bad[:3])}{' ...' if len(bad) > 3 else ''}")
            if zi["encrypted"]:
                flag("archive_encrypted", "Archive entries are password-protected, which hides content from mail scanners")
    elif kind in ("rar", "7z"):
        rec["notes"].append(f"{kind} contents are not inspected by this tool")
    # html / svg payloads
    if kind in ("html", "svg") or ext in set(lists["html_exts"]):
        text = data[:2_000_000].decode("utf-8", errors="replace")
        is_svg = kind == "svg" or ext == "svg"
        pay = analyze_html_payload(text)
        if is_svg:
            low = text.lower()
            if "<script" in low or re.search(r"\bon(load|click|mouseover)\s*=", low) or "javascript:" in low:
                flag("svg_script", "SVG image contains script or event handlers")
        else:
            flag("html_attachment", "HTML attachment opens in the user's browser with local-file privileges")
            if len(pay["smuggling"]) >= 2:
                flag("html_smuggling", "HTML smuggling indicators: " + "; ".join(pay["smuggling"][:5]))
            if pay["password_form"]:
                host = f" posting to {pay['form_hosts'][0]}" if pay["form_hosts"] else ""
                flag("html_credential_form", f"HTML attachment contains a password field{host}")
        rec["html"] = pay
    # pdf
    if kind == "pdf":
        raw = data.decode("latin-1")
        hits = [t for t in ("/JavaScript", "/JS", "/OpenAction", "/Launch", "/EmbeddedFile", "/AA") if re.search(re.escape(t) + r"(?![A-Za-z])", raw)]
        if hits:
            flag("pdf_active_content", "PDF contains " + ", ".join(hits))
    if sha256 in {h.lower() for h in cfg["known_bad_sha256"]}:
        flag("attachment_known_bad", f"SHA-256 matches a known-bad sample ({cfg['known_bad_sha256'][sha256] if isinstance(cfg['known_bad_sha256'], dict) else 'list'})")
    return rec


_PW_HINT = re.compile(r"pass(?:word|code)\s*(?:to (?:open|unlock|extract)[^:.\n]{0,20})?\s*(?:is|:|=)\s*[:\"'\-]?\s*\S{3,}", re.I)


def analyze_attachments(pe, cfg: dict, visible_html_text: str = ""):
    body = (pe.text or "") + "\n" + visible_html_text
    recs = [analyze_attachment(p, cfg, body) for p in pe.attachments]
    has_archive = any(r["archive"] is not None or r["extension"] in ("zip", "rar", "7z") for r in recs)
    hint = _PW_HINT.search(body) if has_archive else None
    if hint:
        for r in recs:
            if r["archive"] is not None or r["extension"] in ("zip", "rar", "7z"):
                r["flags"].append({"id": "archive_password_hint", "detail": "Message text gives a password for the attachment: '" + hint.group(0)[:60] + "'"})
                break
    by_id: Dict[str, List[str]] = {}
    details: Dict[str, str] = {}
    for r in recs:
        for f in r["flags"]:
            by_id.setdefault(f["id"], []).append(f"{r['display_name']}: {f['detail']}")
            details.setdefault(f["id"], f["detail"])
    findings = [Finding(i, details[i] + (f" (+{len(ev) - 1} more)" if len(ev) > 1 else ""), ev) for i, ev in by_id.items()]
    return recs, findings
