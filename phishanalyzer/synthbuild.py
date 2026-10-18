"""Low-level builders for the synthetic corpus: deterministic MIME assembly, inert attachment payloads, ZipCrypto.

Everything here produces SYNTHETIC test data. Payloads are inert text stubs with the right magic bytes; nothing is
executable, no macro is real, and every domain/IP is reserved for documentation (example.*, .test, .invalid, RFC 5737).
"""
from __future__ import annotations

import base64
import binascii
import datetime as _dt
import random
import struct
import zipfile
import zlib
import io
from typing import List, Optional, Sequence, Tuple

ORG_DOMAIN = "northwind-analytics.example"
RCPT = f"alex.morgan@{ORG_DOMAIN}"
WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def rfc_date(day: int, hh: int, mm: int, ss: int = 0, tz: str = "+0000", month: int = 3) -> str:
    d = _dt.date(2026, month, day)
    return f"{WEEKDAYS[d.weekday()]}, {day:02d} {MONTHS[month - 1]} 2026 {hh:02d}:{mm:02d}:{ss:02d} {tz}"


def b64_lines(data: bytes) -> str:
    s = base64.b64encode(data).decode("ascii")
    return "\r\n".join(s[i:i + 76] for i in range(0, len(s), 76))


def enc_word(s: str) -> str:
    if all(ord(c) < 128 for c in s):
        return s
    return "=?utf-8?B?" + base64.b64encode(s.encode("utf-8")).decode("ascii") + "?="


def fold(name: str, value: str) -> str:
    """Fold a header at whitespace so no physical line exceeds ~76 chars (parsers must unfold)."""
    line = f"{name}: {value}"
    if len(line) <= 76:
        return line
    out, cur = [], ""
    for w in line.split(" "):
        if cur and len(cur) + 1 + len(w) > 76:
            out.append(cur)
            cur = " " + w
        else:
            cur = (cur + " " + w) if cur else w
    out.append(cur)
    return "\r\n".join(out)


class Att:
    def __init__(self, filename: str, data: bytes, ctype: str = "application/octet-stream", inline_cid: str = ""):
        self.filename, self.data, self.ctype, self.cid = filename, data, ctype, inline_cid


def _text_part(ctype: str, body: str) -> str:
    if all(ord(c) < 128 for c in body):
        return f"Content-Type: {ctype}; charset=us-ascii\r\nContent-Transfer-Encoding: 7bit\r\n\r\n" + body.replace("\n", "\r\n")
    return f"Content-Type: {ctype}; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" + b64_lines(body.encode("utf-8"))


def build_eml(headers: Sequence[Tuple[str, str]], text: Optional[str] = None, html: Optional[str] = None, atts: Sequence[Att] = ()) -> bytes:
    head = [fold(k, v) for k, v in headers] + ["MIME-Version: 1.0"]
    bmix, balt = "=_synthetic_mixed_7f3a", "=_synthetic_alt_7f3a"
    if text is not None and html is not None:
        body_ctype = f'multipart/alternative; boundary="{balt}"'
        body = (f"--{balt}\r\n" + _text_part("text/plain", text) + f"\r\n--{balt}\r\n" + _text_part("text/html", html) + f"\r\n--{balt}--\r\n")
    elif html is not None:
        body_ctype, body = None, _text_part("text/html", html)
    else:
        body_ctype, body = None, _text_part("text/plain", text or "")
    if not atts:
        if body_ctype:
            head.append(f"Content-Type: {body_ctype}")
            return ("\r\n".join(head) + "\r\n\r\n" + body).encode("ascii")
        return ("\r\n".join(head) + "\r\n" + body + "\r\n").encode("ascii")
    head.append(f'Content-Type: multipart/mixed; boundary="{bmix}"')
    parts = [f"--{bmix}\r\n" + (f"Content-Type: {body_ctype}\r\n\r\n{body}" if body_ctype else body)]
    for a in atts:
        name = enc_word(a.filename)
        disp = "inline" if a.cid else "attachment"
        cid = f"Content-ID: <{a.cid}>\r\n" if a.cid else ""
        parts.append(f'--{bmix}\r\nContent-Type: {a.ctype}; name="{name}"\r\nContent-Transfer-Encoding: base64\r\n{cid}Content-Disposition: {disp}; filename="{name}"\r\n\r\n{b64_lines(a.data)}')
    return ("\r\n".join(head) + "\r\n\r\n" + "\r\n".join(parts) + f"\r\n--{bmix}--\r\n").encode("ascii")


# ------------------------------------------------------------------------------------------------ inert payloads
def pdf_clean(title: str = "Synthetic sample") -> bytes:
    return (f"%PDF-1.4\n% SYNTHETIC SAMPLE: {title}\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n").encode()


def exe_stub(label: str) -> bytes:
    return b"MZ\x90\x00" + b"This program cannot be run in DOS mode.\r\n" + f"SYNTHETIC INERT TEST STUB ({label}). NOT A PROGRAM.".encode() + b"\x00" * 32


def png_tiny() -> bytes:
    def chunk(t: bytes, d: bytes) -> bytes:
        c = struct.pack(">I", len(d)) + t + d
        return c + struct.pack(">I", binascii.crc32(t + d) & 0xFFFFFFFF)
    raw = zlib.compress(b"\x00\xff\xff\xff")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)) + chunk(b"IDAT", raw) + chunk(b"IEND", b"")


def make_zip(entries: Sequence[Tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, data in entries:
            zi = zipfile.ZipInfo(name, date_time=(2026, 3, 1, 0, 0, 0))
            zi.external_attr = 0o600 << 16
            zf.writestr(zi, data)
    return buf.getvalue()


def make_ooxml(kind: str, with_macro: bool) -> bytes:
    ents = [("[Content_Types].xml", b"<Types>SYNTHETIC</Types>"), ("_rels/.rels", b"<Relationships/>"), (f"{kind}/document.xml", b"<doc>SYNTHETIC SAMPLE</doc>")]
    if with_macro:
        ents.append((f"{kind}/vbaProject.bin", b"SYNTHETIC INERT PLACEHOLDER - NOT A REAL VBA PROJECT"))
    return make_zip(ents)


# ZipCrypto (legacy PKWARE encryption): enough to build a genuinely password-protected archive that we never open.
_CRC = [0] * 256
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if _c & 1 else _c >> 1
    _CRC[_i] = _c


def _crc32_update(crc: int, b: int) -> int:
    return ((crc >> 8) & 0xFFFFFF) ^ _CRC[(crc ^ b) & 0xFF]


def zipcrypto_zip(entries: Sequence[Tuple[str, bytes]], password: str, seed: int = 7) -> bytes:
    rng = random.Random(seed)
    out = bytearray()
    central = bytearray()
    for name, data in entries:
        k = [0x12345678, 0x23456789, 0x34567890]

        def upd(c: int) -> None:
            k[0] = _crc32_update(k[0], c)
            k[1] = ((k[1] + (k[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
            k[2] = _crc32_update(k[2], k[1] >> 24)

        def dec_byte() -> int:
            t = (k[2] | 2) & 0xFFFF
            return ((t * (t ^ 1)) >> 8) & 0xFF

        for ch in password.encode():
            upd(ch)
        crc = binascii.crc32(data) & 0xFFFFFFFF
        hdr = bytearray(rng.randrange(256) for _ in range(11)) + bytes([crc >> 24])
        enc = bytearray()
        for p in bytes(hdr) + data:
            c = p ^ dec_byte()
            upd(p)
            enc.append(c)
        nb = name.encode()
        dos_time, dos_date = 0, ((2026 - 1980) << 9) | (3 << 5) | 1
        local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0x1, 0, dos_time, dos_date, crc, len(enc), len(data), len(nb), 0) + nb
        off = len(out)
        out += local + enc
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0x1, 0, dos_time, dos_date, crc, len(enc), len(data), len(nb), 0, 0, 0, 0, 0o600 << 16, off) + nb
    cd_off = len(out)
    out += central
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(central), cd_off, 0)
    return bytes(out)
