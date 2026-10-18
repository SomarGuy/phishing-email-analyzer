"""Turn raw RFC 822 bytes into a plain data structure. Uses the standard-library parser; never renders anything."""
from __future__ import annotations

import email
import email.policy
import mailbox
import os
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple

from .textutil import decode_words, unfold


@dataclass
class Part:
    filename: str
    content_type: str
    disposition: str
    data: bytes
    content_id: str = ""


@dataclass
class ParsedEmail:
    headers: List[Tuple[str, str]]                 # (name, unfolded value) in original order
    text: str                                      # concatenated text/plain bodies
    html: str                                      # concatenated text/html bodies
    attachments: List[Part] = field(default_factory=list)
    size: int = 0
    raw: bytes = b""
    defects: List[str] = field(default_factory=list)

    def get_all(self, name: str) -> List[str]:
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]

    def get(self, name: str, default: str = "") -> str:
        v = self.get_all(name)
        return v[0] if v else default


def _decode_payload(part, data: bytes) -> str:
    charset = part.get_content_charset() or "utf-8"
    try:
        return data.decode(charset, errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


def parse_bytes(raw: bytes) -> ParsedEmail:
    msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    headers = [(k, unfold(str(v))) for k, v in msg.raw_items()]
    texts: List[str] = []
    htmls: List[str] = []
    atts: List[Part] = []
    defects = [type(d).__name__ for d in msg.defects]
    for part in msg.walk():
        if part.is_multipart():
            defects.extend(type(d).__name__ for d in part.defects)
            continue
        ctype = part.get_content_type()
        disp = (part.get_content_disposition() or "").lower()
        fname = part.get_filename()
        fname = decode_words(unfold(fname)) if fname else ""
        data = part.get_payload(decode=True) or b""
        if ctype in ("text/plain", "text/html") and disp != "attachment" and not fname:
            (htmls if ctype == "text/html" else texts).append(_decode_payload(part, data))
            continue
        if not fname:
            ext = ctype.split("/")[-1].split("+")[0]
            fname = f"unnamed.{ext}" if ext else "unnamed"
        atts.append(Part(fname, ctype, disp or "inline", data, (part.get("Content-ID") or "").strip("<> ")))
    return ParsedEmail(headers, "\n".join(texts), "\n".join(htmls), atts, len(raw), raw, defects)


def iter_mbox(path: str) -> Iterator[Tuple[str, bytes]]:
    """Yield (label, raw bytes) for each message in an mbox file."""
    box = mailbox.mbox(path, create=False)
    try:
        for i, key in enumerate(box.keys()):
            yield f"{os.path.basename(path)}#{i + 1}", box.get_bytes(key)
    finally:
        box.close()
