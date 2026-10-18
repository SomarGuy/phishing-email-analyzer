"""Small, dependency-free text primitives shared by every analysis step.

Everything here is mirrored line-for-line in dashboard/core.js so the browser version of the analyzer behaves
the same as the command-line one (tests/test_js_parity.py checks that on the whole synthetic corpus).
"""
from __future__ import annotations

import base64
import re
import unicodedata
from typing import Dict, List, Optional, Tuple
from email.header import decode_header

# ---------------------------------------------------------------------------------------------- headers
_UNFOLD = re.compile(r"\r?\n[ \t]+")


def unfold(value: str) -> str:
    return _UNFOLD.sub(" ", value or "").strip()


def decode_words(value: str) -> str:
    """Decode RFC 2047 encoded-words (=?utf-8?B?...?=) without raising on bad input."""
    if not value or "=?" not in value:
        return value or ""
    out = []
    try:
        for part, charset in decode_header(value):
            if isinstance(part, bytes):
                try:
                    out.append(part.decode(charset or "utf-8", errors="replace"))
                except LookupError:
                    out.append(part.decode("utf-8", errors="replace"))
            else:
                out.append(part)
    except Exception:
        return value
    return "".join(out)


class Addr:
    __slots__ = ("display", "addr", "local", "domain")

    def __init__(self, display: str, addr: str):
        self.display = display
        self.addr = addr.strip().lower()
        self.local, _, dom = self.addr.rpartition("@")
        self.domain = dom.strip().rstrip(".")

    def as_dict(self) -> dict:
        return {"display": self.display, "addr": self.addr, "domain": self.domain}


_ANGLE = re.compile(r"^(.*?)<([^<>]*)>\s*$", re.S)
_BARE = re.compile(r"[^\s<>\"',;()]+@[^\s<>\"',;()]+")


def parse_address(value: str) -> Optional[Addr]:
    """First mailbox in a header value: '"Display" <a@b>', 'Display <a@b>' or 'a@b'. None if there is no address."""
    v = decode_words(unfold(value or ""))
    if not v:
        return None
    m = _ANGLE.match(v)
    if m:
        disp = m.group(1).strip()
        if len(disp) >= 2 and disp[0] == disp[-1] and disp[0] in "\"'":
            disp = disp[1:-1]
        return Addr(disp.replace('\\"', '"').strip(), m.group(2))
    m = _BARE.search(v)
    if m:
        return Addr("", m.group(0))
    return None


def parse_addresses(value: str) -> List[Addr]:
    out = []
    for piece in re.split(r",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", value or ""):
        a = parse_address(piece)
        if a:
            out.append(a)
    return out


# ---------------------------------------------------------------------------------------------- dates
_MONTHS = {m: i + 1 for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split())}
_DATE_RE = re.compile(r"(?:[A-Za-z]{3,9},?\s+)?(\d{1,2})\s+([A-Za-z]{3})[a-z]*\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([+-]\d{4}|[A-Za-z]{1,5})?")
_ZONES = {"gmt": 0, "ut": 0, "utc": 0, "z": 0, "est": -300, "edt": -240, "cst": -360, "cdt": -300, "mst": -420, "mdt": -360, "pst": -480, "pdt": -420}


def _days_from_civil(y: int, m: int, d: int) -> int:
    y -= m <= 2
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def parse_date(value: str) -> Optional[int]:
    """RFC 5322 date -> epoch seconds (UTC), or None. Hand-rolled so Python and JavaScript agree."""
    m = _DATE_RE.search(value or "")
    if not m:
        return None
    day, mon, year, hh, mm, ss, zone = m.groups()
    month = _MONTHS.get(mon.lower())
    if not month:
        return None
    y = int(year)
    if y < 100:
        y += 2000 if y < 50 else 1900
    elif y < 1000:
        y += 1900
    d, h, mi, s = int(day), int(hh), int(mm), int(ss or 0)
    if not (1 <= d <= 31 and h < 24 and mi < 60 and s < 61):
        return None
    off = 0
    if zone:
        if zone[0] in "+-" and len(zone) == 5:
            off = (int(zone[1:3]) * 60 + int(zone[3:5])) * (1 if zone[0] == "+" else -1)
        else:
            off = _ZONES.get(zone.lower(), 0)
    return _days_from_civil(y, month, d) * 86400 + h * 3600 + mi * 60 + s - off * 60


def format_epoch(ts: Optional[int]) -> str:
    if ts is None:
        return ""
    days, rem = divmod(int(ts), 86400)
    z = days + 719468
    era = (z if z >= 0 else z - 146096) // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    mth = mp + (3 if mp < 10 else -9)
    y += mth <= 2
    return "%04d-%02d-%02d %02d:%02d:%02dZ" % (y, mth, d, rem // 3600, rem % 3600 // 60, rem % 60)


# ---------------------------------------------------------------------------------------------- html
_COMMENT = re.compile(r"<!--.*?-->", re.S)
_HIDDEN = re.compile(r"<(script|style)\b[^>]*>.*?</\1\s*>", re.S | re.I)
_TAG = re.compile(r"<(/?)([a-zA-Z][a-zA-Z0-9:-]*)((?:[^>\"']|\"[^\"]*\"|'[^']*')*)>")
_ATTR = re.compile(r"([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'>]+)))?")
_BLOCK = {"br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "ul", "ol", "blockquote", "hr"}
_ENT = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'", "nbsp": " "}
_ENT_RE = re.compile(r"&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);")


def decode_entities(s: str) -> str:
    def rep(m):
        e = m.group(1)
        try:
            if e[0] == "#":
                cp = int(e[2:], 16) if e[1] in "xX" else int(e[1:])
                return chr(cp) if 0 < cp < 0x110000 else m.group(0)
        except ValueError:  # pragma: no cover - defensive: the regex only admits valid digits
            return m.group(0)
        return _ENT.get(e.lower(), m.group(0))
    return _ENT_RE.sub(rep, s)


def parse_attrs(raw: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in _ATTR.finditer(raw or ""):
        name = m.group(1).lower()
        val = m.group(2) if m.group(2) is not None else (m.group(3) if m.group(3) is not None else (m.group(4) or ""))
        if name not in out:
            out[name] = decode_entities(val)
    return out


def analyze_html(html: str) -> dict:
    """Visible text, links (href + visible text), images and form hints from an HTML fragment. No DOM, no network."""
    html = _COMMENT.sub("", html or "")
    html = _HIDDEN.sub(" ", html)
    text: List[str] = []
    links: List[dict] = []
    images: List[dict] = []
    cur: Optional[dict] = None
    has_form = has_password = False
    pos = 0
    for m in _TAG.finditer(html):
        chunk = decode_entities(html[pos:m.start()])
        if chunk:
            text.append(chunk)
            if cur is not None:
                cur["text"] += chunk
        pos = m.end()
        closing, tag, rest = m.group(1) == "/", m.group(2).lower(), m.group(3)
        if tag == "a":
            if closing:
                if cur is not None:
                    cur["text"] = re.sub(r"\s+", " ", cur["text"]).strip()
                    links.append(cur)
                    cur = None
            else:
                if cur is not None:
                    cur["text"] = re.sub(r"\s+", " ", cur["text"]).strip()
                    links.append(cur)
                a = parse_attrs(rest)
                cur = {"href": a.get("href", "").strip(), "text": ""} if "href" in a else None
        elif tag == "img" and not closing:
            a = parse_attrs(rest)
            images.append({"src": a.get("src", ""), "alt": a.get("alt", "")})
            if cur is not None and a.get("alt"):
                cur["text"] += a["alt"]
        elif tag == "form" and not closing:
            has_form = True
        elif tag == "input" and not closing and parse_attrs(rest).get("type", "").lower() == "password":
            has_password = True
        if tag in _BLOCK:
            text.append("\n")
    tail = decode_entities(html[pos:])
    if tail:
        text.append(tail)
        if cur is not None:
            cur["text"] += tail
    if cur is not None:
        cur["text"] = re.sub(r"\s+", " ", cur["text"]).strip()
        links.append(cur)
    plain = re.sub(r"[ \t\r\f\v\u00a0]+", " ", "".join(text))
    plain = re.sub(r" ?\n ?", "\n", plain)
    plain = re.sub(r"\n{3,}", "\n\n", plain).strip()
    return {"text": plain, "links": links, "images": images, "form": has_form, "password_input": has_password}


# ---------------------------------------------------------------------------------------------- urls
_URL_RE = re.compile(r"(?:(?:https?|hxxps?|ftp)://|www\.)[^\s<>\"'`]+", re.I)
_TRAIL = ".,;:!?)]}>'\""


def refang(s: str) -> str:
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    return s.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")


def extract_urls(text: str) -> List[str]:
    out = []
    for m in _URL_RE.finditer(text or ""):
        u = m.group(0)
        while u and u[-1] in _TRAIL:
            u = u[:-1]
        if len(u) < 8:
            continue
        u = refang(u)
        if u.lower().startswith("www."):
            u = "http://" + u
        out.append(u)
    return out


_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):(.*)$", re.S)


def parse_url(url: str) -> dict:
    """Split a URL by hand. Returns scheme, userinfo, host, port, path, query, fragment (strings, host lowercased)."""
    u = (url or "").strip()
    res = {"url": u, "scheme": "", "userinfo": "", "host": "", "port": "", "path": "", "query": "", "fragment": ""}
    m = _SCHEME.match(u)
    if not m:
        return res
    scheme, rest = m.group(1).lower(), m.group(2)
    res["scheme"] = scheme
    if not rest.startswith("//"):
        res["path"] = rest
        return res
    rest = rest[2:]
    frag = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)
    auth, slash, path = rest.partition("/")
    path = slash + path
    userinfo = ""
    if "@" in auth:
        userinfo, auth = auth.rsplit("@", 1)
    host, port = auth, ""
    if auth.startswith("["):
        end = auth.find("]")
        host, port = (auth[1:end], auth[end + 2:]) if end > 0 else (auth, "")
    elif ":" in auth:
        h, _, p = auth.rpartition(":")
        if p.isdigit() or p == "":
            host, port = h, p
    res.update(userinfo=userinfo, host=host.lower().rstrip("."), port=port, path=path, query=query, fragment=frag)
    return res


def percent_decode(s: str) -> str:
    from urllib.parse import unquote_to_bytes
    return unquote_to_bytes(s).decode("utf-8", errors="replace") if "%" in s else s


def query_pairs(query: str) -> List[Tuple[str, str]]:
    out = []
    for piece in (query or "").split("&"):
        if not piece:
            continue
        k, _, v = piece.partition("=")
        out.append((percent_decode(k.replace("+", " ")).lower(), percent_decode(v.replace("+", " "))))
    return out


# ---------------------------------------------------------------------------------------------- domains / ips
def is_ipv4(host: str) -> bool:
    p = host.split(".")
    return len(p) == 4 and all(x.isdigit() and 0 <= int(x) <= 255 and len(x) <= 3 for x in p)


def is_ipv6(host: str) -> bool:
    return ":" in host and re.fullmatch(r"[0-9a-fA-F:.]+", host) is not None and host.count(":") >= 2


def obfuscated_ipv4(host: str) -> Optional[str]:
    """Decimal (3405803853), hex (0xCB007101) or octal-dotted (0313.0.113.1) hosts -> dotted quad, else None."""
    h = host.lower()
    n: Optional[int] = None
    if re.fullmatch(r"\d{8,10}", h):
        n = int(h)
    elif re.fullmatch(r"0x[0-9a-f]{1,8}", h):
        n = int(h, 16)
    elif re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){3}", h) and not is_ipv4(h):
        try:
            parts = [int(x, 16) if x.startswith("0x") else (int(x, 8) if len(x) > 1 and x[0] == "0" else int(x)) for x in h.split(".")]
        except ValueError:
            return None
        if all(0 <= x <= 255 for x in parts):
            return ".".join(str(x) for x in parts)
        return None
    if n is None or n > 0xFFFFFFFF:
        return None
    return ".".join(str((n >> s) & 255) for s in (24, 16, 8, 0))


def ip_scope(ip: str) -> str:
    """private | loopback | documentation | public (IPv4, plus the basic IPv6 ranges)."""
    if is_ipv4(ip):
        a, b, c, _ = (int(x) for x in ip.split("."))
        if a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 169 and b == 254):
            return "private"
        if a == 127:
            return "loopback"
        if (a, b, c) in ((192, 0, 2), (198, 51, 100), (203, 0, 113)):
            return "documentation"
        return "public"
    low = ip.lower()
    if low in ("::1", "::"):
        return "loopback"
    if low.startswith(("fc", "fd", "fe8", "fe9", "fea", "feb")):
        return "private"
    if low.startswith("2001:db8"):
        return "documentation"
    return "public"


def registered_domain(host: str, multi_suffixes) -> str:
    labels = [x for x in host.split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in multi_suffixes:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def split_registered(host: str, multi_suffixes) -> Tuple[List[str], str, str]:
    """(subdomain labels, registered-domain label, registered domain)."""
    rd = registered_domain(host, multi_suffixes)
    rd_labels = rd.split(".")
    labels = [x for x in host.split(".") if x]
    sub = labels[:len(labels) - len(rd_labels)]
    n_suffix = 2 if ".".join(rd_labels[-2:]) in multi_suffixes else 1
    sld = rd_labels[-(n_suffix + 1)] if len(rd_labels) > n_suffix else rd_labels[0]
    return sub, sld, rd


def same_org(a: str, b: str, multi_suffixes) -> bool:
    return bool(a) and bool(b) and registered_domain(a, multi_suffixes) == registered_domain(b, multi_suffixes)


# ---------------------------------------------------------------------------------------------- punycode / scripts
def _punycode_decode(s: str) -> Optional[str]:
    base, tmin, tmax, skew, damp = 36, 1, 26, 38, 700
    n, i, bias = 128, 0, 72
    b = s.rfind("-")
    out: List[str] = list(s[:b]) if b > 0 else []
    idx = b + 1 if b > 0 else 0

    def adapt(delta, numpoints, first):
        delta = delta // damp if first else delta // 2
        delta += delta // numpoints
        k = 0
        while delta > ((base - tmin) * tmax) // 2:
            delta //= base - tmin
            k += base
        return k + (base - tmin + 1) * delta // (delta + skew)

    while idx < len(s):
        oldi, w, k = i, 1, base
        while True:
            if idx >= len(s):
                return None
            c = s[idx]
            idx += 1
            if "a" <= c <= "z":
                digit = ord(c) - 97
            elif "A" <= c <= "Z":
                digit = ord(c) - 65
            elif "0" <= c <= "9":
                digit = ord(c) - 22
            else:
                return None
            i += digit * w
            t = tmin if k <= bias else (tmax if k >= bias + tmax else k - bias)
            if digit < t:
                break
            w *= base - t
            k += base
        bias = adapt(i - oldi, len(out) + 1, oldi == 0)
        n += i // (len(out) + 1)
        i %= len(out) + 1
        if n > 0x10FFFF:
            return None
        out.insert(i, chr(n))
        i += 1
    return "".join(out)


def host_unicode(host: str) -> str:
    """Decode xn-- labels to Unicode (labels that fail to decode are kept)."""
    out = []
    for lab in host.split("."):
        if lab.lower().startswith("xn--"):
            dec = _punycode_decode(lab[4:])
            out.append(dec if dec is not None else lab)
        else:
            out.append(lab)
    return ".".join(out)


def script_of(ch: str) -> str:
    o = ord(ch)
    if ch.isdigit() or ch in "-_.":
        return "common"
    if o < 0x80:
        return "latin" if ch.isalpha() else "common"
    if 0x0370 <= o <= 0x03FF or 0x1F00 <= o <= 0x1FFF:
        return "greek"
    if 0x0400 <= o <= 0x052F:
        return "cyrillic"
    if 0x00C0 <= o <= 0x024F or 0x1E00 <= o <= 0x1EFF:
        return "latin"
    if 0x0530 <= o <= 0x058F:
        return "armenian"
    if 0x4E00 <= o <= 0x9FFF or 0x3040 <= o <= 0x30FF:
        return "cjk"
    if 0x0600 <= o <= 0x06FF:
        return "arabic"
    return "other"


def scripts_in(label: str) -> List[str]:
    return sorted({script_of(c) for c in label if script_of(c) != "common"})


_CONFUSABLE = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ɡ": "g",
               "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "ɑ": "a", "ℓ": "l", "0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a"}


def normalize_confusables(label: str) -> str:
    s = "".join(_CONFUSABLE.get(c, c) for c in label.lower())
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    return s.replace("rn", "m").replace("vv", "w")


def edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment): insert, delete, substitute and adjacent swap each cost 1."""
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


# ---------------------------------------------------------------------------------------------- defanging
def defang_host(host: str) -> str:
    return host.replace(".", "[.]")


def defang_url(url: str) -> str:
    u = re.sub(r"^http", "hxxp", url, flags=re.I)
    m = re.match(r"^([A-Za-z]+://)([^/?#]*)(.*)$", u, re.S)
    if not m:
        return u.replace(".", "[.]")
    return m.group(1) + m.group(2).replace(".", "[.]") + m.group(3)


def defang_email(addr: str) -> str:
    return addr.replace("@", "[@]").replace(".", "[.]")


def defang_text(s: str) -> str:
    """Defang every URL-looking and email-looking token in free text (for ticket notes)."""
    s = re.sub(r"(?:https?|ftp)://[^\s<>\"'`]+", lambda m: defang_url(m.group(0)), s, flags=re.I)
    return re.sub(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b", lambda m: defang_email(m.group(0)), s)


def defang_known(s: str, hosts) -> str:
    """Defang every occurrence (including sub-domains) of the given domains/IPs in free text, longest first.
    Used for ticket notes: a bare domain such as evil.test would otherwise be auto-linked by chat and ticket tools."""
    for h in sorted({x for x in hosts if x}, key=lambda x: (-len(x), x)):
        s = re.sub(r"(?<![A-Za-z0-9-])((?:[A-Za-z0-9-]+\.)*" + re.escape(h) + r")(?![A-Za-z0-9-])", lambda m: m.group(1).replace(".", "[.]"), s, flags=re.I)
    return s


def b64decode_lenient(s: str) -> bytes:
    s = re.sub(r"[^A-Za-z0-9+/=]", "", s)
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s)
    except Exception:
        return b""
