"""URL extraction and analysis. URLs are parsed as strings; nothing is ever fetched, resolved or opened."""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from .headers import brand_matches
from .models import Finding
from .textutil import (analyze_html, defang_url, extract_urls, host_unicode, is_ipv4, is_ipv6, normalize_confusables, obfuscated_ipv4,
                       parse_url, percent_decode, query_pairs, registered_domain, same_org, scripts_in, ip_scope, split_registered)

MAX_LINKS = 100
_TEXT_HOST = re.compile(r"(?:https?://)?((?:[a-z0-9\u00a1-\uffff-]+\.)+[a-z\u00a1-\uffff]{2,})(?::\d+)?(?:/\S*)?", re.I)
SCRIPT_SCHEMES = ("javascript", "vbscript", "data")
NON_LATIN_CONFUSABLE = ("cyrillic", "greek", "armenian")


def collect_links(pe) -> List[dict]:
    """Every URL in the message with its origin ('html link', 'html text', 'plain text') and anchor text."""
    seen: Dict[str, dict] = {}
    order: List[dict] = []

    def add(url: str, text: str, source: str) -> None:
        url = url.strip()
        if not url or url in seen or len(order) >= MAX_LINKS:
            return
        rec = {"url": url, "text": text, "source": source}
        seen[url] = rec
        order.append(rec)

    visible = ""
    if pe.html:
        h = analyze_html(pe.html)
        visible = h["text"]
        for lk in h["links"]:
            add(lk["href"], lk["text"], "html link")
        collect_extra = extract_urls(visible)
    else:
        collect_extra = []
    for u in collect_extra:
        add(u, "", "html text")
    for u in extract_urls(pe.text):
        add(u, "", "plain text")
    return order


def is_idn_homograph(host: str) -> Optional[str]:
    """Return a reason if a label of the (decoded) host mixes scripts or is a non-Latin confusable of ASCII."""
    uni = host_unicode(host)
    for label in uni.split("."):
        if all(ord(c) < 128 for c in label):
            continue
        sc = scripts_in(label)
        if len(sc) > 1:
            return f"label '{label}' mixes scripts ({', '.join(sc)})"
        if sc and sc[0] in NON_LATIN_CONFUSABLE:
            norm = normalize_confusables(label)
            if all(ord(c) < 128 for c in norm):
                return f"label '{label}' is {sc[0]} lookalike of '{norm}'"
    return None


def analyze_link(rec: dict, cfg: dict, sender_domains: List[str]) -> dict:
    suffixes = cfg["multi_label_suffixes"]
    th = cfg["thresholds"]
    lists = cfg["lists"]
    url = rec["url"]
    u = parse_url(url)
    flags: List[dict] = []
    host = u["host"]
    out = {"url": url, "defanged": defang_url(url), "text": rec["text"], "source": rec["source"], "host": host, "host_unicode": "", "domain": "", "scheme": u["scheme"], "flags": flags}

    def flag(i: str, detail: str) -> None:
        flags.append({"id": i, "detail": detail})

    if u["scheme"] in SCRIPT_SCHEMES:
        flag("url_script_scheme", f"{u['scheme']}: URL")
        return out
    if u["scheme"] not in ("http", "https", "ftp") or not host:
        return out
    uni = host_unicode(host)
    out["host_unicode"] = uni if uni != host else ""
    sender_rds = [registered_domain(d, suffixes) for d in sender_domains if d]
    safe = host in [h.lower() for h in lists["safe_url_hosts"]]
    ip = host if (is_ipv4(host) or is_ipv6(host)) else ""
    obf = obfuscated_ipv4(host)
    if obf:
        flag("url_ip_host", f"Host is the IP address {obf} written as '{host}'")
        flag("url_obfuscated", f"IP address hidden as '{host}'")
    elif ip:
        flag("url_ip_host", f"Host is the IP address {ip} ({ip_scope(ip)})")
    if ip or obf:
        out["domain"] = ""
        rd = ""
    else:
        rd = registered_domain(uni, suffixes)
        out["domain"] = rd
        why = is_idn_homograph(host)
        if why:
            flag("url_idn_homograph", f"Internationalised host {host}: {why}")
        if not safe:
            for m in brand_matches(host, cfg):
                if m["where"] == "domain" and not (why and m["kind"] == "look-alike characters"):
                    flag("url_lookalike_domain", f"{rd} imitates {m['brand']} ({m['kind']})")
                elif m["where"] == "domain-token":
                    flag("url_brand_in_domain", f"{m['brand']} used inside the domain {rd}")
                elif m["where"] == "subdomain":
                    flag("url_brand_in_subdomain", f"{m['brand']} used as a subdomain of {rd}")
        if rd in [d.lower() for d in lists["shorteners"]] or host in [d.lower() for d in lists["shorteners"]]:
            flag("url_shortener", f"{rd} is a URL shortener; the destination is hidden")
        tld = uni.rpartition(".")[2]
        if tld in [t.lower() for t in lists["suspicious_tlds"]]:
            flag("url_suspicious_tld", f"Top-level domain .{tld} is heavily abused")
        if "%" in host or len(uni.split(".")) - len(rd.split(".")) >= th["deep_subdomains"]:
            flag("url_obfuscated", "Percent-encoded host" if "%" in host else f"{len(uni.split('.'))} labels in the host name")
    if len(url) > th["long_url_chars"]:
        flag("url_obfuscated", f"Very long URL ({len(url)} characters)")
    if u["userinfo"]:
        flag("url_userinfo", f"URL has credentials-style prefix '{u['userinfo']}@' before the real host {host}")
    link_is_sender = bool(rd) and rd in sender_rds
    # display text vs real destination
    txt = rec["text"] or ""
    m = _TEXT_HOST.search(txt) if txt else None
    if m and rec["source"] == "html link":
        shown = m.group(1).lower()
        shown_rd = registered_domain(host_unicode(shown) if shown.startswith("xn--") else shown, suffixes)
        if rd and shown_rd != rd and not (obf or ip):
            flag("url_text_mismatch", f"Link text shows {shown} but the link goes to {host}")
        elif (ip or obf) and shown:
            flag("url_text_mismatch", f"Link text shows {shown} but the link goes to {host}")
    # redirect-looking parameters
    if not link_is_sender:
        for k, v in query_pairs(u["query"]):
            if k in [p.lower() for p in lists["redirect_params"]]:
                t = v if re.match(r"^[a-z][a-z0-9+.\-]*://", v, re.I) else ""
                if t:
                    th_host = parse_url(t)["host"]
                    trd = registered_domain(th_host, suffixes)
                    if trd and trd != rd and trd not in sender_rds:
                        flag("url_redirect_param", f"Parameter '{k}' carries another destination ({th_host})")
                        break
    if not link_is_sender and not safe:
        low = (u["path"] + "?" + u["query"] + " " + host).lower()
        hits = [w for w in lists["login_keywords"] if w in low]
        if hits:
            flag("url_login_keywords", f"URL contains credential keywords ({', '.join(hits[:3])}) and is not on the sender's domain")
    return out


def analyze_urls(pe, cfg: dict, sender_domains: List[str]):
    """Returns (link records, findings)."""
    links = [analyze_link(r, cfg, sender_domains) for r in collect_links(pe)]
    by_id: Dict[str, List[str]] = {}
    details: Dict[str, str] = {}
    for lk in links:
        for f in lk["flags"]:
            by_id.setdefault(f["id"], []).append(f"{lk['defanged']} - {f['detail']}")
            details.setdefault(f["id"], f["detail"])
    findings = []
    for i, ev in by_id.items():
        n = len(ev)
        findings.append(Finding(i, details[i] + (f" (+{n - 1} more link(s))" if n > 1 else ""), ev))
    return links, findings
