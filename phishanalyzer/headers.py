"""Header analysis: sender identity, Received chain, Message-ID and Date checks."""
from __future__ import annotations

import re
from typing import List, Optional

from .models import Finding
from .textutil import (Addr, decode_words, format_epoch, ip_scope, parse_address, parse_date, same_org, registered_domain,
                       split_registered, normalize_confusables, edit_distance, host_unicode)

_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
_MSGID = re.compile(r"^<[^<>@\s]+@[^<>@\s]+\.[^<>@\s]+>$")


# ---------------------------------------------------------------------------------------------- Received
def parse_received(value: str) -> dict:
    body, _, datepart = value.rpartition(";") if ";" in value else (value, "", "")
    m_from = re.search(r"\bfrom\s+(\S+)", body, re.I)
    helo = m_from.group(1).strip("()[]") if m_from else ""
    paren = re.search(r"\bfrom\s+\S+\s*\(([^)]*)\)", body, re.I)
    ptxt = paren.group(1) if paren else ""
    ip = ""
    m_ip = re.search(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]", ptxt or body)
    if m_ip:
        ip = m_ip.group(1)
    rdns = ""
    for tok in re.split(r"\s+", re.sub(r"\[[^\]]*\]", " ", ptxt).strip()):
        if tok and not re.match(r"^(helo|ehlo)", tok, re.I) and not tok.startswith("[") and tok.lower() not in ("postfix", "authenticated"):
            rdns = tok.strip(",").lower()
            break
    m_by = re.search(r"\bby\s+(\S+)", body, re.I)
    m_with = re.search(r"\bwith\s+(\S+)", body, re.I)
    ts = parse_date(datepart)
    return {"from_helo": helo.lower(), "rdns": rdns, "ip": ip, "ip_scope": ip_scope(ip) if ip else "", "by": (m_by.group(1) if m_by else "").lower(),
            "with": m_with.group(1) if m_with else "", "time": ts, "time_text": format_epoch(ts), "raw": value}


def basic_info(pe, cfg: dict) -> dict:
    th = cfg["thresholds"]
    frm = parse_address(pe.get("From"))
    rto = parse_address(pe.get("Reply-To"))
    rp_raw = pe.get("Return-Path")
    rpa = parse_address(rp_raw) if rp_raw and rp_raw.strip() not in ("<>", "") else None
    hops_new_first = [parse_received(v) for v in pe.get_all("Received")]
    hops = list(reversed(hops_new_first))                      # origin first
    for i, h in enumerate(hops):
        h["index"] = i + 1
        h["delta_s"] = None
        h["anomalies"] = []
    prev: Optional[dict] = None
    for h in hops:
        if prev is not None and prev["time"] is not None and h["time"] is not None:
            h["delta_s"] = h["time"] - prev["time"]
            if h["delta_s"] < -th["received_backwards_seconds"]:
                h["anomalies"].append("time goes backwards")
            elif h["delta_s"] > th["received_long_delay_hours"] * 3600:
                h["anomalies"].append("delay of more than %d hours" % th["received_long_delay_hours"])
        if h["time"] is not None:
            prev = h
    origin_ip = ""
    for h in hops:
        if h["ip"] and h["ip_scope"] in ("public", "documentation"):
            origin_ip = h["ip"]
            break
    date_raw = pe.get("Date")
    mid = pe.get("Message-ID")
    return {
        "from": frm.as_dict() if frm else None, "reply_to": rto.as_dict() if rto else None, "return_path": rpa.as_dict() if rpa else None,
        "to": pe.get("To"), "subject": decode_words(pe.get("Subject")), "message_id": mid, "date": date_raw, "date_epoch": parse_date(date_raw),
        "date_text": format_epoch(parse_date(date_raw)), "hops": hops, "origin_ip": origin_ip, "list_id": pe.get("List-Id"),
        "list_unsubscribe": pe.get("List-Unsubscribe"), "x_mailer": pe.get("X-Mailer") or pe.get("User-Agent"),
    }


# ---------------------------------------------------------------------------------------------- brand matching
def _has_run(toks: List[str], run: List[str]) -> bool:
    return any(toks[i:i + len(run)] == run for i in range(len(toks) - len(run) + 1))


def brand_matches(host: str, cfg: dict) -> List[dict]:
    """Does this host imitate a brand or the organisation? Returns one match per brand (empty list if none).

    `where` is "domain" (the registered domain itself imitates the brand), "domain-token" (brand name is a hyphen-separated
    token of the registered domain) or "subdomain" (brand name or brand domain used as a subdomain).
    """
    suffixes = cfg["multi_label_suffixes"]
    th = cfg["thresholds"]
    sub, sld, rd = split_registered(host_unicode(host.lower()), suffixes)
    norm_sld = normalize_confusables(sld)
    toks = [normalize_confusables(t) for t in sld.split("-") if t]
    sub_labels = [normalize_confusables(x) for x in sub]
    sub_joined = ".".join(sub)
    out: List[dict] = []
    for b in cfg["lists"]["brands"]:
        legit = [d.lower() for d in b["domains"]]
        if any(registered_domain(d, suffixes) == rd for d in legit):
            continue
        bl = b["label"]
        nb = normalize_confusables(bl)
        long_enough = len(bl) >= th["min_brand_label_len"]
        k = th["lookalike_short_distance"] if len(bl) < th["lookalike_short_len"] else th["lookalike_max_distance"]
        kind, where = "", "domain"
        if sld == bl:
            kind = "same name, different domain"
        elif long_enough and norm_sld == nb:
            kind = "look-alike characters"
        elif long_enough and abs(len(sld) - len(bl)) <= k and edit_distance(sld, bl) <= k:
            kind = "typo of the brand name"
        elif long_enough and len(toks) > len(nb.split("-")) and _has_run(toks, nb.split("-")):
            kind, where = "brand name inside the domain", "domain-token"
        elif long_enough and "-" not in nb and len(toks) > 1 and any(t != nb and len(t) >= th["min_brand_label_len"] and edit_distance(t, nb) <= 1 for t in toks):
            kind, where = "typo of the brand name inside the domain", "domain-token"
        elif long_enough and (nb in sub_labels or any(d in sub_joined for d in legit)):
            kind, where = "brand domain used as a subdomain", "subdomain"
        if kind:
            out.append({"brand": b["name"], "kind": kind, "domain": rd, "where": where, "org": bool(b.get("org"))})
    return out


# ---------------------------------------------------------------------------------------------- findings
def _name_hit(display: str, name: str) -> bool:
    return bool(re.search(r"(?<![A-Za-z])" + re.escape(name.lower()) + r"(?![A-Za-z])", display.lower()))


def header_findings(pe, info: dict, auth: dict, aligned: bool, cfg: dict) -> List[Finding]:
    suffixes = cfg["multi_label_suffixes"]
    th = cfg["thresholds"]
    out: List[Finding] = []
    frm, rto, rp = info["from"], info["reply_to"], info["return_path"]
    from_dom = frm["domain"] if frm else ""
    org_domains = [d.lower() for d in cfg["organisation"]["domains"]]
    brands = [b for b in cfg["lists"]["brands"] if not b.get("org")]
    freemail = {d.lower() for d in cfg["lists"]["freemail"]}
    from_is_org = any(same_org(from_dom, d, suffixes) for d in org_domains)
    from_is_free = registered_domain(from_dom, suffixes) in freemail

    if rto and frm and not same_org(rto["domain"], from_dom, suffixes) and not info.get("list_id"):
        out.append(Finding("reply_to_mismatch", f"Reply-To domain {rto['domain']} differs from From domain {from_dom}", [f"From: {frm['addr']}", f"Reply-To: {rto['addr']}"]))
    if rp and frm and not same_org(rp["domain"], from_dom, suffixes) and not aligned:
        out.append(Finding("return_path_mismatch", f"Return-Path domain {rp['domain']} differs from From domain {from_dom}", [f"Return-Path: {rp['addr']}", f"From: {frm['addr']}"]))

    if frm and frm["display"]:
        disp = frm["display"]
        for m in _EMAIL_IN_TEXT.finditer(disp):
            if not same_org(m.group(1).lower(), from_dom, suffixes):
                out.append(Finding("display_name_email_spoof", f"Display name \"{disp}\" shows {m.group(0)} but the real sender is {frm['addr']}", [f"Display name: {disp}", f"Actual address: {frm['addr']}"]))
                break
        hit_brand = None
        for b in brands:
            if _name_hit(disp, b["name"]) and not any(registered_domain(from_dom, suffixes) == registered_domain(d, suffixes) for d in b["domains"]):
                hit_brand = b["name"]
                break
        if hit_brand:
            out.append(Finding("display_name_brand_spoof", f"Display name uses '{hit_brand}' but the sender domain is {from_dom}", [f"Display name: {disp}", f"Sender domain: {from_dom}"]))
        hit_prot = None
        if not from_is_org:
            for p in cfg["organisation"]["protected_names"]:
                if _name_hit(disp, p["name"]):
                    hit_prot = p
                    break
        if hit_prot:
            out.append(Finding("display_name_exec_spoof", f"Display name '{disp}' matches protected name '{hit_prot['name']}' ({hit_prot['role']}) but the domain is {from_dom}", [f"Display name: {disp}", f"Sender domain: {from_dom}"]))
        if (hit_brand or hit_prot) and from_is_free:
            out.append(Finding("freemail_display_spoof", f"Free-mail address {frm['addr']} uses the name '{hit_brand or hit_prot['name']}'", [f"From: {disp} <{frm['addr']}>"]))

    seen = set()
    for label, a in (("From", frm), ("Reply-To", rto), ("Return-Path", rp)):
        if not a or not a["domain"] or a["domain"] in seen:
            continue
        seen.add(a["domain"])
        for m in brand_matches(a["domain"], cfg):
            if m["where"] in ("domain", "domain-token"):
                out.append(Finding("sender_domain_lookalike", f"{label} domain {a['domain']} imitates {m['brand']} ({m['kind']})", [f"{label}: {a['addr']}", f"Imitates: {m['brand']}"]))
                break

    mid = info["message_id"]
    if not mid:
        out.append(Finding("message_id_missing", "No Message-ID header", []))
    else:
        if not _MSGID.match(mid.strip()) or mid.strip().lower().rpartition("@")[2].startswith("localhost"):
            out.append(Finding("message_id_malformed", f"Message-ID {mid} is not of the form <unique@domain>", [f"Message-ID: {mid}"]))
        else:
            mdom = mid.strip().strip("<>").rpartition("@")[2].lower()
            related = same_org(mdom, from_dom, suffixes) or (rp and same_org(mdom, rp["domain"], suffixes))
            if not related and not aligned and frm:
                out.append(Finding("message_id_domain_mismatch", f"Message-ID domain {mdom} is unrelated to the sender domain {from_dom}", [f"Message-ID: {mid}"]))

    hops = info["hops"]
    if not hops:
        out.append(Finding("received_missing", "No Received headers", []))
    else:
        bad = [h for h in hops if h["anomalies"]]
        if bad:
            out.append(Finding("received_time_anomaly", "Received hop timestamps: " + "; ".join(sorted({a for h in bad for a in h["anomalies"]})),
                               [f"hop {h['index']} ({h['by'] or 'unknown'}): {', '.join(h['anomalies'])}, delta {h['delta_s']}s" for h in bad]))
        origin = hops[0]
        if origin["from_helo"] and origin["ip_scope"] not in ("private", "loopback", ""):
            helo, rdns = origin["from_helo"], origin["rdns"]
            if not rdns or rdns == "unknown" or not same_org(helo, rdns, suffixes):
                out.append(Finding("received_helo_mismatch", f"Origin hop HELO '{helo}' vs reverse DNS '{rdns or 'none'}' ({origin['ip']})", [f"Received: {origin['raw'][:160]}"]))
        if len(hops) >= th["received_many_hops"]:
            out.append(Finding("received_many_hops", f"{len(hops)} Received headers", []))

    if not info["date"] or info["date_epoch"] is None:
        out.append(Finding("date_invalid", "Date header is missing" if not info["date"] else f"Date header unparseable: {info['date']}", []))
    else:
        times = [h["time"] for h in hops if h["time"] is not None]
        if times:
            if info["date_epoch"] - max(times) > th["date_future_hours"] * 3600:
                out.append(Finding("date_future", f"Date {info['date_text']} is {(info['date_epoch'] - max(times)) // 3600} h after the last Received hop ({format_epoch(max(times))})", [f"Date: {info['date']}"]))
            elif min(times) - info["date_epoch"] > th["date_stale_days"] * 86400:
                out.append(Finding("date_stale", f"Date {info['date_text']} is {(min(times) - info['date_epoch']) // 86400} days before the first Received hop ({format_epoch(min(times))})", [f"Date: {info['date']}"]))
    return out
