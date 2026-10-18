"""SPF / DKIM / DMARC results from Authentication-Results (or Received-SPF), alignment, and offline SPF."""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from .models import Finding
from .spf import evaluate_spf
from .textutil import parse_address, same_org

_PROP = re.compile(r"([a-z0-9\-]+\.[a-z0-9\-]+)=([^\s;]+)", re.I)
_RES = re.compile(r"^([a-z0-9\-]+)=([a-z]+)", re.I)
BAD_SPF = {"fail", "hardfail"}


def parse_authentication_results(value: str) -> dict:
    out = {"authserv": "", "spf": None, "dkim": [], "dmarc": None, "raw": value}
    parts = [p.strip() for p in value.split(";")]
    if parts:
        out["authserv"] = parts[0].split()[0] if parts[0] else ""
    for seg in parts[1:]:
        m = _RES.match(seg)
        if not m:
            continue
        method, result = m.group(1).lower(), m.group(2).lower()
        props = {k.lower(): v.strip('"') for k, v in _PROP.findall(seg)}
        if method == "spf":
            dom = props.get("smtp.mailfrom", props.get("smtp.helo", ""))
            out["spf"] = {"result": result, "domain": dom.rpartition("@")[2].lower(), "source": "Authentication-Results"}
        elif method == "dkim":
            d = props.get("header.d") or props.get("header.i", "").rpartition("@")[2]
            out["dkim"].append({"result": result, "domain": d.lower(), "selector": props.get("header.s", ""), "source": "Authentication-Results"})
        elif method == "dmarc":
            out["dmarc"] = {"result": result, "from": props.get("header.from", "").lower(), "source": "Authentication-Results"}
    return out


def parse_received_spf(value: str) -> Optional[dict]:
    m = re.match(r"\s*(pass|fail|softfail|neutral|none|permerror|temperror)\b", value, re.I)
    if not m:
        return None
    env = re.search(r"envelope-from=\"?<?([^\s;\">]+)", value, re.I)
    dom = env.group(1).rpartition("@")[2].lower() if env else ""
    return {"result": m.group(1).lower(), "domain": dom, "source": "Received-SPF"}


def analyze_auth(pe, info: dict, cfg: dict, dns: Optional[dict]) -> (dict, List[Finding], bool):
    """Returns (auth dict, findings, authenticated_aligned flag). `info` is the basic header info."""
    suffixes = cfg["multi_label_suffixes"]
    from_dom = (info.get("from") or {}).get("domain", "")
    ar_values = pe.get_all("Authentication-Results")
    ar = parse_authentication_results(ar_values[0]) if ar_values else {"authserv": "", "spf": None, "dkim": [], "dmarc": None, "raw": ""}
    spf = ar["spf"]
    if spf is None:
        rs = pe.get("Received-SPF")
        spf = parse_received_spf(rs) if rs else None
    offline = None
    rp_dom = (info.get("return_path") or {}).get("domain") or from_dom
    if spf is None and dns and info.get("origin_ip") and rp_dom:
        offline = evaluate_spf(info["origin_ip"], rp_dom, dns)
        spf = None if offline["result"] == "none" else {"result": offline["result"], "domain": rp_dom, "source": "offline (synthetic DNS fixtures)", "detail": offline["detail"], "ip": info["origin_ip"]}
    dkim = list(ar["dkim"])
    sigs = []
    for v in pe.get_all("DKIM-Signature"):
        d = re.search(r"\bd=([^;\s]+)", v)
        s = re.search(r"\bs=([^;\s]+)", v)
        if d:
            sigs.append({"domain": d.group(1).lower(), "selector": s.group(1) if s else ""})
    if not dkim:
        dkim = [{"result": "unverified", "domain": x["domain"], "selector": x["selector"], "source": "DKIM-Signature header (signature not verified offline)"} for x in sigs]
    spf_aligned = bool(spf and spf["result"] == "pass" and same_org(spf.get("domain", ""), from_dom, suffixes))
    dkim_aligned = any(d["result"] == "pass" and same_org(d["domain"], from_dom, suffixes) for d in dkim)
    dmarc = ar["dmarc"]
    if dmarc is None:
        evaluated = bool(spf and spf["result"] in ("pass", "fail", "softfail", "neutral", "hardfail")) or any(d["result"] in ("pass", "fail") for d in dkim)
        if spf_aligned or dkim_aligned:
            dmarc = {"result": "pass", "from": from_dom, "source": "computed from SPF/DKIM alignment"}
        elif evaluated:
            dmarc = {"result": "fail", "from": from_dom, "source": "computed from SPF/DKIM alignment"}
        else:
            dmarc = {"result": "none", "from": from_dom, "source": "no data"}
    auth = {"authserv": ar["authserv"], "spf": spf, "dkim": dkim, "dmarc": dmarc, "spf_aligned": spf_aligned, "dkim_aligned": dkim_aligned,
            "present": bool(ar_values or spf or sigs), "raw": ar_values}
    f: List[Finding] = []
    if spf and spf["result"] in BAD_SPF:
        f.append(Finding("spf_fail", f"SPF result '{spf['result']}' for {spf.get('domain') or 'the envelope domain'} ({spf['source']})", [spf.get("detail") or f"spf={spf['result']} domain={spf.get('domain', '')}"]))
    elif spf and spf["result"] == "softfail":
        f.append(Finding("spf_softfail", f"SPF softfail for {spf.get('domain', '')} ({spf['source']})", [spf.get("detail", "")] if spf.get("detail") else []))
    fails = [d for d in dkim if d["result"] in ("fail", "permerror")]
    if fails and not any(d["result"] == "pass" for d in dkim):
        f.append(Finding("dkim_fail", f"DKIM {fails[0]['result']} for d={fails[0]['domain']}", [f"d={d['domain']} s={d['selector']} result={d['result']}" for d in fails]))
    if dmarc and dmarc["result"] == "fail":
        f.append(Finding("dmarc_fail", f"DMARC fail for {from_dom or 'From domain'} ({dmarc['source']})", [f"dmarc={dmarc['result']} header.from={dmarc.get('from', '')}"]))
    passing = [d for d in dkim if d["result"] == "pass"]
    if passing and not dkim_aligned and not spf_aligned:
        f.append(Finding("dkim_misaligned", f"DKIM passed for {passing[0]['domain']}, not for the From domain {from_dom}", [f"d={d['domain']}" for d in passing]))
    if not auth["present"]:
        f.append(Finding("auth_absent", "No Authentication-Results, Received-SPF or DKIM-Signature headers", []))
    aligned = bool((dmarc and dmarc["result"] == "pass") or spf_aligned or dkim_aligned)
    return auth, f, aligned
