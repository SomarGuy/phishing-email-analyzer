"""A small offline SPF evaluator (RFC 7208 subset) that reads DNS records from a fixture dictionary.

It never touches the network. Supported: ip4, ip6, a, mx, include, exists, all, redirect, with qualifiers and
CIDR lengths, plus the 10-lookup limit. Not supported (reported as permerror): macros (%{...}) and ptr.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional

QUAL = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
LOOKUP_LIMIT = 10


class _State:
    def __init__(self, dns: Dict[str, dict]):
        self.dns = {k.lower(): v for k, v in dns.items()}
        self.lookups = 0
        self.trace: List[str] = []


def _a_records(st: _State, domain: str, v6: bool) -> List[str]:
    rec = st.dns.get(domain.lower().rstrip("."), {})
    return list(rec.get("AAAA" if v6 else "A", []))


def _mx_hosts(st: _State, domain: str) -> List[str]:
    return list(st.dns.get(domain.lower().rstrip("."), {}).get("MX", []))


def _cidr_match(ip, net_text: str, default_len: int, v6_len: int) -> bool:
    try:
        if "/" not in net_text:
            net_text += "/%d" % (v6_len if ip.version == 6 else default_len)
        return ip in ipaddress.ip_network(net_text, strict=False)
    except ValueError:
        return False


_MOD = re.compile(r"^[A-Za-z][A-Za-z0-9_.\-]*=")
_AMX = re.compile(r"^(a|mx)(?::([^/\s]+))?(?:/(\d+))?(?://(\d+))?$", re.I)


def _check(st: _State, ip, domain: str, depth: int) -> dict:
    if depth > LOOKUP_LIMIT:
        return {"result": "permerror", "detail": "too many nested includes"}  # pragma: no cover - defensive: the lookup counter trips first
    recs = [t for t in st.dns.get(domain.lower(), {}).get("TXT", []) if t.lower().startswith("v=spf1")]
    if not recs:
        return {"result": "none", "detail": f"no SPF record for {domain}"}
    if len(recs) > 1:
        return {"result": "permerror", "detail": f"multiple SPF records for {domain}"}
    redirect: Optional[str] = None

    def over() -> bool:
        st.lookups += 1
        return st.lookups > LOOKUP_LIMIT

    limit_err = {"result": "permerror", "detail": "more than 10 DNS-lookup mechanisms"}
    for term in recs[0].split()[1:]:
        if _MOD.match(term):
            if term.lower().startswith("redirect="):
                redirect = term.split("=", 1)[1]
            continue
        q = "+"
        if term[0] in QUAL:
            q, term = term[0], term[1:]
        if "%{" in term:
            return {"result": "permerror", "detail": "SPF macros are not supported offline"}
        res = QUAL[q]
        name, _, arg = term.partition(":")
        name_l = name.lower().split("/")[0]
        if name_l == "all":
            return {"result": res, "detail": f"{domain}: matched '{'' if q == '+' else q}all'"}
        if name_l in ("ip4", "ip6"):
            if _cidr_match(ip, arg, 32, 128):
                return {"result": res, "detail": f"{domain}: ip matched {name_l}:{arg}"}
        elif name_l in ("a", "mx"):
            m = _AMX.match(term)
            if not m:
                return {"result": "permerror", "detail": f"cannot parse '{term}'"}
            if over():
                return limit_err
            tgt = (m.group(2) or domain).lower()
            l4 = int(m.group(3)) if m.group(3) else 32
            l6 = int(m.group(4)) if m.group(4) else 128
            hosts = [tgt] if name_l == "a" else _mx_hosts(st, tgt)
            for host in hosts:
                if name_l == "mx" and over():
                    return limit_err
                for addr in _a_records(st, host, ip.version == 6):
                    if _cidr_match(ip, f"{addr}/{l6 if ip.version == 6 else l4}", 32, 128):
                        return {"result": res, "detail": f"{domain}: ip matched {'A record of' if name_l == 'a' else 'MX host'} {host}"}
        elif name_l == "exists":
            if over():
                return limit_err
            if _a_records(st, arg, False):
                return {"result": res, "detail": f"{domain}: exists:{arg} resolves"}
        elif name_l == "include":
            if over():
                return limit_err
            sub = _check(st, ip, arg.lower(), depth + 1)
            if sub["result"] == "pass":
                return {"result": res, "detail": f"{domain}: matched via include:{arg} ({sub['detail']})"}
            if sub["result"] in ("none", "permerror"):
                return {"result": "permerror", "detail": f"include:{arg} -> {sub['result']}"}
        elif name_l == "ptr":
            return {"result": "permerror", "detail": "ptr mechanism is not supported offline"}
        else:
            return {"result": "permerror", "detail": f"unknown mechanism '{name}'"}
    if redirect:
        if over():
            return limit_err
        sub = _check(st, ip, redirect.lower(), depth + 1)
        return {"result": "permerror" if sub["result"] == "none" else sub["result"], "detail": f"redirect={redirect}: {sub['detail']}"}
    return {"result": "neutral", "detail": f"{domain}: no mechanism matched and no 'all'"}


def evaluate_spf(ip_text: str, domain: str, dns: Dict[str, dict]) -> dict:
    """Return {'result', 'detail', 'lookups'} for sender IP and envelope domain using only the fixture records."""
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return {"result": "none", "detail": f"not an IP address: {ip_text}", "lookups": 0}
    st = _State(dns)
    out = _check(st, ip, domain.lower().rstrip("."), 0)
    out["lookups"] = st.lookups
    return out
