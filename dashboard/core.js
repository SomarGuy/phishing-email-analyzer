/* core.js: browser port of the phishanalyzer analysis steps (mime, spf, headers, auth, urls, attachments, language, scoring, IOCs).
 * Mirrors phishanalyzer/*.py; tests/test_js_parity.py checks both give the same verdicts and scores on the whole corpus.
 * Static analysis only: it parses strings. It never fetches, resolves, renders or executes anything. */
(function (root) {
  "use strict";
  const T = root.PhishCoreParts.T;
  const { unfold, decodeWords, parseAddress, addrDict, parseDate, formatEpoch, analyzeHtml, extractUrls, parseUrl, queryPairs, isIPv4, isIPv6, obfuscatedIPv4, ipScope,
    registeredDomain, splitRegistered, sameOrg, hostUnicode, scriptsIn, normalizeConfusables, editDistance, defangHost, defangUrl, defangEmail, defangText, defangKnown, decodeBytes, b64bytes, cps, rpartition, partition } = T;
  const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
  const F = (id, detail, evidence) => ({ id, detail, evidence: evidence || [] });

  /* ------------------------------------------------------------------ MIME (small, tolerant) */
  function splitHeaderBody(text) {
    const m = /\r?\n\r?\n/.exec(text);
    if (!m) return [text, ""];
    return [text.slice(0, m.index), text.slice(m.index + m[0].length)];
  }
  function parseHeaderBlock(block) {
    const out = []; let cur = null;
    for (const line of block.split(/\r?\n/)) {
      if (/^[ \t]/.test(line) && cur) { cur[1] += "\r\n" + line; continue; }
      const i = line.indexOf(":");
      if (i <= 0 || /\s/.test(line.slice(0, i))) { continue; }
      cur = [line.slice(0, i), line.slice(i + 1)]; out.push(cur);
    }
    return out.map(([k, v]) => [k, unfold(v)]);
  }
  const hget = (hs, name) => { const n = name.toLowerCase(); const f = hs.find(([k]) => k.toLowerCase() === n); return f ? f[1] : ""; };
  const hgetAll = (hs, name) => { const n = name.toLowerCase(); return hs.filter(([k]) => k.toLowerCase() === n).map(([, v]) => v); };
  function ctypeParts(v) {
    const [main, , rest] = partition(v || "", ";");
    const params = {}; const re = /;?\s*([A-Za-z0-9_*-]+)\s*=\s*(?:"([^"]*)"|([^;\s]*))/g; let m;
    const s = ";" + rest;
    while ((m = re.exec(s)) !== null) params[m[1].toLowerCase()] = m[2] !== undefined ? m[2] : m[3];
    return { type: main.trim().toLowerCase(), params };
  }
  function decodeBody(body, cte) {
    cte = (cte || "7bit").trim().toLowerCase();
    if (cte === "base64") return b64bytes(body);
    if (cte === "quoted-printable") {
      const s = body.replace(/=\r?\n/g, ""); const arr = [];
      for (let i = 0; i < s.length; i++) {
        if (s[i] === "=" && /^[0-9A-Fa-f]{2}$/.test(s.substr(i + 1, 2))) { arr.push(parseInt(s.substr(i + 1, 2), 16)); i += 2; } else arr.push(s.charCodeAt(i) & 255);
      }
      return Uint8Array.from(arr);
    }
    const enc = new TextEncoder().encode(body);
    return enc;
  }
  function parseMime(text) {
    const [hb, body] = splitHeaderBody(text);
    const headers = parseHeaderBlock(hb);
    const texts = [], htmls = [], atts = [];
    const walk = (hs, bodyText, top) => {
      const ct = ctypeParts(hget(hs, "Content-Type") || "text/plain");
      if (ct.type.startsWith("multipart/") && ct.params.boundary) {
        const b = "--" + ct.params.boundary;
        const lines = bodyText.split(/\r?\n/); let part = null; const parts = [];
        for (const line of lines) {
          if (line === b) { if (part) parts.push(part); part = []; }
          else if (line === b + "--") { if (part) parts.push(part); part = null; break; }
          else if (part) part.push(line);
        }
        if (part) parts.push(part);
        for (const p of parts) { const raw = p.join("\r\n"); const [h2, b2] = splitHeaderBody(raw); walk(parseHeaderBlock(h2), b2, false); }
        return;
      }
      const cd = hget(hs, "Content-Disposition");
      const disp = (cd.split(";")[0] || "").trim().toLowerCase();
      let fname = "";
      const mf = /;\s*filename\s*=\s*(?:"([^"]*)"|([^;\s]+))/i.exec(cd) || /;\s*name\s*=\s*(?:"([^"]*)"|([^;\s]+))/i.exec(hget(hs, "Content-Type"));
      if (mf) fname = decodeWords(unfold(mf[1] !== undefined ? mf[1] : mf[2]));
      const data = decodeBody(bodyText, hget(hs, "Content-Transfer-Encoding"));
      if ((ct.type === "text/plain" || ct.type === "text/html") && disp !== "attachment" && !fname) {
        const t = decodeBytes(data, ct.params.charset);
        (ct.type === "text/html" ? htmls : texts).push(t);
        return;
      }
      if (!fname) { const ext = ct.type.split("/").pop().split("+")[0]; fname = ext ? "unnamed." + ext : "unnamed"; }
      atts.push({ filename: fname, content_type: ct.type, disposition: disp || "inline", data });
    };
    walk(headers, body, true);
    return { headers, text: texts.join("\n"), html: htmls.join("\n"), attachments: atts, size: text.length,
      get: (n) => hget(headers, n), getAll: (n) => hgetAll(headers, n) };
  }

  /* ------------------------------------------------------------------ SPF (offline, DNS fixtures only) */
  function parseIp(t) {
    if (isIPv4(t)) { return { v: 4, n: t.split(".").reduce((a, x) => (a << 8n) + BigInt(x), 0n) }; }
    if (!t.includes(":") || !/^[0-9a-fA-F:.]+$/.test(t)) return null;
    let s = t;
    if (s.includes(".")) { const i = s.lastIndexOf(":"); const v4 = s.slice(i + 1); if (!isIPv4(v4)) return null; const q = v4.split(".").map(Number); s = s.slice(0, i + 1) + ((q[0] << 8) | q[1]).toString(16) + ":" + ((q[2] << 8) | q[3]).toString(16); }
    const dc = s.split("::"); if (dc.length > 2) return null;
    const parse = (x) => (x === "" ? [] : x.split(":"));
    const head = parse(dc[0]), rest = dc.length === 2 ? parse(dc[1]) : [];
    const total = 8;
    const groups = dc.length === 2 ? head.concat(new Array(total - head.length - rest.length).fill("0"), rest) : head;
    if (dc.length === 2 && total - head.length - rest.length < 0) return null;
    if (groups.length !== total || groups.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return null;
    let n = 0n; for (const g of groups) n = (n << 16n) + BigInt(parseInt(g, 16));
    return { v: 6, n };
  }
  function cidrMatch(ip, netText, v4len, v6len) {
    if (!netText.includes("/")) netText += "/" + (ip.v === 6 ? v6len : v4len);
    const [addr, , plen] = partition(netText, "/");
    const net = parseIp(addr); if (!net || net.v !== ip.v || !/^\d+$/.test(plen)) return false;
    const bits = ip.v === 4 ? 32 : 128, p = parseInt(plen, 10); if (p > bits) return false;
    const sh = BigInt(bits - p); return (ip.n >> sh) === (net.n >> sh);
  }
  const QUAL = { "+": "pass", "-": "fail", "~": "softfail", "?": "neutral" };
  const LIM = 10;
  function spfCheck(st, ip, domain, depth) {
    if (depth > LIM) return { result: "permerror", detail: "too many nested includes" };
    const dom = (st.dns[domain.toLowerCase()] || {});
    const recs = (dom.TXT || []).filter((t) => t.toLowerCase().startsWith("v=spf1"));
    if (!recs.length) return { result: "none", detail: `no SPF record for ${domain}` };
    if (recs.length > 1) return { result: "permerror", detail: `multiple SPF records for ${domain}` };
    let redirect = null;
    const over = () => { st.lookups += 1; return st.lookups > LIM; };
    const limitErr = { result: "permerror", detail: "more than 10 DNS-lookup mechanisms" };
    const recs0 = (d) => st.dns[d.toLowerCase().replace(/\.$/, "")] || {};
    for (let term of recs[0].split(/\s+/).slice(1)) {
      if (/^[A-Za-z][A-Za-z0-9_.\-]*=/.test(term)) { if (term.toLowerCase().startsWith("redirect=")) redirect = term.split("=").slice(1).join("="); continue; }
      let q = "+";
      if (has(QUAL, term[0])) { q = term[0]; term = term.slice(1); }
      if (term.includes("%{")) return { result: "permerror", detail: "SPF macros are not supported offline" };
      const res = QUAL[q];
      const [name, , arg] = partition(term, ":");
      const nameL = name.toLowerCase().split("/")[0];
      if (nameL === "all") return { result: res, detail: `${domain}: matched '${q === "+" ? "" : q}all'` };
      if (nameL === "ip4" || nameL === "ip6") { if (cidrMatch(ip, arg, 32, 128)) return { result: res, detail: `${domain}: ip matched ${nameL}:${arg}` }; }
      else if (nameL === "a" || nameL === "mx") {
        const m = /^(a|mx)(?::([^/\s]+))?(?:\/(\d+))?(?:\/\/(\d+))?$/i.exec(term);
        if (!m) return { result: "permerror", detail: `cannot parse '${term}'` };
        if (over()) return limitErr;
        const tgt = (m[2] || domain).toLowerCase(), l4 = m[3] ? +m[3] : 32, l6 = m[4] ? +m[4] : 128;
        const hosts = nameL === "a" ? [tgt] : (recs0(tgt).MX || []);
        for (const host of hosts) {
          if (nameL === "mx" && over()) return limitErr;
          for (const addr of (recs0(host)[ip.v === 6 ? "AAAA" : "A"] || [])) if (cidrMatch(ip, `${addr}/${ip.v === 6 ? l6 : l4}`, 32, 128)) return { result: res, detail: `${domain}: ip matched ${nameL === "a" ? "A record of" : "MX host"} ${host}` };
        }
      } else if (nameL === "exists") { if (over()) return limitErr; if ((recs0(arg).A || []).length) return { result: res, detail: `${domain}: exists:${arg} resolves` }; }
      else if (nameL === "include") {
        if (over()) return limitErr;
        const sub = spfCheck(st, ip, arg.toLowerCase(), depth + 1);
        if (sub.result === "pass") return { result: res, detail: `${domain}: matched via include:${arg} (${sub.detail})` };
        if (sub.result === "none" || sub.result === "permerror") return { result: "permerror", detail: `include:${arg} -> ${sub.result}` };
      } else if (nameL === "ptr") return { result: "permerror", detail: "ptr mechanism is not supported offline" };
      else return { result: "permerror", detail: `unknown mechanism '${name}'` };
    }
    if (redirect) {
      if (over()) return limitErr;
      const sub = spfCheck(st, ip, redirect.toLowerCase(), depth + 1);
      return { result: sub.result === "none" ? "permerror" : sub.result, detail: `redirect=${redirect}: ${sub.detail}` };
    }
    return { result: "neutral", detail: `${domain}: no mechanism matched and no 'all'` };
  }
  function evaluateSpf(ipText, domain, dns) {
    const ip = parseIp(ipText);
    if (!ip) return { result: "none", detail: `not an IP address: ${ipText}`, lookups: 0 };
    const lower = {}; for (const k of Object.keys(dns || {})) lower[k.toLowerCase()] = dns[k];
    const st = { dns: lower, lookups: 0 };
    const out = spfCheck(st, ip, domain.toLowerCase().replace(/\.$/, ""), 0);
    out.lookups = st.lookups; return out;
  }

  /* ------------------------------------------------------------------ headers */
  function parseReceived(value) {
    const [body, , datepart] = value.includes(";") ? rpartition(value, ";").map((x, i) => x) : [value, "", ""];
    const mFrom = /\bfrom\s+(\S+)/i.exec(body);
    const strip2 = (s, ch) => { let a = 0, b = s.length; while (a < b && ch.includes(s[a])) a++; while (b > a && ch.includes(s[b - 1])) b--; return s.slice(a, b); };
    const helo = mFrom ? strip2(mFrom[1].trim(), "()[]") : "";
    const paren = /\bfrom\s+\S+\s*\(([^)]*)\)/i.exec(body);
    const ptxt = paren ? paren[1] : "";
    let ip = ""; const mIp = /\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]/.exec(ptxt || body);
    if (mIp) ip = mIp[1];
    let rdns = "";
    for (const tok of ptxt.replace(/\[[^\]]*\]/g, " ").trim().split(/\s+/)) {
      if (tok && !/^(helo|ehlo)/i.test(tok) && !tok.startsWith("[") && !["postfix", "authenticated"].includes(tok.toLowerCase())) { rdns = strip2(tok, ",").toLowerCase(); break; }
    }
    const mBy = /\bby\s+(\S+)/i.exec(body), mWith = /\bwith\s+(\S+)/i.exec(body);
    const ts = parseDate(datepart);
    return { from_helo: helo.toLowerCase(), rdns, ip, ip_scope: ip ? ipScope(ip) : "", by: (mBy ? mBy[1] : "").toLowerCase(), with: mWith ? mWith[1] : "", time: ts, time_text: formatEpoch(ts), raw: value };
  }
  function basicInfo(pe, cfg) {
    const th = cfg.thresholds;
    const frm = parseAddress(pe.get("From")), rto = parseAddress(pe.get("Reply-To"));
    const rpRaw = pe.get("Return-Path");
    const rpa = rpRaw && !["<>", ""].includes(rpRaw.trim()) ? parseAddress(rpRaw) : null;
    const hops = pe.getAll("Received").map(parseReceived).reverse();
    hops.forEach((h, i) => { h.index = i + 1; h.delta_s = null; h.anomalies = []; });
    let prev = null;
    for (const h of hops) {
      if (prev && prev.time !== null && h.time !== null) {
        h.delta_s = h.time - prev.time;
        if (h.delta_s < -th.received_backwards_seconds) h.anomalies.push("time goes backwards");
        else if (h.delta_s > th.received_long_delay_hours * 3600) h.anomalies.push(`delay of more than ${th.received_long_delay_hours} hours`);
      }
      if (h.time !== null) prev = h;
    }
    let originIp = "";
    for (const h of hops) if (h.ip && (h.ip_scope === "public" || h.ip_scope === "documentation")) { originIp = h.ip; break; }
    const dateRaw = pe.get("Date"), de = parseDate(dateRaw);
    return { from: addrDict(frm), reply_to: addrDict(rto), return_path: addrDict(rpa), to: pe.get("To"), subject: decodeWords(pe.get("Subject")), message_id: pe.get("Message-ID"),
      date: dateRaw, date_epoch: de, date_text: formatEpoch(de), hops, origin_ip: originIp, list_id: pe.get("List-Id"), list_unsubscribe: pe.get("List-Unsubscribe") };
  }
  const hasRun = (toks, run) => { for (let i = 0; i + run.length <= toks.length; i++) if (run.every((x, j) => toks[i + j] === x)) return true; return false; };
  function brandMatches(host, cfg) {
    const suf = cfg.multi_label_suffixes, th = cfg.thresholds;
    const [sub, sld, rd] = splitRegistered(hostUnicode(host.toLowerCase()), suf);
    const normSld = normalizeConfusables(sld);
    const toks = sld.split("-").filter(Boolean).map(normalizeConfusables);
    const subLabels = sub.map(normalizeConfusables), subJoined = sub.join(".");
    const out = [];
    for (const b of cfg.lists.brands) {
      const legit = b.domains.map((d) => d.toLowerCase());
      if (legit.some((d) => registeredDomain(d, suf) === rd)) continue;
      const bl = b.label, nb = normalizeConfusables(bl), longEnough = cps(bl).length >= th.min_brand_label_len;
      const k = bl.length < th.lookalike_short_len ? th.lookalike_short_distance : th.lookalike_max_distance;
      let kind = "", where = "domain";
      if (sld === bl) kind = "same name, different domain";
      else if (longEnough && normSld === nb) kind = "look-alike characters";
      else if (longEnough && Math.abs(cps(sld).length - cps(bl).length) <= k && editDistance(sld, bl) <= k) kind = "typo of the brand name";
      else if (longEnough && toks.length > nb.split("-").length && hasRun(toks, nb.split("-"))) { kind = "brand name inside the domain"; where = "domain-token"; }
      else if (longEnough && !nb.includes("-") && toks.length > 1 && toks.some((t) => t !== nb && cps(t).length >= th.min_brand_label_len && editDistance(t, nb) <= 1)) { kind = "typo of the brand name inside the domain"; where = "domain-token"; }
      else if (longEnough && (subLabels.includes(nb) || legit.some((d) => subJoined.includes(d)))) { kind = "brand domain used as a subdomain"; where = "subdomain"; }
      if (kind) out.push({ brand: b.name, kind, domain: rd, where, org: !!b.org });
    }
    return out;
  }
  const nameHit = (display, name) => new RegExp("(?<![A-Za-z])" + T.ESC(name.toLowerCase()) + "(?![A-Za-z])").test(display.toLowerCase());
  const MSGID = /^<[^<>@\s]+@[^<>@\s]+\.[^<>@\s]+>$/;
  function headerFindings(pe, info, auth, aligned, cfg) {
    const suf = cfg.multi_label_suffixes, th = cfg.thresholds, out = [];
    const frm = info.from, rto = info.reply_to, rp = info.return_path, fromDom = frm ? frm.domain : "";
    const orgDomains = cfg.organisation.domains.map((d) => d.toLowerCase());
    const brands = cfg.lists.brands.filter((b) => !b.org);
    const freemail = new Set(cfg.lists.freemail.map((d) => d.toLowerCase()));
    const fromIsOrg = orgDomains.some((d) => sameOrg(fromDom, d, suf));
    const fromIsFree = freemail.has(registeredDomain(fromDom, suf));
    if (rto && frm && !sameOrg(rto.domain, fromDom, suf) && !info.list_id) out.push(F("reply_to_mismatch", `Reply-To domain ${rto.domain} differs from From domain ${fromDom}`, [`From: ${frm.addr}`, `Reply-To: ${rto.addr}`]));
    if (rp && frm && !sameOrg(rp.domain, fromDom, suf) && !aligned) out.push(F("return_path_mismatch", `Return-Path domain ${rp.domain} differs from From domain ${fromDom}`, [`Return-Path: ${rp.addr}`, `From: ${frm.addr}`]));
    if (frm && frm.display) {
      const disp = frm.display;
      const re = /[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/g; let m;
      while ((m = re.exec(disp)) !== null) {
        if (!sameOrg(m[1].toLowerCase(), fromDom, suf)) { out.push(F("display_name_email_spoof", `Display name "${disp}" shows ${m[0]} but the real sender is ${frm.addr}`, [`Display name: ${disp}`, `Actual address: ${frm.addr}`])); break; }
      }
      let hitBrand = null;
      for (const b of brands) if (nameHit(disp, b.name) && !b.domains.some((d) => registeredDomain(fromDom, suf) === registeredDomain(d, suf))) { hitBrand = b.name; break; }
      if (hitBrand) out.push(F("display_name_brand_spoof", `Display name uses '${hitBrand}' but the sender domain is ${fromDom}`, [`Display name: ${disp}`, `Sender domain: ${fromDom}`]));
      let hitProt = null;
      if (!fromIsOrg) for (const p of cfg.organisation.protected_names) if (nameHit(disp, p.name)) { hitProt = p; break; }
      if (hitProt) out.push(F("display_name_exec_spoof", `Display name '${disp}' matches protected name '${hitProt.name}' (${hitProt.role}) but the domain is ${fromDom}`, [`Display name: ${disp}`, `Sender domain: ${fromDom}`]));
      if ((hitBrand || hitProt) && fromIsFree) out.push(F("freemail_display_spoof", `Free-mail address ${frm.addr} uses the name '${hitBrand || hitProt.name}'`, [`From: ${disp} <${frm.addr}>`]));
    }
    const seen = new Set();
    for (const [label, a] of [["From", frm], ["Reply-To", rto], ["Return-Path", rp]]) {
      if (!a || !a.domain || seen.has(a.domain)) continue;
      seen.add(a.domain);
      for (const m of brandMatches(a.domain, cfg)) if (m.where === "domain" || m.where === "domain-token") { out.push(F("sender_domain_lookalike", `${label} domain ${a.domain} imitates ${m.brand} (${m.kind})`, [`${label}: ${a.addr}`, `Imitates: ${m.brand}`])); break; }
    }
    const mid = info.message_id;
    if (!mid) out.push(F("message_id_missing", "No Message-ID header", []));
    else if (!MSGID.test(mid.trim()) || rpartition(mid.trim().toLowerCase(), "@")[2].startsWith("localhost")) out.push(F("message_id_malformed", `Message-ID ${mid} is not of the form <unique@domain>`, [`Message-ID: ${mid}`]));
    else {
      const mdom = rpartition(mid.trim().replace(/^<|>$/g, ""), "@")[2].toLowerCase();
      const related = sameOrg(mdom, fromDom, suf) || (rp && sameOrg(mdom, rp.domain, suf));
      if (!related && !aligned && frm) out.push(F("message_id_domain_mismatch", `Message-ID domain ${mdom} is unrelated to the sender domain ${fromDom}`, [`Message-ID: ${mid}`]));
    }
    const hops = info.hops;
    if (!hops.length) out.push(F("received_missing", "No Received headers", []));
    else {
      const bad = hops.filter((h) => h.anomalies.length);
      if (bad.length) out.push(F("received_time_anomaly", "Received hop timestamps: " + Array.from(new Set(bad.flatMap((h) => h.anomalies))).sort().join("; "), bad.map((h) => `hop ${h.index} (${h.by || "unknown"}): ${h.anomalies.join(", ")}, delta ${h.delta_s}s`)));
      const origin = hops[0];
      if (origin.from_helo && !["private", "loopback", ""].includes(origin.ip_scope)) {
        const helo = origin.from_helo, rdns = origin.rdns;
        if (!rdns || rdns === "unknown" || !sameOrg(helo, rdns, suf)) out.push(F("received_helo_mismatch", `Origin hop HELO '${helo}' vs reverse DNS '${rdns || "none"}' (${origin.ip})`, [`Received: ${origin.raw.slice(0, 160)}`]));
      }
      if (hops.length >= th.received_many_hops) out.push(F("received_many_hops", `${hops.length} Received headers`, []));
    }
    if (!info.date || info.date_epoch === null) out.push(F("date_invalid", !info.date ? "Date header is missing" : `Date header unparseable: ${info.date}`, []));
    else {
      const times = hops.filter((h) => h.time !== null).map((h) => h.time);
      if (times.length) {
        const mx = Math.max(...times), mn = Math.min(...times);
        if (info.date_epoch - mx > th.date_future_hours * 3600) out.push(F("date_future", `Date ${info.date_text} is ${Math.floor((info.date_epoch - mx) / 3600)} h after the last Received hop (${formatEpoch(mx)})`, [`Date: ${info.date}`]));
        else if (mn - info.date_epoch > th.date_stale_days * 86400) out.push(F("date_stale", `Date ${info.date_text} is ${Math.floor((mn - info.date_epoch) / 86400)} days before the first Received hop (${formatEpoch(mn)})`, [`Date: ${info.date}`]));
      }
    }
    return out;
  }

  /* ------------------------------------------------------------------ authentication */
  function parseAuthResults(value) {
    const out = { authserv: "", spf: null, dkim: [], dmarc: null, raw: value };
    const parts = value.split(";").map((p) => p.trim());
    if (parts.length) out.authserv = parts[0] ? parts[0].split(/\s+/)[0] : "";
    for (const seg of parts.slice(1)) {
      const m = /^([a-z0-9-]+)=([a-z]+)/i.exec(seg); if (!m) continue;
      const method = m[1].toLowerCase(), result = m[2].toLowerCase(), props = {};
      const re = /([a-z0-9-]+\.[a-z0-9-]+)=([^\s;]+)/gi; let pm;
      while ((pm = re.exec(seg)) !== null) props[pm[1].toLowerCase()] = pm[2].replace(/^"|"$/g, "");
      if (method === "spf") { const dom = props["smtp.mailfrom"] || props["smtp.helo"] || ""; out.spf = { result, domain: rpartition(dom, "@")[2].toLowerCase(), source: "Authentication-Results" }; }
      else if (method === "dkim") { const d = props["header.d"] || rpartition(props["header.i"] || "", "@")[2]; out.dkim.push({ result, domain: d.toLowerCase(), selector: props["header.s"] || "", source: "Authentication-Results" }); }
      else if (method === "dmarc") out.dmarc = { result, from: (props["header.from"] || "").toLowerCase(), source: "Authentication-Results" };
    }
    return out;
  }
  function analyzeAuth(pe, info, cfg, dns) {
    const suf = cfg.multi_label_suffixes, fromDom = info.from ? info.from.domain : "";
    const arValues = pe.getAll("Authentication-Results");
    const ar = arValues.length ? parseAuthResults(arValues[0]) : { authserv: "", spf: null, dkim: [], dmarc: null, raw: "" };
    let spf = ar.spf;
    if (!spf) {
      const rs = pe.get("Received-SPF"); const m = rs ? /^\s*(pass|fail|softfail|neutral|none|permerror|temperror)\b/i.exec(rs) : null;
      if (m) { const env = /envelope-from="?<?([^\s;">]+)/i.exec(rs); spf = { result: m[1].toLowerCase(), domain: env ? rpartition(env[1], "@")[2].toLowerCase() : "", source: "Received-SPF" }; }
    }
    const rpDom = (info.return_path && info.return_path.domain) || fromDom;
    if (!spf && dns && info.origin_ip && rpDom) {
      const off = evaluateSpf(info.origin_ip, rpDom, dns);
      if (off.result !== "none") spf = { result: off.result, domain: rpDom, source: "offline (synthetic DNS fixtures)", detail: off.detail, ip: info.origin_ip };
    }
    let dkim = ar.dkim.slice(); const sigs = [];
    for (const v of pe.getAll("DKIM-Signature")) { const d = /\bd=([^;\s]+)/.exec(v), s = /\bs=([^;\s]+)/.exec(v); if (d) sigs.push({ domain: d[1].toLowerCase(), selector: s ? s[1] : "" }); }
    if (!dkim.length) dkim = sigs.map((x) => ({ result: "unverified", domain: x.domain, selector: x.selector, source: "DKIM-Signature header (signature not verified offline)" }));
    const spfAligned = !!(spf && spf.result === "pass" && sameOrg(spf.domain || "", fromDom, suf));
    const dkimAligned = dkim.some((d) => d.result === "pass" && sameOrg(d.domain, fromDom, suf));
    let dmarc = ar.dmarc;
    if (!dmarc) {
      const evaluated = !!(spf && ["pass", "fail", "softfail", "neutral", "hardfail"].includes(spf.result)) || dkim.some((d) => d.result === "pass" || d.result === "fail");
      if (spfAligned || dkimAligned) dmarc = { result: "pass", from: fromDom, source: "computed from SPF/DKIM alignment" };
      else if (evaluated) dmarc = { result: "fail", from: fromDom, source: "computed from SPF/DKIM alignment" };
      else dmarc = { result: "none", from: fromDom, source: "no data" };
    }
    const auth = { authserv: ar.authserv, spf, dkim, dmarc, spf_aligned: spfAligned, dkim_aligned: dkimAligned, present: !!(arValues.length || spf || sigs.length), raw: arValues };
    const f = [];
    if (spf && (spf.result === "fail" || spf.result === "hardfail")) f.push(F("spf_fail", `SPF result '${spf.result}' for ${spf.domain || "the envelope domain"} (${spf.source})`, [spf.detail || `spf=${spf.result} domain=${spf.domain || ""}`]));
    else if (spf && spf.result === "softfail") f.push(F("spf_softfail", `SPF softfail for ${spf.domain || ""} (${spf.source})`, spf.detail ? [spf.detail] : []));
    const fails = dkim.filter((d) => d.result === "fail" || d.result === "permerror");
    if (fails.length && !dkim.some((d) => d.result === "pass")) f.push(F("dkim_fail", `DKIM ${fails[0].result} for d=${fails[0].domain}`, fails.map((d) => `d=${d.domain} s=${d.selector} result=${d.result}`)));
    if (dmarc && dmarc.result === "fail") f.push(F("dmarc_fail", `DMARC fail for ${fromDom || "From domain"} (${dmarc.source})`, [`dmarc=${dmarc.result} header.from=${dmarc.from || ""}`]));
    const passing = dkim.filter((d) => d.result === "pass");
    if (passing.length && !dkimAligned && !spfAligned) f.push(F("dkim_misaligned", `DKIM passed for ${passing[0].domain}, not for the From domain ${fromDom}`, passing.map((d) => `d=${d.domain}`)));
    if (!auth.present) f.push(F("auth_absent", "No Authentication-Results, Received-SPF or DKIM-Signature headers", []));
    const aligned = !!((dmarc && dmarc.result === "pass") || spfAligned || dkimAligned);
    return [auth, f, aligned];
  }

  /* ------------------------------------------------------------------ urls */
  const MAX_LINKS = 100;
  const SCRIPT_SCHEMES = ["javascript", "vbscript", "data"];
  function collectLinks(pe) {
    const seen = new Set(), order = [];
    const add = (url, text, source) => { url = url.trim(); if (!url || seen.has(url) || order.length >= MAX_LINKS) return; seen.add(url); order.push({ url, text, source }); };
    let extra = [];
    if (pe.html) { const h = analyzeHtml(pe.html); for (const lk of h.links) add(lk.href, lk.text, "html link"); extra = extractUrls(h.text); }
    for (const u of extra) add(u, "", "html text");
    for (const u of extractUrls(pe.text)) add(u, "", "plain text");
    return order;
  }
  function idnHomograph(host) {
    for (const label of hostUnicode(host).split(".")) {
      if (cps(label).every((c) => c.codePointAt(0) < 128)) continue;
      const sc = scriptsIn(label);
      if (sc.length > 1) return `label '${label}' mixes scripts (${sc.join(", ")})`;
      if (sc.length && ["cyrillic", "greek", "armenian"].includes(sc[0])) {
        const norm = normalizeConfusables(label);
        if (cps(norm).every((c) => c.codePointAt(0) < 128)) return `label '${label}' is ${sc[0]} lookalike of '${norm}'`;
      }
    }
    return null;
  }
  const TEXT_HOST = /(?:https?:\/\/)?((?:[a-z0-9\u00a1-\uffff-]+\.)+[a-z\u00a1-\uffff]{2,})(?::\d+)?(?:\/\S*)?/i;
  function analyzeLink(rec, cfg, senderDomains) {
    const suf = cfg.multi_label_suffixes, th = cfg.thresholds, lists = cfg.lists;
    const url = rec.url, u = parseUrl(url), flags = [], host = u.host;
    const out = { url, defanged: defangUrl(url), text: rec.text, source: rec.source, host, host_unicode: "", domain: "", scheme: u.scheme, flags };
    const flag = (id, detail) => flags.push({ id, detail });
    if (SCRIPT_SCHEMES.includes(u.scheme)) { flag("url_script_scheme", `${u.scheme}: URL`); return out; }
    if (!["http", "https", "ftp"].includes(u.scheme) || !host) return out;
    const uni = hostUnicode(host); out.host_unicode = uni !== host ? uni : "";
    const senderRds = senderDomains.filter(Boolean).map((d) => registeredDomain(d, suf));
    const safe = lists.safe_url_hosts.map((h) => h.toLowerCase()).includes(host);
    const ip = (isIPv4(host) || isIPv6(host)) ? host : "", obf = obfuscatedIPv4(host);
    let rd = "";
    if (obf) { flag("url_ip_host", `Host is the IP address ${obf} written as '${host}'`); flag("url_obfuscated", `IP address hidden as '${host}'`); }
    else if (ip) flag("url_ip_host", `Host is the IP address ${ip} (${ipScope(ip)})`);
    if (!(ip || obf)) {
      rd = registeredDomain(uni, suf); out.domain = rd;
      const why = idnHomograph(host);
      if (why) flag("url_idn_homograph", `Internationalised host ${host}: ${why}`);
      if (!safe) for (const m of brandMatches(host, cfg)) {
        if (m.where === "domain" && !(why && m.kind === "look-alike characters")) flag("url_lookalike_domain", `${rd} imitates ${m.brand} (${m.kind})`);
        else if (m.where === "domain-token") flag("url_brand_in_domain", `${m.brand} used inside the domain ${rd}`);
        else if (m.where === "subdomain") flag("url_brand_in_subdomain", `${m.brand} used as a subdomain of ${rd}`);
      }
      const shorts = lists.shorteners.map((d) => d.toLowerCase());
      if (shorts.includes(rd) || shorts.includes(host)) flag("url_shortener", `${rd} is a URL shortener; the destination is hidden`);
      const tld = uni.slice(uni.lastIndexOf(".") + 1);
      if (lists.suspicious_tlds.map((t) => t.toLowerCase()).includes(tld)) flag("url_suspicious_tld", `Top-level domain .${tld} is heavily abused`);
      if (host.includes("%") || uni.split(".").length - rd.split(".").length >= th.deep_subdomains) flag("url_obfuscated", host.includes("%") ? "Percent-encoded host" : `${uni.split(".").length} labels in the host name`);
    }
    if (cps(url).length > th.long_url_chars) flag("url_obfuscated", `Very long URL (${cps(url).length} characters)`);
    if (u.userinfo) flag("url_userinfo", `URL has credentials-style prefix '${u.userinfo}@' before the real host ${host}`);
    const linkIsSender = !!rd && senderRds.includes(rd);
    const txt = rec.text || "", m = txt ? TEXT_HOST.exec(txt) : null;
    if (m && rec.source === "html link") {
      const shown = m[1].toLowerCase();
      const shownRd = registeredDomain(shown.startsWith("xn--") ? hostUnicode(shown) : shown, suf);
      if (rd && shownRd !== rd && !(obf || ip)) flag("url_text_mismatch", `Link text shows ${shown} but the link goes to ${host}`);
      else if ((ip || obf) && shown) flag("url_text_mismatch", `Link text shows ${shown} but the link goes to ${host}`);
    }
    if (!linkIsSender) {
      const rp = lists.redirect_params.map((p) => p.toLowerCase());
      for (const [k, v] of queryPairs(u.query)) {
        if (rp.includes(k)) {
          const t = /^[a-z][a-z0-9+.\-]*:\/\//i.test(v) ? v : "";
          if (t) { const thHost = parseUrl(t).host, trd = registeredDomain(thHost, suf); if (trd && trd !== rd && !senderRds.includes(trd)) { flag("url_redirect_param", `Parameter '${k}' carries another destination (${thHost})`); break; } }
        }
      }
    }
    if (!linkIsSender && !safe) {
      const low = (u.path + "?" + u.query + " " + host).toLowerCase();
      const hits = lists.login_keywords.filter((w) => low.includes(w));
      if (hits.length) flag("url_login_keywords", `URL contains credential keywords (${hits.slice(0, 3).join(", ")}) and is not on the sender's domain`);
    }
    return out;
  }
  function groupFlags(items, labelOf, more) {
    const byId = new Map(), details = new Map();
    for (const it of items) for (const f of it.flags) { if (!byId.has(f.id)) { byId.set(f.id, []); details.set(f.id, f.detail); } byId.get(f.id).push(labelOf(it, f)); }
    return Array.from(byId, ([id, ev]) => F(id, details.get(id) + (ev.length > 1 ? ` (+${ev.length - 1} ${more})` : ""), ev));
  }
  function analyzeUrls(pe, cfg, senderDomains) {
    const links = collectLinks(pe).map((r) => analyzeLink(r, cfg, senderDomains));
    return [links, groupFlags(links, (lk, f) => `${lk.defanged} - ${f.detail}`, "more link(s)")];
  }

  /* ------------------------------------------------------------------ attachments */
  async function sha256Hex(bytes) { return sha256(bytes); }
  function sha256(bytes) {
    const K = new Uint32Array([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
    const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    const len = bytes.length, padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
    padded.set(bytes); padded[len] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, Math.floor((len * 8) / 0x100000000)); dv.setUint32(padded.length - 4, (len * 8) >>> 0);
    const w = new Uint32Array(64);
    const rr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let off = 0; off < padded.length; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) { const s0 = rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >>> 3), s1 = rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >>> 10); w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0; }
      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) {
        const S1 = rr(e, 6) ^ rr(e, 11) ^ rr(e, 25), ch = (e & f) ^ (~e & g), t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
        const S0 = rr(a, 2) ^ rr(a, 13) ^ rr(a, 22), mj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + mj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
    return Array.from(H, (x) => (x >>> 0).toString(16).padStart(8, "0")).join("");
  }
  const startsWith = (data, arr, off) => { off = off || 0; if (data.length < off + arr.length) return false; for (let i = 0; i < arr.length; i++) if (data[off + i] !== arr[i]) return false; return true; };
  const ascii = (s) => Array.from(s, (c) => c.charCodeAt(0));
  const latin1 = (data, n) => { let s = ""; const m = Math.min(data.length, n || data.length); for (let i = 0; i < m; i++) s += String.fromCharCode(data[i]); return s; };
  function sniff(data) {
    if (startsWith(data, [0x4d, 0x5a])) return "pe";
    if (startsWith(data, ascii("%PDF-"))) return "pdf";
    if (startsWith(data, [0x50, 0x4b, 3, 4]) || startsWith(data, [0x50, 0x4b, 5, 6])) return "zip";
    if (startsWith(data, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return "ole";
    if (startsWith(data, ascii("Rar!"))) return "rar";
    if (startsWith(data, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return "7z";
    if (startsWith(data, [0x7f, 0x45, 0x4c, 0x46])) return "elf";
    if (startsWith(data, [0x4c, 0, 0, 0]) && startsWith(data, [1, 0x14, 2, 0], 4)) return "lnk";
    if (startsWith(data, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return "png";
    if (startsWith(data, [0xff, 0xd8, 0xff])) return "jpg";
    if (startsWith(data, ascii("GIF8"))) return "gif";
    if (startsWith(data, ascii("{\\rtf"))) return "rtf";
    if (data.length > 0x8005 && startsWith(data, ascii("CD001"), 0x8001)) return "iso";
    let head = latin1(data, 2048); head = head.replace(/^[\xef\xbb\xbf \t\r\n]+/, "").toLowerCase();
    if (["<!doctype html", "<html", "<head", "<body", "<script", "<meta", "<form", "<a ", "<div"].some((p) => head.startsWith(p))) return "html";
    if ((head.startsWith("<svg") || head.startsWith("<?xml")) && latin1(data, 4096).toLowerCase().includes("<svg")) return "svg";
    if (head.startsWith("#!")) return "script";
    const first = data.slice(0, 512); let texty = first.length > 0;
    for (const b of first) { if (!(b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127) || b >= 128) || b === 0) { texty = false; break; } }
    return texty ? "text" : "unknown";
  }
  const BIDI = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069";
  function splitName(name) {
    const had = cps(name).some((c) => BIDI.includes(c));
    const clean = cps(name).filter((c) => !BIDI.includes(c)).join("");
    const base = clean.split("/").pop().split("\\").pop();
    const parts = base.split(".");
    const exts = parts.length > 1 ? parts.slice(1).filter(Boolean).map((p) => p.toLowerCase()) : [];
    return [base, exts, had];
  }
  function zipInfo(data) {
    const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
    let eocd = -1;
    for (let i = data.length - 22; i >= Math.max(0, data.length - 22 - 65535); i--) if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    if (eocd < 0) return null;
    const total = dv.getUint16(eocd + 10, true), cdOff = dv.getUint32(eocd + 16, true);
    const entries = []; let off = cdOff, count = 0;
    for (let n = 0; n < total; n++) {
      if (off + 46 > data.length || dv.getUint32(off, true) !== 0x02014b50) return null;
      const flag = dv.getUint16(off + 8, true), size = dv.getUint32(off + 24, true), nl = dv.getUint16(off + 28, true), el = dv.getUint16(off + 30, true), cl = dv.getUint16(off + 32, true);
      const name = latin1(data.slice(off + 46, off + 46 + nl));
      count++; if (entries.length < 500) entries.push({ name, size, encrypted: !!(flag & 1) });
      off += 46 + nl + el + cl;
    }
    return { entries, count, encrypted: entries.some((e) => e.encrypted) };
  }
  const EXPECTED = { pdf: ["pdf"], docx: ["zip"], xlsx: ["zip"], pptx: ["zip"], docm: ["zip"], xlsm: ["zip"], pptm: ["zip"], zip: ["zip"], doc: ["ole", "rtf"], xls: ["ole"], ppt: ["ole"], rtf: ["rtf"], png: ["png"], jpg: ["jpg"], jpeg: ["jpg"], gif: ["gif"], rar: ["rar"], "7z": ["7z"], txt: ["text"], csv: ["text"], exe: ["pe"], dll: ["pe"] };
  const BINARY_DANGEROUS = ["pe", "elf", "lnk"];
  function htmlPayload(text) {
    const low = text.toLowerCase(), smug = [];
    if (/new\s+blob\s*\(/.test(low)) smug.push("builds a Blob in the browser");
    if (low.includes("createobjecturl") || low.includes("mssaveoropenblob") || low.includes("mssaveblob")) smug.push("saves it via createObjectURL / msSaveOrOpenBlob");
    if (/\batob\s*\(/.test(low) || low.includes("uint8array")) smug.push("decodes embedded base64 (atob / Uint8Array)");
    if (/\.download\s*=|download\s*=\s*["']/.test(low)) smug.push("sets a download file name");
    if (/\.click\s*\(/.test(low)) smug.push("clicks it programmatically");
    if (/[A-Za-z0-9+/=]{400,}/.test(text)) smug.push("contains a large base64 blob");
    if (/\beval\s*\(|\bunescape\s*\(|fromcharcode/.test(low)) smug.push("uses eval/unescape/fromCharCode obfuscation");
    const h = analyzeHtml(text), formHosts = [];
    const re = /<form[^>]*\baction\s*=\s*["']?https?:\/\/([^/"'\s>:]+)/g; let m;
    while ((m = re.exec(low)) !== null) formHosts.push(m[1].toLowerCase());
    return { smuggling: smug, password_form: !!h.password_input, form_hosts: formHosts };
  }
  const PW_HINT = /pass(?:word|code)\s*(?:to (?:open|unlock|extract)[^:.\n]{0,20})?\s*(?:is|:|=)\s*[:"'\-]?\s*\S{3,}/i;
  function analyzeAttachment(part, cfg) {
    const lists = cfg.lists, data = part.data, [base, exts, hadBidi] = splitName(part.filename);
    const ext = exts.length ? exts[exts.length - 1] : "", kind = sniff(data), flags = [];
    const flag = (id, detail) => flags.push({ id, detail });
    const sha = sha256(data);
    const rec = { filename: part.filename, display_name: base, content_type: part.content_type, size: data.length, extension: ext, detected_type: kind, md5: "", sha1: "", sha256: sha, flags, archive: null, notes: [] };
    const exe = lists.executable_exts, macro = lists.macro_exts, decoy = lists.decoy_exts, htmlExts = lists.html_exts;
    if (exe.includes(ext) || BINARY_DANGEROUS.includes(kind) || kind === "script") flag("attachment_executable", `${base} is a ${exe.includes(ext) ? "file of type ." + ext : "detected " + kind + " file"} that can run code`);
    if (hadBidi) flag("attachment_rtl_override", `File name contains a right-to-left override; it is displayed differently from its real name '${base}'`);
    const expect = has(EXPECTED, ext) ? EXPECTED[ext] : null; let mism = "";
    if (BINARY_DANGEROUS.includes(kind) && !exe.includes(ext)) mism = `content is ${kind} but name ends in .${ext || "(none)"}`;
    else if (expect !== null && kind !== "unknown" && !expect.includes(kind) && !((ext === "txt" || ext === "csv") && ["html", "script", "svg"].includes(kind))) mism = `name says .${ext} but the content is ${kind}`;
    else if ((ext === "txt" || ext === "csv") && ["html", "script", "svg"].includes(kind)) mism = `name says .${ext} but the content is ${kind}`;
    if (mism) flag("attachment_magic_mismatch", mism);
    if (exts.length >= 2 && decoy.includes(exts[exts.length - 2]) && (exe.includes(exts[exts.length - 1]) || htmlExts.includes(exts[exts.length - 1]) || macro.includes(exts[exts.length - 1]))) flag("attachment_double_extension", `'${base}' pretends to be .${exts[exts.length - 2]} but really ends in .${exts[exts.length - 1]}`);
    const hasVba = () => { const s = latin1(data); return s.includes("_VBA_PROJECT") || s.includes("V\u0000B\u0000A\u0000") || s.includes("Attribut\u0000e VB_Name") || s.includes("Attribute VB_Name"); };
    if (macro.includes(ext)) flag("attachment_macro", `.${ext} is a macro-enabled Office format`);
    else if (kind === "ole" && lists.ole_exts.includes(ext) && hasVba()) flag("attachment_macro", "Legacy Office file contains a VBA project");
    else if (kind === "zip") { const zi = zipInfo(data); if (zi && zi.entries.some((e) => e.name.toLowerCase().endsWith("vbaproject.bin"))) flag("attachment_macro", "Office Open XML package contains vbaProject.bin"); }
    if (kind === "zip" || ext === "zip") {
      const zi = kind === "zip" ? zipInfo(data) : null;
      if (zi) {
        rec.archive = { format: "zip", count: zi.count, encrypted: zi.encrypted, entries: zi.entries.slice(0, 20) };
        if (!zi.entries.some((e) => e.name === "[Content_Types].xml")) {
          const bad = [];
          for (const e of zi.entries) { const [, es] = splitName(e.name); if (es.length && (exe.includes(es[es.length - 1]) || macro.includes(es[es.length - 1]))) bad.push(e.name); }
          if (bad.length) flag("archive_contains_executable", `Archive contains ${bad.slice(0, 3).join(", ")}${bad.length > 3 ? " ..." : ""}`);
        }
        if (zi.encrypted) flag("archive_encrypted", "Archive entries are password-protected, which hides content from mail scanners");
      }
    } else if (kind === "rar" || kind === "7z") rec.notes.push(`${kind} contents are not inspected by this tool`);
    if (kind === "html" || kind === "svg" || htmlExts.includes(ext)) {
      const text = decodeBytes(data.slice(0, 2000000), "utf-8"), isSvg = kind === "svg" || ext === "svg", pay = htmlPayload(text);
      if (isSvg) { const low = text.toLowerCase(); if (low.includes("<script") || /\bon(load|click|mouseover)\s*=/.test(low) || low.includes("javascript:")) flag("svg_script", "SVG image contains script or event handlers"); }
      else {
        flag("html_attachment", "HTML attachment opens in the user's browser with local-file privileges");
        if (pay.smuggling.length >= 2) flag("html_smuggling", "HTML smuggling indicators: " + pay.smuggling.slice(0, 5).join("; "));
        if (pay.password_form) flag("html_credential_form", `HTML attachment contains a password field${pay.form_hosts.length ? " posting to " + pay.form_hosts[0] : ""}`);
      }
      rec.html = pay;
    }
    if (kind === "pdf") {
      const raw = latin1(data);
      const hits = ["/JavaScript", "/JS", "/OpenAction", "/Launch", "/EmbeddedFile", "/AA"].filter((t) => new RegExp(T.ESC(t) + "(?![A-Za-z])").test(raw));
      if (hits.length) flag("pdf_active_content", "PDF contains " + hits.join(", "));
    }
    const kb = cfg.known_bad_sha256 || {};
    if (Object.keys(kb).map((h) => h.toLowerCase()).includes(sha)) flag("attachment_known_bad", `SHA-256 matches a known-bad sample (${kb[sha] !== undefined ? kb[sha] : "list"})`);
    return rec;
  }
  function analyzeAttachments(pe, cfg, visible) {
    const body = (pe.text || "") + "\n" + (visible || "");
    const recs = pe.attachments.map((p) => analyzeAttachment(p, cfg));
    const isArc = (r) => r.archive !== null || ["zip", "rar", "7z"].includes(r.extension);
    const hint = recs.some(isArc) ? PW_HINT.exec(body) : null;
    if (hint) { const r = recs.find(isArc); r.flags.push({ id: "archive_password_hint", detail: "Message text gives a password for the attachment: '" + hint[0].slice(0, 60) + "'" }); }
    return [recs, groupFlags(recs, (r, f) => `${r.display_name}: ${f.detail}`, "more")];
  }

  /* ------------------------------------------------------------------ language */
  const LANG = [["urgency", "urgency_language", "Pressure/urgency wording"], ["credential", "credential_lure", "Credential-harvesting wording"], ["payment", "payment_lure", "Payment/invoice wording"],
    ["gift_card", "gift_card_scam", "Gift-card request wording"], ["bec", "bec_wording", "Business-email-compromise phrasing"], ["qr", "qr_lure", "QR-code instruction with an image"],
    ["enable_content", "enable_content_lure", "Enable-content/macro instruction"], ["greeting", "generic_greeting", "Generic greeting"]];
  function analyzeLanguage(subject, text, htmlText, hasImages, cfg) {
    const combined = [subject, text, htmlText].filter(Boolean).join("\n"), minm = cfg.thresholds.min_matches || {}, hits = {};
    for (const [cat, pats] of Object.entries(cfg.language)) {
      hits[cat] = [];
      for (const p of pats) { const m = new RegExp(p, "im").exec(combined); if (m) hits[cat].push(m[0].replace(/\s+/g, " ").trim().slice(0, 60)); }
    }
    const findings = [];
    for (const [cat, ind, label] of LANG) {
      const h = hits[cat] || [];
      if (h.length < (minm[cat] || 1)) continue;
      if (cat === "qr" && !hasImages) continue;
      findings.push(F(ind, `${label}: ` + h.slice(0, 3).map((x) => `'${x}'`).join(", "), h.slice(0, 4).map((x) => `"${x}"`)));
    }
    return [findings, hits];
  }

  /* ------------------------------------------------------------------ scoring */
  const IDENTITY = ["display_name_exec_spoof", "display_name_brand_spoof", "display_name_email_spoof", "sender_domain_lookalike", "freemail_display_spoof"];
  const DECEPTIVE = ["url_text_mismatch", "url_lookalike_domain", "url_idn_homograph", "url_userinfo", "url_ip_host", "url_brand_in_domain", "url_brand_in_subdomain", "url_script_scheme"];
  const LURE = ["credential_lure", "payment_lure", "urgency_language"], MONEY = ["payment_lure", "bec_wording", "gift_card_scam"];
  const verdictFor = (score, cfg) => (score >= cfg.thresholds.phishing ? "likely_phishing" : (score >= cfg.thresholds.suspicious ? "suspicious" : "benign"));
  function comboFindings(ids) {
    const out = [], lure = LURE.filter((i) => ids.has(i)), link = DECEPTIVE.filter((i) => ids.has(i));
    if (lure.length && link.length) out.push(F("combo_lure_deceptive_link", "Persuasion wording plus a deceptive link", lure.concat(link)));
    const ident = IDENTITY.filter((i) => ids.has(i)), money = MONEY.filter((i) => ids.has(i));
    if (ident.length && money.length) out.push(F("combo_exec_payment", "Impersonated sender combined with a money request", ident.concat(money)));
    if (ident.length && (ids.has("dmarc_fail") || ids.has("spf_fail"))) out.push(F("combo_unauth_spoof", "Impersonated sender that also fails authentication", ident.concat(["dmarc_fail", "spf_fail"].filter((i) => ids.has(i)))));
    return out;
  }
  const cfgIndex = (cfg) => { if (!cfg._by_id) { cfg._by_id = {}; for (const i of cfg.indicators) cfg._by_id[i.id] = i; } return cfg._by_id; };

  function analyzeMessage(rawText, cfg, dns, label) {
    const by = cfgIndex(cfg), th = cfg.thresholds, caps = cfg.category_caps;
    const pe = parseMime(rawText);
    const info = basicInfo(pe, cfg);
    const [auth, authFindings, aligned] = analyzeAuth(pe, info, cfg, dns);
    const hdrFindings = headerFindings(pe, info, auth, aligned, cfg);
    const html = pe.html ? analyzeHtml(pe.html) : { text: "", links: [], images: [], form: false, password_input: false };
    const senderDomains = [info.from && info.from.domain, info.reply_to && info.reply_to.domain, info.return_path && info.return_path.domain].filter(Boolean);
    const [links, urlFindings] = analyzeUrls(pe, cfg, senderDomains.slice(0, 1));
    const [atts, attFindings] = analyzeAttachments(pe, cfg, html.text);
    const hasImages = html.images.length > 0 || atts.some((a) => ["png", "jpg", "gif"].includes(a.detected_type));
    const [langFindings, langHits] = analyzeLanguage(info.subject, pe.text, html.text, hasImages, cfg);
    let findings = [].concat(hdrFindings, authFindings, urlFindings, attFindings, langFindings);
    findings = findings.concat(comboFindings(new Set(findings.map((f) => f.id))));
    const indicators = findings.map((f) => { const ind = by[f.id]; return { id: f.id, category: ind.category, title: ind.title, severity: ind.severity, weight: ind.weight, points: ind.weight, detail: f.detail, evidence: f.evidence.slice(0, th.max_evidence).map(defangText), mitre: ind.mitre.slice(), description: ind.description }; });
    const breakdown = {};
    for (const cat of ["header", "auth", "url", "attachment", "language", "combo"]) {
      const items = indicators.filter((i) => i.category === cat), rawSum = items.reduce((a, i) => a + i.weight, 0), capped = Math.min(rawSum, caps[cat]);
      if (rawSum > caps[cat] && rawSum) {
        let run = 0;
        for (const i of items.slice().sort((a, b) => b.weight - a.weight)) { const give = Math.min(i.weight, capped - run); i.points = Math.max(give, 0); run += i.points; }
      }
      breakdown[cat] = { raw: rawSum, capped, cap: caps[cat] };
    }
    const subtotal = Object.values(breakdown).reduce((a, b) => a + b.capped, 0);
    const ids = new Set(indicators.map((i) => i.id)), mitigations = [];
    const hasIdentity = IDENTITY.some((i) => ids.has(i));
    const mit = (id, detail) => { const m = by[id]; mitigations.push({ id, category: "mitigation", title: m.title, severity: m.severity, weight: m.weight, points: m.weight, detail, evidence: [], mitre: [], description: m.description }); };
    if (aligned && !hasIdentity && !ids.has("dmarc_fail") && subtotal > 0) mit("authenticated_aligned", "SPF or DKIM passed for a domain aligned with the From domain");
    if (aligned && !hasIdentity && info.list_unsubscribe && subtotal > 0) mit("list_unsubscribe", "List-Unsubscribe header present on authenticated mail");
    const mitTotal = Math.max(mitigations.reduce((a, m) => a + m.points, 0), -th.mitigation_cap);
    const score = Math.max(0, Math.min(100, subtotal + mitTotal)), verdict = verdictFor(score, cfg);
    indicators.sort((a, b) => (b.points - a.points) || (b.weight - a.weight) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    const mitreIds = [];
    for (const i of indicators) if (i.points > 0) for (const t of i.mitre) if (!mitreIds.includes(t)) mitreIds.push(t);
    if (verdict !== "benign" && !mitreIds.some((t) => t.startsWith("T1566"))) {
      if (atts.some((a) => a.flags.length)) mitreIds.unshift("T1566.001"); else if (links.some((u) => u.flags.length)) mitreIds.unshift("T1566.002");
    }
    const mitre = mitreIds.map((t) => ({ id: t, name: cfg.mitre[t] || t }));
    const full = [];
    for (const i of indicators) if (i.points > 0) for (const st of by[i.id].response) if (!full.includes(st)) full.push(st);
    const response = full.slice(0, 6).concat(cfg.generic_response[verdict].filter((st) => !full.includes(st)));
    const res = {
      id: label || "pasted", label: label || "", sha256: sha256(new TextEncoder().encode(rawText)), size: rawText.length, subject: info.subject, from: info.from, reply_to: info.reply_to, return_path: info.return_path, to: info.to,
      date: info.date, date_text: info.date_text, message_id: info.message_id, score, verdict, breakdown, subtotal, mitigation_total: mitTotal, indicators, mitigations, mitre, response,
      hops: info.hops.map((h) => { const c = Object.assign({}, h); delete c.raw; return c; }), origin_ip: info.origin_ip, auth, urls: links, attachments: atts,
      language: Object.fromEntries(Object.entries(langHits).filter(([, v]) => v.length)), synthetic: pe.get("X-Synthetic-Sample").trim().toLowerCase() === "yes", engine: VERSION + " (browser port)",
    };
    res.iocs = verdict !== "benign" ? extractIocs(res) : [];
    res.ticket_note = ticketNote(res);
    return res;
  }

  /* ------------------------------------------------------------------ IOCs + ticket note */
  function extractIocs(r) {
    const out = [], seen = new Set();
    const add = (t, value, defanged, context) => { if (!value || seen.has(t + "\u0000" + value)) return; seen.add(t + "\u0000" + value); out.push({ type: t, value, defanged, context }); };
    const frm = r.from;
    if (frm) { add("email", frm.addr, defangEmail(frm.addr), "From address"); add("domain", frm.domain, defangHost(frm.domain), "Sender domain"); }
    for (const [key, label] of [["reply_to", "Reply-To address"], ["return_path", "Return-Path address"]]) {
      const a = r[key];
      if (a && (!frm || a.addr !== frm.addr)) { add("email", a.addr, defangEmail(a.addr), label); if (!frm || a.domain !== frm.domain) add("domain", a.domain, defangHost(a.domain), label.replace("address", "domain")); }
    }
    if (r.origin_ip) add("ip", r.origin_ip, defangHost(r.origin_ip), "Origin of the Received chain");
    for (const u of r.urls) if (u.flags.length) {
      add("url", u.url, u.defanged, u.flags.slice(0, 3).map((f) => f.id).join("; "));
      if (u.domain) add("domain", u.domain, defangHost(u.domain), "Domain of a flagged URL");
      else if (u.host && (isIPv4(u.host) || isIPv6(u.host))) add("ip", u.host, defangHost(u.host), "IP host of a flagged URL");
    }
    for (const a of r.attachments) if (a.flags.length) { add("sha256", a.sha256, a.sha256, `Attachment ${a.display_name}: ` + a.flags.slice(0, 3).map((f) => f.id).join(", ")); add("filename", a.display_name, a.display_name, "Flagged attachment name"); }
    return out;
  }
  const VERSION = "1.0.0";
  const VERDICT_TEXT = { benign: "BENIGN", suspicious: "SUSPICIOUS", likely_phishing: "LIKELY PHISHING" };
  const addrText = (a) => (a ? `${a.display ? `"${a.display}" ` : ""}<${defangEmail(a.addr)}>` : "(none)");
  function authLine(r) {
    const a = r.auth, spf = a.spf ? a.spf.result : "none", dkim = a.dkim.length ? Array.from(new Set(a.dkim.map((d) => d.result))).sort().join(", ") : "none", dmarc = a.dmarc ? a.dmarc.result : "none";
    return `SPF ${spf} | DKIM ${dkim} | DMARC ${dmarc}`;
  }
  const topReasons = (r, n) => r.indicators.filter((i) => i.points > 0 && i.category !== "combo").slice(0, n === undefined ? 5 : n);
  function ticketNote(r) {
    const L = [`PHISHING TRIAGE - ${VERDICT_TEXT[r.verdict]} (risk ${r.score}/100)`, `Subject: ${defangText(r.subject)}`, `From: ${addrText(r.from)}`];
    if (r.reply_to && (!r.from || r.reply_to.addr !== r.from.addr)) L.push(`Reply-To: ${addrText(r.reply_to)}`);
    if (r.return_path && (!r.from || r.return_path.addr !== r.from.addr)) L.push(`Return-Path: ${addrText(r.return_path)}`);
    L.push(`Sent: ${r.date_text || "unknown"} | Origin IP: ${r.origin_ip ? defangHost(r.origin_ip) : "not determined"}`);
    L.push(`Authentication: ${authLine(r)}`);
    const reasons = topReasons(r);
    if (reasons.length) { L.push("Why it was flagged:"); reasons.forEach((i, k) => L.push(`  ${k + 1}. ${defangText(i.title)} (+${i.points}) - ${defangText(i.detail)}`)); }
    else L.push("Why: no suspicious indicators fired.");
    const urls = r.urls.filter((u) => u.flags.length);
    if (urls.length) L.push("Suspicious links: " + urls.slice(0, 4).map((u) => u.defanged).join("; "));
    if (r.attachments.length) L.push("Attachments: " + r.attachments.slice(0, 4).map((a) => `${a.display_name} (sha256 ${a.sha256.slice(0, 16)}...)` + (a.flags.length ? " [FLAGGED]" : "")).join("; "));
    if (r.mitre.length) L.push("ATT&CK: " + r.mitre.map((m) => m.id).join(", "));
    L.push("Recommended actions:");
    for (const s of r.response.slice(0, 6)) L.push(`  [ ] ${s}`);
    L.push("User impact: UNKNOWN - ask the recipient whether they clicked a link, opened an attachment, entered credentials or replied.");
    L.push(`Method: phishanalyzer ${VERSION} static analysis (nothing was opened, executed or fetched).`);
    return defangKnown(L.join("\n"), r.iocs.filter((i) => i.type === "domain" || i.type === "ip").map((i) => i.value));
  }
  function iocsToCsv(results) {
    const q = (v) => { v = String(v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return /[",\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
    const rows = [["message_id", "type", "value", "defanged", "context", "verdict", "score"].join(",")];
    for (const r of results) for (const i of r.iocs) rows.push([r.id, i.type, i.value, i.defanged, i.context, r.verdict, r.score].map(q).join(","));
    return rows.join("\n") + "\n";
  }

  root.PhishCore = { analyzeMessage, parseMime, evaluateSpf, brandMatches, sha256, ticketNote, iocsToCsv, extractIocs, VERDICT_TEXT, T };
  if (typeof module !== "undefined" && module.exports) module.exports = root.PhishCore;
})(typeof window !== "undefined" ? window : globalThis);
