/* core-text.js: text primitives of the browser port (mirrors phishanalyzer/textutil.py). core.js has the analysis steps.
 * It mirrors phishanalyzer/*.py. tests/test_js_parity.py checks that both give the same verdicts on the whole corpus.
 * Static analysis only: it parses strings. It never fetches, resolves, renders or executes anything.
 * No HTML is ever injected in this project; the UI uses textContent. */
(function (root) {
  "use strict";

  /* ------------------------------------------------------------------ small helpers */
  const cps = (s) => Array.from(s);
  const strip = (s, chars) => { let a = 0, b = s.length; while (a < b && chars.includes(s[a])) a++; while (b > a && chars.includes(s[b - 1])) b--; return s.slice(a, b); };
  const rpartition = (s, sep) => { const i = s.lastIndexOf(sep); return i < 0 ? ["", "", s] : [s.slice(0, i), sep, s.slice(i + sep.length)]; };
  const partition = (s, sep) => { const i = s.indexOf(sep); return i < 0 ? [s, "", ""] : [s.slice(0, i), sep, s.slice(i + sep.length)]; };
  const ESC = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  /* ------------------------------------------------------------------ headers / addresses */
  const unfold = (v) => (v || "").replace(/\r?\n[ \t]+/g, " ").trim();

  function b64bytes(s) {
    s = s.replace(/[^A-Za-z0-9+/=]/g, ""); while (s.length % 4) s += "=";
    try { const bin = atob(s); const out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; } catch (e) { return new Uint8Array(0); }
  }
  function decodeBytes(bytes, charset) {
    try { return new TextDecoder(charset || "utf-8").decode(bytes); } catch (e) { return new TextDecoder("utf-8").decode(bytes); }
  }
  function decodeWords(value) {
    if (!value || !value.includes("=?")) return value || "";
    const re = /=\?([^?\s]+)\?([bBqQ])\?([^?\s]*)\?=/g;
    let out = "", last = 0, m, prevEnc = false;
    while ((m = re.exec(value)) !== null) {
      const gap = value.slice(last, m.index);
      if (!(prevEnc && /^\s*$/.test(gap))) out += gap;
      let bytes;
      if (m[2].toLowerCase() === "b") bytes = b64bytes(m[3]);
      else { const q = m[3].replace(/_/g, " "); const arr = []; for (let i = 0; i < q.length; i++) { if (q[i] === "=" && /^[0-9A-Fa-f]{2}$/.test(q.substr(i + 1, 2))) { arr.push(parseInt(q.substr(i + 1, 2), 16)); i += 2; } else arr.push(q.charCodeAt(i) & 255); } bytes = Uint8Array.from(arr); }
      out += decodeBytes(bytes, m[1]);
      last = m.index + m[0].length; prevEnc = true;
    }
    return out + value.slice(last);
  }
  function mkAddr(display, addr) {
    addr = addr.trim().toLowerCase();
    const [local, , dom] = rpartition(addr, "@");
    return { display, addr, domain: dom.trim().replace(/\.+$/, ""), local };
  }
  function parseAddress(value) {
    const v = decodeWords(unfold(value || ""));
    if (!v) return null;
    let m = /^([\s\S]*?)<([^<>]*)>\s*$/.exec(v);
    if (m) {
      let disp = m[1].trim();
      if (disp.length >= 2 && disp[0] === disp[disp.length - 1] && "\"'".includes(disp[0])) disp = disp.slice(1, -1);
      return mkAddr(disp.split('\\"').join('"').trim(), m[2]);
    }
    m = /[^\s<>"',;()]+@[^\s<>"',;()]+/.exec(v);
    return m ? mkAddr("", m[0]) : null;
  }
  const addrDict = (a) => a ? { display: a.display, addr: a.addr, domain: a.domain } : null;

  /* ------------------------------------------------------------------ dates */
  const MONTHS = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12 };
  const ZONES = { gmt: 0, ut: 0, utc: 0, z: 0, est: -300, edt: -240, cst: -360, cdt: -300, mst: -420, mdt: -360, pst: -480, pdt: -420 };
  const DATE_RE = /(?:[A-Za-z]{3,9},?\s+)?(\d{1,2})\s+([A-Za-z]{3})[a-z]*\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([+-]\d{4}|[A-Za-z]{1,5})?/;
  function daysFromCivil(y, m, d) {
    if (m <= 2) y -= 1;
    const era = Math.floor((y >= 0 ? y : y - 399) / 400);
    const yoe = y - era * 400;
    const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
    const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
    return era * 146097 + doe - 719468;
  }
  function parseDate(value) {
    const m = DATE_RE.exec(value || "");
    if (!m) return null;
    const month = MONTHS[m[2].toLowerCase()];
    if (!month) return null;
    let y = parseInt(m[3], 10);
    if (y < 100) y += y < 50 ? 2000 : 1900; else if (y < 1000) y += 1900;
    const d = parseInt(m[1], 10), h = parseInt(m[4], 10), mi = parseInt(m[5], 10), s = parseInt(m[6] || "0", 10);
    if (!(d >= 1 && d <= 31 && h < 24 && mi < 60 && s < 61)) return null;
    let off = 0; const zone = m[7];
    if (zone) {
      if ((zone[0] === "+" || zone[0] === "-") && zone.length === 5) off = (parseInt(zone.slice(1, 3), 10) * 60 + parseInt(zone.slice(3, 5), 10)) * (zone[0] === "+" ? 1 : -1);
      else off = ZONES[zone.toLowerCase()] || 0;
    }
    return daysFromCivil(y, month, d) * 86400 + h * 3600 + mi * 60 + s - off * 60;
  }
  const pad = (n, w) => String(n).padStart(w, "0");
  function formatEpoch(ts) {
    if (ts === null || ts === undefined) return "";
    const days = Math.floor(ts / 86400), rem = ts - days * 86400;
    const z = days + 719468;
    const era = Math.floor((z >= 0 ? z : z - 146096) / 146097);
    const doe = z - era * 146097;
    const yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365);
    let y = yoe + era * 400;
    const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
    const mp = Math.floor((5 * doy + 2) / 153);
    const d = doy - Math.floor((153 * mp + 2) / 5) + 1;
    const mth = mp + (mp < 10 ? 3 : -9);
    if (mth <= 2) y += 1;
    return `${pad(y, 4)}-${pad(mth, 2)}-${pad(d, 2)} ${pad(Math.floor(rem / 3600), 2)}:${pad(Math.floor((rem % 3600) / 60), 2)}:${pad(rem % 60, 2)}Z`;
  }

  /* ------------------------------------------------------------------ html */
  const ENT = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
  function decodeEntities(s) {
    return s.replace(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);/g, (all, e) => {
      if (e[0] === "#") {
        const cp = (e[1] === "x" || e[1] === "X") ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        return cp > 0 && cp < 0x110000 ? String.fromCodePoint(cp) : all;
      }
      const k = e.toLowerCase();
      return Object.prototype.hasOwnProperty.call(ENT, k) ? ENT[k] : all;
    });
  }
  function parseAttrs(raw) {
    const out = {}; const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g; let m;
    while ((m = re.exec(raw || "")) !== null) {
      const name = m[1].toLowerCase();
      const val = m[2] !== undefined ? m[2] : (m[3] !== undefined ? m[3] : (m[4] || ""));
      if (!Object.prototype.hasOwnProperty.call(out, name)) out[name] = decodeEntities(val);
      if (m[0] === "") re.lastIndex++;
    }
    return out;
  }
  const BLOCK = new Set(["br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "ul", "ol", "blockquote", "hr"]);
  function analyzeHtml(html) {
    html = (html || "").replace(/<!--[\s\S]*?-->/g, "");
    html = html.replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, " ");
    const text = [], links = [], images = [];
    let cur = null, hasForm = false, hasPassword = false, pos = 0, m;
    const TAG = /<(\/?)([a-zA-Z][a-zA-Z0-9:-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>/g;
    const fin = (c) => { c.text = c.text.replace(/\s+/g, " ").trim(); links.push(c); };
    while ((m = TAG.exec(html)) !== null) {
      const chunk = decodeEntities(html.slice(pos, m.index));
      if (chunk) { text.push(chunk); if (cur) cur.text += chunk; }
      pos = m.index + m[0].length;
      const closing = m[1] === "/", tag = m[2].toLowerCase(), rest = m[3];
      if (tag === "a") {
        if (closing) { if (cur) { fin(cur); cur = null; } }
        else { if (cur) fin(cur); const a = parseAttrs(rest); cur = ("href" in a) ? { href: a.href.trim(), text: "" } : null; }
      } else if (tag === "img" && !closing) {
        const a = parseAttrs(rest); images.push({ src: a.src || "", alt: a.alt || "" });
        if (cur && a.alt) cur.text += a.alt;
      } else if (tag === "form" && !closing) hasForm = true;
      else if (tag === "input" && !closing && (parseAttrs(rest).type || "").toLowerCase() === "password") hasPassword = true;
      if (BLOCK.has(tag)) text.push("\n");
    }
    const tail = decodeEntities(html.slice(pos));
    if (tail) { text.push(tail); if (cur) cur.text += tail; }
    if (cur) fin(cur);
    let plain = text.join("").replace(/[ \t\r\f\v\u00a0]+/g, " ");
    plain = plain.replace(/ ?\n ?/g, "\n").replace(/\n{3,}/g, "\n\n").trim();
    return { text: plain, links, images, form: hasForm, password_input: hasPassword };
  }

  /* ------------------------------------------------------------------ urls / domains */
  function refang(s) { return s.replace(/^hxxp/i, "http").split("[.]").join(".").split("(.)").join(".").split("[:]").join(":"); }
  function extractUrls(text) {
    const out = []; const re = /(?:(?:https?|hxxps?|ftp):\/\/|www\.)[^\s<>"'`]+/gi; let m;
    while ((m = re.exec(text || "")) !== null) {
      let u = m[0];
      while (u && ".,;:!?)]}>'\"".includes(u[u.length - 1])) u = u.slice(0, -1);
      if (u.length < 8) continue;
      u = refang(u);
      if (u.toLowerCase().startsWith("www.")) u = "http://" + u;
      out.push(u);
    }
    return out;
  }
  function parseUrl(url) {
    const u = (url || "").trim();
    const res = { url: u, scheme: "", userinfo: "", host: "", port: "", path: "", query: "", fragment: "" };
    const m = /^([A-Za-z][A-Za-z0-9+.\-]*):([\s\S]*)$/.exec(u);
    if (!m) return res;
    res.scheme = m[1].toLowerCase();
    let rest = m[2];
    if (!rest.startsWith("//")) { res.path = rest; return res; }
    rest = rest.slice(2);
    let frag = "", query = "";
    if (rest.includes("#")) { const i = rest.indexOf("#"); frag = rest.slice(i + 1); rest = rest.slice(0, i); }
    if (rest.includes("?")) { const i = rest.indexOf("?"); query = rest.slice(i + 1); rest = rest.slice(0, i); }
    const si = rest.indexOf("/");
    let auth = si < 0 ? rest : rest.slice(0, si); const path = si < 0 ? "" : rest.slice(si);
    let userinfo = "";
    if (auth.includes("@")) { const i = auth.lastIndexOf("@"); userinfo = auth.slice(0, i); auth = auth.slice(i + 1); }
    let host = auth, port = "";
    if (auth.startsWith("[")) { const end = auth.indexOf("]"); if (end > 0) { host = auth.slice(1, end); port = auth.slice(end + 2); } }
    else if (auth.includes(":")) { const i = auth.lastIndexOf(":"); const p = auth.slice(i + 1); if (/^\d*$/.test(p)) { host = auth.slice(0, i); port = p; } }
    Object.assign(res, { userinfo, host: host.toLowerCase().replace(/\.+$/, ""), port, path, query, fragment: frag });
    return res;
  }
  function percentDecode(s) {
    if (!s.includes("%")) return s;
    const src = new TextEncoder().encode(s), out = [];
    for (let i = 0; i < src.length; i++) {
      if (src[i] === 37 && i + 2 < src.length + 0 && /^[0-9A-Fa-f]{2}$/.test(String.fromCharCode(src[i + 1], src[i + 2]))) { out.push(parseInt(String.fromCharCode(src[i + 1], src[i + 2]), 16)); i += 2; }
      else out.push(src[i]);
    }
    return new TextDecoder("utf-8").decode(Uint8Array.from(out));
  }
  function queryPairs(query) {
    const out = [];
    for (const piece of (query || "").split("&")) {
      if (!piece) continue;
      const [k, , v] = partition(piece, "=");
      out.push([percentDecode(k.replace(/\+/g, " ")).toLowerCase(), percentDecode(v.replace(/\+/g, " "))]);
    }
    return out;
  }
  const isIPv4 = (h) => { const p = h.split("."); return p.length === 4 && p.every((x) => /^\d+$/.test(x) && +x >= 0 && +x <= 255 && x.length <= 3); };
  const isIPv6 = (h) => h.includes(":") && /^[0-9a-fA-F:.]+$/.test(h) && (h.match(/:/g) || []).length >= 2;
  function obfuscatedIPv4(host) {
    const h = host.toLowerCase(); let n = null;
    if (/^\d{8,10}$/.test(h)) n = parseInt(h, 10);
    else if (/^0x[0-9a-f]{1,8}$/.test(h)) n = parseInt(h, 16);
    else if (/^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){3}$/.test(h) && !isIPv4(h)) {
      const parts = [];
      for (const x of h.split(".")) {
        if (x.startsWith("0x")) parts.push(parseInt(x, 16));
        else if (x.length > 1 && x[0] === "0") { if (!/^[0-7]+$/.test(x)) return null; parts.push(parseInt(x, 8)); }
        else parts.push(parseInt(x, 10));
      }
      return parts.every((x) => x >= 0 && x <= 255) ? parts.join(".") : null;
    }
    if (n === null || n > 0xFFFFFFFF) return null;
    return [24, 16, 8, 0].map((s) => (Math.floor(n / Math.pow(2, s)) % 256)).join(".");
  }
  function ipScope(ip) {
    if (isIPv4(ip)) {
      const [a, b, c] = ip.split(".").map(Number);
      if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254)) return "private";
      if (a === 127) return "loopback";
      if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) return "documentation";
      return "public";
    }
    const low = ip.toLowerCase();
    if (low === "::1" || low === "::") return "loopback";
    if (/^(fc|fd|fe8|fe9|fea|feb)/.test(low)) return "private";
    if (low.startsWith("2001:db8")) return "documentation";
    return "public";
  }
  function registeredDomain(host, suffixes) {
    const labels = host.split(".").filter(Boolean);
    if (labels.length <= 2) return labels.join(".");
    if (suffixes.includes(labels.slice(-2).join("."))) return labels.slice(-3).join(".");
    return labels.slice(-2).join(".");
  }
  function splitRegistered(host, suffixes) {
    const rd = registeredDomain(host, suffixes), rdl = rd.split(".");
    const labels = host.split(".").filter(Boolean);
    const sub = labels.slice(0, labels.length - rdl.length);
    const nSuffix = suffixes.includes(rdl.slice(-2).join(".")) ? 2 : 1;
    const sld = rdl.length > nSuffix ? rdl[rdl.length - (nSuffix + 1)] : rdl[0];
    return [sub, sld, rd];
  }
  const sameOrg = (a, b, suf) => !!a && !!b && registeredDomain(a, suf) === registeredDomain(b, suf);

  /* punycode / scripts / confusables */
  function punycodeDecode(s) {
    const base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700;
    let n = 128, i = 0, bias = 72;
    const b = s.lastIndexOf("-");
    const out = b > 0 ? cps(s.slice(0, b)) : [];
    let idx = b > 0 ? b + 1 : 0;
    const adapt = (delta, numpoints, first) => {
      delta = first ? Math.floor(delta / damp) : Math.floor(delta / 2);
      delta += Math.floor(delta / numpoints);
      let k = 0;
      while (delta > Math.floor(((base - tmin) * tmax) / 2)) { delta = Math.floor(delta / (base - tmin)); k += base; }
      return k + Math.floor(((base - tmin + 1) * delta) / (delta + skew));
    };
    while (idx < s.length) {
      const oldi = i; let w = 1, k = base;
      for (;;) {
        if (idx >= s.length) return null;
        const c = s[idx++]; let digit;
        if (c >= "a" && c <= "z") digit = c.charCodeAt(0) - 97;
        else if (c >= "A" && c <= "Z") digit = c.charCodeAt(0) - 65;
        else if (c >= "0" && c <= "9") digit = c.charCodeAt(0) - 22;
        else return null;
        i += digit * w;
        const t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias);
        if (digit < t) break;
        w *= base - t; k += base;
      }
      bias = adapt(i - oldi, out.length + 1, oldi === 0);
      n += Math.floor(i / (out.length + 1));
      i %= out.length + 1;
      if (n > 0x10FFFF) return null;
      out.splice(i, 0, String.fromCodePoint(n));
      i++;
    }
    return out.join("");
  }
  function hostUnicode(host) {
    return host.split(".").map((lab) => { if (lab.toLowerCase().startsWith("xn--")) { const d = punycodeDecode(lab.slice(4)); return d !== null ? d : lab; } return lab; }).join(".");
  }
  function scriptOf(ch) {
    const o = ch.codePointAt(0);
    if (/\p{Nd}/u.test(ch) || "-_.".includes(ch)) return "common";
    if (o < 0x80) return /\p{L}/u.test(ch) ? "latin" : "common";
    if ((o >= 0x0370 && o <= 0x03FF) || (o >= 0x1F00 && o <= 0x1FFF)) return "greek";
    if (o >= 0x0400 && o <= 0x052F) return "cyrillic";
    if ((o >= 0x00C0 && o <= 0x024F) || (o >= 0x1E00 && o <= 0x1EFF)) return "latin";
    if (o >= 0x0530 && o <= 0x058F) return "armenian";
    if ((o >= 0x4E00 && o <= 0x9FFF) || (o >= 0x3040 && o <= 0x30FF)) return "cjk";
    if (o >= 0x0600 && o <= 0x06FF) return "arabic";
    return "other";
  }
  function scriptsIn(label) { const s = new Set(); for (const c of cps(label)) { const k = scriptOf(c); if (k !== "common") s.add(k); } return Array.from(s).sort(); }
  const CONFUSABLE = { "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ɡ": "g", "ο": "o", "α": "a", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "ɑ": "a", "ℓ": "l", "0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a" };
  function normalizeConfusables(label) {
    let s = cps(label.toLowerCase()).map((c) => (Object.prototype.hasOwnProperty.call(CONFUSABLE, c) ? CONFUSABLE[c] : c)).join("");
    s = s.normalize("NFKD").replace(/\p{M}/gu, "");
    return s.split("rn").join("m").split("vv").join("w");
  }
  function editDistance(a, b) {
    a = cps(a); b = cps(b);
    const la = a.length, lb = b.length;
    const d = Array.from({ length: la + 1 }, () => new Array(lb + 1).fill(0));
    for (let i = 0; i <= la; i++) d[i][0] = i;
    for (let j = 0; j <= lb; j++) d[0][j] = j;
    for (let i = 1; i <= la; i++) for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
    return d[la][lb];
  }

  /* defanging */
  const defangHost = (h) => h.split(".").join("[.]");
  function defangUrl(url) {
    const u = url.replace(/^http/i, "hxxp");
    const m = /^([A-Za-z]+:\/\/)([^/?#]*)([\s\S]*)$/.exec(u);
    if (!m) return u.split(".").join("[.]");
    return m[1] + m[2].split(".").join("[.]") + m[3];
  }
  const defangEmail = (a) => a.split("@").join("[@]").split(".").join("[.]");
  function defangText(s) {
    s = s.replace(/(?:https?|ftp):\/\/[^\s<>"'`]+/gi, (m) => defangUrl(m));
    return s.replace(/\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b/g, (m) => defangEmail(m));
  }

  function defangKnown(s, hosts) {
    const uniq = Array.from(new Set((hosts || []).filter(Boolean))).sort((a, b) => b.length - a.length || (a < b ? -1 : a > b ? 1 : 0));
    for (const h of uniq) {
      const re = new RegExp("(?<![A-Za-z0-9-])((?:[A-Za-z0-9-]+\\.)*" + h.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")(?![A-Za-z0-9-])", "gi");
      s = s.replace(re, (m, g1) => g1.split(".").join("[.]"));
    }
    return s;
  }

  const T = { defangKnown, unfold, decodeWords, parseAddress, addrDict, parseDate, formatEpoch, analyzeHtml, extractUrls, parseUrl, percentDecode, queryPairs, isIPv4, isIPv6, obfuscatedIPv4, ipScope, registeredDomain, splitRegistered, sameOrg, hostUnicode, scriptsIn, normalizeConfusables, editDistance, defangHost, defangUrl, defangEmail, defangText, decodeBytes, b64bytes, cps, rpartition, partition, ESC };
  root.PhishCoreParts = { T };
})(typeof window !== "undefined" ? window : globalThis);
