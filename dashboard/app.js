/* Phishing Email Analyzer dashboard. Vanilla JS, no dependencies, no HTML string injection: every value is inserted with
   textContent because e-mail content is attacker-controlled (display names, URLs, file names, <script> ...).
   Nothing is fetched except this site's own JSON files. */
(function () {
  "use strict";

  var VCOLOR = { benign: "#4ade80", suspicious: "#f5c542", likely_phishing: "#ff4d6d" };
  var VLABEL = { benign: "benign", suspicious: "suspicious", likely_phishing: "likely phishing" };
  var VRANK = { likely_phishing: 3, suspicious: 2, benign: 1 };
  var SEVCOLOR = { critical: "#ff4d6d", high: "#ff8a3d", medium: "#f5c542", low: "#5aa9ff", info: "#8b9bb8" };
  var CAT_LABEL = { header: "Headers", auth: "Authentication", url: "Links", attachment: "Attachments", language: "Wording", combo: "Combinations" };
  var IOC_LIMIT = 150;
  var D = null, S = { v: {}, q: "", sel: "", iocType: "", iocQ: "" };
  var Core = window.PhishCore, T = Core && Core.T;

  function $(id) { return document.getElementById(id); }
  function h(tag, attrs, kids) {
    var el = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k.slice(0, 2) === "on") el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    });
    (kids || []).forEach(function (c) { if (c === null || c === undefined) return; el.appendChild(typeof c === "object" ? c : document.createTextNode(String(c))); });
    return el;
  }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
  function num(n) { return Number(n).toLocaleString("en-US"); }
  function short(s, n) { return s && s.length > n ? s.slice(0, n) + "…" : s; }
  function bytes(n) { return n < 1024 ? n + " B" : (n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB"); }
  function vbadge(v) { return h("span", { class: "vbadge v-" + v, text: VLABEL[v] }); }
  function flagTag(id, sev) { var e = h("span", { class: "flag" + (sev ? " f-" + sev : ""), text: id }); return e; }
  function showError(msg) { var e = $("error"); e.hidden = false; e.textContent = msg; }
  function sevOf(id) { var i = D.indById[id]; return i ? i.severity : ""; }
  function td(content, cls) { return h("td", cls ? { class: cls } : null, [content]); }

  // ------------------------------------------------------------------ loading
  function getJson(url) {
    return fetch(url, { credentials: "omit" }).then(function (r) { if (!r.ok) throw new Error(url + ": HTTP " + r.status); return r.json(); });
  }
  function load() {
    return Promise.all(["data/analysis.json", "data/config.json", "data/emls.json", "data/evaluation.json", "data/dns_fixtures.json"].map(getJson)).then(function (r) {
      D = { analysis: r[0], cfg: r[1], emls: r[2], ev: r[3], dns: r[4].domains || r[4] };
      D.msgs = D.analysis.messages;
      D.byId = {}; D.msgs.forEach(function (m) { D.byId[m.id] = m; });
      D.indById = {}; D.cfg.indicators.forEach(function (i) { D.indById[i.id] = i; });
      D.truth = {}; ((D.ev && D.ev.rows) || []).forEach(function (row) { D.truth[row.id] = row; });
    });
  }

  // ------------------------------------------------------------------ KPIs + inbox
  function renderKpis() {
    var s = D.analysis.summary, box = $("kpis"); clear(box);
    function card(label, n, v) {
      var b = h("button", { type: "button", class: "kpi", "data-v": v || "all", "aria-pressed": v ? String(!!S.v[v]) : null }, [h("span", { class: "n", text: num(n) }), h("span", { class: "l", text: label })]);
      if (v) b.addEventListener("click", function () { if (S.v[v]) delete S.v[v]; else S.v[v] = true; syncFilters(); });
      else b.className = "kpi static";
      if (v && S.v[v]) b.classList.add("active");
      return b;
    }
    box.appendChild(card("Messages", s.messages));
    box.appendChild(card("Likely phishing", s.likely_phishing, "likely_phishing"));
    box.appendChild(card("Suspicious", s.suspicious, "suspicious"));
    box.appendChild(card("Benign", s.benign, "benign"));
    var io = h("div", { class: "kpi static", "data-v": "all" }, [h("span", { class: "n", text: num(s.iocs) }), h("span", { class: "l", text: "IOCs extracted" })]);
    box.appendChild(io);
    $("dataset-meta").textContent = s.messages + " synthetic messages · engine " + D.analysis.version;
  }
  function renderChips() {
    var box = $("inbox-chips"); clear(box);
    ["likely_phishing", "suspicious", "benign"].forEach(function (v) {
      var c = h("button", { type: "button", class: "chip", "aria-pressed": String(!!S.v[v]), text: VLABEL[v] });
      c.style.setProperty("--c", VCOLOR[v]);
      c.addEventListener("click", function () { if (S.v[v]) delete S.v[v]; else S.v[v] = true; syncFilters(); });
      box.appendChild(c);
    });
  }
  function matches(m) {
    var any = Object.keys(S.v).length;
    if (any && !S.v[m.verdict]) return false;
    if (S.q) {
      var hay = [m.id, m.subject, m.from ? m.from.display + " " + m.from.addr : "", m.indicators.map(function (i) { return i.id; }).join(" ")].join(" ").toLowerCase();
      if (hay.indexOf(S.q.toLowerCase()) < 0) return false;
    }
    return true;
  }
  function renderInbox() {
    var list = $("inbox-list"); clear(list);
    var rows = D.msgs.filter(matches).sort(function (a, b) { return b.score - a.score || (a.id < b.id ? -1 : 1); });
    $("inbox-count").textContent = rows.length + " of " + D.msgs.length;
    $("inbox-empty").hidden = rows.length > 0;
    rows.forEach(function (m) {
      var top = m.indicators.filter(function (i) { return i.points > 0 && i.category !== "combo"; }).slice(0, 3).map(function (i) { return i.id; }).join(", ");
      var b = h("button", { type: "button", class: "mail" + (m.id === S.sel ? " active" : ""), "data-id": m.id, "aria-current": m.id === S.sel ? "true" : null }, [
        h("span", { class: "r1" }, [h("span", { class: "from", text: m.from ? (m.from.display || m.from.addr) : "(no sender)" }), h("span", { class: "score", text: String(m.score) })]),
        h("span", { class: "subj", text: m.subject || "(no subject)" }),
        h("span", { class: "r1" }, [vbadge(m.verdict), h("span", { class: "why", text: top || "no indicators" })])
      ]);
      b.style.setProperty("--c", VCOLOR[m.verdict]);
      b.addEventListener("click", function () { select(m.id, true); });
      list.appendChild(h("li", null, [b]));
    });
  }
  function syncFilters() { renderKpis(); renderChips(); renderInbox(); }

  // ------------------------------------------------------------------ detail view (shared by corpus and pasted messages)
  function section(title, body) { return h("div", { class: "sec" }, [h("h3", { text: title }), body]); }
  function simpleTable(head, rows, cls) {
    var t = h("table", { class: "data " + (cls || "") }, [h("thead", null, [h("tr", null, head.map(function (x) { return h("th", { text: x }); }))])]);
    var tb = h("tbody"); rows.forEach(function (r) { tb.appendChild(r); }); t.appendChild(tb);
    return h("div", { class: "table-scroll" }, [t]);
  }
  function tr(cells, cls) { return h("tr", { class: "static-row" + (cls ? " " + cls : "") }, cells); }

  function gauge(score, th) {
    var v = score >= th.likely_phishing ? "likely_phishing" : (score >= th.suspicious ? "suspicious" : "benign");
    var g = h("div", { class: "gauge", role: "img", "aria-label": "Risk score " + score + " of 100" }, [h("i"), h("b"), h("b")]);
    g.children[0].style.width = score + "%"; g.children[0].style.setProperty("--c", VCOLOR[v]);
    g.children[1].style.left = th.suspicious + "%"; g.children[2].style.left = th.likely_phishing + "%";
    return h("div", null, [g, h("div", { class: "gauge-legend" }, [h("span", { text: "0" }), h("span", { text: "suspicious ≥ " + th.suspicious }), h("span", { text: "likely phishing ≥ " + th.likely_phishing }), h("span", { text: "100" })])]);
  }
  function reasons(r) {
    var items = r.indicators.filter(function (i) { return i.points > 0; });
    if (!items.length) return h("p", { class: "muted", text: "No indicator fired." });
    var ul = h("ul", { class: "reasons" });
    items.forEach(function (i) {
      var li = h("li", { class: "reason" }, [
        h("span", { class: "pts", text: "+" + i.points }),
        h("div", null, [
          h("div", { class: "ttl", text: i.title + (i.points !== i.weight ? " (weight " + i.weight + ", capped)" : "") }),
          h("div", { class: "dt", text: i.detail }),
          i.evidence.length ? h("div", { class: "ev", text: i.evidence.join("\n") }) : null,
          i.mitre.length ? h("div", { class: "mt" }, i.mitre.map(function (t) { return h("span", { class: "mitre-chip", text: t }); })) : null
        ])]);
      li.style.setProperty("--c", SEVCOLOR[i.severity] || SEVCOLOR.info);
      if (i.evidence.length) li.querySelector(".ev").style.whiteSpace = "pre-wrap";
      ul.appendChild(li);
    });
    r.mitigations.forEach(function (m) {
      var li = h("li", { class: "reason" }, [h("span", { class: "pts", text: String(m.points) }), h("div", null, [h("div", { class: "ttl", text: m.title }), h("div", { class: "dt", text: m.detail })])]);
      li.style.setProperty("--c", "#4ade80"); ul.appendChild(li);
    });
    return ul;
  }
  function breakdown(r) {
    var box = h("div", { class: "bars" });
    ["header", "auth", "url", "attachment", "language", "combo"].forEach(function (c) {
      var b = r.breakdown[c], max = b.cap;
      var track = h("div", { class: "track" }, [h("i", { class: "raw" }), h("i")]);
      track.children[0].style.width = Math.min(100, (b.raw / max) * 100) + "%";
      track.children[1].style.width = (b.capped / max) * 100 + "%";
      box.appendChild(h("div", { class: "barrow" }, [h("span", { class: "lab", text: CAT_LABEL[c] }), track, h("span", { class: "val", text: b.capped + " / " + b.cap + (b.raw > b.cap ? " (raw " + b.raw + ")" : "") })]));
    });
    if (r.mitigation_total) box.appendChild(h("div", { class: "barrow" }, [h("span", { class: "lab", text: "Mitigation" }), h("span", { class: "mono-note", text: "authenticated, aligned mail" }), h("span", { class: "val t-ok", text: String(r.mitigation_total) })]));
    box.appendChild(h("div", { class: "barrow" }, [h("span", { class: "lab", text: "Total" }), h("span", { class: "mono-note", text: "sum of capped categories + mitigation, limited to 0-100" }), h("span", { class: "val", text: r.score + " / 100" })]));
    return box;
  }
  function hopDiagram(r) {
    if (!r.hops.length) return h("p", { class: "muted", text: "No Received headers: the delivery path cannot be reconstructed." });
    var box = h("div", { class: "hops", role: "list", "aria-label": "Received chain, oldest hop first" });
    r.hops.forEach(function (hp, idx) {
      var d = hp.delta_s, txt = idx === 0 ? "" : (d === null ? "after previous hop: time unknown" : "after previous hop: " + (Math.abs(d) >= 3600 ? (d / 3600).toFixed(1) + " h" : d + " s"));
      var node = h("div", { class: "hop" + (hp.anomalies.length ? " bad" : ""), role: "listitem" }, [
        h("span", { class: "n", text: (idx === 0 ? "hop 1 · origin" : "→ hop " + (idx + 1)) }),
        h("span", { class: "h", text: "from " + (hp.from_helo || "?") }),
        h("span", { class: "h", text: "rDNS " + (hp.rdns || "none") }),
        h("span", { class: "ip", text: hp.ip ? T.defangHost(hp.ip) + " (" + hp.ip_scope + ")" : "no IP" }),
        h("span", { class: "h", text: "by " + (hp.by || "?") }),
        hp.time_text ? h("span", { class: "ip", text: hp.time_text }) : null,
        txt ? h("span", { class: "delta" + (hp.anomalies.length ? " bad" : ""), text: txt }) : null,
        hp.anomalies.length ? h("span", { class: "tag2", text: hp.anomalies.join("; ") }) : null
      ]);
      box.appendChild(node);
    });
    return box;
  }
  function authChips(r) {
    var a = r.auth, row = h("div", { class: "authrow" });
    function chip(k, res, sub) { row.appendChild(h("div", { class: "achip " + res }, [h("span", { class: "k", text: k }), h("span", { class: "v", text: res }), sub ? h("span", { class: "s", text: sub }) : null])); }
    chip("SPF", a.spf ? a.spf.result : "none", a.spf ? (a.spf.domain || "") + " · " + a.spf.source + (a.spf_aligned ? " · aligned" : "") : "no result");
    if (a.dkim.length) a.dkim.forEach(function (d) { chip("DKIM", d.result, "d=" + d.domain + (d.selector ? " s=" + d.selector : "") + (d.result === "pass" && a.dkim_aligned ? " · aligned" : "")); });
    else chip("DKIM", "none", "no signature");
    chip("DMARC", a.dmarc ? a.dmarc.result : "none", a.dmarc ? a.dmarc.source : "");
    return row;
  }
  function identityTable(r) {
    var suf = D.cfg.multi_label_suffixes, fd = r.from ? r.from.domain : "";
    function row(label, a) {
      if (!a) return tr([td(label), td("(not present)", "muted"), td(""), td("")]);
      var same = T.sameOrg(a.domain, fd, suf);
      return tr([td(label), td((a.display ? '"' + a.display + '" ' : "") + a.addr, "wrap-any"), td(a.domain, "mono"), h("td", { class: label === "From" ? "" : (same ? "okc" : "mis"), text: label === "From" ? "—" : (same ? "same organisation" : "DIFFERENT domain") })]);
    }
    var rows = [row("From", r.from), row("Reply-To", r.reply_to), row("Return-Path", r.return_path)];
    var mid = r.message_id || "", md = mid.replace(/^<|>$/g, "").split("@").pop().toLowerCase();
    rows.push(tr([td("Message-ID"), td(mid || "(missing)", "wrap-any"), td(mid ? md : "", "mono"), h("td", { class: !mid ? "mis" : (T.sameOrg(md, fd, suf) ? "okc" : ""), text: !mid ? "missing" : (T.sameOrg(md, fd, suf) ? "same organisation" : "different (normal for ESPs/lists)") })]));
    rows.push(tr([td("Date"), td(r.date || "(missing)", "wrap-any"), td(r.date_text, "mono"), td(r.hops.length ? "first hop " + (r.hops[0].time_text || "?") : "")]));
    return simpleTable(["Header", "Value", "Domain / UTC", "Check"], rows, "cmp");
  }
  function urlTable(r) {
    if (!r.urls.length) return h("p", { class: "muted", text: "No URLs found in the text or HTML parts." });
    var rows = r.urls.map(function (u) {
      var flags = h("div", null, u.flags.map(function (f) { return flagTag(f.id, sevOf(f.id)); }));
      return tr([h("td", null, [h("span", { class: "ioc-val", text: u.defanged }), u.host_unicode ? h("span", { class: "sub", text: "decoded host: " + u.host_unicode }) : null]),
        td(u.text ? short(u.text, 60) : "—", "wrap-any"), h("td", null, [flags.childNodes.length ? flags : h("span", { class: "muted", text: "clean" })]), td(u.source)]);
    });
    return simpleTable(["URL (defanged, never clickable)", "Text shown", "Flags", "Where"], rows);
  }
  function attTable(r) {
    if (!r.attachments.length) return h("p", { class: "muted", text: "No attachments." });
    var rows = r.attachments.map(function (a) {
      return tr([h("td", null, [h("span", { class: "path" }, [h("span", { class: "nm", text: a.display_name })]), a.archive ? h("span", { class: "sub", text: "zip: " + a.archive.count + " entr" + (a.archive.count === 1 ? "y" : "ies") + (a.archive.encrypted ? ", encrypted" : "") + " · " + a.archive.entries.slice(0, 3).map(function (e) { return e.name; }).join(", ") }) : null]),
        td(a.detected_type + (a.extension ? " (." + a.extension + ")" : ""), "mono"), td(bytes(a.size), "num"), td(a.sha256.slice(0, 16) + "…", "hash"),
        h("td", null, a.flags.length ? a.flags.map(function (f) { return flagTag(f.id, sevOf(f.id)); }) : [h("span", { class: "muted", text: "clean" })])]);
    });
    return simpleTable(["File", "Detected type", "Size", "SHA-256", "Flags"], rows);
  }
  function iocMini(r) {
    if (!r.iocs.length) return h("p", { class: "muted", text: r.verdict === "benign" ? "IOCs are only exported for suspicious or worse messages." : "None." });
    return simpleTable(["Type", "Value (defanged)", "Context"], r.iocs.map(function (i) { return tr([td(i.type), td(i.defanged, "ioc-val"), td(i.context, "muted")]); }));
  }
  function copyText(text, statusEl) {
    function done(ok) { statusEl.textContent = ok ? "Copied to clipboard" : "Copy blocked: select the text and copy manually"; setTimeout(function () { statusEl.textContent = ""; }, 3000); }
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
    else done(false);
  }
  function renderDetail(el, r, opts) {
    opts = opts || {};
    clear(el);
    var th = D.analysis.thresholds, truth = opts.truth;
    var head = h("div", { class: "det-head" }, [
      h("div", { class: "btn-row" }, [vbadge(r.verdict), h("span", { class: "score", text: "risk " + r.score + " / 100" }),
        truth ? h("span", { class: "flag " + (truth.correct ? "f-ok" : "f-critical"), text: "ground truth: " + truth.truth.replace("likely_", "") + (truth.correct ? " ✓" : " ✗") }) : null,
        truth ? h("span", { class: "tag", text: truth.set }) : null]),
      h("h2", { text: r.subject || "(no subject)" }),
      h("p", { class: "hint", text: (r.from ? (r.from.display ? r.from.display + " " : "") + "<" + r.from.addr + ">" : "(no From)") + " · " + (r.date_text || "no valid date") }),
      gauge(r.score, th)
    ]);
    el.appendChild(head);
    if (truth) el.appendChild(h("p", { class: "mono-note", text: r.id + " · " + truth.category + ": " + truth.description }));
    el.appendChild(section("Why this score", reasons(r)));
    el.appendChild(section("Score breakdown (per-category caps keep one noisy area from dominating)", breakdown(r)));
    el.appendChild(section("Received chain (oldest hop first; times from each hop's own header)", hopDiagram(r)));
    el.appendChild(section("Authentication results", authChips(r)));
    el.appendChild(section("Sender identity and header checks", identityTable(r)));
    el.appendChild(section("Links (" + r.urls.length + ")", urlTable(r)));
    el.appendChild(section("Attachments (" + r.attachments.length + ")", attTable(r)));
    if (r.mitre.length) el.appendChild(section("MITRE ATT&CK", h("div", { class: "chip-row" }, r.mitre.map(function (m) { return h("span", { class: "mitre-chip", title: m.name, text: m.id + " " + m.name }); }))));
    el.appendChild(section("Recommended response", h("ul", { class: "plain" }, r.response.map(function (s) { return h("li", { text: "☐ " + s }); }))));
    el.appendChild(section("Indicators of compromise (defanged)", iocMini(r)));
    var st = h("span", { class: "toast", "aria-live": "polite" });
    el.appendChild(section("Ticket note (copy-ready)", h("div", null, [h("pre", { class: "note", text: r.ticket_note }),
      h("div", { class: "btn-row mt-s" }, [h("button", { type: "button", class: "btn", text: "Copy ticket note", onclick: function () { copyText(r.ticket_note, st); } }), st])])));
  }

  function select(id, push) {
    var r = D.byId[id]; if (!r) return;
    S.sel = id;
    Array.prototype.forEach.call($("inbox-list").querySelectorAll(".mail"), function (b) { var on = b.getAttribute("data-id") === id; b.classList.toggle("active", on); if (on) b.setAttribute("aria-current", "true"); else b.removeAttribute("aria-current"); });
    renderDetail($("detail"), r, { truth: D.truth[id] });
    if (push && window.history && history.replaceState) history.replaceState(null, "", "#msg=" + encodeURIComponent(id));
  }

  // ------------------------------------------------------------------ paste analyser
  function setupPaste() {
    var sel = $("paste-sample");
    sel.appendChild(h("option", { value: "", text: "— choose a sample message —" }));
    D.msgs.slice().sort(function (a, b) { return a.id < b.id ? -1 : 1; }).forEach(function (m) { sel.appendChild(h("option", { value: m.id, text: m.id + " · " + short(m.subject, 50) })); });
    sel.addEventListener("change", function () { if (sel.value) { $("paste-input").value = D.emls[sel.value] || ""; $("paste-status").textContent = "Sample loaded: press Analyse."; } });
    $("paste-clear").addEventListener("click", function () { $("paste-input").value = ""; sel.value = ""; $("paste-result").hidden = true; clear($("paste-result")); $("paste-status").textContent = ""; });
    $("paste-run").addEventListener("click", function () {
      var text = $("paste-input").value, st = $("paste-status");
      if (!text.trim()) { st.textContent = "Paste a message first."; return; }
      if (text.length > 2000000) { st.textContent = "Too large for the in-browser analyser (limit 2 MB)."; return; }
      var t0 = performance.now();
      try {
        var r = Core.analyzeMessage(text, D.cfg, D.dns, "pasted");
        var box = $("paste-result"); box.hidden = false;
        renderDetail(box, r, null);
        st.textContent = "Analysed in " + Math.round(performance.now() - t0) + " ms: " + VLABEL[r.verdict] + ", risk " + r.score + ". Nothing left this page.";
      } catch (e) { st.textContent = "Could not analyse that text: " + e.message; }
    });
  }

  // ------------------------------------------------------------------ evaluation, IOCs, catalogue
  function renderEval() {
    var ev = D.ev, o = ev.overall, f = o.flagged_vs_benign;
    $("eval-caveat").textContent = "The corpus and its labels were written by the same person who wrote the detector, and the 'tuning' messages were used to set the weights. The 'holdout' messages were written after the weights were frozen, but by the same author, so treat both as a regression suite, not as real-world accuracy.";
    var body = $("eval-body"); clear(body);
    var rows = Object.keys(ev.by_set).concat(["all"]).map(function (k) {
      var s = k === "all" ? o : ev.by_set[k], g = s.flagged_vs_benign;
      return tr([td(k), td(s.messages, "num"), td(s.exact + "/" + s.messages, "num"), td(g.tp, "num"), td(g.fp, "num"), td(g.fn, "num"), td(g.tn, "num"), td(String(g.precision), "num"), td(String(g.recall), "num")]);
    });
    body.appendChild(simpleTable(["Set", "Msgs", "Exact verdict", "TP", "FP", "FN", "TN", "Precision", "Recall"], rows));
    var V = ["benign", "suspicious", "likely_phishing"], cm = h("table", { class: "cm", "aria-label": "Confusion matrix, rows are ground truth" });
    cm.appendChild(h("thead", null, [h("tr", null, [h("th", { text: "truth ↓ / verdict →" })].concat(V.map(function (v) { return h("th", { text: VLABEL[v] }); })))]));
    var tb = h("tbody");
    V.forEach(function (t) { tb.appendChild(h("tr", null, [h("th", { text: VLABEL[t] })].concat(V.map(function (p) { return h("td", { class: t === p ? "diag" : (o.confusion[t][p] ? "off" : ""), text: String(o.confusion[t][p]) }); })))); });
    cm.appendChild(tb);
    body.appendChild(h("h3", { class: "sub-h", text: "Confusion matrix (all messages)" }));
    body.appendChild(h("div", { class: "table-scroll" }, [cm]));
    body.appendChild(h("h3", { class: "sub-h", text: "Misses and surprises (kept, not hidden)" }));
    if (!ev.errors.length) body.appendChild(h("p", { class: "muted", text: "None." }));
    else body.appendChild(h("ul", { class: "plain" }, ev.errors.map(function (e) {
      var bits = []; if (!e.correct) bits.push("verdict " + VLABEL[e.verdict] + " (" + e.score + "), expected " + VLABEL[e.truth]);
      if (e.missing.length) bits.push("missing " + e.missing.join(", ")); if (e.violations.length) bits.push("forbidden " + e.violations.join(", "));
      var a = h("button", { type: "button", class: "linklike", text: e.id, onclick: function () { select(e.id, true); $("detail").scrollIntoView({ block: "start" }); } });
      return h("li", null, [a, " (" + e.category + "): " + bits.join("; ")]);
    })));
  }
  function allIocs() {
    var out = []; D.msgs.forEach(function (m) { m.iocs.forEach(function (i) { out.push({ id: m.id, type: i.type, defanged: i.defanged, value: i.value, context: i.context }); }); }); return out;
  }
  function renderIocs() {
    var all = allIocs(), types = {}; all.forEach(function (i) { types[i.type] = 1; });
    var sel = $("ioc-type"); if (!sel.childNodes.length) { sel.appendChild(h("option", { value: "", text: "All types" })); Object.keys(types).sort().forEach(function (t) { sel.appendChild(h("option", { value: t, text: t })); }); }
    var q = S.iocQ.toLowerCase();
    var rows = all.filter(function (i) { return (!S.iocType || i.type === S.iocType) && (!q || (i.defanged + " " + i.id + " " + i.context).toLowerCase().indexOf(q) >= 0); });
    var tb = $("ioc-table").querySelector("tbody"); clear(tb);
    rows.slice(0, IOC_LIMIT).forEach(function (i) {
      var b = h("button", { type: "button", class: "linklike", text: i.id, onclick: function () { select(i.id, true); $("detail").scrollIntoView({ block: "start" }); } });
      tb.appendChild(tr([td(i.type), td(i.defanged, "ioc-val"), td(b)]));
    });
    $("ioc-more").textContent = rows.length > IOC_LIMIT ? "Showing " + IOC_LIMIT + " of " + rows.length + "; use the filters or download the full list." : rows.length + " IOC(s)";
  }
  function download(name, text, type) {
    var a = h("a", { href: URL.createObjectURL(new Blob([text], { type: type })), download: name });
    document.body.appendChild(a); a.click(); document.body.removeChild(a); setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }
  function renderCatalog() {
    var inds = D.cfg.indicators.slice().sort(function (a, b) { return a.category < b.category ? -1 : a.category > b.category ? 1 : b.weight - a.weight; });
    $("catalog-meta").textContent = inds.length + " indicators · thresholds " + D.analysis.thresholds.suspicious + " / " + D.analysis.thresholds.likely_phishing;
    var tb = $("catalog-table").querySelector("tbody"); clear(tb);
    inds.forEach(function (i) { tb.appendChild(tr([td(i.id, "mono"), td(i.category), td(String(i.weight), "num"), td(i.severity), td(i.mitre.join(", ") || "—", "mono"), td(i.title + ". " + i.description)])); });
  }

  // ------------------------------------------------------------------ boot
  function boot() {
    if (!Core) { showError("The analysis engine script failed to load."); return; }
    load().then(function () {
      renderKpis(); renderChips(); renderInbox(); renderEval(); renderIocs(); renderCatalog(); setupPaste();
      $("inbox-q").addEventListener("input", function (e) { S.q = e.target.value; renderInbox(); });
      $("ioc-type").addEventListener("change", function (e) { S.iocType = e.target.value; renderIocs(); });
      $("ioc-q").addEventListener("input", function (e) { S.iocQ = e.target.value; renderIocs(); });
      $("ioc-csv").addEventListener("click", function () { download("iocs.csv", Core.iocsToCsv(D.msgs), "text/csv"); });
      $("ioc-json").addEventListener("click", function () {
        var rows = []; D.msgs.forEach(function (m) { m.iocs.forEach(function (i) { rows.push({ message_id: m.id, type: i.type, value: i.value, defanged: i.defanged, context: i.context, verdict: m.verdict, score: m.score }); }); });
        download("iocs.json", JSON.stringify({ tool: "phishanalyzer", note: "Synthetic corpus: none of these are real indicators.", iocs: rows }, null, 2) + "\n", "application/json");
      });
      var m = /^#msg=(.+)$/.exec(location.hash), want = m ? decodeURIComponent(m[1]) : "";
      var first = D.byId["P01-paypal-lookalike-credential"] || D.msgs.filter(function (x) { return x.verdict === "likely_phishing"; })[0] || D.msgs[0];
      select(D.byId[want] ? want : first.id, false);
    }).catch(function (e) { showError("Could not load the dashboard data: " + e.message); });
  }
  boot();
})();
