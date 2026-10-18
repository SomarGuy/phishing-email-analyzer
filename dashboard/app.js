/* Phishing Email Analyzer dashboard (webmail-style). Vanilla JS, no dependencies, no HTML string injection: every value is
   inserted with textContent because e-mail content is attacker-controlled (display names, URLs, file names, <script> ...).
   Nothing is fetched except this site's own JSON files. */
(function () {
  "use strict";

  var VLABEL = { benign: "looks fine", suspicious: "suspicious", likely_phishing: "likely phishing" };
  var CAT_LABEL = { header: "Headers", auth: "Sign-in checks", url: "Links", attachment: "Attachments", language: "Wording", combo: "Combinations" };
  var SEV_LABEL = { critical: "critical", high: "serious", medium: "worth a look", low: "minor", info: "info" };
  var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  var IOC_LIMIT = 150;
  var D = null, S = { v: "", q: "", sel: "", sort: "risk", iocType: "", iocQ: "" };
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
  function flagTag(id, sev) { return h("span", { class: "flag" + (sev ? " f-" + sev : ""), text: id }); }
  function showError(msg) { var e = $("error"); e.hidden = false; e.textContent = msg; }
  function sevOf(id) { var i = D.indById[id]; return i ? i.severity : ""; }
  function td(content, cls) { return h("td", cls ? { class: cls } : null, [content]); }
  function verdictOf(score, th) { return score >= th.likely_phishing ? "likely_phishing" : (score >= th.suspicious ? "suspicious" : "benign"); }

  // avatars: initials plus one of eight soft colours picked from the sender's domain
  function initials(f) {
    var name = f ? (f.display || f.addr.split("@")[0]) : "?";
    var words = name.replace(/[^\p{L}\p{N} ._-]/gu, "").split(/[ ._-]+/).filter(Boolean);
    if (!words.length) return "?";
    var a = Array.from(words[0])[0], b = words.length > 1 ? Array.from(words[1])[0] : (Array.from(words[0])[1] || "");
    return (a + b).toUpperCase();
  }
  function colourOf(f) {
    var s = f ? (f.domain || f.addr || "") : "", n = 0, i;
    for (i = 0; i < s.length; i++) n = (n * 31 + s.charCodeAt(i)) % 8;
    return n;
  }
  function avatar(f, big) { return h("span", { class: "av av" + colourOf(f) + (big ? " lg" : ""), "aria-hidden": "true", text: initials(f) }); }
  function when(m) {
    var t = m.date_text || "", x = /^(\d{4})-(\d\d)-(\d\d)/.exec(t);
    return x ? MONTHS[+x[2] - 1] + " " + (+x[3]) : "no date";
  }
  function senderName(m) { return m.from ? (m.from.display || m.from.addr) : "(no sender)"; }

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

  // ------------------------------------------------------------------ views (the mail view keeps the list; the others take the room)
  var VIEWS = { paste: "view-paste", iocs: "view-iocs", eval: "view-eval", rules: "catalog" };
  function setView(v) {
    document.body.setAttribute("data-view", v);
    $("detail").hidden = v !== "mail";
    $("note").hidden = v !== "about";
    Object.keys(VIEWS).forEach(function (k) { $(VIEWS[k]).hidden = v !== k; });
    Array.prototype.forEach.call(document.querySelectorAll("[data-view].tool, .compose"), function (b) { b.classList.toggle("active", b.getAttribute("data-view") === v); });
    $("note-open").classList.toggle("active", v === "about");
    if (v === "about") { document.body.classList.add("reading"); Array.prototype.forEach.call($("inbox-list").querySelectorAll(".mail"), function (b) { b.classList.remove("active"); b.removeAttribute("aria-current"); }); }
    if (v !== "mail" && v !== "about") document.body.classList.add("reading");
    $("main").scrollTop = 0;
    window.scrollTo(0, 0);
  }

  // ------------------------------------------------------------------ folders + message list
  function renderFolders() {
    var s = D.analysis.summary, counts = { all: s.messages, likely_phishing: s.likely_phishing, suspicious: s.suspicious, benign: s.benign };
    Array.prototype.forEach.call($("kpis").querySelectorAll(".folder"), function (b) {
      var key = b.getAttribute("data-v"), on = (S.v || "all") === key;
      b.querySelector(".n").textContent = num(counts[key]);
      b.classList.toggle("active", on); b.setAttribute("aria-pressed", String(on));
    });
    $("tool-iocs-n").textContent = num(s.iocs);
    $("dataset-meta").textContent = s.messages + " made-up messages · engine " + D.analysis.version;
  }
  function wireFolders() {
    Array.prototype.forEach.call($("kpis").querySelectorAll(".folder"), function (b) {
      b.addEventListener("click", function () {
        var key = b.getAttribute("data-v"); S.v = key === "all" ? "" : key;
        $("inbox-title").textContent = b.querySelector(".lbl").textContent;
        renderFolders(); renderInbox(); setView("mail"); document.body.classList.remove("reading");
      });
    });
  }
  function matches(m) {
    if (S.v && m.verdict !== S.v) return false;
    if (S.q) {
      var hay = [m.id, m.subject, m.from ? m.from.display + " " + m.from.addr : "", m.indicators.map(function (i) { return i.id; }).join(" ")].join(" ").toLowerCase();
      if (hay.indexOf(S.q.toLowerCase()) < 0) return false;
    }
    return true;
  }
  function snippet(m) {
    var hits = m.indicators.filter(function (i) { return i.points > 0 && i.category !== "combo"; });
    if (!hits.length) return m.verdict === "benign" ? "Nothing odd found." : "No single rule stands out.";
    var first = hits[0].title.charAt(0).toUpperCase() + hits[0].title.slice(1);
    return first + (hits.length > 1 ? " (+" + (hits.length - 1) + " more)" : "");
  }
  function renderInbox() {
    var list = $("inbox-list"); clear(list);
    var rows = D.msgs.filter(matches).sort(function (a, b) {
      if (S.sort === "new") return (a.date_text < b.date_text ? 1 : a.date_text > b.date_text ? -1 : 0) || (a.id < b.id ? -1 : 1);
      return b.score - a.score || (a.id < b.id ? -1 : 1);
    });
    $("inbox-count").textContent = rows.length === D.msgs.length ? rows.length + " messages" : rows.length + " of " + D.msgs.length;
    $("inbox-empty").hidden = rows.length > 0;
    rows.forEach(function (m) {
      var b = h("button", { type: "button", class: "mail v-" + m.verdict + (m.id === S.sel && document.body.getAttribute("data-view") === "mail" ? " active" : ""), "data-id": m.id, "aria-current": m.id === S.sel ? "true" : null }, [
        avatar(m.from),
        h("span", { class: "mbody" }, [
          h("span", { class: "r1" }, [h("span", { class: "from", text: senderName(m) }), h("span", { class: "when", text: when(m) })]),
          h("span", { class: "subj", text: m.subject || "(no subject)" }),
          h("span", { class: "snip", text: snippet(m) }),
          h("span", { class: "r3" }, [vbadge(m.verdict), h("span", { class: "score", title: "risk score out of 100", text: String(m.score) })])
        ])
      ]);
      b.addEventListener("click", function () { setView("mail"); select(m.id, true, true); });
      list.appendChild(h("li", null, [b]));
    });
  }

  // ------------------------------------------------------------------ message view (shared by the demo mailbox and pasted mail)
  function section(title, body, cls) { return h("div", { class: "sec" + (cls ? " " + cls : "") }, [h("h3", { text: title }), body]); }
  function simpleTable(head, rows, cls) {
    var t = h("table", { class: "data " + (cls || "") }, [h("thead", null, [h("tr", null, head.map(function (x) { return h("th", { text: x }); }))])]);
    var tb = h("tbody"); rows.forEach(function (r) { tb.appendChild(r); }); t.appendChild(tb);
    return h("div", { class: "table-scroll" }, [t]);
  }
  function tr(cells, cls) { return h("tr", { class: "static-row" + (cls ? " " + cls : "") }, cells); }

  function gauge(score, th) {
    var v = verdictOf(score, th);
    var g = h("div", { class: "gauge v-" + v, role: "img", "aria-label": "Risk score " + score + " out of 100" }, [h("i", { class: "needle" }), h("b", { class: "tick" }), h("b", { class: "tick" })]);
    g.style.setProperty("--s", th.suspicious + "%"); g.style.setProperty("--p", th.likely_phishing + "%");
    g.children[0].style.left = score + "%";
    g.children[1].style.left = th.suspicious + "%"; g.children[2].style.left = th.likely_phishing + "%";
    return h("div", { class: "gauge-wrap" }, [
      h("div", { class: "gauge-num" }, [h("span", { class: "big", text: String(score) }), h("span", { class: "of", text: " out of 100" })]),
      g,
      h("div", { class: "gauge-legend" }, [h("span", { text: "fine" }), h("span", { text: "suspicious from " + th.suspicious }), h("span", { text: "phishing from " + th.likely_phishing })])
    ]);
  }
  var BANNER = {
    likely_phishing: ["This looks like phishing.", "I would not click anything in it or open the attachments. Links and files are shown as plain text here, so you can look but nothing can bite."],
    suspicious: ["Something about this one is off.", "It is not a slam dunk, but I would double check with the sender some other way before clicking anything."],
    benign: ["No red flags worth worrying about.", "It looks like ordinary mail. Links and files are still shown as plain text, same as everything else on this page."]
  };
  function warnBanner(r) {
    var b = BANNER[r.verdict];
    return h("div", { class: "warn v-" + r.verdict, role: "note" }, [
      h("span", { class: "warn-ic", "aria-hidden": "true", text: r.verdict === "benign" ? "✓" : "!" }),
      h("div", { class: "warn-text" }, [h("strong", { text: b[0] }), h("span", { text: " " + b[1] })])
    ]);
  }
  function reasons(r) {
    var items = r.indicators.filter(function (i) { return i.points > 0; });
    if (!items.length) return h("p", { class: "muted", text: "Nothing fired. That is the whole story." });
    var ul = h("ul", { class: "reasons" });
    items.forEach(function (i) {
      var li = h("li", { class: "reason sev-" + (i.severity || "info") }, [
        h("span", { class: "pts", text: "+" + i.points }),
        h("div", null, [
          h("div", { class: "ttl", text: i.title + (i.points !== i.weight ? " (worth " + i.weight + ", trimmed by the cap)" : "") }),
          h("div", { class: "dt", text: i.detail }),
          i.evidence.length ? h("div", { class: "ev", text: i.evidence.join("\n") }) : null,
          i.mitre.length ? h("div", { class: "mt" }, i.mitre.map(function (t) { return h("span", { class: "mitre-chip", text: t }); })) : null
        ])]);
      ul.appendChild(li);
    });
    r.mitigations.forEach(function (m) {
      ul.appendChild(h("li", { class: "reason good" }, [h("span", { class: "pts", text: String(m.points) }), h("div", null, [h("div", { class: "ttl", text: m.title }), h("div", { class: "dt", text: m.detail })])]));
    });
    return ul;
  }
  function breakdown(r) {
    var box = h("div", { class: "bars" });
    ["header", "auth", "url", "attachment", "language", "combo"].forEach(function (c) {
      var b = r.breakdown[c], max = b.cap;
      var track = h("div", { class: "track" }, [h("i", { class: "raw" }), h("i", { class: "got" })]);
      track.children[0].style.width = Math.min(100, (b.raw / max) * 100) + "%";
      track.children[1].style.width = (b.capped / max) * 100 + "%";
      box.appendChild(h("div", { class: "barrow" }, [h("span", { class: "lab", text: CAT_LABEL[c] }), track, h("span", { class: "val", text: b.capped + " of " + b.cap + (b.raw > b.cap ? " (would be " + b.raw + ")" : "") })]));
    });
    if (r.mitigation_total) box.appendChild(h("div", { class: "barrow" }, [h("span", { class: "lab", text: "Good signs" }), h("span", { class: "mono-note", text: "the sender checked out, so points come off" }), h("span", { class: "val t-ok", text: String(r.mitigation_total) })]));
    box.appendChild(h("div", { class: "barrow total" }, [h("span", { class: "lab", text: "Total" }), h("span", { class: "mono-note", text: "add it up, then keep it between 0 and 100" }), h("span", { class: "val", text: r.score + " out of 100" })]));
    return box;
  }
  function routeList(r) {
    if (!r.hops.length) return h("p", { class: "muted", text: "There are no Received headers, so I cannot rebuild the route this email took." });
    var ol = h("ol", { class: "route", "aria-label": "Servers the email passed through, oldest first" });
    r.hops.forEach(function (hp, idx) {
      var d = hp.delta_s, txt = idx === 0 ? "" : (d === null ? "time since the last stop is unknown" : (Math.abs(d) >= 3600 ? (d / 3600).toFixed(1) + " h" : d + " s") + " after the last stop");
      ol.appendChild(h("li", { class: "hop" + (hp.anomalies.length ? " bad" : "") }, [
        h("span", { class: "stop", text: idx === 0 ? "Started at" : "Stop " + (idx + 1) }),
        h("span", { class: "h", text: (hp.from_helo || "?") + "  (reverse DNS: " + (hp.rdns || "none") + ")" }),
        h("span", { class: "ip", text: (hp.ip ? T.defangHost(hp.ip) + " (" + hp.ip_scope + ")" : "no IP") + "  ·  handed to " + (hp.by || "?") }),
        hp.time_text ? h("span", { class: "ip", text: hp.time_text }) : null,
        txt ? h("span", { class: "delta" + (hp.anomalies.length ? " bad" : ""), text: txt }) : null,
        hp.anomalies.length ? h("span", { class: "tag2", text: hp.anomalies.join("; ") }) : null
      ]));
    });
    return ol;
  }
  function authChips(r) {
    var a = r.auth, row = h("div", { class: "authrow" });
    function chip(k, res, sub) { row.appendChild(h("div", { class: "achip " + res }, [h("span", { class: "k", text: k }), h("span", { class: "v", text: res }), sub ? h("span", { class: "s", text: sub }) : null])); }
    chip("SPF", a.spf ? a.spf.result : "none", a.spf ? (a.spf.domain || "") + " · " + a.spf.source + (a.spf_aligned ? " · matches From" : "") : "no result");
    if (a.dkim.length) a.dkim.forEach(function (d) { chip("DKIM", d.result, "d=" + d.domain + (d.selector ? " s=" + d.selector : "") + (d.result === "pass" && a.dkim_aligned ? " · matches From" : "")); });
    else chip("DKIM", "none", "no signature");
    chip("DMARC", a.dmarc ? a.dmarc.result : "none", a.dmarc ? a.dmarc.source : "");
    return row;
  }
  function identityTable(r) {
    var suf = D.cfg.multi_label_suffixes, fd = r.from ? r.from.domain : "";
    function row(label, a) {
      if (!a) return tr([td(label), td("(not there)", "muted"), td(""), td("")]);
      var same = T.sameOrg(a.domain, fd, suf);
      return tr([td(label), td((a.display ? '"' + a.display + '" ' : "") + a.addr, "wrap-any"), td(a.domain, "mono"), h("td", { class: label === "From" ? "" : (same ? "okc" : "mis"), text: label === "From" ? "the sender it claims" : (same ? "same organisation" : "DIFFERENT domain") })]);
    }
    var rows = [row("From", r.from), row("Reply-To", r.reply_to), row("Return-Path", r.return_path)];
    var mid = r.message_id || "", md = mid.replace(/^<|>$/g, "").split("@").pop().toLowerCase();
    rows.push(tr([td("Message-ID"), td(mid || "(missing)", "wrap-any"), td(mid ? md : "", "mono"), h("td", { class: !mid ? "mis" : (T.sameOrg(md, fd, suf) ? "okc" : ""), text: !mid ? "missing" : (T.sameOrg(md, fd, suf) ? "same organisation" : "different (normal for newsletters and lists)") })]));
    rows.push(tr([td("Date"), td(r.date || "(missing)", "wrap-any"), td(r.date_text, "mono"), td(r.hops.length ? "first stop " + (r.hops[0].time_text || "?") : "")]));
    return simpleTable(["Header", "What it says", "Domain / UTC time", "Does it match?"], rows, "cmp");
  }
  function urlTable(r) {
    if (!r.urls.length) return h("p", { class: "muted", text: "No links in the text or HTML parts." });
    var rows = r.urls.map(function (u) {
      var flags = h("div", null, u.flags.map(function (f) { return flagTag(f.id, sevOf(f.id)); }));
      return tr([h("td", null, [h("span", { class: "ioc-val", text: u.defanged }), u.host_unicode ? h("span", { class: "sub", text: "real host name: " + u.host_unicode }) : null]),
        td(u.text ? short(u.text, 60) : "(no text)", "wrap-any"), h("td", null, [flags.childNodes.length ? flags : h("span", { class: "muted", text: "clean" })]), td(u.source)]);
    });
    return simpleTable(["Link (defanged, never clickable)", "What the text says", "Flags", "Found in"], rows, "t-urls");
  }
  function attTable(r) {
    if (!r.attachments.length) return h("p", { class: "muted", text: "No attachments." });
    var rows = r.attachments.map(function (a) {
      return tr([h("td", null, [h("span", { class: "path" }, [h("span", { class: "nm", text: a.display_name })]), a.archive ? h("span", { class: "sub", text: "zip: " + a.archive.count + " entr" + (a.archive.count === 1 ? "y" : "ies") + (a.archive.encrypted ? ", password protected" : "") + " · " + a.archive.entries.slice(0, 3).map(function (e) { return e.name; }).join(", ") }) : null]),
        td(a.detected_type + (a.extension ? " (." + a.extension + ")" : ""), "mono"), td(bytes(a.size), "num"), td(a.sha256.slice(0, 16) + "…", "hash"),
        h("td", null, a.flags.length ? a.flags.map(function (f) { return flagTag(f.id, sevOf(f.id)); }) : [h("span", { class: "muted", text: "clean" })])]);
    });
    return simpleTable(["File", "What it really is", "Size", "SHA-256", "Flags"], rows, "t-att");
  }
  function iocMini(r) {
    if (!r.iocs.length) return h("p", { class: "muted", text: r.verdict === "benign" ? "I only list these for suspicious or worse mail." : "None." });
    return simpleTable(["Type", "Value (defanged)", "Where it came from"], r.iocs.map(function (i) { return tr([td(i.type), td(i.defanged, "ioc-val"), td(i.context, "muted")]); }), "t-ioc");
  }
  function copyText(text, statusEl) {
    function done(ok) { statusEl.textContent = ok ? "Copied. Go paste it somewhere useful." : "Your browser blocked that. Select the text and copy it by hand."; setTimeout(function () { statusEl.textContent = ""; }, 3000); }
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
    else done(false);
  }
  function renderDetail(el, r, opts) {
    opts = opts || {};
    clear(el);
    var th = D.analysis.thresholds, truth = opts.truth;
    el.appendChild(warnBanner(r));
    var tags = h("div", { class: "tagrow" }, [vbadge(r.verdict),
      truth ? h("span", { class: "flag " + (truth.correct ? "f-ok" : "f-critical"), title: "what I decided the right answer was before running the tool", text: "my label: " + truth.truth.replace("likely_", "") + (truth.correct ? " ✓" : " ✗") }) : null,
      truth ? h("span", { class: "tag", text: truth.set + " set" }) : null]);
    el.appendChild(h("div", { class: "msg-head" }, [
      avatar(r.from, true),
      h("div", { class: "who" }, [
        h("h2", { text: r.subject || "(no subject)" }),
        h("p", { class: "from-line" }, [h("strong", { text: r.from ? (r.from.display || r.from.addr) : "(no From)" }), r.from ? h("span", { class: "addr", text: " <" + r.from.addr + ">" }) : null]),
        h("p", { class: "meta-line", text: (r.to ? "to " + r.to + "  ·  " : "") + (r.date_text || "no valid date") }),
        tags
      ]),
      gauge(r.score, th)
    ]));
    if (truth) el.appendChild(h("p", { class: "mono-note case-note", text: r.id + " · " + truth.category + ": " + truth.description }));
    var jumps = [];
    function add(label, title, body, cls) { var sec = section(title, body, cls); el.appendChild(sec); jumps.push([label, sec]); }
    var jumpRow = h("div", { class: "jump", "aria-label": "Jump to a part of this message" }, [h("span", { class: "jl", text: "Jump to" })]);
    el.appendChild(jumpRow);
    add("Why", "Why it got this score", reasons(r), "reasons-sec");
    add("Points", "Where the points came from (each area has a cap so one noisy area can't take over)", breakdown(r));
    add("Route", "The trip this email took (oldest stop first, times from each server's own header)", routeList(r));
    add("Sign-in", "Did the sender prove who they are?", authChips(r));
    add("Sender", "Is it really from who it says?", identityTable(r));
    add("Links", "Links (" + r.urls.length + ")", urlTable(r));
    add("Files", "Attachments (" + r.attachments.length + ")", attTable(r));
    if (r.mitre.length) add("ATT&CK", "Attack techniques it matches (MITRE ATT&CK)", h("div", { class: "chip-row" }, r.mitre.map(function (m) { return h("span", { class: "mitre-chip", title: m.name, text: m.id + " " + m.name }); })));
    add("What to do", "What I would do about it", h("ul", { class: "plain todo" }, r.response.map(function (s) { return h("li", { text: s }); })));
    add("Block list", "Things to block from this message", iocMini(r));
    var st = h("span", { class: "toast", "aria-live": "polite" });
    add("Ticket note", "Note for the ticket", h("div", null, [h("pre", { class: "note", text: r.ticket_note }),
      h("div", { class: "btn-row mt-s" }, [h("button", { type: "button", class: "btn", text: "Copy the ticket note", onclick: function () { copyText(r.ticket_note, st); } }), st])]));
    jumps.forEach(function (j) { jumpRow.appendChild(h("button", { type: "button", class: "jchip", text: j[0], onclick: function () { j[1].scrollIntoView({ block: "start", behavior: "smooth" }); } })); });
    var raw = opts.raw;
    if (raw) {
      var shown = raw.length > 30000 ? raw.slice(0, 30000) + "\n[cut off here, " + (raw.length - 30000) + " more characters]" : raw;
      el.appendChild(h("details", { class: "orig" }, [h("summary", { text: "Show the original message" }), h("pre", { class: "rawsrc", text: shown })]));
    }
  }

  function select(id, push, fromUser) {
    var r = D.byId[id]; if (!r) return;
    S.sel = id;
    Array.prototype.forEach.call($("inbox-list").querySelectorAll(".mail"), function (b) { var on = b.getAttribute("data-id") === id; b.classList.toggle("active", on); if (on) b.setAttribute("aria-current", "true"); else b.removeAttribute("aria-current"); });
    renderDetail($("detail"), r, { truth: D.truth[id], raw: D.emls[id] });
    $("main").scrollTop = 0;
    if (fromUser) window.scrollTo(0, 0);
    if (fromUser) document.body.classList.add("reading");
    if (push && window.history && history.replaceState) history.replaceState(null, "", "#msg=" + encodeURIComponent(id));
  }

  // ------------------------------------------------------------------ paste analyser
  function setupPaste() {
    var sel = $("paste-sample");
    sel.appendChild(h("option", { value: "", text: "pick a sample message" }));
    D.msgs.slice().sort(function (a, b) { return a.id < b.id ? -1 : 1; }).forEach(function (m) { sel.appendChild(h("option", { value: m.id, text: m.id + " · " + short(m.subject, 50) })); });
    sel.addEventListener("change", function () { if (sel.value) { $("paste-input").value = D.emls[sel.value] || ""; $("paste-status").textContent = "Sample loaded. Press Check it."; } });
    $("paste-clear").addEventListener("click", function () { $("paste-input").value = ""; sel.value = ""; $("paste-result").hidden = true; clear($("paste-result")); $("paste-status").textContent = ""; });
    $("paste-run").addEventListener("click", function () {
      var text = $("paste-input").value, st = $("paste-status");
      if (!text.trim()) { st.textContent = "Paste something first, I have nothing to read yet."; return; }
      if (text.length > 2000000) { st.textContent = "That is too big for the in-browser version (2 MB limit)."; return; }
      var t0 = performance.now();
      try {
        var r = Core.analyzeMessage(text, D.cfg, D.dns, "pasted");
        var box = $("paste-result"); box.hidden = false;
        renderDetail(box, r, null);
        st.textContent = "Checked in " + Math.round(performance.now() - t0) + " ms: " + VLABEL[r.verdict] + ", risk " + r.score + ". Nothing left this page.";
      } catch (e) { st.textContent = "I could not make sense of that: " + e.message; }
    });
  }

  // ------------------------------------------------------------------ evaluation, IOCs, rulebook
  function renderEval() {
    var ev = D.ev, o = ev.overall;
    $("eval-caveat").textContent = "Read this first: I wrote the mail, I labelled it, and I wrote the detector. The 'tuning' messages are the ones I used to set the weights. The 'holdout' messages came after I froze the weights, but they are still mine, so please treat all of this as a regression test and not as real-world accuracy.";
    var body = $("eval-body"); clear(body);
    var rows = Object.keys(ev.by_set).concat(["all"]).map(function (k) {
      var s = k === "all" ? o : ev.by_set[k], g = s.flagged_vs_benign;
      return tr([td(k), td(s.messages, "num"), td(s.exact + "/" + s.messages, "num"), td(g.tp, "num"), td(g.fp, "num"), td(g.fn, "num"), td(g.tn, "num"), td(String(g.precision), "num"), td(String(g.recall), "num")]);
    });
    body.appendChild(simpleTable(["Set", "Messages", "Right verdict", "Phish caught", "False alarms", "Phish missed", "Fine, left alone", "Precision", "Recall"], rows));
    var V = ["benign", "suspicious", "likely_phishing"], cm = h("table", { class: "cm", "aria-label": "Confusion matrix, rows are my label" });
    cm.appendChild(h("thead", null, [h("tr", null, [h("th", { text: "my label ↓ / what the tool said →" })].concat(V.map(function (v) { return h("th", { text: VLABEL[v] }); })))]));
    var tb = h("tbody");
    V.forEach(function (t) { tb.appendChild(h("tr", null, [h("th", { text: VLABEL[t] })].concat(V.map(function (p) { return h("td", { class: t === p ? "diag" : (o.confusion[t][p] ? "off" : ""), text: String(o.confusion[t][p]) }); })))); });
    cm.appendChild(tb);
    body.appendChild(h("h3", { class: "sub-h", text: "All messages, label against verdict" }));
    body.appendChild(h("div", { class: "table-scroll" }, [cm]));
    body.appendChild(h("h3", { class: "sub-h", text: "Where it got things wrong (left in on purpose)" }));
    if (!ev.errors.length) body.appendChild(h("p", { class: "muted", text: "Nothing." }));
    else body.appendChild(h("ul", { class: "plain" }, ev.errors.map(function (e) {
      var bits = []; if (!e.correct) bits.push("said " + VLABEL[e.verdict] + " (" + e.score + "), I expected " + VLABEL[e.truth]);
      if (e.missing.length) bits.push("did not fire " + e.missing.join(", ")); if (e.violations.length) bits.push("fired but should not have: " + e.violations.join(", "));
      var a = h("button", { type: "button", class: "linklike", text: e.id, onclick: function () { setView("mail"); S.v = ""; renderFolders(); renderInbox(); select(e.id, true, true); } });
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
      var b = h("button", { type: "button", class: "linklike", text: i.id, onclick: function () { setView("mail"); S.v = ""; renderFolders(); renderInbox(); select(i.id, true, true); } });
      tb.appendChild(tr([td(i.type), td(i.defanged, "ioc-val"), td(b)]));
    });
    $("ioc-more").textContent = rows.length > IOC_LIMIT ? "Showing " + IOC_LIMIT + " of " + rows.length + ". Filter them or download the full list." : rows.length + " item" + (rows.length === 1 ? "" : "s");
  }
  function download(name, text, type) {
    var a = h("a", { href: URL.createObjectURL(new Blob([text], { type: type })), download: name });
    document.body.appendChild(a); a.click(); document.body.removeChild(a); setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }
  function renderCatalog() {
    var inds = D.cfg.indicators.slice().sort(function (a, b) { return a.category < b.category ? -1 : a.category > b.category ? 1 : b.weight - a.weight; });
    $("catalog-meta").textContent = inds.length + " rules · suspicious from " + D.analysis.thresholds.suspicious + ", phishing from " + D.analysis.thresholds.likely_phishing;
    var tb = $("catalog-table").querySelector("tbody"); clear(tb);
    inds.forEach(function (i) { tb.appendChild(tr([td(i.id, "mono"), td(i.category), td(String(i.weight), "num"), td(SEV_LABEL[i.severity] || i.severity), td(i.mitre.join(", ") || "none", "mono"), td(i.title + ". " + i.description)])); });
  }

  // ------------------------------------------------------------------ boot
  function boot() {
    if (!Core) { showError("The analysis script did not load, so there is nothing to show. Try reloading."); return; }
    load().then(function () {
      renderFolders(); wireFolders(); renderInbox(); renderEval(); renderIocs(); renderCatalog(); setupPaste();
      $("inbox-q").addEventListener("input", function (e) { S.q = e.target.value; if (document.body.getAttribute("data-view") !== "mail") setView("mail"); document.body.classList.remove("reading"); renderInbox(); });
      $("inbox-sort").addEventListener("change", function (e) { S.sort = e.target.value; renderInbox(); });
      $("ioc-type").addEventListener("change", function (e) { S.iocType = e.target.value; renderIocs(); });
      $("ioc-q").addEventListener("input", function (e) { S.iocQ = e.target.value; renderIocs(); });
      $("ioc-csv").addEventListener("click", function () { download("iocs.csv", Core.iocsToCsv(D.msgs), "text/csv"); });
      $("ioc-json").addEventListener("click", function () {
        var rows = []; D.msgs.forEach(function (m) { m.iocs.forEach(function (i) { rows.push({ message_id: m.id, type: i.type, value: i.value, defanged: i.defanged, context: i.context, verdict: m.verdict, score: m.score }); }); });
        download("iocs.json", JSON.stringify({ tool: "phishanalyzer", note: "Synthetic corpus: none of these are real indicators.", iocs: rows }, null, 2) + "\n", "application/json");
      });
      Array.prototype.forEach.call(document.querySelectorAll("[data-view].tool, .compose"), function (b) { b.addEventListener("click", function () { setView(b.getAttribute("data-view")); }); });
      $("note-open").addEventListener("click", function () { setView("about"); });
      $("back-btn").addEventListener("click", function () { document.body.classList.remove("reading"); if (document.body.getAttribute("data-view") !== "about") setView("mail"); });
      var m = /^#msg=(.+)$/.exec(location.hash), want = m ? decodeURIComponent(m[1]) : "";
      var first = D.byId["P01-paypal-lookalike-credential"] || D.msgs.filter(function (x) { return x.verdict === "likely_phishing"; })[0] || D.msgs[0];
      select(D.byId[want] ? want : first.id, false, false);
      setView("mail");
    }).catch(function (e) { showError("I could not load the data files: " + e.message); });
  }
  boot();
})();
