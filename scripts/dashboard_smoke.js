/* Optional end-to-end check of the dashboard in a real (headless) Chrome, plus README screenshots.
 *   npm i playwright-core            (no browser download: uses your installed Chrome/Chromium)
 *   python -m http.server 8077 --directory dashboard &
 *   CHROME=/usr/bin/google-chrome node scripts/dashboard_smoke.js http://127.0.0.1:8077 screenshots
 * Run from the project root (it reads dashboard/data/*.json for the expected values).
 */
const { chromium } = require("playwright-core");
const assert = require("assert");
const fs = require("fs");
const base = process.argv[2] || "http://127.0.0.1:8077";
const outDir = process.argv[3] || "screenshots";
const analysis = JSON.parse(fs.readFileSync("dashboard/data/analysis.json", "utf8"));
const emls = JSON.parse(fs.readFileSync("dashboard/data/emls.json", "utf8"));
const byId = Object.fromEntries(analysis.messages.map((m) => [m.id, m]));
const VL = { benign: "benign", suspicious: "suspicious", likely_phishing: "likely phishing" };

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME || "/usr/bin/google-chrome", args: ["--no-sandbox"] });
  const errors = [], requests = [];
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("request", (r) => requests.push(r.url()));
  let dialogs = 0;
  page.on("dialog", async (d) => { dialogs++; await d.dismiss(); });
  const rows = (sel) => page.locator(sel + " tbody tr").count();

  await page.goto(base + "/", { waitUntil: "networkidle" });
  await page.waitForSelector("#inbox-list .mail");

  // ---- banner, KPIs, inbox match the analysis
  assert(/SYNTHETIC/.test(await page.locator("#banner").textContent()), "synthetic banner");
  const s = analysis.summary;
  for (const [v, n] of [["likely_phishing", s.likely_phishing], ["suspicious", s.suspicious], ["benign", s.benign]]) {
    assert.strictEqual((await page.locator(`.kpi[data-v="${v}"] .n`).textContent()).trim(), String(n), "KPI " + v);
  }
  assert.strictEqual(await page.locator("#inbox-list .mail").count(), analysis.messages.length, "inbox lists every message");
  assert.strictEqual(await page.locator("#inbox-list .vbadge").count(), analysis.messages.length, "every row has a verdict badge");
  assert.strictEqual(await rows("#ioc-table"), Math.min(150, s.iocs), "IOC table rows");
  assert((await rows("#catalog-table")) > 50, "indicator catalogue listed");

  // ---- default selection: drill-down content
  const sel = await page.locator("#inbox-list .mail.active").getAttribute("data-id");
  const m0 = byId[sel];
  const detail = page.locator("#detail");
  assert(new RegExp(m0.subject.slice(0, 20).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).test(await detail.textContent()), "detail shows the subject");
  assert((await detail.locator(".hop").count()) === m0.hops.length, "hop diagram has one node per Received header");
  assert((await detail.locator(".barrow").count()) >= 7, "score breakdown bars");
  assert((await detail.locator(".achip").count()) >= 3, "auth chips");
  assert((await detail.locator("table.cmp tbody tr").count()) === 5, "identity comparison rows");
  assert.strictEqual(await detail.locator(".reason").count(), m0.indicators.filter((i) => i.points > 0).length + m0.mitigations.length, "one reason card per scoring indicator");
  assert(/hxxp/.test(await detail.textContent()) && !/https?:\/\/[a-z0-9.-]+\.(test|example|invalid)/i.test(await detail.locator("table").nth(1).textContent()), "URLs are shown defanged");
  assert(/PHISHING TRIAGE/.test(await detail.locator("pre.note").textContent()), "ticket note present");
  await page.screenshot({ path: outDir + "/01-dashboard.png" });
  await page.screenshot({ path: outDir + "/01-dashboard-full.png", fullPage: true });

  // ---- filters
  await page.click('.kpi[data-v="benign"]');
  assert.strictEqual(await page.locator("#inbox-list .mail").count(), s.benign, "benign filter count");
  await page.click('.kpi[data-v="benign"]');
  await page.click("#inbox-chips button:has-text('suspicious')");
  assert.strictEqual(await page.locator("#inbox-list .mail").count(), s.suspicious, "suspicious chip count");
  await page.click("#inbox-chips button:has-text('suspicious')");
  await page.fill("#inbox-q", "gift_card");
  const gift = await page.locator("#inbox-list .mail").count();
  assert(gift >= 1 && gift < analysis.messages.length, "search by indicator id, got " + gift);
  await page.fill("#inbox-q", "zzz-no-such");
  assert(await page.locator("#inbox-empty").isVisible(), "empty state");
  await page.fill("#inbox-q", "");

  // ---- drill into specific messages
  const open = async (id) => { await page.locator(`#inbox-list .mail[data-id="${id}"]`).click(); await page.waitForFunction((i) => document.querySelector("#inbox-list .mail.active")?.dataset.id === i, id); };
  await open("P04-remittance-html-smuggling");
  assert(/HTML smuggling/i.test(await detail.textContent()), "smuggling indicator explained");
  assert(/Remittance-0041\.html/.test(await detail.locator("table").nth(2).textContent()), "attachment table lists the file");
  await open("P13-amazon-userinfo-ip-url");
  assert(/userinfo|credentials-style/i.test(await detail.textContent()), "userinfo trick explained");
  assert(/T1566\.002/.test(await detail.textContent()), "ATT&CK technique shown");
  await open("P10-cfo-vendor-bank-change-lookalike");
  assert(/offline/i.test(await detail.locator(".authrow").textContent()), "offline SPF evaluation shown");
  assert((await detail.locator("td.mis").count()) >= 1, "mismatching domains highlighted");
  await open("B01-newsletter-harbour-gazette");
  assert(/benign/.test(await detail.locator(".vbadge").first().textContent()), "newsletter is benign");
  assert(/ground truth: benign ✓/.test(await detail.textContent()), "ground truth tag");
  await open("B12-secops-awareness-quoted-phish");
  assert(/ground truth: benign ✗/.test(await detail.textContent()), "known hard negative flagged as a miss");
  await open("P09-ceo-gift-card-bec");
  await page.waitForTimeout(300);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.locator("#detail").scrollIntoViewIfNeeded();
  await page.setViewportSize({ width: 1440, height: 1400 });
  await page.locator("#detail").scrollIntoViewIfNeeded();
  const bb2 = await page.locator("#detail").boundingBox();
  await page.screenshot({ path: outDir + "/02-message-drilldown.png", clip: { x: bb2.x, y: Math.max(0, bb2.y), width: bb2.width, height: Math.min(1250, bb2.height) } });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.locator("#detail .sec", { hasText: "Score breakdown" }).first().scrollIntoViewIfNeeded();
  await open("P10-cfo-vendor-bank-change-lookalike");
  assert((await detail.locator(".hop.bad").count()) >= 1 && (await detail.locator(".hop .delta.bad").count()) >= 1, "anomalous hop highlighted in the diagram");
  await page.locator("#detail .sec", { hasText: "Received chain" }).first().screenshot({ path: outDir + "/03-hop-diagram.png" });
  await page.locator("#detail .sec", { hasText: "Score breakdown" }).first().screenshot({ path: outDir + "/03-score-breakdown.png" });

  // ---- copy ticket note button gives feedback
  await page.click("text=Copy ticket note");
  await page.waitForFunction(() => /Copied|Copy blocked/.test(document.querySelector("#detail .toast").textContent));

  // ---- paste analyser: same verdict as the Python engine
  await page.selectOption("#paste-sample", "P05-invoice-double-extension-exe");
  assert(/Content-Type: multipart\/mixed/.test(await page.inputValue("#paste-input")), "sample loaded into the textarea");
  await page.click("#paste-run");
  await page.waitForSelector("#paste-result:not([hidden]) .vbadge");
  const py = byId["P05-invoice-double-extension-exe"];
  assert.strictEqual((await page.locator("#paste-result .vbadge").first().textContent()).trim(), VL[py.verdict], "browser verdict equals Python verdict");
  assert(new RegExp("risk " + py.score + " / 100").test(await page.locator("#paste-result").textContent()), "browser score equals Python score " + py.score);
  assert(/Invoice_8841\.pdf\.exe/.test(await page.locator("#paste-result").textContent()), "pasted attachment analysed");
  // headers only
  await page.fill("#paste-input", "From: \"IT Help Desk\" <helpdesk@northwind-analytics-support.test>\nReply-To: it@freemail.example\nSubject: Password expires today - verify your account\nDate: Mon, 02 Mar 2026 10:00:00 +0000\nMessage-ID: <x@northwind-analytics-support.test>\nAuthentication-Results: mx; spf=fail smtp.mailfrom=northwind-analytics-support.test; dmarc=fail header.from=northwind-analytics-support.test\n");
  await page.click("#paste-run");
  await page.waitForFunction(() => /Analysed in/.test(document.getElementById("paste-status").textContent));
  assert(/likely phishing/.test(await page.locator("#paste-result .vbadge").first().textContent()), "header-only paste scores as likely phishing");
  await page.locator("#paste-title").scrollIntoViewIfNeeded();
  await page.setViewportSize({ width: 1440, height: 1500 });
  await page.locator("#paste-title").scrollIntoViewIfNeeded();
  const pb = await page.locator("section[aria-labelledby=paste-title]").boundingBox();
  await page.screenshot({ path: outDir + "/05-paste-analyser.png", clip: { x: pb.x, y: Math.max(0, pb.y), width: pb.width, height: Math.min(1050, pb.height) } });
  await page.setViewportSize({ width: 1440, height: 900 });

  // ---- hostile text stays inert, nothing fetched
  const hostile = "From: \"<img src=x onerror=alert(1)>\" <a@evil.test>\nSubject: <script>alert(2)</script>\nDate: Mon, 02 Mar 2026 10:00:00 +0000\nContent-Type: text/html\n\n<a href=\"https://<svg onload=alert(3)>.test/x\">click <b onmouseover=alert(4)>here</b></a><img src=\"https://tracker.test/p.gif\"><script>alert(5)</script>";
  await page.fill("#paste-input", hostile);
  const before = requests.length;
  await page.click("#paste-run");
  await page.waitForFunction(() => /Analysed in|Could not/.test(document.getElementById("paste-status").textContent));
  assert.strictEqual(await page.locator("main img, main svg[onload], main script, main b[onmouseover]").count(), 0, "hostile HTML stays text");
  assert(/<script>alert\(2\)<\/script>/.test(await page.locator("#paste-result").textContent()), "hostile subject shown as text");
  assert.strictEqual(requests.slice(before).filter((u) => !u.startsWith(base)).length, 0, "no external requests while analysing");
  assert.strictEqual(requests.filter((u) => !u.startsWith(base)).length, 0, "no external requests at all");
  assert.strictEqual(dialogs, 0, "no dialogs");
  await page.click("#paste-clear");

  // ---- IOC filters and evaluation panel
  await page.selectOption("#ioc-type", "sha256");
  const sh = await rows("#ioc-table");
  assert(sh >= 1 && sh < s.iocs, "IOC type filter, got " + sh);
  await page.selectOption("#ioc-type", "");
  const evText = await page.locator("#eval-body").textContent();
  assert(/holdout/.test(evText) && /tuning/.test(evText) && /Misses and surprises/.test(evText), "evaluation shows tuning and holdout separately");
  assert(/self-authored|same person/.test(await page.locator("#eval-caveat").textContent()), "honest caveat shown");
  await page.locator("#eval-title").scrollIntoViewIfNeeded();

  // ---- mobile
  const m = await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
  m.on("pageerror", (e) => errors.push("mobile: " + e));
  m.on("console", (x) => { if (x.type() === "error") errors.push("mobile: " + x.text()); });
  await m.goto(base + "/", { waitUntil: "networkidle" });
  await m.waitForSelector("#inbox-list .mail");
  const sw = await m.evaluate(() => document.documentElement.scrollWidth);
  assert(sw <= 392, "no horizontal overflow on mobile, got " + sw);
  await m.screenshot({ path: outDir + "/04-mobile.png" });

  assert.deepStrictEqual(errors, [], "no console errors: " + errors.join("; "));
  console.log("dashboard smoke test OK:", { messages: analysis.messages.length, iocRows: Math.min(150, s.iocs), giftSearchHits: gift });
  await browser.close();
})().catch((e) => { console.error("FAILED:", e.message); process.exit(1); });
