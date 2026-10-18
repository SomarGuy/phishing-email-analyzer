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
const VL = { benign: "looks fine", suspicious: "suspicious", likely_phishing: "likely phishing" };

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME || "/usr/bin/google-chrome", args: ["--no-sandbox"] });
  const errors = [], requests = [];
  // the existing checks and screenshots run as a returning visitor who already dismissed the Start here bar
  const dismissed = () => { try { localStorage.setItem("phishing-analyzer-guide-dismissed", "1"); } catch (e) { /* ignore */ } };
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await ctx.addInitScript(dismissed);
  const page = await ctx.newPage();
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("request", (r) => requests.push(r.url()));
  let dialogs = 0;
  page.on("dialog", async (d) => { dialogs++; await d.dismiss(); });
  const rows = (sel) => page.locator(sel + " tbody tr").count();

  await page.goto(base + "/", { waitUntil: "networkidle" });
  await page.waitForSelector("#inbox-list .mail");

  // ---- banner, KPIs, inbox match the analysis
  assert(/SYNTHETIC DATA/.test(await page.locator("#banner").textContent()), "synthetic banner");
  assert(await page.locator("#banner").isVisible(), "synthetic banner is visible");
  // three panes, like a webmail: folders, message list, reading pane
  for (const sel of [".folders", ".listpane", ".readpane"]) assert(await page.locator(sel).isVisible(), sel + " visible");
  const bx = await Promise.all([".folders", ".listpane", ".readpane"].map((q) => page.locator(q).boundingBox()));
  assert(bx[0].x < bx[1].x && bx[1].x < bx[2].x && Math.abs(bx[0].y - bx[2].y) < 2, "panes sit side by side");
  const s = analysis.summary;
  for (const [v, n] of [["likely_phishing", s.likely_phishing], ["suspicious", s.suspicious], ["benign", s.benign]]) {
    assert.strictEqual((await page.locator(`.folder[data-v="${v}"] .n`).textContent()).trim(), String(n), "KPI " + v);
  }
  assert.strictEqual(await page.locator("#inbox-list .mail").count(), analysis.messages.length, "inbox lists every message");
  assert.strictEqual(await page.locator("#inbox-list .vbadge").count(), analysis.messages.length, "every row has a verdict chip");
  assert.strictEqual(await page.locator("#inbox-list .mail .av").count(), analysis.messages.length, "every row has a sender avatar");
  assert.strictEqual((await page.locator("#inbox-list .mail .av").first().textContent()).trim().length >= 1, true, "avatar has initials");
  assert.strictEqual(await rows("#ioc-table"), Math.min(150, s.iocs), "IOC table rows");
  assert((await rows("#catalog-table")) > 50, "indicator catalogue listed");

  // ---- default selection: drill-down content
  const sel = await page.locator("#inbox-list .mail.active").getAttribute("data-id");
  const m0 = byId[sel];
  const detail = page.locator("#detail");
  assert(new RegExp(m0.subject.slice(0, 20).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).test(await detail.textContent()), "detail shows the subject");
  assert((await detail.locator("ol.route li.hop").count()) === m0.hops.length, "route list has one stop per Received header");
  assert(/phishing/.test(await detail.locator(".warn").first().textContent()) && (await detail.locator(".warn.v-likely_phishing").count()) === 1, "suspicious banner sits over the message");
  assert((await detail.locator(".gauge .needle").count()) === 1 && (await detail.locator(".gauge-num .big").textContent()).trim() === String(m0.score), "plain gauge shows the score");
  assert(/Show the original message/.test(await detail.locator("details.orig summary").textContent()), "original message is available");
  assert((await detail.locator(".barrow").count()) >= 7, "score breakdown bars");
  assert((await detail.locator(".achip").count()) >= 3, "auth chips");
  assert((await detail.locator("table.cmp tbody tr").count()) === 5, "identity comparison rows");
  assert.strictEqual(await detail.locator(".reason").count(), m0.indicators.filter((i) => i.points > 0).length + m0.mitigations.length, "one reason card per scoring indicator");
  assert(/hxxp/.test(await detail.textContent()) && !/https?:\/\/[a-z0-9.-]+\.(test|example|invalid)/i.test(await detail.locator("table.t-urls").textContent()), "URLs are shown defanged");
  assert(/PHISHING TRIAGE/.test(await detail.locator("pre.note").textContent()), "ticket note present");
  await page.screenshot({ path: outDir + "/01-dashboard.png" });
  await page.setViewportSize({ width: 1440, height: 1500 });
  await page.screenshot({ path: outDir + "/01-dashboard-full.png" });
  await page.setViewportSize({ width: 1440, height: 900 });

  // ---- filters
  await page.click('.folder[data-v="benign"]');
  assert.strictEqual(await page.locator("#inbox-list .mail").count(), s.benign, "benign folder count");
  assert.strictEqual((await page.locator("#inbox-title").textContent()).trim(), "Looks fine", "list heading follows the folder");
  await page.click('.folder[data-v="suspicious"]');
  assert.strictEqual(await page.locator("#inbox-list .mail").count(), s.suspicious, "suspicious folder count");
  await page.click('.folder[data-v="likely_phishing"]');
  assert.strictEqual(await page.locator("#inbox-list .mail").count(), s.likely_phishing, "phishing folder count");
  await page.click('.folder[data-v="all"]');
  assert.strictEqual(await page.locator("#inbox-list .mail").count(), analysis.messages.length, "inbox shows everything again");
  await page.selectOption("#inbox-sort", "new");
  const firstNew = await page.locator("#inbox-list .mail").first().getAttribute("data-id");
  const newest = analysis.messages.slice().sort((a, b) => (a.date_text < b.date_text ? 1 : a.date_text > b.date_text ? -1 : 0) || (a.id < b.id ? -1 : 1))[0].id;
  assert.strictEqual(firstNew, newest, "newest-first sort");
  await page.selectOption("#inbox-sort", "risk");
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
  assert(/Remittance-0041\.html/.test(await detail.locator("table.t-att").textContent()), "attachment table lists the file");
  await open("P13-amazon-userinfo-ip-url");
  assert(/userinfo|credentials-style/i.test(await detail.textContent()), "userinfo trick explained");
  assert(/T1566\.002/.test(await detail.textContent()), "ATT&CK technique shown");
  await open("P10-cfo-vendor-bank-change-lookalike");
  assert(/offline/i.test(await detail.locator(".authrow").textContent()), "offline SPF evaluation shown");
  assert((await detail.locator("td.mis").count()) >= 1, "mismatching domains highlighted");
  await open("B01-newsletter-harbour-gazette");
  assert(/looks fine/.test(await detail.locator(".vbadge").first().textContent()), "newsletter looks fine");
  assert(/my label: benign ✓/.test(await detail.textContent()), "ground truth tag");
  assert((await detail.locator(".warn.v-benign").count()) === 1, "benign mail gets the calm banner");
  await open("B12-secops-awareness-quoted-phish");
  assert(/my label: benign ✗/.test(await detail.textContent()), "known hard negative flagged as a miss");
  await open("P09-ceo-gift-card-bec");
  await page.waitForTimeout(300);
  await page.setViewportSize({ width: 1440, height: 1300 });
  await page.screenshot({ path: outDir + "/02-message-drilldown.png" });
  await page.setViewportSize({ width: 1440, height: 900 });
  await open("P10-cfo-vendor-bank-change-lookalike");
  assert((await detail.locator(".hop.bad").count()) >= 1 && (await detail.locator(".hop .delta.bad").count()) >= 1, "anomalous hop highlighted in the diagram");
  await detail.locator('details.fold[data-key="Route"]').evaluate((d) => { d.open = true; });
  await detail.locator('details.fold[data-key="Points"]').evaluate((d) => { d.open = true; });
  await page.locator("#detail details.fold", { hasText: "The trip this email took" }).first().screenshot({ path: outDir + "/03-hop-diagram.png" });
  await page.locator("#detail details.fold", { hasText: "Where the points came from" }).first().screenshot({ path: outDir + "/03-score-breakdown.png" });

  await detail.locator('details.fold[data-key="Sign-in"]').evaluate((d) => { d.open = true; d.scrollIntoView({ block: "start" }); });
  await page.waitForTimeout(250);
  await page.screenshot({ path: outDir + "/12-look-closer-open.png" });
  await detail.locator('details.fold[data-key="Route"]').evaluate((d) => { d.open = false; });
  await detail.locator('details.fold[data-key="Points"]').evaluate((d) => { d.open = false; });

  // ---- copy ticket note button gives feedback
  await detail.locator('details.fold[data-key="Ticket note"] > summary').click();
  await page.click("text=Copy the ticket note");
  await page.waitForFunction(() => /Copied|Copy blocked/.test(document.querySelector("#detail .toast").textContent));

  // ---- paste analyser: same verdict as the Python engine
  await page.click(".compose");
  assert(await page.locator("#view-paste").isVisible() && !(await page.locator(".listpane").isVisible()), "paste view takes over the room");
  await page.selectOption("#paste-sample", "P05-invoice-double-extension-exe");
  assert(/Content-Type: multipart\/mixed/.test(await page.inputValue("#paste-input")), "sample loaded into the textarea");
  await page.click("#paste-run");
  await page.waitForSelector("#paste-result:not([hidden]) .vbadge");
  const py = byId["P05-invoice-double-extension-exe"];
  assert.strictEqual((await page.locator("#paste-result .vbadge").first().textContent()).trim(), VL[py.verdict], "browser verdict equals Python verdict");
  assert(new RegExp("(^|\\D)" + py.score + " out of 100").test(await page.locator("#paste-result").textContent()), "browser score equals Python score " + py.score);
  assert(/Invoice_8841\.pdf\.exe/.test(await page.locator("#paste-result").textContent()), "pasted attachment analysed");
  // headers only
  await page.fill("#paste-input", "From: \"IT Help Desk\" <helpdesk@northwind-analytics-support.test>\nReply-To: it@freemail.example\nSubject: Password expires today - verify your account\nDate: Mon, 02 Mar 2026 10:00:00 +0000\nMessage-ID: <x@northwind-analytics-support.test>\nAuthentication-Results: mx; spf=fail smtp.mailfrom=northwind-analytics-support.test; dmarc=fail header.from=northwind-analytics-support.test\n");
  await page.click("#paste-run");
  await page.waitForFunction(() => /Checked in/.test(document.getElementById("paste-status").textContent));
  assert(/likely phishing/.test(await page.locator("#paste-result .vbadge").first().textContent()), "header-only paste scores as likely phishing");
  await page.setViewportSize({ width: 1440, height: 1300 });
  await page.screenshot({ path: outDir + "/05-paste-analyser.png" });
  await page.setViewportSize({ width: 1440, height: 900 });

  // ---- hostile text stays inert, nothing fetched
  const hostile = "From: \"<img src=x onerror=alert(1)>\" <a@evil.test>\nSubject: <script>alert(2)</script>\nDate: Mon, 02 Mar 2026 10:00:00 +0000\nContent-Type: text/html\n\n<a href=\"https://<svg onload=alert(3)>.test/x\">click <b onmouseover=alert(4)>here</b></a><img src=\"https://tracker.test/p.gif\"><script>alert(5)</script>";
  await page.fill("#paste-input", hostile);
  const before = requests.length;
  await page.click("#paste-run");
  await page.waitForFunction(() => /Checked in|I could not/.test(document.getElementById("paste-status").textContent));
  assert.strictEqual(await page.locator("main img, main svg[onload], main script, main b[onmouseover]").count(), 0, "hostile HTML stays text");
  assert(/<script>alert\(2\)<\/script>/.test(await page.locator("#paste-result").textContent()), "hostile subject shown as text");
  assert.strictEqual(requests.slice(before).filter((u) => !u.startsWith(base)).length, 0, "no external requests while analysing");
  assert.strictEqual(requests.filter((u) => !u.startsWith(base)).length, 0, "no external requests at all");
  assert.strictEqual(dialogs, 0, "no dialogs");
  await page.click("#paste-clear");

  // ---- IOC filters and evaluation panel
  await page.click('.tool[data-view="iocs"]');
  await page.selectOption("#ioc-type", "sha256");
  const sh = await rows("#ioc-table");
  assert(sh >= 1 && sh < s.iocs, "IOC type filter, got " + sh);
  await page.selectOption("#ioc-type", "");
  const evText = await page.locator("#eval-body").textContent();
  assert(/holdout/.test(evText) && /tuning/.test(evText) && /Where it got things wrong/.test(evText), "evaluation shows tuning and holdout separately");
  assert(/I wrote the mail/.test(await page.locator("#eval-caveat").textContent()), "honest caveat shown");
  await page.click('.tool[data-view="eval"]');
  assert(await page.locator("#eval-title").isVisible(), "report card view opens");
  await page.screenshot({ path: outDir + "/08-how-well-does-it-work.png" });
  await page.click('.tool[data-view="rules"]');
  assert(await page.locator("#catalog-table").isVisible(), "rulebook view opens");

  // ---- the note from Diogo, pinned at the top of the list
  await page.click('.folder[data-v="all"]');
  await page.click("#note-open");
  assert(await page.locator("#note").isVisible() && await page.locator(".listpane").isVisible(), "note opens in the reading pane and keeps the list");
  const note = await page.locator("#note").textContent();
  assert(/Geek Squad/.test(note) && /Toronto/.test(note) && /What it can.t do/.test(note) && /What I would do next/.test(note), "note covers background, limits and next steps");
  assert(!/[\u2014\u2013]/.test(note), "no em or en dashes in the note");
  await page.screenshot({ path: outDir + "/07-why-i-built-this.png" });
  await page.click('#inbox-list .mail[data-id="P01-paypal-lookalike-credential"]');
  assert(await page.locator("#detail").isVisible() && !(await page.locator("#note").isVisible()), "back to a message");
  assert(!/[\u2014]/.test(await page.locator("body").innerText()), "no em dash anywhere in the page");

  // ---- mobile
  const mctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
  await mctx.addInitScript(dismissed);
  const m = await mctx.newPage();
  m.on("pageerror", (e) => errors.push("mobile: " + e));
  m.on("console", (x) => { if (x.type() === "error") errors.push("mobile: " + x.text()); });
  await m.goto(base + "/", { waitUntil: "networkidle" });
  await m.waitForSelector("#inbox-list .mail");
  const sw = await m.evaluate(() => document.documentElement.scrollWidth);
  assert(sw <= 392, "no horizontal overflow on mobile, got " + sw);
  assert(!(await m.locator(".readpane").isVisible()), "phone shows the list first");
  await m.screenshot({ path: outDir + "/04-mobile.png" });
  await m.click('#inbox-list .mail[data-id="P09-ceo-gift-card-bec"]');
  assert(await m.locator("#detail").isVisible() && !(await m.locator(".listpane").isVisible()), "phone shows the message after a tap");
  const sw2 = await m.evaluate(() => document.documentElement.scrollWidth);
  assert(sw2 <= 392, "no horizontal overflow on a mobile message, got " + sw2);
  await m.screenshot({ path: outDir + "/04-mobile-reading.png" });
  await m.click("#back-btn");
  assert(await m.locator(".listpane").isVisible(), "back button returns to the list");

  // ---- the "How to use this" guide: Start here bar, remembered dismissal, and every step in the guide really works
  async function guideWalk(vp, shot) {
    const gctx = await browser.newContext({ viewport: vp, deviceScaleFactor: vp.width < 500 ? 2 : 1 });
    const g = await gctx.newPage();
    g.on("console", (x) => { if (x.type() === "error") errors.push("guide: " + x.text()); });
    g.on("pageerror", (e) => errors.push("guide: " + e));
    const phone = vp.width < 500;
    const noOverflow = async (why) => assert((await g.evaluate(() => document.documentElement.scrollWidth)) <= vp.width + 2, "no horizontal overflow: " + why);
    await g.goto(base + "/", { waitUntil: "networkidle" });
    await g.waitForSelector("#inbox-list .mail");
    assert(await g.locator("#start-here").isVisible(), "Start here bar shows on a first visit");
    await noOverflow("first visit");
    await g.click("#start-dismiss");
    assert(await g.locator("#start-here").isHidden(), "dismiss hides the bar");
    await g.reload({ waitUntil: "networkidle" });
    await g.waitForSelector("#inbox-list .mail");
    assert(await g.locator("#start-here").isHidden(), "dismissal is remembered after a reload");
    assert(await g.locator("#guide-open").isVisible() && /How to use this/.test(await g.locator("#guide-open").textContent()), "top bar button is always visible");
    assert.strictEqual(await g.locator("#guide-pin").count(), 0, "the extra pinned guide message is gone (one less thing in the list)");
    // open it two ways: Extras folder, top bar (on a phone the folder chips are visible too)
    await g.click('.tool[data-view="guide"]');
    assert(await g.locator("#view-guide").isVisible(), "Extras folder opens the guide");
    if (phone) await g.click("#back-btn"); else await g.click('.folder[data-v="all"]');
    await g.click("#guide-open");
    assert(await g.locator("#view-guide").isVisible(), "top bar button opens the guide");
    assert.strictEqual(await g.evaluate(() => document.activeElement.id), "guide-title", "focus moves to the guide heading");
    await noOverflow("guide page");
    assert.strictEqual(await g.locator("#view-guide .walk > li").count(), 5, "five steps");
    for (const w of ["Try this in 60 seconds", "Words you will see", "What this shows about my skills"]) assert((await g.locator("#view-guide").textContent()).includes(w), w);
    assert((await g.locator("#view-guide .gloss dt").count()) >= 14, "glossary terms");
    if (phone) await g.evaluate(() => document.getElementById("walk-title").scrollIntoView());
    await g.screenshot({ path: outDir + "/" + shot });
    // step 1: the PayPal email
    await g.locator("#view-guide .go").nth(0).click();
    const d1 = await g.locator("#detail").innerText();
    assert(await g.locator("#detail").isVisible() && /Action required: unusual sign-in detected/.test(d1) && /Why it got this score/i.test(d1) && /100\s+out of 100/.test(d1) && /likely phishing/i.test(d1), "step 1: PayPal email, reasons and 100 out of 100");
    assert(await g.locator("#detail .warn").first().isVisible(), "step 1: the red bar");
    // the reasons start at three with the rest behind a button
    assert.strictEqual(await g.locator("#detail .reason:visible").count(), 3, "step 1: three reasons shown");
    assert(/Show the other 8/.test(await g.locator("#detail .more-reasons").first().textContent()), "step 1: the button names how many more");
    await g.locator("#detail .more-reasons").first().click();
    assert((await g.locator("#detail .reason:visible").count()) >= 9, "step 1: all the reasons after the button");
    // steps 2 and 3: the folds named in the guide really exist, start closed, and open with the right content
    for (const [i, key, expect] of [[1, "Sign-in", /SPF\s+fail[\s\S]*DKIM\s+none[\s\S]*DMARC\s+fail/i], [2, "Links", /paypa1-secure\[\.\]test[\s\S]*hxxps/i]]) {
      if (phone) await g.click("#back-btn");
      await g.locator("#view-guide, #inbox-list").first().waitFor({ state: "attached" });
      await g.click("#guide-open");
      await g.locator("#view-guide .go").nth(i).click();
      const sec = g.locator('#detail details.fold[data-key="' + key + '"]');
      assert(await sec.count() === 1, "step " + (i + 1) + ": fold " + key);
      assert(await sec.evaluate((d) => d.open), "step " + (i + 1) + ": Take me there opens " + key);
      assert(expect.test(await sec.innerText()), "step " + (i + 1) + ": " + key + " content: " + (await sec.innerText()).slice(0, 200));
    }
    // by hand: the folds start closed and one click opens them
    if (phone) await g.click("#back-btn");
    await g.click('#inbox-list .mail[data-id="P01-paypal-lookalike-credential"]');
    assert.strictEqual(await g.locator("#detail details.fold[open]").count(), 0, "folds start closed");
    await g.locator('#detail details.fold[data-key="Route"] > summary').click();
    assert(/stop 2/i.test(await g.locator('#detail details.fold[data-key="Route"]').innerText()), "step 3: Route lists the stops");
    await g.locator('#detail details.fold[data-key="Links"] > summary').click();
    const linkSec = await g.locator('#detail details.fold[data-key="Links"]').innerText();
    assert(/https:\/\/www\.paypal\.com\/verify/.test(linkSec) && /paypa1-secure/.test(linkSec), "step 3: text says paypal.com, link goes to paypa1-secure");
    assert.strictEqual(await g.locator("#detail a[href^='http']").count(), 0, "step 3: no clickable links");
    // step 4: the safe email
    if (phone) await g.click("#back-btn");
    await g.click("#guide-open");
    await g.locator("#view-guide .go").nth(3).click();
    const d5 = await g.locator("#detail").innerText();
    assert(/This week: harbour dredging, new ferry timetable/.test(d5) && /Nothing fired\. That is the whole story\./.test(d5) && /0\s+out of 100/.test(d5), "step 4: safe email, nothing fired, 0 out of 100");
    // the manual route for step 5 also works: Looks fine folder, then that email
    if (phone) await g.click("#back-btn");
    await g.click('.folder[data-v="benign"]');
    await g.locator("#inbox-list .mail", { hasText: "This week: harbour dredging" }).click();
    assert(/Nothing fired/.test(await g.locator("#detail").innerText()), "step 4: manual route");
    // step 5: Check your own email -> load the P01 sample -> Check it
    if (phone) await g.click("#back-btn");
    await g.click(".compose");
    await g.selectOption("#paste-sample", "P01-paypal-lookalike-credential");
    assert((await g.locator("#paste-input").inputValue()).length > 500, "step 5: sample text loaded");
    await g.click("#paste-run");
    await g.waitForFunction(() => /Checked in/.test(document.getElementById("paste-status").textContent));
    const st = await g.locator("#paste-status").textContent();
    assert(/likely phishing, risk 100/.test(st), "step 5: scored live in the browser: " + st);
    // the Start here bar returns when storage is cleared, and its button opens the guide from the keyboard
    await g.evaluate(() => localStorage.clear());
    await g.reload({ waitUntil: "networkidle" });
    await g.waitForSelector("#inbox-list .mail");
    assert(await g.locator("#start-here").isVisible(), "bar returns when storage is cleared");
    await g.focus("#start-open"); await g.keyboard.press("Enter");
    assert(await g.locator("#view-guide").isVisible(), "Start here button opens the guide from the keyboard");
    assert(!/[\u2014\u2013]/.test(await g.locator("#view-guide").innerText()), "no em or en dashes in the guide");
    await gctx.close();
  }
  await guideWalk({ width: 1440, height: 900 }, "09-how-to-use.png");
  await guideWalk({ width: 390, height: 844 }, "10-how-to-use-mobile.png");

  assert.deepStrictEqual(errors, [], "no console errors: " + errors.join("; "));
  console.log("dashboard smoke test OK:", { messages: analysis.messages.length, iocRows: Math.min(150, s.iocs), giftSearchHits: gift });
  await browser.close();
})().catch((e) => { console.error("FAILED:", e.message); process.exit(1); });
