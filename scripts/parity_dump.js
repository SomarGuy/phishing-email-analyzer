// Reads {"cfg":..., "dns":..., "messages":[{"id","raw"}]} on stdin, prints the browser engine's results as JSON.
// Used by tests/test_js_parity.py to prove the dashboard port behaves exactly like the Python engine.
const path = require("path");
require(path.join(__dirname, "..", "dashboard", "core-text.js"));
const core = require(path.join(__dirname, "..", "dashboard", "core.js"));
let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => (buf += c));
process.stdin.on("end", () => {
  const job = JSON.parse(buf);
  const out = (job.messages || []).map((m) => core.analyzeMessage(m.raw, job.cfg, job.dns, m.id));
  const spf = (job.spf || []).map(([ip, dom]) => core.evaluateSpf(ip, dom, job.spf_dns));
  let prims = null;
  if (job.prims) {
    const T = globalThis.PhishCoreParts.T;
    prims = job.prims.map(([fn, args]) => { try { return T[fn](...args); } catch (e) { return "ERROR " + e.message; } });
  }
  if (job.csv_results) { process.stdout.write(JSON.stringify(core.iocsToCsv(job.csv_results))); return; }
  process.stdout.write(JSON.stringify(job.prims ? prims : job.spf ? spf : out));
});
