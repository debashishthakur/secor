// The dashboard page (spec section 12.2): one HTML document with all CSS and JS inline, no external requests of any
// kind, fixed panel order and labels. Every value from /api/summary is written with textContent (never as markup):
// titles, file names and server names come from the project or from editor configs and are untrusted.
//
// The inline <style> and <script> carry a per-response nonce that the Content-Security-Policy header allows.
// Keep this template free of backticks and "${" so it stays a plain string.

export const NONCE_PLACEHOLDER = "__SECOR_NONCE__";

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="referrer" content="no-referrer">
<title>SECOR</title>
<style nonce="__SECOR_NONCE__">
:root {
  color-scheme: light dark;
  --bg: #eef0f3;
  --panel: #ffffff;
  --fg: #16181d;
  --muted: #5f646f;
  --rule: #e1e4ea;
  --track: #e3e6ec;
  --tick: #b9bec8;
  --sel: #d4d8e0;
  --red: #c0271b;
  --amber: #995000;
  --green: #1b7a36;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d0f13;
    --panel: #14171d;
    --fg: #eceef2;
    --muted: #9aa0ab;
    --rule: #242832;
    --track: #252a34;
    --tick: #4a505c;
    --sel: #353b48;
    --red: #ff7468;
    --amber: #f2ab45;
    --green: #5cc878;
  }
}
*, *::before, *::after { box-sizing: border-box; }
[hidden] { display: none !important; }
html { -webkit-text-size-adjust: 100%; text-size-adjust: 100%; background: var(--bg); }
body {
  margin: 0;
  background: var(--bg);
  color: var(--fg);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  font-variant-numeric: tabular-nums;
  -webkit-font-smoothing: antialiased;
}
::selection { background: var(--sel); color: var(--fg); }
main { max-width: 760px; margin: 0 auto; padding: 24px 16px 48px; }
.panel { background: var(--panel); border: 1px solid var(--rule); border-radius: 18px; padding: 4px 28px 24px; }
h1 { margin: 0 0 16px; font-size: 13px; font-weight: 400; color: var(--muted); overflow-wrap: anywhere; text-align: center; }
h1 strong { color: var(--fg); font-weight: 650; letter-spacing: 0.14em; }
h1 .val { color: var(--fg); }
#lastCheck { white-space: nowrap; }
.label { margin: 0; font-size: 11.5px; font-weight: 600; letter-spacing: 0.14em; color: var(--muted); text-transform: uppercase; }
code { font: 0.92em var(--mono); }
section { padding: 22px 0 0; }
section + section { border-top: 1px solid var(--rule); margin-top: 24px; }

.hero { text-align: center; padding-top: 22px; }
.dial { position: relative; width: min(100%, 340px); margin: 4px auto 0; }
.dial svg { display: block; width: 100%; height: auto; overflow: visible; }
.dial .track { fill: none; stroke: var(--track); stroke-width: 12; stroke-linecap: round; }
.dial .arc { fill: none; stroke: var(--muted); stroke-width: 12; stroke-linecap: round; stroke-dasharray: 100 100; stroke-dashoffset: 100; transition: stroke-dashoffset 1.4s cubic-bezier(0.16, 1, 0.3, 1); }
.dial .tick { stroke: var(--tick); stroke-width: 1.5; stroke-linecap: round; }
.dial .tick.major { stroke: var(--muted); stroke-width: 2; }
.dial text { fill: var(--muted); font: 10px var(--mono); text-anchor: middle; }
.dial .needle { transform-box: view-box; transform-origin: 120px 120px; transform: rotate(-135deg); transition: transform 1.4s cubic-bezier(0.16, 1, 0.3, 1); }
.dial .needle line { stroke: var(--fg); stroke-width: 3; stroke-linecap: round; }
.dial .hub { fill: var(--panel); stroke: var(--fg); stroke-width: 2.5; }
.dial.red .arc { stroke: var(--red); filter: drop-shadow(0 0 6px var(--red)); }
.dial.amber .arc { stroke: var(--amber); filter: drop-shadow(0 0 6px var(--amber)); }
.dial.green .arc { stroke: var(--green); filter: drop-shadow(0 0 6px var(--green)); }
.readout { position: absolute; left: 0; right: 0; top: 64%; color: var(--fg); font-weight: 400; }
.big { display: block; font: 300 60px/1 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; letter-spacing: -0.02em; }
.big.none { color: var(--muted); font-size: 40px; }
.outof { display: block; margin-top: 4px; color: var(--muted); font: 12px var(--mono); letter-spacing: 0.08em; }
.verdict { margin-top: 12px; display: flex; flex-wrap: wrap; justify-content: center; align-items: baseline; gap: 4px 14px; }
.band { font-size: 17px; font-weight: 600; }
.delta { color: var(--muted); font-size: 13.5px; }
.notice { margin: 10px auto 0; font-size: 12.5px; color: var(--muted); max-width: 52ch; }

.gauges { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); margin-top: 26px; border-top: 1px solid var(--rule); }
.gauges > div { padding: 18px 12px 0; text-align: center; min-width: 0; }
.gauges > div + div { border-left: 1px solid var(--rule); }
.gauges .label { margin-bottom: 6px; }
.gauges .v { margin: 0; overflow-wrap: anywhere; }
.gauges .v.empty { font-size: 13px; }
.num { display: block; font: 300 34px/1.1 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
.detail { display: block; margin-top: 4px; font-size: 12.5px; color: var(--muted); text-wrap: balance; }

.counters { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; margin: 12px 0 0; }
.counters > span { display: block; border: 1px solid var(--rule); border-radius: 12px; padding: 10px 14px; color: var(--muted); }
.counters b { display: block; font: 300 30px/1.1 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: var(--muted); }
.counters small { font-size: 12px; }
.counters .red b, .counters .red small { color: var(--red); }
.counters .amber b, .counters .amber small { color: var(--amber); }
.counters .nz b, .counters .nz small { color: var(--fg); }
.counters .red b, .counters .amber b, .counters .nz b { font-weight: 500; }
.counters .red { border-color: var(--red); }
.counters .amber { border-color: var(--amber); }
.others { margin: 10px 0 0; font-size: 13.5px; color: var(--muted); }
.red { color: var(--red); font-weight: 600; }
.amber { color: var(--amber); font-weight: 600; }
.green { color: var(--green); font-weight: 600; }
.empty { margin: 10px 0 0; font-size: 14px; color: var(--muted); }

.fix { list-style: none; margin: 10px 0 0; padding: 0; }
.fix li { display: grid; grid-template-columns: 1.5rem 5rem minmax(0, 1fr); gap: 2px 8px; padding: 10px 0; border-top: 1px solid var(--rule); font-size: 14px; align-items: baseline; }
.fix li:first-child { border-top: 0; }
.fix .n { color: var(--muted); font: 12.5px var(--mono); }
.fix .sev { font-weight: 600; }
.fix .what { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0 12px; min-width: 0; }
.fix .title { overflow-wrap: anywhere; }
.fix .loc { color: var(--muted); font: 12.5px/1.6 var(--mono); overflow-wrap: anywhere; }

.servers { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13.5px; }
.servers th { text-align: left; font-weight: 500; font-size: 11.5px; letter-spacing: 0.04em; color: var(--muted); padding: 4px 8px 8px 0; border-bottom: 1px solid var(--rule); white-space: nowrap; }
.servers td { padding: 10px 8px 10px 0; border-bottom: 1px solid var(--rule); vertical-align: top; }
.servers tbody tr:last-child td { border-bottom: 0; }
.servers th.num, .servers td.num { display: table-cell; font: inherit; text-align: right; padding-right: 0; padding-left: 8px; }
.servers th.num { font-size: 11.5px; font-weight: 500; }
.servers td.num:last-child { font-weight: 600; }
.servers td.name { font-weight: 600; overflow-wrap: anywhere; }

.grid { display: grid; grid-template-columns: 7.5rem minmax(0, 1fr); gap: 10px 14px; margin: 0; }
.grid dt { padding-top: 2px; }
.grid dd { margin: 0; font-size: 14px; overflow-wrap: anywhere; }
.spark { font: 18px/0 var(--mono); letter-spacing: 0.25em; vertical-align: 0.2em; }
.history-note { color: var(--muted); margin-left: 6px; }
.status { margin: 18px 0 0; font-size: 13px; color: var(--muted); text-align: center; }

@media (prefers-reduced-motion: reduce) {
  .dial .arc, .dial .needle { transition: none; }
}
@media (max-width: 600px) {
  main { padding: 16px 12px 40px; }
  .panel { padding: 2px 16px 20px; border-radius: 14px; }
  .big { font-size: 50px; }
  .num { font-size: 26px; }
  .gauges > div { padding: 14px 6px 0; }
  .counters { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .grid { grid-template-columns: minmax(0, 1fr); gap: 2px; }
  .grid dd { margin-bottom: 12px; }
  .servers thead { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
  .servers, .servers tbody, .servers tr, .servers td { display: block; width: 100%; }
  .servers tr { padding: 10px 0; border-bottom: 1px solid var(--rule); }
  .servers tbody tr:last-child { border-bottom: 0; padding-bottom: 0; }
  .servers td, .servers td.num { display: grid; grid-template-columns: 6.5rem minmax(0, 1fr); column-gap: 14px; border: 0; padding: 2px 0; text-align: left; }
  .servers td::before { content: attr(data-label); color: var(--muted); font-weight: 400; }
}
</style>
</head>
<body>
<main>
  <h1><strong>SECOR</strong> · <span class="val" id="project">—</span> · last check <span class="val" id="lastCheck">—</span> · rules v<span id="rulesVersion">—</span> · scoring v<span id="scoringVersion">—</span></h1>
  <div class="panel">
  <section class="hero" aria-labelledby="l-overall">
    <h2 class="label" id="l-overall">OVERALL</h2>
    <div class="dial" id="dial">
      <svg viewBox="0 10 240 194" role="img" aria-labelledby="dialLabel">
        <title id="dialLabel">Overall score</title>
        <path class="track" d="M 52.12 187.88 A 96 96 0 1 1 187.88 187.88" pathLength="100"/>
        <path class="arc" id="arc" d="M 52.12 187.88 A 96 96 0 1 1 187.88 187.88" pathLength="100"/>
        <g aria-hidden="true">
          <line class="tick major" x1="62.0" y1="178.0" x2="67.7" y2="172.3"/>
          <line class="tick" x1="50.1" y1="162.8" x2="53.5" y2="160.8"/>
          <line class="tick" x1="42.0" y1="145.3" x2="45.8" y2="144.1"/>
          <line class="tick" x1="38.3" y1="126.4" x2="42.2" y2="126.1"/>
          <line class="tick" x1="39.0" y1="107.2" x2="43.0" y2="107.8"/>
          <line class="tick major" x1="44.2" y1="88.6" x2="51.6" y2="91.7"/>
          <line class="tick" x1="53.7" y1="71.8" x2="56.9" y2="74.2"/>
          <line class="tick" x1="66.7" y1="57.6" x2="69.3" y2="60.7"/>
          <line class="tick" x1="82.8" y1="46.9" x2="84.6" y2="50.5"/>
          <line class="tick" x1="100.9" y1="40.3" x2="101.8" y2="44.2"/>
          <line class="tick major" x1="120.0" y1="38.0" x2="120.0" y2="46.0"/>
          <line class="tick" x1="139.1" y1="40.3" x2="138.2" y2="44.2"/>
          <line class="tick" x1="157.2" y1="46.9" x2="155.4" y2="50.5"/>
          <line class="tick" x1="173.3" y1="57.6" x2="170.7" y2="60.7"/>
          <line class="tick" x1="186.3" y1="71.8" x2="183.1" y2="74.2"/>
          <line class="tick major" x1="195.8" y1="88.6" x2="188.4" y2="91.7"/>
          <line class="tick" x1="201.0" y1="107.2" x2="197.0" y2="107.8"/>
          <line class="tick" x1="201.7" y1="126.4" x2="197.8" y2="126.1"/>
          <line class="tick" x1="198.0" y1="145.3" x2="194.2" y2="144.1"/>
          <line class="tick" x1="189.9" y1="162.8" x2="186.5" y2="160.8"/>
          <line class="tick major" x1="178.0" y1="178.0" x2="172.3" y2="172.3"/>
          <text x="77.6" y="166.4">0</text>
          <text x="64.6" y="101.0">25</text>
          <text x="120.0" y="64.0">50</text>
          <text x="175.4" y="101.0">75</text>
          <text x="162.4" y="166.4">100</text>
        </g>
        <g class="needle" id="needle" aria-hidden="true">
          <line x1="120" y1="126" x2="120" y2="50"/>
          <circle cx="120" cy="120" r="7" class="hub"/>
        </g>
      </svg>
      <div class="readout"><span class="big" id="overall">—</span><span class="outof">/ 100</span></div>
    </div>
    <div class="verdict"><span class="band" id="band"></span><span class="delta" id="delta"></span></div>
    <p class="notice">This score counts known issues in the checks SECOR ran. It does not measure how hard your system is to attack.</p>
    <div class="gauges">
      <div><h3 class="label">Ship</h3><p class="v" id="ship">—</p></div>
      <div><h3 class="label">Connect</h3><p class="v" id="connect">—</p></div>
      <div><h3 class="label">Coverage</h3><p class="v" id="coverage">—</p></div>
    </div>
  </section>

  <section aria-labelledby="l-open">
    <h2 class="label" id="l-open">OPEN FINDINGS</h2>
    <p class="counters" id="counts">—</p>
    <p class="others" id="others" hidden></p>
  </section>

  <section aria-labelledby="l-fix">
    <h2 class="label" id="l-fix">FIX NEXT</h2>
    <ol class="fix" id="fixNext" hidden></ol>
    <p class="empty" id="fixEmpty">—</p>
  </section>

  <section aria-labelledby="l-servers">
    <h2 class="label" id="l-servers">CONNECTED SERVERS</h2>
    <table class="servers" id="servers" hidden>
      <thead>
        <tr><th scope="col">server</th><th scope="col">vetted</th><th scope="col">scope</th><th scope="col">sandbox</th><th scope="col">changed</th><th scope="col" class="num">sent 7d</th><th scope="col" class="num">blocked 7d</th><th scope="col" class="num">score</th></tr>
      </thead>
      <tbody id="serverRows"></tbody>
    </table>
    <p class="empty" id="serversEmpty">—</p>
  </section>

  <section aria-label="History and not checked">
    <dl class="grid">
      <dt class="label">HISTORY</dt><dd id="history">—</dd>
      <dt class="label">NOT CHECKED</dt><dd id="notChecked">—</dd>
    </dl>
  </section>
  </div>

  <p class="status" id="status" role="status" aria-live="polite">Loading…</p>
  <noscript><p class="status">This dashboard needs JavaScript to show the summary.</p></noscript>
</main>
<script nonce="__SECOR_NONCE__">
(function () {
  "use strict";
  try {
    if (location.search) history.replaceState(null, "", location.pathname);
  } catch (e) {
    // the address bar keeps the token; nothing else depends on this
  }

  var SPARK = "▁▂▃▄▅▆▇█";
  var BANDS = {
    "fix-before-deploy": ["Fix before deploy", "red"],
    "needs-work": ["Needs work", "amber"],
    "no-known-critical-or-high": ["No critical or high issues known", "green"]
  };
  var SEVERITY = {
    critical: ["Critical", "red"],
    high: ["High", "amber"],
    medium: ["Medium", "amber"],
    low: ["Low", ""]
  };

  function own(map, key) {
    return typeof key === "string" && Object.prototype.hasOwnProperty.call(map, key) ? map[key] : null;
  }
  function byId(id) {
    return document.getElementById(id);
  }
  function node(tag, className, text) {
    var e = document.createElement(tag);
    if (className) e.className = className;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function fill(id, parts) {
    var el = byId(id);
    el.replaceChildren.apply(el, parts.map(function (p) {
      return typeof p === "string" ? document.createTextNode(p) : p;
    }));
  }
  function show(id, on) {
    byId(id).hidden = !on;
  }
  function num(v) {
    return typeof v === "number" && isFinite(v) ? String(v) : "—";
  }
  function yesNo(v) {
    return v === true ? "yes" : "no";
  }
  function two(n) {
    return (n < 10 ? "0" : "") + n;
  }
  function stamp(iso) {
    var d = new Date(iso);
    if (isNaN(d.getTime())) return "—";
    return d.getFullYear() + "-" + two(d.getMonth() + 1) + "-" + two(d.getDate()) + " " + two(d.getHours()) + ":" + two(d.getMinutes());
  }
  function hint(lead, command) {
    return [lead + " Run ", node("code", "", command), "."];
  }
  function notRun() {
    return hint("Not run yet.", "secor ship");
  }
  function notSetUp() {
    return hint("Not set up.", "secor connect add <server>");
  }
  function list(v) {
    return Array.isArray(v) ? v : [];
  }

  function render(s) {
    var ran = typeof s.lastCheck === "string";
    var findings = s.findings || {};
    document.title = "SECOR · " + String(s.project);
    fill("project", [String(s.project)]);
    fill("lastCheck", [ran ? stamp(s.lastCheck) : "—"]);
    fill("rulesVersion", [String(s.rulesVersion)]);
    fill("scoringVersion", [String(s.scoringVersion)]);

    var overall = s.overall || {};
    var scored = typeof overall.score === "number";
    fill("overall", [num(overall.score)]);
    byId("overall").className = scored ? "big" : "big none";
    var band = own(BANDS, overall.band);
    var v = scored ? Math.max(0, Math.min(100, overall.score)) : 0;
    byId("arc").style.strokeDashoffset = String(100 - v);
    byId("needle").style.transform = "rotate(" + ((v - 50) * 2.7) + "deg)";
    byId("dial").className = "dial" + (band ? " " + band[1] : "");
    byId("dialLabel").textContent = scored ? "Overall score " + v + " out of 100" : "Overall score not available yet";
    var bandEl = byId("band");
    bandEl.textContent = band ? band[0] : "";
    bandEl.className = "band" + (band ? " " + band[1] : "");
    var d = overall.delta;
    fill("delta", [typeof d !== "number" ? "" : d > 0 ? "▲ " + d + " since last check" : d < 0 ? "▼ " + -d + " since last check" : "No change since last check"]);

    var ship = s.ship || {};
    fill("ship", ran ? [node("span", "num", num(ship.score)), node("span", "detail", "API " + num(ship.api) + " · MCP server " + num(ship.mcp) + " · Website " + num(ship.web))] : notRun());
    byId("ship").className = ran ? "v" : "v empty";
    var c = s.connect || {};
    var count = typeof c.serverCount === "number" ? c.serverCount : 0;
    fill("connect", count > 0 ? [node("span", "num", num(c.score)), node("span", "detail", count + (count === 1 ? " server" : " servers") + " · hooks " + String(c.hooks))] : notSetUp());
    byId("connect").className = count > 0 ? "v" : "v empty";
    var cov = s.coverage || {};
    fill("coverage", ran ? [node("span", "num", num(cov.percent)), node("span", "detail", num(cov.percent) + "% of applicable checks" + (cov.incomplete ? " · incomplete" : ""))] : ["—"]);
    byId("coverage").className = ran ? "v" : "v empty";

    if (ran) {
      var parts = [];
      ["critical", "high", "medium", "low"].forEach(function (k) {
        var sev = SEVERITY[k];
        var n = findings[k];
        var cell = node("span", typeof n === "number" && n > 0 ? (sev[1] || "nz") : "");
        cell.append(node("b", "", num(n)), node("small", "", sev[0]));
        parts.push(cell);
      });
      fill("counts", parts);
      byId("counts").className = "counters";
      fill("others", ["Ignored " + num(findings.ignored) + ", each with a reason · Advisory " + num(findings.advisory) + " (not scored)"]);
    } else {
      fill("counts", notRun());
      byId("counts").className = "empty";
    }
    show("others", ran);

    var next = ran ? list(s.fixNext) : [];
    byId("fixNext").replaceChildren.apply(byId("fixNext"), next.map(function (f, i) {
      var sev = own(SEVERITY, f.severity);
      var li = node("li");
      var what = node("span", "what");
      what.append(node("span", "title", f.title), node("span", "loc", String(f.file) + ":" + num(f.line)));
      li.append(node("span", "n", String(i + 1)), node("span", "sev", sev ? sev[0] : f.severity), what);
      return li;
    }));
    show("fixNext", next.length > 0);
    fill("fixEmpty", ran ? ["No counted findings."] : notRun());
    show("fixEmpty", next.length === 0);

    var rows = list(s.servers).map(function (v) {
      var tr = node("tr");
      [
        ["server", v.name, "name"],
        ["vetted", yesNo(v.vetted), ""],
        ["scope", yesNo(v.scoped), ""],
        ["sandbox", v.sandbox, ""],
        ["changed", yesNo(v.changed), ""],
        ["sent 7d", num(v.sent7d), "num"],
        ["blocked 7d", num(v.blocked7d), "num"],
        ["score", num(v.score), "num"]
      ].forEach(function (cell) {
        var td = node("td", cell[2], cell[1]);
        td.setAttribute("data-label", cell[0]);
        tr.append(td);
      });
      return tr;
    });
    byId("serverRows").replaceChildren.apply(byId("serverRows"), rows);
    show("servers", rows.length > 0);
    fill("serversEmpty", notSetUp());
    show("serversEmpty", rows.length === 0);

    var h = list(s.history);
    if (h.length < 2) {
      fill("history", ["Fewer than 2 checks so far."]);
    } else {
      var spark = node("span", "spark", h.map(function (x) {
        return typeof x.overall === "number" ? SPARK.charAt(Math.min(7, Math.max(0, Math.floor(x.overall / 12.5)))) : "·";
      }).join(""));
      var label = "Overall score of the last " + h.length + " checks, oldest first: " + h.map(function (x) { return num(x.overall); }).join(", ");
      spark.setAttribute("role", "img");
      spark.setAttribute("aria-label", label);
      spark.setAttribute("title", label);
      fill("history", [spark, node("span", "history-note", "last " + h.length + " checks")]);
    }
    byId("history").className = h.length < 2 ? "empty" : "";
    var gaps = list(s.notChecked);
    fill("notChecked", ran ? [gaps.length ? gaps.join(" · ") : "—"] : notRun());
    byId("notChecked").className = ran ? "" : "empty";
  }

  function status(message) {
    var el = byId("status");
    el.textContent = message;
    el.hidden = !message;
  }

  function refresh() {
    return fetch("/api/summary", { cache: "no-store", credentials: "same-origin", headers: { Accept: "application/json" } }).then(function (res) {
      if (res.status === 401 || res.status === 403) {
        status("This page has lost its access. Open the dashboard again with the link that secor dashboard prints.");
        return;
      }
      if (!res.ok) {
        status("Could not load the summary (HTTP " + res.status + "). Retrying.");
        return;
      }
      return res.json().then(function (summary) {
        try {
          render(summary);
          status("");
        } catch (e) {
          status("Could not show the summary. Retrying.");
        }
      });
    }, function () {
      status("Cannot reach the dashboard server. It stops after 30 minutes without requests; run secor dashboard to start it again.");
    });
  }

  function loop() {
    refresh().then(schedule, schedule);
  }
  function schedule() {
    setTimeout(loop, 5000);
  }
  loop();
})();
</script>
</body>
</html>
`;

/** The page with `nonce` set on its inline style and script. */
export function renderPage(nonce: string): string {
  return PAGE.split(NONCE_PLACEHOLDER).join(nonce);
}
