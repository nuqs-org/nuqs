// Renders real engine events and reports for the Nuqs local prototype.
"use strict";

const byId = id => document.getElementById(id);
const levels = ["critical", "high", "medium", "low", "info"];
const reportKey = "nuqs:last-report:v1";
let current;
let controller;
let started;
let phase;
let total;
let completed;

function node(tag, text, className) {
  const el = document.createElement(tag);
  el.textContent = text;
  if (className) el.className = className;
  return el;
}

function read(key) {
  try { return JSON.parse(localStorage.getItem(key)); } catch { return null; }
}

function save(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); return true; } catch { return false; }
}

function theme(light) {
  document.documentElement.classList.toggle("light", light);
  byId("theme").textContent = light ? "Dark theme" : "Light theme";
}
theme(read("nuqs:light") === true);
byId("theme").onclick = () => {
  const light = !document.documentElement.classList.contains("light");
  theme(light);
  save("nuqs:light", light);
};

function tab(checks) {
  byId("scanPage").hidden = checks;
  byId("checksPage").hidden = !checks;
  byId(checks ? "checksTab" : "scanTab").setAttribute("aria-current", "page");
  byId(checks ? "scanTab" : "checksTab").removeAttribute("aria-current");
}
byId("scanTab").onclick = () => tab(false);
byId("checksTab").onclick = async () => {
  tab(true);
  const catalog = byId("catalog");
  catalog.textContent = "Loading checks…";
  try {
    const response = await fetch("/api/checks");
    if (!response.ok) throw new Error();
    const checks = await response.json();
    catalog.replaceChildren(...checks.map(check => {
      const card = node("article", "");
      card.append(badge(check.severity), node("h3", check.title),
        node("p", [check.id, ...(check.services || [])].join(" · "), "endpoint"), node("p", check.fix));
      return card;
    }));
  } catch { catalog.textContent = "Can't reach the checks catalog."; }
};

function badge(level) {
  return node("span", level, "badge " + (levels.includes(level) ? level : "info"));
}

function findingCard(finding) {
  const card = node("article", "");
  const copy = node("button", "Copy fix", "copy");
  copy.onclick = async () => {
    try { await navigator.clipboard.writeText(finding.fix); copy.textContent = "Copied"; }
    catch { copy.textContent = "Copy unavailable"; }
  };
  card.append(badge(finding.severity), node("h3", finding.title),
    node("p", finding.host + ":" + finding.port + "/" + finding.protocol + " · " + finding.check_id, "endpoint"),
    node("p", "Evidence · " + finding.evidence), node("p", "Fix · " + finding.fix), copy);
  return card;
}

function renderFindings() {
  const selected = byId("filter").value;
  const findings = current.report.findings.filter(f => !selected || f.severity === selected);
  findings.sort((a,b) => levels.indexOf(a.severity) - levels.indexOf(b.severity));
  byId("findings").replaceChildren(...findings.map(findingCard));
  if (!findings.length) byId("findings").textContent = selected ? "No findings at this severity." : "No findings reported.";
}
for (const level of levels) byId("filter").add(new Option(level, level));
byId("filter").onchange = renderFindings;

function raw(show) {
  byId("raw").hidden = !show;
  byId("rawToggle").setAttribute("aria-expanded", String(show));
  byId("rawToggle").textContent = show ? "Hide raw JSON" : "Show raw JSON";
}
byId("rawToggle").onclick = () => raw(byId("raw").hidden);
byId("download").onclick = () => {
  const url = URL.createObjectURL(new Blob([byId("raw").textContent], {type:"application/json"}));
  const link = node("a", "");
  link.href = url;
  link.download = "nuqs-report.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};

function render(saved, restored) {
  const {report, message} = saved;
  current = saved;
  const duration = (Date.parse(report.finished) - Date.parse(report.started)) / 1000;
  const incomplete = message || report.errors.length;
  const outcome = incomplete ? "Scan incomplete" : "Scan finished";
  byId("status").textContent = (restored ? "Last report · " : "") + outcome + " in " + duration.toFixed(2) + "s";
  byId("metadata").textContent = report.targets.join(", ") + " · " + new Date(report.finished).toLocaleString();
  byId("counts").replaceChildren(...levels.map(level => {
    const count = report.findings.filter(f => f.severity === level).length;
    return node("span", count + " " + level, "badge " + (count ? level : "info"));
  }));
  byId("raw").textContent = JSON.stringify(report, null, 2);
  raw(false);
  byId("filter").value = "";
  renderFindings();
  const errors = byId("errors");
  errors.replaceChildren();
  if (incomplete) errors.append(node("h3", "Scan errors"));
  if (message) errors.append(node("p", message));
  for (const err of report.errors) errors.append(node("p", err.host + ":" + err.port + " · " + err.check_id + " · " + err.error));
  byId("results").hidden = false;
}

function progress() {
  byId("status").textContent = "Scanning… " + phase + " · " + ((performance.now()-started)/1000).toFixed(1) + "s";
}

function handleEvent(event) {
  if (event.type === "error") throw new Error(event.message || "Scan failed.");
  if (event.type === "report" && event.report) return {report:event.report, message:event.message || ""};
  if (event.kind === "discovery_started") phase = "Discovering services";
  if (event.kind === "discovery_done") phase = "Discovered " + (event.count || 0) + " hosts";
  if (event.kind === "checks_started") { total = event.count || 0; phase = "Running " + total + " checks"; }
  if (event.kind === "check_done") phase = "Completed " + (++completed) + " of " + total + " checks";
  if (event.kind === "scan_done") phase = "Preparing report";
  progress();
}

async function receive(response) {
  const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = "";
  try {
    while (true) {
      const {value, done} = await reader.read();
      if (done) throw new Error("Connection closed before the report arrived.");
      buffer += value;
      let boundary;
      while ((boundary = buffer.indexOf("\n\n")) !== -1) {
        const frame = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        if (!frame.startsWith("data:")) continue;
        const report = handleEvent(JSON.parse(frame.slice(5)));
        if (report) return report;
      }
    }
  } finally { reader.releaseLock(); }
}

byId("stop").onclick = () => controller?.abort();
byId("scanForm").addEventListener("invalid", event => {
  if (event.target.closest("details")) event.target.closest("details").open = true;
}, true);
byId("scanForm").onsubmit = async event => {
  event.preventDefault();
  if (controller) return;
  const request = {target:byId("target").value.trim(),ports:byId("ports").value.trim(),
    timeout:byId("timeout").value.trim(), workers:byId("workers").valueAsNumber,
    skip_ping:byId("skipPing").checked, force:byId("force").checked};
  controller = new AbortController();
  started = performance.now();
  phase = "Starting";
  completed = 0;
  total = 0;
  byId("settings").disabled = true;
  byId("stop").hidden = false;
  byId("results").hidden = true;
  progress();
  const timer = setInterval(progress, 250);
  try {
    const response = await fetch("/api/scan", {method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify(request), signal:controller.signal});
    if (!response.ok) throw new Error((await response.text()).trim() || "Scan request failed.");
    const saved = await receive(response);
    render(saved, false);
    if (!save(reportKey, saved)) byId("status").textContent += " · Report could not be saved on this device.";
  } catch (err) {
    byId("status").textContent = controller.signal.aborted ? "Scan stopped." :
      err instanceof TypeError ? "Can't reach the scan server." : err.message;
  } finally {
    clearInterval(timer);
    controller = null;
    byId("settings").disabled = false;
    byId("stop").hidden = true;
  }
};
const previous = read(reportKey);
if (previous) {
  try { render(previous, true); } catch { byId("results").hidden = true; byId("status").textContent = ""; }
}
