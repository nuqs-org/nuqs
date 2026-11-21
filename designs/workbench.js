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

const appearance = matchMedia("(prefers-color-scheme: light)");
let themePreference = read("nuqs:theme");
function applyAppearance() {
  const light = themePreference === "light" || (themePreference !== "dark" && appearance.matches);
  document.documentElement.classList.toggle("light", light);
  byId("themeToggle").setAttribute("aria-pressed", String(!light));
  byId("themeToggle").title = light ? "Switch to dark mode" : "Switch to light mode";
}
applyAppearance();
appearance.addEventListener("change", applyAppearance);
byId("themeToggle").onclick = () => {
  themePreference = document.documentElement.classList.contains("light") ? "dark" : "light";
  save("nuqs:theme", themePreference);
  applyAppearance();
};

const narrowWindow = matchMedia("(max-width: 740px)");
function sidebarKey() {
  return narrowWindow.matches ? "nuqs:compact-mobile" : "nuqs:compact";
}
function setCompact(compact) {
  document.documentElement.classList.toggle("compactRail", compact);
  const button = byId("railToggle");
  button.setAttribute("aria-expanded", String(!compact));
  button.title = compact ? "Expand sidebar" : "Collapse sidebar";
  button.setAttribute("aria-label", button.title);
}
function restoreSidebar() {
  const stored = read(sidebarKey());
  setCompact(typeof stored === "boolean" ? stored : narrowWindow.matches);
}
restoreSidebar();
narrowWindow.addEventListener("change", restoreSidebar);
byId("railToggle").onclick = () => {
  const compact = !document.documentElement.classList.contains("compactRail");
  setCompact(compact);
  save(sidebarKey(), compact);
};
document.addEventListener("keydown", event => {
  if (event.key === "Escape" && narrowWindow.matches && !byId("profileDialog").open &&
      !document.documentElement.classList.contains("compactRail")) {
    setCompact(true);
    byId("railToggle").focus();
  }
});
function showProfile(value) {
  const name = typeof value === "string" && value.trim() ? value.trim().slice(0,40) : "Local user";
  byId("profileName").textContent = name;
  byId("initials").textContent = name.split(/\s+/u).slice(0,2).map(word => Array.from(word)[0]).join("").toLocaleUpperCase();
  byId("profileButton").title = "Edit profile · " + name;
  byId("profileButton").setAttribute("aria-label", byId("profileButton").title);
}
showProfile(read("nuqs:display-name"));
byId("profileButton").onclick = () => {
  byId("displayName").value = byId("profileName").textContent;
  byId("displayName").setCustomValidity("");
  byId("profileDialog").showModal();
};
byId("displayName").oninput = () => byId("displayName").setCustomValidity("");
byId("cancelProfile").onclick = () => byId("profileDialog").close();
byId("profileForm").onsubmit = event => {
  event.preventDefault();
  const input = byId("displayName");
  const name = input.value.trim();
  if (!name || !save("nuqs:display-name", name)) {
    input.setCustomValidity(name ? "Browser storage is unavailable." : "Enter a display name.");
    input.reportValidity();
    return;
  }
  showProfile(name);
  byId("profileDialog").close();
};

let catalog = [];
let libraryRequest = 0;

function navigate(page, fresh = false) {
  if (narrowWindow.matches) setCompact(true);
  const reportOnly = page === "report";
  const hasReport = Boolean(current);
  byId("scanPage").hidden = page === "checks" || (reportOnly && !hasReport);
  byId("scanPage").classList.toggle("reportOnly", reportOnly);
  byId("checksPage").hidden = page !== "checks";
  byId("reportEmpty").hidden = !reportOnly || hasReport;
  for (const [key, label] of [["scan","Scan console"], ["checks","Check library"], ["report","Latest report"]]) {
    const button = byId(key + "Tab");
    if (key === page) {
      button.setAttribute("aria-current", "page");
      byId("crumb").textContent = label;
    } else button.removeAttribute("aria-current");
  }
  if (reportOnly && hasReport) {
    if (!fresh) render(current, true);
    byId("reportHeading").focus({preventScroll:true});
  } else if (reportOnly) {
    const heading = byId("reportEmpty").querySelector("h1");
    heading.tabIndex = -1;
    heading.focus({preventScroll:true});
  }
  byId("results").hidden = !reportOnly || !hasReport;
  window.scrollTo(0, 0);
}
byId("scanTab").onclick = byId("backScan").onclick = () => navigate("scan");
byId("checksTab").onclick = byId("openLibrary").onclick = () => {
  navigate("checks");
  loadCatalog();
};
byId("reportTab").onclick = () => navigate("report");

function renderLibrary() {
  const term = byId("checkSearch").value.trim().toLowerCase();
  const matches = catalog.filter(check =>
    [check.title,check.id,check.severity,...(check.services || [])].join(" ").toLowerCase().includes(term));
  byId("catalog").replaceChildren(...matches.map(check => {
    const card = node("article", "");
    card.append(badge(check.severity), node("h3", check.title),
      node("p", [check.id, ...(check.services || [])].join(" · "), "endpoint"), node("p", check.fix));
    return card;
  }));
  if (!matches.length) byId("catalog").textContent = "No matching checks.";
}
byId("checkSearch").oninput = renderLibrary;

async function loadCatalog() {
  const request = ++libraryRequest;
  try {
    const response = await fetch("/api/checks");
    if (!response.ok) throw new Error();
    const checks = await response.json();
    if (request !== libraryRequest) return;
    catalog = checks;
    renderLibrary();
    const header = node("div", "", "checkRow head");
    header.append(node("span","Check"),node("span","Services"),node("span","Severity"));
    byId("inventoryRows").replaceChildren(header,...checks.map(check => {
      const row = node("div", "", "checkRow");
      const name = node("div", check.title);
      name.append(node("small", check.id));
      row.append(name, node("span",(check.services || []).join(", ") || "—"), badge(check.severity));
      return row;
    }));
  } catch {
    if (request !== libraryRequest) return;
    byId("catalog").textContent = byId("inventoryRows").textContent = "Can't reach the checks catalog.";
  }
}
loadCatalog();
async function engineStatus() {
  try {
    const response = await fetch("/api/status");
    if (!response.ok) throw new Error();
    const status = await response.json();
    byId("runner").textContent = status.runner;
    byId("connection").textContent = "Engine online";
    byId("connection").classList.add("ready");
  } catch {
    byId("connection").classList.remove("ready");
    byId("connection").textContent = "Engine offline";
  }
}
engineStatus();
function updateProfile() {
  byId("profilePorts").textContent = byId("ports").value.trim() || "Top 1000";
  byId("discovery").textContent = byId("skipPing").checked ? "Skipped" : "Enabled";
  byId("profileTimeout").textContent = byId("timeout").value || "—";
  byId("profileWorkers").textContent = (byId("workers").value || "—") + " workers";
}
byId("scanForm").addEventListener("input", updateProfile);

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
for (const level of levels) byId("filter").add(new Option("Severity: " + level[0].toUpperCase() + level.slice(1), level));
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

function updateClock() {
  byId("elapsed").textContent = ((performance.now() - started) / 1000).toFixed(1) + "s elapsed";
}

function announcePhase() {
  if (byId("scanPhase").textContent !== phase) byId("scanPhase").textContent = phase;
}

function handleEvent(event) {
  if (event.type === "error") throw new Error(event.message || "Scan failed.");
  if (event.type === "report" && event.report) return {report:event.report, message:event.message || ""};
  if (event.kind === "discovery_started") phase = "Discovering services";
  if (event.kind === "discovery_done") phase = "Discovered " + (event.count || 0) + " hosts";
  if (event.kind === "checks_started") { total = event.count || 0; phase = "Running " + total + " checks"; }
  if (event.kind === "checks_started" || event.kind === "check_done") {
    if (event.kind === "check_done") completed++;
    byId("checkCount").hidden = false;
    byId("checkCount").textContent = completed + " of " + total + " checks completed";
  }
  if (event.kind === "scan_done") phase = "Preparing report";
  announcePhase();
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

const scanButton = document.querySelector(".scanOrb");
const reduceEffects = window.matchMedia("(prefers-reduced-motion: reduce), (prefers-reduced-transparency: reduce), (prefers-contrast: more)");
// Highlight the nearest glass edge without changing the contrast of its contents.
for (const surface of document.querySelectorAll(".rail,.workgrid,.top,.toolbar,.scanOrb")) {
  function reflectContact(event) {
    if (surface.disabled || reduceEffects.matches) return;
    const bounds = surface.getBoundingClientRect();
    surface.style.setProperty("--reflection-x", (event.clientX - bounds.left) / bounds.width * 100 + "%");
    surface.style.setProperty("--reflection-y", (event.clientY - bounds.top) / bounds.height * 100 + "%");
  }
  function resetReflection() {
    surface.style.removeProperty("--reflection-x");
    surface.style.removeProperty("--reflection-y");
  }
  surface.addEventListener("pointermove", reflectContact);
  surface.addEventListener("pointerdown", reflectContact);
  surface.addEventListener("pointerleave", resetReflection);
  surface.addEventListener("pointerup", resetReflection);
  surface.addEventListener("pointercancel", resetReflection);
  reduceEffects.addEventListener("change", resetReflection);
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
  byId("reportTab").disabled = true;
  started = performance.now();
  phase = "Starting";
  completed = 0;
  total = 0;
  byId("settings").disabled = true;
  byId("checkCount").hidden = true;
  byId("stop").hidden = false;
  byId("results").hidden = true;
  announcePhase();
  byId("launchTitle").textContent = "Scan in progress";
  byId("activeTarget").textContent = request.target;
  byId("activeTarget").hidden = false;
  byId("scanPage").classList.add("running");
  byId("elapsed").hidden = false;
  updateClock();
  byId("stop").focus({preventScroll:true});
  const timer = setInterval(updateClock, 250);
  try {
    const response = await fetch("/api/scan", {method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify(request), signal:controller.signal});
    if (!response.ok) throw new Error((await response.text()).trim() || "Scan request failed.");
    const saved = await receive(response);
    render(saved, false);
    if (!byId("scanPage").hidden) navigate("report", true);
    if (!save(reportKey, saved)) byId("status").textContent += " · Report could not be saved on this device.";
  } catch (err) {
    byId("scanPhase").textContent = controller.signal.aborted ? "Scan stopped." :
      err instanceof TypeError ? "Can't reach the scan server." : err.message;
  } finally {
    if (!controller.signal.aborted) void engineStatus();
    clearInterval(timer);
    byId("scanPage").classList.remove("running");
    byId("launchTitle").textContent = "New scan";
    byId("activeTarget").hidden = true;
    byId("elapsed").hidden = true;
    if (!byId("results").hidden) byId("scanPhase").textContent = "";
    const returnFocus = document.activeElement === byId("stop");
    controller = null;
    byId("reportTab").disabled = false;
    byId("settings").disabled = false;
    byId("checkCount").hidden = true;
    byId("stop").hidden = true;
    if (returnFocus) scanButton.focus();
  }
};
const previous = read(reportKey);
if (previous) {
  try { current = previous; navigate("report"); } catch { current = null; navigate("scan"); byId("status").textContent = ""; }
}
