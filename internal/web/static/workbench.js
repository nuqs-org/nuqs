// Enhances the server-rendered Nuqs workspace with SSE live progress, persistence and theme controls.
"use strict";

const byId = id => document.getElementById(id);
const levels = ["critical", "high", "medium", "low", "info"];
const reportKey = "nuqs:last-report:v1";
let current = null;
let hasServerReport = byId("results")?.dataset.hasServerReport === "true";
let controller = null;
let started = 0;
let phase = "";
let total = 0;
let completed = 0;

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
  const name = typeof value === "string" && value.trim() ? value.trim().slice(0, 40) : "Local user";
  byId("profileName").textContent = name;
  byId("initials").textContent = name.split(/\s+/u).slice(0, 2).map(word => Array.from(word)[0]).join("").toLocaleUpperCase();
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

function hasAnyReport() {
  return hasServerReport || Boolean(current);
}

function navigate(page, fresh = false) {
  if (narrowWindow.matches) setCompact(true);
  const reportOnly = page === "report";
  const hasReport = hasAnyReport();
  byId("scanPage").hidden = page === "checks" || (reportOnly && !hasReport);
  byId("scanPage").classList.toggle("reportOnly", reportOnly);
  byId("checksPage").hidden = page !== "checks";
  byId("reportEmpty").hidden = !reportOnly || hasReport;
  for (const [key, label] of [["scan", "Scan console"], ["checks", "Check library"], ["report", "Latest report"]]) {
    const button = byId(key + "Tab");
    if (key === page) {
      button.setAttribute("aria-current", "page");
      byId("crumb").textContent = label;
    } else button.removeAttribute("aria-current");
  }
  if (reportOnly && hasReport) {
    if (!fresh && !hasServerReport && current) renderLocalReport(current, true);
    byId("reportHeading").focus({preventScroll: true});
  } else if (reportOnly) {
    const heading = byId("reportEmpty").querySelector("h1");
    heading.tabIndex = -1;
    heading.focus({preventScroll: true});
  }
  byId("results").hidden = !reportOnly || !hasReport;
  window.scrollTo(0, 0);
}
byId("scanTab").onclick = byId("backScan").onclick = () => navigate("scan");
byId("checksTab").onclick = byId("openLibrary").onclick = () => {
  navigate("checks");
  if (window.htmx) window.htmx.trigger(byId("checkSearch"), "search");
};
byId("reportTab").onclick = () => navigate("report");

async function engineStatus() {
  try {
    const response = await fetch("/api/status");
    if (!response.ok) throw new Error();
    const status = await response.json();
    byId("runner").textContent = status.runner;
    if (status.addr) {
      const addrEl = document.querySelector(".localAddress");
      if (addrEl) addrEl.textContent = status.addr;
    }
    if (status.allowed_scope) {
      byId("scope").textContent = "Allowed scope: " + status.allowed_scope + ".";
    }
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
byId("scanForm").addEventListener("change", updateProfile);
updateProfile();

function badge(level) {
  return node("span", level, "badge " + (levels.includes(level) ? level : "info"));
}

function rank(level) {
  const index = levels.indexOf(level);
  return index === -1 ? levels.length : index;
}

function findingCard(finding) {
  const card = node("article", "");
  const copy = node("button", "Copy fix", "copy");
  copy.type = "button";
  copy.dataset.fix = finding.fix || "";
  card.append(
    badge(finding.severity),
    node("h3", finding.title),
    node("p", finding.host + ":" + finding.port + "/" + finding.protocol + " · " + finding.check_id, "endpoint"),
    node("p", "Evidence · " + finding.evidence),
    node("p", "Fix · " + finding.fix),
    copy
  );
  return card;
}

function renderLocalFindings() {
  if (!current || !current.report) return;
  const filter = byId("filter");
  const selected = filter ? filter.value : "";
  const findings = (current.report.findings || []).filter(f => !selected || f.severity === selected);
  findings.sort((a, b) => rank(a.severity) - rank(b.severity));
  byId("findings").replaceChildren(...findings.map(findingCard));
  if (!findings.length) {
    const hostsUp = (current.report.hosts || []).length;
    byId("findings").textContent = selected ? "No findings at this severity." :
      hostsUp === 0 ? "No live hosts responded (try Skip host discovery if ping is blocked)." : "No findings reported.";
  }
}

function setRawVisible(show) {
  const rawEl = byId("raw");
  const toggleEl = byId("rawToggle");
  if (!rawEl || !toggleEl) return;
  rawEl.hidden = !show;
  toggleEl.setAttribute("aria-expanded", String(show));
  toggleEl.textContent = show ? "Hide raw JSON" : "Show raw JSON";
}

function renderLocalReport(saved, restored) {
  const {report, message} = saved;
  current = saved;
  const findings = report.findings || [];
  const reportErrors = report.errors || [];
  const targets = report.targets || [];
  const hosts = report.hosts || [];
  const openServices = hosts.reduce((sum, h) => sum + (h.services ? h.services.length : 0), 0);
  const duration = Math.max(0, (Date.parse(report.finished) - Date.parse(report.started)) / 1000);
  const incomplete = message || reportErrors.length;
  const outcome = incomplete ? "Scan incomplete" : "Scan finished";
  byId("status").textContent = (restored ? "Last report · " : "") + outcome + " in " + duration.toFixed(2) + "s";
  const hostSummary = hosts.length + (hosts.length === 1 ? " host up" : " hosts up") + " · " +
    openServices + (openServices === 1 ? " open service" : " open services");
  byId("metadata").textContent = targets.join(", ") + " · " + hostSummary + " · " + new Date(report.finished).toLocaleString();
  byId("counts").replaceChildren(...levels.map(level => {
    const count = findings.filter(f => f.severity === level).length;
    return node("span", count + " " + level, "badge " + (count ? level : "info"));
  }));
  byId("raw").textContent = JSON.stringify(report, null, 2);
  setRawVisible(false);
  if (byId("filter")) byId("filter").value = "";
  renderLocalFindings();
  const errors = byId("errors");
  errors.replaceChildren();
  if (incomplete) errors.append(node("h3", "Scan errors"));
  if (message) errors.append(node("p", message));
  for (const err of reportErrors) errors.append(node("p", err.host + ":" + err.port + " · " + err.check_id + " · " + err.error));
  byId("results").hidden = false;
}

// Delegated interactions inside #results survive htmx swaps of #reportContent.
byId("results").addEventListener("click", async event => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  if (target.id === "rawToggle") {
    setRawVisible(byId("raw").hidden);
    return;
  }
  if (target.id === "download") {
    const rawEl = byId("raw");
    const url = URL.createObjectURL(new Blob([rawEl ? rawEl.textContent : "{}"], {type: "application/json"}));
    const link = node("a", "");
    link.href = url;
    link.download = "nuqs-report.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    return;
  }
  if (target.classList.contains("copy")) {
    const fixText = target.dataset.fix || "";
    clearTimeout(Number(target.dataset.resetTimer || 0));
    try { await navigator.clipboard.writeText(fixText); target.textContent = "Copied"; }
    catch { target.textContent = "Copy unavailable"; }
    target.dataset.resetTimer = String(setTimeout(() => { target.textContent = "Copy fix"; }, 2000));
  }
});

// When showing a localStorage-restored report after a server restart, filter locally instead of hitting the server.
document.body.addEventListener("htmx:beforeRequest", event => {
  if (event.target && event.target.id === "filter" && !hasServerReport && current) {
    event.preventDefault();
    renderLocalFindings();
  }
});
byId("results").addEventListener("change", event => {
  if (event.target && event.target.id === "filter" && !hasServerReport && current) {
    renderLocalFindings();
  }
});

async function refreshServerReport(saved) {
  current = saved;
  hasServerReport = true;
  if (window.htmx) {
    try {
      await window.htmx.ajax("GET", "/partials/report?fresh=1", {target: "#reportContent", swap: "innerHTML"});
      byId("results").hidden = false;
      return;
    } catch {
      // Fall back to local DOM rendering if partial fetch fails.
    }
  }
  renderLocalReport(saved, false);
}

function updateClock() {
  byId("elapsed").textContent = ((performance.now() - started) / 1000).toFixed(1) + "s elapsed";
}

function announcePhase() {
  if (byId("scanPhase").textContent !== phase) byId("scanPhase").textContent = phase;
}

function markStage(index) {
  Array.from(byId("scanSteps").children).forEach((step, position) => {
    step.classList.toggle("done", position < index);
    if (position === index) step.setAttribute("aria-current", "step");
    else step.removeAttribute("aria-current");
  });
}

function handleEvent(event) {
  if (event.type === "error") throw new Error(event.message || "Scan failed.");
  if (event.type === "report" && event.report) return {report: event.report, message: event.message || ""};
  if (event.kind === "discovery_started") { markStage(0); phase = "Discovering services"; }
  if (event.kind === "discovery_done") phase = "Discovered " + (event.count || 0) + " hosts";
  if (event.kind === "checks_started") { markStage(1); total = event.count || 0; phase = "Running " + total + " checks"; }
  if (event.kind === "checks_started" || event.kind === "check_done") {
    if (event.kind === "check_done") completed++;
    byId("checkCount").hidden = false;
    byId("checkCount").textContent = completed + " of " + total + " checks completed";
  }
  if (event.kind === "scan_done") { markStage(2); phase = "Preparing report"; }
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
function bindReflections(root) {
  for (const surface of root.querySelectorAll(".rail,.workgrid,.top,.toolbar,.scanOrb")) {
    if (surface.dataset.reflectionBound) continue;
    surface.dataset.reflectionBound = "1";
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
}
bindReflections(document);
document.body.addEventListener("htmx:afterSwap", event => bindReflections(event.target));

byId("stop").onclick = () => controller?.abort();
// Keep the native disclosure and keyboard behavior when layout animation is unavailable.
const scanOptions = document.querySelector(".launch details");
let optionsTransition;
let requestedOpen;
scanOptions.querySelector("summary").addEventListener("click", event => {
  if (!document.startViewTransition || reduceEffects.matches) return;
  event.preventDefault();
  requestedOpen = !(optionsTransition ? requestedOpen : scanOptions.open);
  optionsTransition?.skipTransition();
  document.documentElement.classList.add("movingOptions");
  const transition = document.startViewTransition(() => {
    scanOptions.open = requestedOpen;
  });
  optionsTransition = transition;
  transition.finished.finally(() => {
    if (transition !== optionsTransition) return;
    optionsTransition = null;
    document.documentElement.classList.remove("movingOptions");
  });
});

byId("scanForm").addEventListener("invalid", event => {
  if (event.target.closest("details")) event.target.closest("details").open = true;
}, true);
byId("scanForm").onsubmit = async event => {
  event.preventDefault();
  if (controller) return;
  const request = {
    target: byId("target").value.trim(),
    ports: byId("ports").value.trim(),
    timeout: byId("timeout").value.trim(),
    workers: byId("workers").valueAsNumber,
    skip_ping: byId("skipPing").checked,
    force: byId("force").checked
  };
  controller = new AbortController();
  byId("reportTab").disabled = true;
  started = performance.now();
  phase = "Starting";
  completed = 0;
  total = 0;
  const before = scanButton.getBoundingClientRect();
  byId("settings").disabled = true;
  byId("checkCount").hidden = true;
  byId("stop").hidden = false;
  byId("results").hidden = true;
  announcePhase();
  byId("launchTitle").textContent = "Scan in progress";
  byId("activeTarget").textContent = request.target;
  byId("activeTarget").hidden = false;
  byId("scanPage").classList.add("running");
  markStage(-1);
  byId("scanSteps").hidden = false;
  if (!reduceEffects.matches) {
    const after = scanButton.getBoundingClientRect();
    scanButton.animate([
      {transform: "translate(" + (before.x - after.x) + "px," + (before.y - after.y) + "px)"},
      {transform: "none"}
    ], {duration: 260, easing: "cubic-bezier(.22,.78,.24,1)"});
  }
  byId("elapsed").hidden = false;
  updateClock();
  byId("stop").focus({preventScroll: true});
  const timer = setInterval(updateClock, 250);
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(request),
      signal: controller.signal
    });
    if (!response.ok) throw new Error((await response.text()).trim() || "Scan request failed.");
    const saved = await receive(response);
    await refreshServerReport(saved);
    if (!byId("scanPage").hidden) navigate("report", true);
    if (!save(reportKey, saved) && byId("status")) {
      byId("status").textContent += " · Report could not be saved on this device.";
    }
  } catch (err) {
    byId("scanPhase").textContent = controller.signal.aborted ? "Scan stopped." :
      err instanceof TypeError ? "Can't reach the scan server." : err.message;
  } finally {
    if (!controller.signal.aborted) void engineStatus();
    clearInterval(timer);
    byId("scanSteps").hidden = true;
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
if (hasServerReport) {
  navigate("report", true);
} else if (previous) {
  try { current = previous; navigate("report"); }
  catch { current = null; navigate("scan"); if (byId("status")) byId("status").textContent = ""; }
}
