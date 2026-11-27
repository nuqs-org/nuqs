// Small helpers for the server-rendered pages: theme, sidebar, the new scan form, live scan progress and copy buttons.
"use strict";

const byId = id => document.getElementById(id);
document.documentElement.classList.add("js");

function read(key) {
  try { return JSON.parse(localStorage.getItem(key)); } catch { return null; }
}
function save(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); return true; } catch { return false; }
}
// Reports used to be kept in the browser. The server is the only copy now.
try { localStorage.removeItem("nuqs:last-report:v1"); } catch { /* storage unavailable */ }

// Light and dark follow the system until the user picks one.
const systemLight = matchMedia("(prefers-color-scheme: light)");
let themeChoice = read("nuqs:theme");
const themeToggle = byId("themeToggle");
function applyTheme() {
  const light = themeChoice === "light" || (themeChoice !== "dark" && systemLight.matches);
  document.documentElement.classList.toggle("light", light);
  if (themeToggle) {
    const label = light ? "Switch to dark mode" : "Switch to light mode";
    themeToggle.title = label;
    themeToggle.setAttribute("aria-label", label);
    themeToggle.setAttribute("aria-pressed", String(!light));
  }
}
applyTheme();
systemLight.addEventListener("change", applyTheme);
if (themeToggle) {
  themeToggle.onclick = () => {
    themeChoice = document.documentElement.classList.contains("light") ? "dark" : "light";
    save("nuqs:theme", themeChoice);
    applyTheme();
  };
}

// The sidebar can fold down to icons.
const railToggle = byId("railToggle");
if (railToggle) {
  function setCompact(compact) {
    document.documentElement.classList.toggle("compactRail", compact);
    railToggle.setAttribute("aria-expanded", String(!compact));
    railToggle.setAttribute("aria-label", compact ? "Expand sidebar" : "Collapse sidebar");
  }
  setCompact(read("nuqs:compact") === true);
  railToggle.onclick = () => {
    const compact = !document.documentElement.classList.contains("compactRail");
    setCompact(compact);
    save("nuqs:compact", compact);
  };
}

// Authenticated account dialog (change password and sign out).
const accountButton = byId("accountButton");
const accountDialog = byId("accountDialog");
if (accountButton && accountDialog) {
  accountButton.onclick = () => {
    const pwForm = byId("passwordForm");
    if (pwForm) {
      pwForm.reset();
      pwForm.elements.confirm_password.setCustomValidity("");
    }
    accountDialog.showModal();
  };
  if (byId("accountError")) {
    accountDialog.showModal();
    const errorCode = new URLSearchParams(location.search).get("account_error");
    const field = errorCode === "mismatch" ? "confirm_password" :
      errorCode === "invalid-password" ? "new_password" : "current_password";
    byId("passwordForm").elements[field].focus();
  }
  const cancelAccount = byId("cancelAccount");
  if (cancelAccount) cancelAccount.onclick = () => accountDialog.close();
  accountDialog.onclick = event => {
    if (event.target === accountDialog) accountDialog.close();
  };
  accountDialog.addEventListener("close", () => {
    byId("accountError")?.remove();
    const url = new URL(location.href);
    if (url.searchParams.has("account_error")) {
      url.searchParams.delete("account_error");
      history.replaceState(null, "", url.pathname + url.search + url.hash);
    }
  });
}

// Instant client-side check that password confirmation fields match (server still verifies).
for (const [passName, confirmName] of [["password", "confirm"], ["new_password", "confirm_password"]]) {
  const pass = document.querySelector(`input[name="${passName}"]`);
  const conf = document.querySelector(`input[name="${confirmName}"]`);
  if (pass && conf) {
    const sync = () => conf.setCustomValidity(conf.value && pass.value !== conf.value ? "Passwords do not match." : "");
    pass.addEventListener("input", sync);
    conf.addEventListener("input", sync);
  }
}

// Confirm destructive or session-revoking user management forms.
document.addEventListener("submit", event => {
  const msg = event.target.dataset?.confirm;
  if (msg && !confirm(msg)) event.preventDefault();
});

// Engine status in the sidebar (only when inside the authenticated workspace).
const connection = byId("connection");
if (connection) {
  connection.title = "Checking engine…";
  fetch("/api/status").then(r => {
    if (r.status === 401) { location.href = "/login"; return; }
    if (!r.ok) throw new Error();
    connection.textContent = "Engine online";
    connection.title = "Engine online";
    connection.classList.add("ready");
  }).catch(() => {
    connection.textContent = "Engine offline";
    connection.title = "Engine offline";
  });
}

// Clicking anywhere on a table row opens its link.
document.addEventListener("click", event => {
  const row = event.target.closest("tr.rowLink");
  if (row && !event.target.closest("a,button,select,input,form")) row.querySelector("a")?.click();
});

// Copy fix, one-time code and reset link buttons.
document.addEventListener("click", async event => {
  const button = event.target.closest(".copy,.copyCode,.copyLink");
  if (!button) return;
  let resetLabel = button.dataset.copyLabel || "Copy fix";
  let payload = button.dataset.fix || "";
  if (button.classList.contains("copyCode")) {
    resetLabel = "Copy code";
    payload = button.dataset.copy || "";
  } else if (button.classList.contains("copyLink")) {
    resetLabel = "Copy reset link";
    payload = location.origin + (button.dataset.copyPath || "");
  }
  try { await navigator.clipboard.writeText(payload); button.textContent = "Copied"; }
  catch { button.textContent = "Couldn't copy"; }
  clearTimeout(Number(button.dataset.timer || 0));
  button.dataset.timer = String(setTimeout(() => { button.textContent = resetLabel; }, 2000));
});

// startScan asks the server to start a scan and opens its page.
async function startScan(body) {
  const response = await fetch("/api/scans", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body)
  });
  if (response.status === 401) { location.href = "/login"; return; }
  if (!response.ok) throw new Error((await response.text()).trim() || "The scan couldn't start.");
  location.href = response.headers.get("Location") || "/scans";
}

// "Scan 127.0.0.1" on an empty scans page.
const tryScan = byId("tryScan");
if (tryScan) {
  tryScan.onclick = () => {
    tryScan.disabled = true;
    startScan({kind: "full", settings: {target: tryScan.dataset.target, timeout: "30s", workers: 10}}).catch(err => {
      byId("tryError").textContent = err.message;
      byId("tryError").hidden = false;
      tryScan.disabled = false;
    });
  };
}

// --- New scan settings ---

// Rough count of how many addresses a target covers, using the same rules
// as the server (internal/target). The server still has the final say,
// this is only so people see mistakes and big scans while typing.
function countOne(spec) {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const isV4 = ip => {
    const m = v4.exec(ip);
    return Boolean(m) && m.slice(1).every(part => Number(part) <= 255);
  };
  if (spec.startsWith("-")) return null;
  if (isV4(spec) || (spec.includes(":") && !spec.includes("/") && /^[0-9a-f:.]+$/i.test(spec))) return 1;
  if (spec.includes("/")) {
    const [ip, bitsText] = spec.split("/");
    const bits = Number(bitsText);
    if (!/^\d+$/.test(bitsText)) return null;
    if (isV4(ip) && bits <= 32) return 2 ** (32 - bits);
    if (ip.includes(":") && bits <= 128) return 2 ** (128 - bits);
    return null;
  }
  const dash = spec.lastIndexOf("-");
  if (dash > 0 && isV4(spec.slice(0, dash))) {
    const first = Number(spec.slice(0, dash).split(".")[3]);
    const endText = spec.slice(dash + 1);
    const end = Number(endText);
    if (!/^\d+$/.test(endText) || end < first || end > 255) return null;
    return end - first + 1;
  }
  const host = spec.replace(/\.$/, "");
  const label = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;
  if (host && host.length <= 253 && host.split(".").every(part => label.test(part))) return 1;
  return null;
}

const form = byId("scanForm");
if (form) {
  // Sections work like System Settings, one shown at a time.
  const links = Array.from(form.querySelectorAll(".sections a"));
  function showSection(name) {
    for (const pane of form.querySelectorAll(".pane")) pane.classList.toggle("open", pane.id === name);
    for (const link of links) {
      if (link.dataset.section === name) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
  }
  for (const link of links) {
    link.onclick = event => {
      event.preventDefault();
      showSection(link.dataset.section);
      history.replaceState(null, "", "#" + link.dataset.section);
    };
  }
  const fromHash = location.hash.slice(1);
  showSection(links.some(l => l.dataset.section === fromHash) ? fromHash : form.dataset.open);

  function toggleCustomPorts() {
    const custom = byId("portPreset").value === "custom";
    byId("customPortsWrap").hidden = !custom;
    byId("ports").required = custom;
  }

  function updateTargetInfo() {
    const input = byId("target");
    const info = byId("targetInfo");
    const specs = input.value.split(/[\s,]+/).filter(Boolean);
    let total = 0;
    let bad = "";
    for (const spec of specs) {
      const n = countOne(spec);
      if (n === null) { bad = spec; break; }
      total += n;
    }
    info.classList.toggle("isError", Boolean(bad));
    if (bad) {
      info.textContent = bad + " doesn't look like an IP, a range like 10.0.0.1-20, a network like 10.0.0.0/24 or a hostname.";
      input.setCustomValidity(info.textContent);
    } else {
      info.textContent = specs.length ? total.toLocaleString() + (total === 1 ? " address" : " addresses") : "";
      input.setCustomValidity("");
    }
    input.setAttribute("aria-invalid", String(Boolean(bad)));
    // Only ask about big scans when the target really is big.
    const big = !bad && total > 1024;
    byId("largeNet").hidden = !big;
    if (big) byId("largeNetText").textContent = "Yes, scan all " + total.toLocaleString() + " addresses";
    else byId("force").checked = false;
  }

  // The scan type keeps its name, changing one of its settings only adds a "modified" tag.
  const tracked = ["portPreset", "ports", "skipPing", "lightVersion", "timeout", "workers"];
  const valueOf = id => byId(id).type === "checkbox" ? byId(id).checked : byId(id).value.trim();
  const defaults = Object.fromEntries(tracked.map(id => [id, valueOf(id)]));
  function updateModified() {
    byId("modifiedTag").hidden = form.dataset.kind === "custom" || tracked.every(id => valueOf(id) === defaults[id]);
  }

  form.addEventListener("input", () => { toggleCustomPorts(); updateModified(); });
  form.addEventListener("change", () => { toggleCustomPorts(); updateModified(); });
  byId("target").addEventListener("input", updateTargetInfo);
  toggleCustomPorts();
  updateTargetInfo();
  updateModified();

  const useNetwork = byId("useNetwork");
  if (useNetwork) {
    useNetwork.onclick = () => {
      byId("target").value = useNetwork.dataset.network;
      updateTargetInfo();
      byId("target").focus();
    };
  }

  const portSettings = {
    top1000: {ports: "", top_ports: 0},
    top100: {ports: "", top_ports: 100},
    web: {ports: "80,443,8080,8443", top_ports: 0},
    all: {ports: "1-65535", top_ports: 0}
  };

  form.onsubmit = async event => {
    event.preventDefault();
    // Show the section with the first problem, then point at it.
    const invalid = form.querySelector(":invalid");
    if (invalid) {
      showSection(invalid.closest(".pane").id);
      invalid.reportValidity();
      return;
    }
    const preset = byId("portPreset").value;
    const ports = preset === "custom" ? {ports: byId("ports").value.trim(), top_ports: 0} : portSettings[preset];
    const launch = byId("launch");
    launch.disabled = true;
    launch.textContent = "Launching…";
    byId("formError").hidden = true;
    try {
      await startScan({
        name: byId("name").value.trim(),
        description: byId("description").value.trim(),
        kind: form.dataset.kind,
        settings: {
          target: byId("target").value.trim(),
          ports: ports.ports,
          top_ports: ports.top_ports,
          light_version: byId("lightVersion").checked,
          skip_ping: byId("skipPing").checked,
          force: byId("force").checked,
          timeout: byId("timeout").value.trim(),
          workers: byId("workers").valueAsNumber
        }
      });
    } catch (err) {
      byId("formError").textContent = err.message;
      byId("formError").hidden = false;
      launch.disabled = false;
      launch.textContent = "Launch";
    }
  };
}

// --- A running scan: live progress, then reload when it's done ---

const watched = document.querySelector("[data-watch]");
if (watched) {
  const id = watched.dataset.watch;
  const setLive = (elementId, text) => { if (byId(elementId)) byId(elementId).textContent = text; };
  const events = new EventSource("/api/scans/" + encodeURIComponent(id) + "/events");
  let shownPercent = Number(byId("progressBar")?.getAttribute("aria-valuenow")) || 0;
  let targetPercent = shownPercent;
  let progressFrame = 0;
  const animateProgress = () => {
    const delta = targetPercent - shownPercent;
    if (Math.abs(delta) < 0.1) {
      shownPercent = targetPercent;
      progressFrame = 0;
    } else {
      shownPercent += delta * 0.08;
      progressFrame = requestAnimationFrame(animateProgress);
    }
    const displayed = Math.floor(shownPercent);
    setLive("percentText", displayed + "%");
    if (byId("progressFill")) byId("progressFill").style.width = shownPercent + "%";
    if (byId("progressBar")) byId("progressBar").setAttribute("aria-valuenow", String(displayed));
  };
  const setTargetProgress = percent => {
    targetPercent = Math.max(shownPercent, Math.min(100, Number(percent) || 0));
    if (!progressFrame) progressFrame = requestAnimationFrame(animateProgress);
  };
  events.onmessage = message => {
    const p = JSON.parse(message.data);
    if (p.status !== "running") {
      events.close();
      location.reload();
      return;
    }
    // The server works out percent and time left the same way the CLI does,
    // the page only shows them.
    setTargetProgress(p.percent);
    const percent = Math.floor(p.percent) + "%";
    const set = (elementId, text) => { if (byId(elementId)) byId(elementId).textContent = text; };
    set("statusLabel", "Scanning · " + percent);
    set("phase", p.phase || "Working");
    const latest = p.latest_host ? "Found " + p.latest_host + " · " + p.latest_open + (p.latest_open === 1 ? " open service" : " open services") : (p.phase || "Working");
    set("liveActivity", latest);
    set("remaining", p.remaining || "working out the time left");
    set("elapsed", elapsed(p.seconds));
    set("hostsFound", p.hosts_found + (p.hosts_found === 1 ? " host found" : " hosts found"));
    set("liveChecks", p.checks_done + " checks complete" + (p.checks_total ? " of " + p.checks_total : ""));
    set("liveFindings", p.findings + (p.findings === 1 ? " finding" : " findings"));
    const liveHosts = byId("liveHosts");
    if (liveHosts && Array.isArray(p.hosts)) {
      liveHosts.replaceChildren(...p.hosts.map(host => {
        const item = document.createElement("span");
        item.className = "liveHost mono";
        item.textContent = host.address + " · " + host.services.length + (host.services.length === 1 ? " service" : " services");
        return item;
      }));
    }
  };
}

// elapsed matches the server's duration format: 0.2s, 12.3s, 1m 5s.
function elapsed(seconds) {
  if (seconds >= 60) return Math.floor(seconds / 60) + "m " + Math.floor(seconds % 60) + "s";
  return seconds > 0 && seconds < 0.1 ? seconds.toFixed(2) + "s" : seconds.toFixed(1) + "s";
}

const stop = byId("stopScan");
if (stop) {
  const dialog = byId("stopScanDialog");
  const cancel = byId("cancelStopScan");
  const confirm = byId("confirmStopScan");
  document.addEventListener("keydown", event => {
    if (event.key !== "Escape" || event.defaultPrevented || event.repeat ||
        event.isComposing || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey ||
        stop.disabled || document.querySelector("dialog[open]") ||
        document.activeElement?.closest("input, textarea, select, [contenteditable]")) return;
    event.preventDefault();
    stop.click();
  });
  stop.onclick = () => dialog.showModal();
  cancel.onclick = () => dialog.close();
  confirm.onclick = async () => {
    dialog.close();
    stop.disabled = true;
    stop.textContent = "Stopping…";
    try {
      const response = await fetch("/api/scans/" + encodeURIComponent(stop.dataset.id) + "/stop", {method: "POST"});
      if (response.status === 401) { location.href = "/login"; return; }
      if (!response.ok) throw new Error();
    } catch {
      stop.disabled = false;
      stop.textContent = "Stop";
    }
  };
}

// Filters apply as soon as one changes, there's no Apply button.
const findingFilters = document.querySelector(".findingFilters");
if (findingFilters) {
  findingFilters.addEventListener("change", () => findingFilters.submit());
}

const exportMenu = document.querySelector(".exportMenu");
if (exportMenu) {
  exportMenu.querySelectorAll("a").forEach(link => link.addEventListener("click", () => { exportMenu.open = false; }));
  document.addEventListener("pointerdown", event => {
    if (!exportMenu.contains(event.target)) exportMenu.open = false;
  });
}
