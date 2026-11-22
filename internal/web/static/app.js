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
function applyTheme() {
  const light = themeChoice === "light" || (themeChoice !== "dark" && systemLight.matches);
  document.documentElement.classList.toggle("light", light);
  const label = light ? "Switch to dark mode" : "Switch to light mode";
  byId("themeToggle").title = label;
  byId("themeToggle").setAttribute("aria-label", label);
  byId("themeToggle").setAttribute("aria-pressed", String(!light));
}
applyTheme();
systemLight.addEventListener("change", applyTheme);
byId("themeToggle").onclick = () => {
  themeChoice = document.documentElement.classList.contains("light") ? "dark" : "light";
  save("nuqs:theme", themeChoice);
  applyTheme();
};

// The sidebar can fold down to icons.
function setCompact(compact) {
  document.documentElement.classList.toggle("compactRail", compact);
  byId("railToggle").setAttribute("aria-expanded", String(!compact));
  byId("railToggle").setAttribute("aria-label", compact ? "Expand sidebar" : "Collapse sidebar");
}
setCompact(read("nuqs:compact") === true);
byId("railToggle").onclick = () => {
  const compact = !document.documentElement.classList.contains("compactRail");
  setCompact(compact);
  save("nuqs:compact", compact);
};

// Local display name, kept in this browser.
function showProfile(value) {
  const name = typeof value === "string" && value.trim() ? value.trim().slice(0, 40) : "Local user";
  byId("profileName").textContent = name;
  byId("initials").textContent = name.split(/\s+/u).slice(0, 2).map(word => Array.from(word)[0]).join("").toLocaleUpperCase();
}
showProfile(read("nuqs:display-name"));
byId("profileButton").onclick = () => {
  byId("displayName").value = byId("profileName").textContent;
  byId("profileDialog").showModal();
};
byId("cancelProfile").onclick = () => byId("profileDialog").close();
byId("profileForm").onsubmit = event => {
  event.preventDefault();
  const name = byId("displayName").value.trim();
  if (name && save("nuqs:display-name", name)) {
    showProfile(name);
    byId("profileDialog").close();
  }
};

// Engine status in the sidebar.
fetch("/api/status").then(r => {
  if (!r.ok) throw new Error();
  byId("connection").textContent = "Engine online";
  byId("connection").classList.add("ready");
}).catch(() => { byId("connection").textContent = "Engine offline"; });

// Clicking anywhere on a table row opens its link.
document.addEventListener("click", event => {
  const row = event.target.closest("tr.rowLink");
  if (row && !event.target.closest("a,button")) row.querySelector("a")?.click();
});

// Copy fix buttons.
document.addEventListener("click", async event => {
  const button = event.target.closest(".copy");
  if (!button) return;
  try { await navigator.clipboard.writeText(button.dataset.fix || ""); button.textContent = "Copied"; }
  catch { button.textContent = "Couldn't copy"; }
  setTimeout(() => { button.textContent = "Copy fix"; }, 2000);
});

// startScan asks the server to start a scan and opens its page.
async function startScan(body) {
  const response = await fetch("/api/scans", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body)
  });
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
  const events = new EventSource("/api/scans/" + encodeURIComponent(id) + "/events");
  events.onmessage = message => {
    const p = JSON.parse(message.data);
    if (p.status !== "running") {
      events.close();
      location.reload();
      return;
    }
    // The server works out percent and time left the same way the CLI does,
    // the page only shows them.
    const percent = Math.floor(p.percent) + "%";
    const set = (elementId, text) => { if (byId(elementId)) byId(elementId).textContent = text; };
    set("statusLabel", "Scanning · " + percent);
    set("phase", p.phase || "Working");
    set("percentText", percent);
    set("remaining", p.remaining || "working out the time left");
    set("elapsed", elapsed(p.seconds));
    if (byId("progressFill")) {
      byId("progressFill").style.width = p.percent + "%";
      byId("progressBar").setAttribute("aria-valuenow", String(Math.floor(p.percent)));
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
  stop.onclick = async () => {
    stop.disabled = true;
    stop.textContent = "Stopping…";
    try {
      const response = await fetch("/api/scans/" + encodeURIComponent(stop.dataset.id) + "/stop", {method: "POST"});
      if (!response.ok) throw new Error();
    } catch {
      stop.disabled = false;
      stop.textContent = "Stop";
    }
  };
}
