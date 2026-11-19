# Nuqs — UI/UX Design System Specification
## HCI-Compliant Network Vulnerability Audit Interface

---

## 1. Human-Computer Interaction (HCI) Design Foundations

This design specification establishes the user interface for **Nuqs**, an open-source network vulnerability scanner written in Go. The interface merges the high-contrast aesthetic of the **Inky Mono** specimen (pitch black `#060709` and electric mint `#00F59B`) with strict adherence to classical Human-Computer Interaction (HCI) heuristics.

---

### 1.1 Nielsen’s 10 Usability Heuristics Mapping

1. **Visibility of System Status (Heuristic #1):**
   * During an audit, the interface enters a live progress state showing real-time elapsed time (`ELAPSED: 0.8s`) and the 4 discrete scanner phase transitions:
     1. `[✓]` Nmap host discovery
     2. `[✓]` Live host and port identification
     3. `[⟳]` Concurrent check dispatch (animated mint spinner)
     4. `[○]` Completion timestamp
   * Actions like `Copy Fix` give immediate, inline visible feedback (`✔ Copied`) right under the user's cursor.
2. **Match Between System and the Real World (Heuristic #2):**
   * Uses plain, transparent networking concepts: IP addresses, CIDRs (`192.168.1.0/24`), target ports, and real CLI flags (`-Pn`, `-timeout`, `-workers`).
3. **User Control and Freedom (Heuristic #3):**
   * **Active Scan Abort:** Users can cancel or stop a scan in progress at any moment via a dedicated `■ Stop scan` button.
   * Seamless `New scan` action to reset the state back to the launchpad.
4. **Consistency and Standards (Heuristic #4):**
   * **Typography Discipline (Dual-Font Pairing):**
     * **UI Prose & Controls (`Inter`):** Used for navigation tabs, labels, explanations, and buttons for maximum legibility and reduced cognitive reading fatigue.
     * **Display & Data (`Space Mono`):** Used for brand wordmark, metrics, and KPI counts.
     * **Technical Monospace (`JetBrains Mono`):** Reserved for IP endpoints, ports, hexadecimal payloads, and raw protocol evidence.
5. **Error Prevention (Heuristic #5):**
   * Clear helper instructions on valid network inputs (IP, CIDR, ranges, hostnames).
   * Safe defaults (target prefilled with loopback `127.0.0.1`, Nmap top 1000 ports, 10 workers, 30s timeout).
6. **Recognition Rather than Recall (Heuristic #6):**
   * Quick-preset filter chips for the most common audit targets: `Redis (6379)`, `Web (80,443)`, `Top 1000 [Default]`.
   * Clear tooltips explaining advanced flags:
     * `-Pn`: *"Treat all hosts as online — skip ping probe"*
     * `--force`: *"Allow scanning subnets larger than /22 (>1024 addresses)"*
7. **Flexibility and Efficiency of Use (Heuristic #7):**
   * Keyboard accelerators: `Enter` to run the scan from the input field, `Esc` to reset.
   * One-click copy buttons for fix directives and JSON report export.
8. **Aesthetic and Minimalist Design (Heuristic #8):**
   * Centered desktop container (`max-width: 920px`) prevents wall-to-wall scanning fatigue.
   * Stripped of all speculative, unbuilt, or decorative third-party clutter.
9. **Help Users Recognize, Diagnose, and Recover from Errors (Heuristic #9):**
   * Explicit unfinished checks warnings (e.g. `ftp-anonymous-login: dial tcp: i/o timeout`) detailing the exact failing host and port.
10. **Help and Documentation (Heuristic #10):**
    * Contextual field hints next to every advanced flag (`-timeout`, `-workers`, `-nmap`).

---

### 1.2 Additional Ergonomic & Psychological Laws
* **Fitts’s Law:** All interactive targets (primary run button, inputs, chips, tabs) meet or exceed the 44px touch/click target threshold with generous padding.
* **Hick’s Law:** Minimizes initial decision latency by presenting a single primary input and prominent call-to-action, keeping complex flags tucked inside progressive disclosure.
* **Miller’s Law & Chunking:** Data is organized into 3 logical visual chunks: **Target Launchpad** ➔ **Live Step Tracker** ➔ **Results Deck (KPIs + Donut Ratios + Findings)**.
* **WCAG 2.1 AA Contrast Compliance:** Text-to-background contrast ratio exceeds 7:1 for white text on `#060709` canvas. Badges use color + symbol + text (e.g. `▲ HIGH`, `◆ MEDIUM`, `● LOW`) to ensure color-blind accessibility.

---

## 2. Color Palette & Dual-Theme Tokens

Nuqs incorporates a fully accessible dual-theme system (Inky Dark + Slate Light) meeting WCAG 2.1 AAA accessibility contrast standards across all components:

### 2.1 Inky Dark Mode Tokens (Specimen Aesthetic)
```
CANVAS & SURFACES
├── Base Canvas (Inky Black): #060709 (Pure void pitch black)
├── Header Bar (56px):        #0a0c10 (Dark violet-black bar)
├── Header Border:            #181b22
├── Surface / Cards:          #0e1117 (Elevated dark card)
├── Card Border:              #1c212c (1px hairline border)
├── Sunken Drawer Panel:      #090b0f (Inner options field)
└── Text Input Background:    #060709 (Border: #242b38 | Focus: #00F59B)

TEXT HIERARCHY
├── Primary Text:             #FFFFFF (Stark white, 18.2:1 contrast)
├── Secondary Text:           #8b92a4 (Cool slate gray, 7.1:1 contrast)
├── Dim / Footnote Text:      #555b6a (Muted slate, 4.5:1 contrast)
└── Code / Evidence:          #FFFFFF (High-contrast monospace)

ACCENT TOKENS
├── Electric Spring Mint:     #00F59B | Dim: rgba(0, 245, 155, 0.12) | Glow: rgba(0, 245, 155, 0.25)
├── Specimen Coral Red:       #FF5A6A | Dim: rgba(255, 90, 106, 0.14) (High severity, stop actions)
├── Specimen Warm Amber:      #FBBF24 | Dim: rgba(251, 191, 36, 0.14) (Medium severity, actions)
└── Specimen Steel Cyan:      #38BDF8 | Dim: rgba(56, 189, 248, 0.14) (Low severity, endpoints)

SEVERITY BADGES (COLOR + ICON + TEXT)
├── HIGH:                     Background: #270f14 | Border: #4d1c25 | Text: #FF6B7A (▲ HIGH)
├── MEDIUM:                   Background: #271c0c | Border: #4a3416 | Text: #FCD34D (◆ MEDIUM)
└── LOW:                      Background: #0d1e28 | Border: #18384b | Text: #7dd3fc (● LOW)
```

### 2.2 Slate Light Mode Tokens (HCI Eye-Strain Prevention)
```
CANVAS & SURFACES
├── Base Canvas (Slate White): #f6f8fb (Prevents ocular glare / photophobia)
├── Header Bar (56px):         #ffffff (Clean elevated bar)
├── Header Border:             #e2e8f0 (Hairline divider)
├── Surface / Cards:           #ffffff (Pure white elevated card)
├── Card Border:               #e2e8f0 (Hairline card border)
├── Sunken Drawer Panel:       #f1f5f9 (Subtle recess)
└── Text Input Background:     #ffffff (Border: #cbd5e1 | Focus: #059669)

TEXT HIERARCHY (WCAG 2.1 AAA COMPLIANT)
├── Primary Text:              #0f172a (Deep slate, 14.8:1 contrast on white)
├── Secondary Text:            #475569 (Medium slate, 7.2:1 contrast on white)
├── Dim / Footnote Text:       #64748b (Muted slate, 4.8:1 contrast on white)
└── Code / Evidence:           #0f172a (Monospace slate on #f8fafc)

ACCENT TOKENS (LIGHT ADAPTED)
├── Deep Emerald Mint:         #059669 | Hover: #047857 | Dim: rgba(5, 150, 105, 0.12)
├── Vibrant Crimson:           #dc2626 | Dim: rgba(220, 38, 38, 0.12) (Stop actions)
├── Deep Amber:                #d97706 | Dim: rgba(217, 119, 6, 0.12) (Medium alerts)
└── Deep Sky Cyan:             #0284c7 | Dim: rgba(2, 132, 199, 0.12) (Endpoints)

SEVERITY BADGES (LIGHT MODE)
├── HIGH:                      Background: #fef2f2 | Border: #fecaca | Text: #991b1b (▲ HIGH)
├── MEDIUM:                    Background: #fffbeb | Border: #fde68a | Text: #92400e (◆ MEDIUM)
└── LOW:                       Background: #f0f9ff | Border: #bae6fd | Text: #075985 (● LOW)
```

---

## 3. Screen Structure & Navigation (Strict 1:1 CLI Parity)

The interface features **2 dedicated navigation views** corresponding directly to the two Nuqs CLI commands:
```
[Scan] (nuqs scan)    [Checks] (nuqs checks)
```

### 3.1 VIEW 1: SCAN (`nuqs scan [flags] <target>...`)
1. **Target Launchpad:**
   * Target input with monospace prompt (`> 127.0.0.1`).
   * Quick port preset chips (`Redis 6379`, `Web 80,443`, `Top 1000`).
   * Flag switches (`-Pn`, `--force`).
   * Progressive disclosure drawer for engine flags (`-timeout`, `-workers`, `-nmap`).
   * Primary action: `Run scan ↵` (44px Fitts's law, swaps with `■ Stop scan` during active audits).
2. **Live Step Progress Tracker (Nielsen Heuristic #1):**
   * Mirrors the 4 real CLI events emitted to `stderr`:
     1. `Finding hosts and open ports with Nmap...`
     2. `Found X host(s).`
     3. `Running Y check(s)...`
     4. `Done at HH:MM:SS.`
   * Includes real-time elapsed timer (`ELAPSED: 0.8s`).
3. **Summary KPI Bar (4 Columns):**
   * `Targets` | `Duration` | `Hosts Up` | `Open Services` (reflecting CLI text output header).
4. **Dual Output View Switcher (`output.Text` vs `output.JSON`):**
   * **Report Table View (`output.Text`):**
     * Verified Findings Card: Severity badge with symbol (`▲ HIGH`), title, target endpoint (`127.0.0.1:6379/tcp`).
     * Verbatim Evidence Block: `Evidence: sent PING without a password and got +PONG`.
     * Actionable Fix Directive: `Fix: Set requirepass in redis.conf, or bind Redis to localhost only.` with inline `Copy Fix` feedback.
     * Clean State (when findings count = 0): `No findings.`
     * Diagnostic Errors Callout: `Checks that could not finish (<n>): <check> on <host>:<port>: <err>`.
   * **Raw JSON View (`output.JSON`):**
     * Complete JSON object identical to `nuqs scan -json` output, with copy and download actions.

### 3.2 VIEW 2: CHECKS (`nuqs checks`)
* Exact output of running `nuqs checks`, listing all checks currently registered in package `checks`:
  1. `ftp-anonymous-login`   | `◆ MEDIUM` | FTP server allows anonymous login
  2. `http-security-headers` | `● LOW`    | Web server is missing security headers
  3. `redis-no-auth`         | `▲ HIGH`   | Redis server has no password
  4. `telnet-open`           | `◆ MEDIUM` | Unencrypted Telnet server

---

## 4. How to Run Nuqs Web

### Option A: Open Directly in Browser
```powershell
Start-Process .\designs\index.html
```

### Option B: Run via Development Server
```powershell
go run .\designs\server.go
```
Visit: **`http://127.0.0.1:9002`**
