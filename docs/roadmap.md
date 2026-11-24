<!-- The 4-month plan, week by week, with what "done" means for each week. -->

# Roadmap (16 Nov 2026 to 16 Mar 2027)

Two parts:

- **FYP-I (16 Nov to 5 Dec):** a working app with complete documentation, shown at the presentation and open house in the first week of December.
- **FYP-II (7 Dec to 16 Mar):** the full product, complete, bug-free and scalable.

Each week is packed on purpose, we'd rather cut a stretch item than finish early.

Every week follows the same rules:

- Each task ships with its **tests** and **doc comments** in the same PR. No "tests later".
- **New checks every week** (see the quota below), each with fake-server tests and a lab test.
- CI must be green on the default branch at the end of every week.
- Friday: a 10 minute demo to each other of what works now.
- If a week slips, we cut the stretch items of that week first, we don't push the whole plan back.

Who owns what: **core and CLI** (engine, checks, storage, data), **API and UI** (`nuqs serve` and the web UI).

What's already done is in [What's done](progress.md).

---

## The order, at a glance

| Week | Dates | What we build |
|---|---|---|
| W1 | 16 to 22 Nov | Setup, test lab, version comparison, confidence, 5 checks, UI design |
| W2 | 23 to 29 Nov | Saving scans, history, diffs, first API and web UI, design docs |
| W3 | 30 Nov to 5 Dec | **FYP-I:** docs finished, hosted demo, poster, presentation and open house |
| W4 | 7 to 13 Dec | Host inventory and all vulnerability data feeds |
| W5 | 14 to 20 Dec | Advisory matching, retro-scan, fix-first, signed feed |
| W6 | 21 to 27 Dec | Full API, live progress, MCP server, full web UI |
| W7 | 28 Dec to 3 Jan | SSH logged-in scanning and the credential check |
| W8 | 4 to 10 Jan | YAML checks, CVE bot, Nuclei import, **mid-point demo** |
| W9 | 11 to 17 Jan | Defence model and verifier model |
| W10 | 18 to 24 Jan | Reports, scheduled scans and alerts |
| W11 | 25 to 31 Jan | Windows logged-in scanning and Windows checks |
| W12 | 1 to 7 Feb | Distributed scan workers and multiple users |
| W13 | 8 to 14 Feb | Speed: big networks, smart scheduling, benchmark against Nessus |
| W14 | 15 to 21 Feb | Packaging: releases, Docker, Homebrew, installer |
| W15 | 22 to 28 Feb | Security review of Nuqs itself |
| W16 | 1 to 7 Mar | Real users, fixes from their feedback, FYP-II docs |
| W17 | 8 to 14 Mar | Freeze, v1.0, demo |
| Buffer | 15 to 16 Mar | Final submission |

## Checks quota

At least **5 new checks every week** from W1 to W14 (except W3, the FYP-I week), so we end with **65+ built-in checks**, plus everything from advisory data (W5), Nuclei templates (W8) and the CVE bot (W8). Ideas, roughly in order:

| Area | Checks |
|---|---|
| Remote access | SSH password login, SSH weak algorithms, SSH old version, Telnet, RDP without NLA, VNC without password |
| Databases | Redis, MongoDB, Elasticsearch, Memcached, CouchDB with no login, MySQL and Postgres default logins |
| Web | missing headers, directory listing, default pages, exposed `.git`, exposed `.env`, admin panels, old TLS, weak ciphers, expired or self-signed certificates |
| Network services | anonymous FTP, open DNS resolver, SNMP with "public", NTP monlist, SMB signing off, SMBv1 on, open NFS shares |
| Containers and cloud | Docker API exposed, Kubernetes API anonymous, etcd open, cloud metadata reachable |
| Devices | UPnP exposed, default router logins (safe list only), printers with open admin |

---

## What FYP-I needs (5 Dec)

What the FYP committee asked for, and where each part lives.

| Requirement | Where |
|---|---|
| Complete in functionality (not yet product-ready) | the demo: scan, findings, fix, rescan, diff, all from the browser |
| Background | `docs/report/background.md` |
| Survey of the 5 most relevant projects | `docs/report/survey.md`: Nessus, OpenVAS (Greenbone), Nuclei, Vuls, Rapid7 InsightVM |
| Scope | `docs/report/scope.md` |
| Functional specifications | `docs/report/functional-spec.md` |
| Architecture | [Architecture](architecture.md) (generated) plus `docs/how-it-works.md` |
| UI design | `docs/report/ui-design.md` with wireframes and screenshots |
| High-level design | `docs/report/high-level-design.md` |
| Detail design, with the pipeline | `docs/report/detailed-design.md` |
| Test cases (AI drafts are fine, we review and finalize them by hand) | `docs/report/test-cases.md` |
| Repo owned by the project email, with collaborators | `fyp26_nuqs@gmail.com` owns `nuqs-org`. Collaborators: the team, the advisor, `undergradoffice.fos@itu.edu.pk` |
| Industry-standard repo layout | Go's standard layout: `cmd/` (binaries), `internal/` and `checks/` (source), `docs/`. Written down in [Decisions](design/decisions.md). |
| Hosted on the cloud | demo server on Azure, docs on GitHub Pages |
| The Missing Semester, applied and shown | `docs/report/missing-semester.md`: where each lecture shows up in Nuqs |

The docs site exports to one PDF for submission.

---

## FYP-I: a working app with complete docs

### W1 (16 to 22 Nov): setup, test lab, version comparison, 5 checks

**Goal:** everyone ships code, we can test against real vulnerable software, and the first docs are written.

- [x] Repo on `nuqs-org/nuqs`, license added (Apache 2.0)
- [ ] GitHub Pages on (Settings, Pages, Source: GitHub Actions), default branch protected
- [ ] Project email `fyp26_nuqs@gmail.com` made, its GitHub account owns `nuqs-org`, advisor and `undergradoffice.fos@itu.edu.pk` added as collaborators
- [ ] Every teammate builds Nuqs, scans their own router, and merges one PR
- [x] **Test lab:** `lab/docker-compose.yml` with real services: vsftpd with anonymous login, a Telnet server, nginx without headers, an old OpenSSH, a TLS 1.0 server, Redis and MongoDB with no login
- [x] Lab CI job: scan the lab, the result must match a saved expected report exactly
- [x] `internal/version`: compare versions like each ecosystem does (semver, Debian, RPM, OpenSSH style `9.6p1`)
- [x] `confidence` on every finding: `confirmed` (we proved it) or `inferred` (from the version)
- [x] 5 checks: `tls-deprecated-protocols`, `ssh-password-auth`, `ssh-weak-algorithms`, `redis-no-auth`, `mongodb-no-auth`
- [ ] **API and UI:** wireframes for every page (new scan, live scan, results, finding detail, history, diff)
- [ ] **Docs:** background, survey, scope
- [ ] Everyone starts [The Missing Semester](https://missing.csail.mit.edu/) (finish by 3 Dec)

**Tests:** fake-server tests for each check, lab test for each check, big table tests and a fuzz test for version comparison (it must be consistent: if a < b then b > a).
**Done when:** the lab scan finds exactly the expected problems in CI, everyone has merged a PR, and the wireframes are agreed.

### W2 (23 to 29 Nov): saving scans, history, diffs, first API and web UI

**Goal:** scans are saved, every scan shows what changed, and it all works from the browser.

- [x] SQLite with `modernc.org/sqlite` (pure Go, our first dependency, reason written in [Decisions](design/decisions.md))
- [x] `internal/store`: scan runs, hosts, services, findings, check errors, simple numbered migrations
- [x] Every scan is saved (`--no-save` to skip), `nuqs history`, `nuqs show <run>`
- [x] Compare runs with stable finding IDs: **new**, **fixed**, **still open**, plus `first_seen` and `last_seen`
- [x] `nuqs diff <old> <new>`, and a short "since last scan" summary after every scan
- [ ] `--fail-on high` exits with code 3 when there's a finding at or above that level
- [ ] **First API:** `nuqs serve` with start a scan, scan status, history, results, diff, a login token, and **allowed targets** (it refuses to scan anything else)
- [ ] **First web UI** on top of it, embedded in the binary: new scan, results, finding detail (evidence, confidence, fix), history, diff
- [ ] 5 checks: `openssh-vulnerable-version`, `elasticsearch-no-auth`, `memcached-exposed`, `http-directory-listing`, `tls-certificate-problems` (expired, self-signed, wrong name)
- [ ] **Docs:** functional specs, high-level design, detail design with the scan pipeline, UI design
- [ ] Stretch: known CVEs for the lab's old OpenSSH, as a preview of W5

**Tests:** store tests on a temp database, migrations from empty, save and load must give the same report, diff cases (no change, all fixed, all new, mixed, host gone), exit code tests, every endpoint with `httptest` (good input, bad input, no token, target not allowed).
**Done when:** fixing a problem in the lab and scanning again from the browser shows it as "fixed".

### W3 (30 Nov to 5 Dec): FYP-I presentation and open house

**Goal:** a polished demo, complete docs, nothing new.

- [ ] Feature freeze on Tuesday 1 Dec, only fixes after that
- [ ] **Hosted demo:** `nuqs serve` and the lab on an Azure VM (student credit), login on, allowed targets set to the lab only
- [ ] **Docs:** test cases written and reviewed by hand, every page proofread, exported to one PDF
- [ ] Repo layout decision written down, README and docs screenshots updated
- [ ] **Missing Semester page:** shell scripts, Git workflow (branches, PRs, protected `master`), a `Makefile` for build, test, lint and docs, CI, profiling with `pprof`, `jq` on the JSON output, checksums
- [ ] Open house poster
- [ ] Demo script, rehearsed three times
- [ ] Tag `v0.1.0`

**Done when:** the hosted demo runs scan, fix, rescan and diff three times in a row, and the PDF has every section in the table above.

---

## FYP-II: the full product

### W4 (7 to 13 Dec): host inventory and all vulnerability data feeds

**Goal:** a clean list of what runs where, and a local copy of all the vulnerability data we need.

- [ ] Inventory from Nmap's CPEs and versions, saved with each scan
- [ ] **Product mapping table** (YAML) from Nmap names to the names used in vulnerability data
- [ ] `nuqs update` downloads and stores: **OSV** (Debian, Ubuntu, Alpine, Red Hat and more), **CISA KEV**, **EPSS**, and the official **CVE list** (cvelistV5)
- [ ] Only download what changed, keep the last good copy if a download fails or is corrupt
- [ ] `nuqs update --status` shows how fresh each source is
- [ ] Retention setting: keep the last N runs per target
- [ ] 5 checks: `dns-open-resolver`, `snmp-default-community`, `ntp-monlist`, `http-exposed-git`, `http-exposed-env`

**Tests:** mapping tests on real Nmap XML from the lab, import tests for every feed on small saved samples (no network in tests), a corrupt download must never damage the existing data.
**Done when:** every lab service has the right product and version, and `nuqs update` works both online and from saved files.

### W5 (14 to 20 Dec): advisory matching, retro-scan, fix-first, signed feed

**Goal:** our headline features work end to end.

- [ ] Match inventory against advisory data with `internal/version`, findings marked `inferred` with a link to the advisory
- [ ] **Retro-scan:** `nuqs rematch` re-checks saved inventories with no network scan, and `nuqs update` runs it automatically. Findings show "affected since <time>".
- [ ] **Fix-first:** group findings by fix, like "Upgrade OpenSSH to 9.8, fixes 6 findings on 3 hosts", in the text and JSON output (`--by-fix`)
- [ ] Rank findings by real risk: KEV first, then EPSS, then severity
- [ ] **Signed content feed** built by CI (checks data, mapping table, advisory snapshot), checked by `nuqs update` before use
- [ ] 5 checks: `docker-api-exposed`, `kubernetes-api-anonymous`, `etcd-exposed`, `couchdb-no-auth`, `vnc-no-auth`

**Tests:** matching cases (in range, out of range, fixed exactly at the version, distro backports), a rematch test that finds a new advisory with no network, grouping tests, signature tests (one changed byte or a wrong key must be refused).
**Done when:** adding a fake advisory for the lab's OpenSSH and running `nuqs update` flags it within seconds, grouped under its fix.

### W6 (21 to 27 Dec): full API, live progress, MCP server, full web UI

**Goal:** everything the CLI does is available to the UI, other tools and AI assistants, and the UI is complete.

- [ ] `internal/tools`: one set of safe actions (list checks, scan, get findings, get evidence, diff, update). API, MCP and the verifier all use these.
- [ ] The rest of the API: checks, update status, and live progress with Server-Sent Events from the engine's events
- [ ] OpenAPI file, checked in CI against the real routes
- [ ] `nuqs mcp`: MCP server with the official Go MCP SDK (second dependency, reason written down). AI scans outside the allowed targets are always refused.
- [ ] UI: live scan page, **fix-first view** as the main results screen, **"since last scan"** view
- [ ] **Beginner mode:** one "Scan my network" button that finds the local network by itself
- [ ] Plain-language explanation for every check, and a dark mode
- [ ] 5 checks: `rdp-no-nla`, `smb-signing-disabled`, `smbv1-enabled`, `http-default-pages`, `tls-weak-ciphers`

**Tests:** live progress end to end with a fake scanner, MCP tested with a test client including "scanning outside the allowed targets is always refused", Playwright browser tests in CI: start a scan against the lab, watch it live, see findings, compare two scans.
**Done when:** a teammate who never saw the UI scans the lab and finds the top fix without help, and Claude Desktop can scan the lab through `nuqs mcp`.

### W7 (28 Dec to 3 Jan): SSH logged-in scanning and the credential check

**Goal:** see installed packages, which is where most real findings come from.

- [ ] **Credential check:** test SSH logins before scanning and say exactly what's wrong (wrong key, needs sudo, locked out, host unreachable)
- [ ] With SSH, collect installed packages (dpkg, rpm, apk) and the OS version into the inventory
- [ ] Advisory matching now covers installed packages, with distro backports handled
- [ ] Credentials stored encrypted, never in logs, reports or API responses
- [ ] Credential setup in the UI with a "Test" button
- [ ] 5 checks (logged in): `ssh-root-login-allowed`, `linux-unattended-upgrades-off`, `linux-world-writable-files`, `linux-firewall-off`, `sudo-nopasswd-all`

**Tests:** SSH server in the lab with known old packages, credential check against good and bad logins, a test that searches every output (logs, JSON, API, UI) and fails if a secret appears anywhere.
**Done when:** a logged-in scan of the lab Debian box shows its outdated packages grouped by fix.

### W8 (4 to 10 Jan): YAML checks, CVE bot, Nuclei import, mid-point demo

**Goal:** checks without Go code, new checks suggested automatically, and a strong demo.

- [ ] Simple YAML check format (banner match, HTTP request and response match, version range). Only safe, read-only actions are allowed.
- [ ] **Nuclei import:** convert safe Nuclei templates (MIT) into our YAML format, refuse anything that isn't read-only
- [ ] **CVE bot:** scheduled GitHub Action that watches the CVE list and CISA KEV, filters to what we can detect over the network, and opens a PR with a draft YAML check, its tests and how to verify it. A human always merges.
- [ ] **Mid-point demo** to supervisors: lab scan, fix, rescan and diff, retro-scan from new data, web UI, logged-in scan, MCP
- [ ] 5 checks as YAML (proves the format works)

**Tests:** YAML loader tests (good, bad, unsafe rejected), Nuclei conversion tests on real templates (safe ones convert, unsafe ones are refused), the bot tested on saved CVE samples with no internet.
**Done when:** the bot opens a real PR for a real recent CVE, and the demo runs end to end twice in a row.

### W9 (11 to 17 Jan): defence model and verifier model

**Goal:** exact fix steps for every host, and one-click proof that a finding is real.

- [ ] Model setup: local Ollama by default, or any OpenAI-compatible endpoint from the config. Nuqs works fully without a model.
- [ ] **Defence model:** "How do I fix this?" gives exact steps for that host from the evidence, OS, version and our fix data. Marked as AI-written, never run by Nuqs.
- [ ] **Verifier model:** "Verify" lets the AI plan extra checks with only the safe tools from W6 (version from a second source, package list over SSH, a config value, a harmless test of the vulnerable behaviour)
- [ ] **The AI is never the proof.** A finding becomes "confirmed" only when a tool returns hard evidence. Every step is saved and shown.
- [ ] Limits: only on a click, one host and port, read-only, step and time limits, allowed targets
- [ ] Both available in the UI, the API and MCP
- [ ] 5 checks

**Tests:** both models tested with a fake model. The defence model gets the right facts and its output is labelled and never run. The fake verifier tries to break every rule (other hosts, unknown tools, past the step limit, "confirming" with no evidence) and must fail every time.
**Done when:** verifying the lab's old OpenSSH turns it "confirmed" with the proof shown, and a fake finding stays "inferred" with the reason.

---

## Month 3: going wide

### W10 (18 to 24 Jan): reports, scheduled scans and alerts

**Goal:** Nuqs runs by itself and tells people what matters.

- [ ] Reports: HTML (fix-first, with evidence), PDF (from the HTML), CSV, SARIF for CI tools
- [ ] Two report styles: **summary** for managers (top fixes, trend) and **technical** (everything)
- [ ] **Scheduled scans** (daily, weekly, custom), set from the CLI, the API and the UI
- [ ] **Alerts** by email and webhook (Slack and Teams work through webhooks) for: new critical finding, newly exploited CVE that affects you (from retro-scan), scan failed
- [ ] GitHub Action: `nuqs-org/nuqs-action` to scan in CI and upload SARIF
- [ ] 5 checks

**Tests:** report output tests (valid HTML, SARIF matches its schema, CSV opens right), schedule tests with a fake clock, alert tests with a fake mail server and a fake webhook.
**Done when:** a weekly scheduled scan of the lab sends a webhook alert when we add a new problem.

### W11 (25 to 31 Jan): Windows logged-in scanning and Windows checks

**Goal:** Windows machines get the same depth as Linux.

- [ ] Windows credentials over **WinRM**, in the credential check too
- [ ] Collect installed software, installed updates (KBs) and Windows version into the inventory
- [ ] Match against Microsoft advisories (MSRC data as a new feed)
- [ ] Windows lab machine (a Windows Server evaluation VM in the lab notes, not in CI if licensing doesn't allow it)
- [ ] 5 Windows checks: `windows-missing-updates`, `windows-smbv1`, `windows-firewall-off`, `windows-defender-off`, `windows-local-admin-password-reuse` (safe check only)

**Tests:** WinRM tested against a fake WinRM server with recorded responses, MSRC import on saved samples, matching tests for KB-based fixes.
**Done when:** a logged-in scan of a Windows VM shows missing updates grouped by KB.

### W12 (1 to 7 Feb): distributed scan workers and multiple users

**Goal:** scan big or separate networks from one place, with a team.

- [ ] `nuqs worker` runs on another machine and takes scan jobs from the main server
- [ ] Workers connect over HTTPS with a join token, jobs are assigned by network ("this worker scans 10.20.0.0/16")
- [ ] A worker going offline mid-scan doesn't lose the scan, the job goes to another worker or waits
- [ ] **Multiple users** with simple roles: admin, scanner (can run scans), viewer (read only)
- [ ] Audit log: who scanned what, when
- [ ] 5 checks

**Tests:** worker tests with several local workers, killing a worker mid-scan, role tests for every API endpoint (each role can do exactly what it should and nothing else), audit log tests.
**Done when:** two workers scan two lab networks into one result, and a viewer can see but not start scans.

### W13 (8 to 14 Feb): speed, smart scheduling, benchmark against Nessus

**Goal:** prove we're faster and at least as accurate, with numbers.

- [ ] Big networks: scan a /16 in the lab setup without running out of memory, results stream to the database as they come
- [ ] **Slow checks first:** per-check time budgets learned from past scans, so nothing drags at the end
- [ ] Honest progress: phase, running checks, ETA, and a "stop and keep what we have" button
- [ ] Nmap tuning per network size (timing, host groups, parallelism)
- [ ] **Benchmark:** same lab with Nessus Essentials and Nuqs. Time, findings, false positives (before and after verifying), missed findings. One script reproduces it.
- [ ] Fix the slowest parts the benchmark finds
- [ ] 5 checks

**Tests:** load test with a fake scanner returning 50,000 hosts (memory stays flat), scheduler tests with fake check durations, a benchmark script that runs in CI on a small lab.
**Done when:** the benchmark table is in the thesis, and our "99%" never sits still.

---

## Month 4: shipping and proving it

### W14 (15 to 21 Feb): packaging and installing

**Goal:** anyone can install Nuqs in one command.

- [ ] Release builds for Linux, macOS and Windows with GoReleaser, signed, with checksums
- [ ] Docker image (Nmap included), `docker run` in the README
- [ ] Homebrew tap and a one-line install script
- [ ] First-run setup: creates the config, downloads the data feeds, prints the login token
- [ ] Optional: a desktop app that wraps the same web UI with Wails (no second UI to maintain)
- [ ] 5 checks

**Tests:** CI installs each package on a clean machine (Ubuntu, macOS, Windows) and runs a smoke scan, the Docker image scans the lab.
**Done when:** a new person installs Nuqs from the README and scans their network in under 5 minutes.

### W15 (22 to 28 Feb): security review of Nuqs itself

**Goal:** a security tool must be secure itself.

- [ ] Threat model written down (what an attacker could do with Nuqs or to Nuqs)
- [ ] Long fuzz runs (hours per target) on every parser, fix everything found
- [ ] `gosec` and dependency checks added to CI
- [ ] Review of the API (auth, rate limits, input checks), the MCP server and the verifier's limits
- [ ] Make sure scanned servers can't attack Nuqs (huge responses, slow responses, weird bytes), with tests
- [ ] Hosted docs: every page reviewed, screenshots updated

**Tests:** one test per item in the threat model.
**Done when:** the threat model has no open items marked high.

### W16 (1 to 7 Mar): real users, thesis results and FYP-II docs

**Goal:** prove it's easy and useful for people who aren't us.

- [ ] 5 to 10 real users (classmates, a teacher's lab, a small office with permission) install and use Nuqs with a short task list
- [ ] Record where they get stuck, fix the top 10 problems
- [ ] Final numbers for the thesis: speed, accuracy, false positives before and after verifying, checks count, test coverage
- [ ] Thesis chapters on design, testing and results
- [ ] **FYP-II docs:** every FYP-I section updated to the final product, plus implementation notes, notes on AI use in each part of the work, and AI automated testing results

**Done when:** every user finished the task list, and the top problems are fixed.

### W17 (8 to 14 Mar): freeze, v1.0, demo

**Goal:** nothing new, everything solid.

- [ ] Feature freeze on Monday, only fixes after that
- [ ] Release **v1.0**
- [ ] Final demo script, rehearsed three times
- [ ] Thesis finished and reviewed

**Done when:** v1.0 is out, the demo works three times in a row, the thesis is ready.

### Buffer (15 to 16 Mar)

Final submission. Anything that slipped gets cut, not rushed.

---

## Later (after the FYP)

- AI drafting checks for the CVE bot
- Agents installed on hosts (for laptops that are often offline)
- Cloud account checks (AWS, Azure, GCP settings)
- A plugin marketplace for community checks
