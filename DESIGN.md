<!-- Design notes for the embedded Nuqs web UI served by nuqs serve. -->
# Scan workspace UI

The embedded web UI in `internal/web/` (backed by `internal/api/` and `internal/tools/`)
implements the scans list, new scan flow, results and check library described in
[the web UI plan](docs/ui/building.md), served directly from the `nuqs` binary via `nuqs serve`.

The pages follow the usual scanner flow, in our own look and words. Every page has
its own URL, so back, refresh and links all work:

- **Scans** (home): every scan with its type, status, real duration and findings.
- **New scan**: scan type cards grouped into Discovery and Vulnerabilities, then a
  settings page with Basic, Discovery and Advanced sections on the left, like System
  Settings. Changing a setting keeps the type and adds a "modified" tag. The target
  field counts addresses and flags mistakes while typing, and asks first when the
  target is over 1,024 addresses.
- **Scan results**: Hosts and Vulnerabilities tabs, a Scan details panel with a
  severity ring, and checks that couldn't finish kept apart from findings. While it
  runs, the page shows live progress over Server-Sent Events and reloads when done.
  Stop keeps what was found so far.
- **Host** and **Vulnerability** pages, each with what we saw and how to fix it.
- **Check library**, searchable with htmx.

Scans run on the server in the background, one at a time, so closing the tab
doesn't stop them. The server remembers the last 50 until there's a proper store.
The browser keeps no copy of any report.

A quiet, Mac-style workspace: a translucent sidebar like Finder that folds down to
icons, a toolbar with the page path and the page's buttons, and cards on a plain
canvas. The sidebar holds an editable local profile at its foot. Appearance follows
the system setting until the user picks light or dark in the toolbar. System fonts
only, nothing to download. Severity colours are used only for severity, and
reduced-motion turns off the spinner and pulse.
