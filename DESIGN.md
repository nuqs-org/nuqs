<!-- Design notes for the embedded Nuqs web UI served by nuqs serve. -->
# Scan workspace UI

The embedded web UI in `internal/web/` (backed by `internal/api/` and `internal/tools/`)
implements the scan console, check library and report workspace described in
[the web UI plan](docs/ui/building.md), served directly from the `nuqs` binary via `nuqs serve`.

Start with scan presets (Quick scan, Full scan, Custom) and the target field.
Provide a port preset selector (Top 1000, Top 100, common web ports, all 65,535,
or custom) and write scan options in plain English with timeout and concurrency
tucked under Advanced. Guide first-time users with an actionable empty state to
try scanning their local host in one click, and translate raw engine or Nmap
errors into plain, actionable instructions. Use a clean monochrome glass palette
in both themes, reserving semantic colors for severity badges and engine
readiness. Label every severity level explicitly.
Use real engine progress and report timestamps so fast scans clearly show
scanning then finished in seconds. Show the target, live host/service counts
and finish time with every report, including after a refresh. Present severity
counts first, followed by findings sorted worst-first with their endpoint,
evidence and fix. Show check errors even when there are no findings.

The persistent workspace navigation connects the scan console, htmx-filtered check
library and latest report. The scan profile reflects current form values and the
registered-check inventory comes from the engine via Go `html/template`. On narrow
screens navigation starts as an icon rail and the profile sits below scan configuration.

A plain canvas supports glass panels with a lightly tinted rim. The full-height
monochrome navigation rail holds an editable local profile at its foot and collapses
to icons. Appearance follows the system setting until the user selects light or dark
mode in the workspace header. Display headings use Avenir Next with sans-serif
fallbacks. Body text uses the system sans serif with zero external fonts. Increased
contrast and reduced transparency use solid panels.

New scan anchors the console. Align the target field, circular submit control
and options disclosure on a shared centerline. Show the busy label and ring
only during a request. Reduced-motion mode keeps the indicator stationary.

While a scan runs, the launch panel shows its target, engine phase, elapsed time
and Stop action. The circular control reads RUN. Its adjacent feedback shows completed
and total checks when available. Only phase changes enter the live region. Completion
opens and focuses the report if the scan page is visible. Someone browsing the check
library stays there. On phones, the expanded rail overlays the workspace.
