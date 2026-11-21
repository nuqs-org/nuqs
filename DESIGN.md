# Scan workspace prototype

The local prototype in `designs/` explores the scan form, checks catalog and report
before the production implementation in [the web UI plan](docs/ui/building.md).

Start with the target field. Keep less common settings under Scan options. Use a
single action color in both themes and reserve severity colors for report data.
Use real engine progress and report timestamps so fast scans can finish immediately.
Show the target and finish time with every report, including after a refresh.
Present severity counts first, followed by findings with their endpoint, evidence
and fix. Show check errors even when there are no findings.

The persistent workspace navigation connects the scan console, searchable check
library and latest report. The scan profile reflects current form values and the
registered-check inventory comes from the engine. On narrow screens navigation
moves above the workspace and the profile sits below scan configuration.
