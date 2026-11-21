# Scan workspace prototype

The local prototype in `designs/` explores the scan form, checks catalog and report
before the production implementation in [the web UI plan](docs/ui/building.md).

Start with the target field. Keep less common settings under Scan options. Use a
single action color in both themes and reserve severity colors for report data.
Use real engine progress and report timestamps so fast scans can finish immediately.
Show the target and finish time with every report, including after a refresh.
Present severity counts first, followed by findings with their endpoint, evidence
and fix. Show check errors even when there are no findings.
