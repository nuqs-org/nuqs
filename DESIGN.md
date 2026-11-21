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

The web treatment of Liquid Glass uses floating navigation, translucent surfaces
and a local CSS wallpaper. Text-heavy report surfaces remain opaque. Browsers
without backdrop filtering receive a solid navigation surface. Increased contrast
and reduced transparency preferences also remove the wallpaper ribbons and blur.

New scan anchors the console. Align the target field, circular submit control
and options disclosure on a shared centerline. Show the busy label and ring
only during a request. Reduced-motion mode keeps the indicator stationary.

While a scan runs, the launch panel shows its target, engine phase, elapsed time
and Stop action. The circular control displays completed and total checks when
available. Only phase changes enter the live region. Completion opens and focuses
the report if the scan page is visible. Someone browsing the check library stays
there. On phones, engine status sits beside the brand above one navigation row.
