# Nuqs local UI prototype

Run `go run ./designs/server.go` from the repository root and open
`http://127.0.0.1:9002`. Install Nmap first. The server resolves Nmap at startup
from PATH or from `NUQS_NMAP_PATH`. Set `PORT` to choose another loopback port.

The prototype uses the existing Go scanner and a same-origin JSON POST with a
streamed report. Allowed targets are localhost and IPv4 loopback addresses or
ranges. The address limit applies unless explicitly overridden within that scope.
The default scan uses host discovery and the top 1000 ports.

The browser stores the last report, including evidence, in local storage on this
origin. Clearing site data removes it. The page uses local assets and system fonts.
The production UI architecture is described in [the web UI plan](../docs/ui/building.md).
