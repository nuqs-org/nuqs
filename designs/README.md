# Nuqs UI/UX Workbench & Live Web Interface

This directory holds the interface designs, visual specifications, and the live Go web server for **Nuqs Web**.

## Structure
- `index.html`: **The Primary Interactive Workbench**. A high-legibility, HCI-compliant security audit interface featuring both **Inky Dark** (`#060709`) and **Slate Light** (`#f6f8fb`) themes. It connects directly to the live Go engine over Server-Sent Events (SSE) or runs standalone in offline mode.
- `server.go`: **Lightweight, Zero-Dependency Go Web Server**. Serves the interface on port `9002` and connects browser actions directly to the real Go `engine.Engine` and Nmap runner.
- `../DESIGN.md`: The complete HCI design system specification, WCAG 2.1 AAA contrast metrics, and typography rationale.

## Quick Start (Run Live UI)

```powershell
go run .\designs\server.go
```
Visit **`http://127.0.0.1:9002`** in your browser.

## Built-in API Endpoints
- `POST /api/scan`: Runs real-time vulnerability scans against targets with Nmap discovery, streaming the 4 discrete engine events over SSE and returning the final `engine.Report` JSON.
- `GET /api/checks`: Returns the catalog of registered security checks currently registered in `package checks`.
- `GET /api/status`: Returns engine status, uptime, runner details, and loaded check IDs.
