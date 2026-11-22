# Getting started

## What you need

- **Go 1.24** or newer
- **Nmap**, installed and on your PATH (`brew install nmap` or `sudo apt install nmap`)

## Build

```bash
git clone https://github.com/nuqs-org/nuqs.git
cd nuqs
go build -o nuqs ./cmd/nuqs
./nuqs version
```

## Run a scan

```bash
./nuqs scan 192.168.1.1
```

You can give one or more targets:

| Target | Example |
|---|---|
| One IP | `192.168.1.1` |
| A network | `192.168.1.0/24` |
| A range (last part only) | `192.168.1.10-20` |
| A hostname | `router.lan` |

!!! warning "Only scan what you own"
    Scanning other people's networks without permission is illegal in most places.

## Useful flags

Flags can go before or after the targets.

| Flag | What it does |
|---|---|
| `-p 22,80,443` | Scan only these ports (default is Nmap's top 1000) |
| `-Pn` | Scan hosts even if they don't answer ping |
| `--json` | Print the report as JSON instead of text |
| `--workers 10` | How many checks run at the same time |
| `--timeout 30s` | Max time for one check |
| `--force` | Allow scanning more than 1024 addresses |
| `--nmap /path/to/nmap` | Use a specific Nmap binary |

## Reading the output

Progress goes to stderr and the report goes to stdout, so `./nuqs scan --json 10.0.0.1 > report.json` gives you a clean JSON file.

Every finding has:

- **Severity**, from info to critical
- **Evidence**, what we actually saw, so you can check it yourself
- **Fix**, what to do about it

If a check couldn't finish (timeout, connection reset and so on), it's listed under "Checks that could not finish". That's not a finding, it just means we couldn't tell.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan finished (with or without findings) |
| 1 | Scan couldn't run, or was stopped |
| 2 | The command was typed wrong |

## Web UI

```bash
./nuqs serve
```

Then open http://127.0.0.1:9002. Pick **New scan**, choose a scan type, enter a target and press **Launch**. Results show by host and by vulnerability, and you can follow a running scan live.

- It only listens on this computer, because it has no login yet.
- By default it only scans this computer (`127.0.0.0/8`). To scan your network too, start it with `./nuqs serve --allow 192.168.1.0/24`.
- One scan runs at a time. The last 50 are kept until you stop the server.

## Other commands

```bash
./nuqs checks    # list the built-in checks
./nuqs version   # print the version
```
