# Getting started

## What you need

- **Go 1.27** or newer
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
| `--no-save` | Don't save this scan to the history |

## Reading the output

Progress goes to stderr and the report goes to stdout, so `./nuqs scan --json 10.0.0.1 > report.json` gives you a clean JSON file.

Every finding has:

- **Severity**, from info to critical
- **Evidence**, what we actually saw, so you can check it yourself
- **Fix**, what to do about it

If a check couldn't finish (timeout, connection reset and so on), it's listed under "Checks that could not finish". That's not a finding, it just means we couldn't tell.

## History

Every scan is saved, from the CLI and from the web UI, so you can look at it again later.

```bash
./nuqs history        # the last 20 scans, newest first
./nuqs history -n 0   # all of them
./nuqs show 12        # print scan 12 again, add --json for JSON
```

## What changed

After every scan, Nuqs compares it with the last finished scan of the same targets and ports and prints one line:

```
Since scan 11 (2026-11-24 10:02): 1 new, 2 fixed, 5 still open. See what changed with: nuqs diff 12
```

```bash
./nuqs diff 12        # scan 12 against the last scan of the same targets and ports
./nuqs diff 9 12      # any two scans, older one first, add --json for JSON
```

Findings are matched by check, host and port. A finding only counts as **fixed** when the newer scan looked again and didn't find it, and it says why: the port is no longer open, or the check no longer finds it. If the host didn't answer or the check couldn't finish, it's listed as **not checked** instead. Scans that stopped early aren't used for the automatic comparison, because everything they missed would look fixed.

Scans are saved in one file, `nuqs.db`, in `~/Library/Application Support/nuqs` on macOS and `~/.config/nuqs` on Linux. Set `NUQS_DATA_DIR` to keep it somewhere else.

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

Then open http://127.0.0.1:9002. On the first start (when no accounts exist yet), `nuqs serve` prints a one-time setup code in the terminal—enter that code at `/setup` to create the initial **admin** account. After that, sign in normally, pick **New scan**, choose a scan type, enter a target and press **Launch**. Results show by host and by vulnerability, who started each scan, and you can follow a running scan live.

- **Team accounts & roles:** admins can open **Users** in the sidebar to add teammates (`admin` or `user`), change roles and issue one-time password reset codes. If someone is locked out, run `./nuqs user reset-password <username>` on the server machine to print a new one-time code.
- **Local only:** `nuqs serve` only listens on this computer (`127.0.0.1` / `localhost`).
- **Allowed scan targets:** by default it only scans this computer (`127.0.0.0/8`). To scan your network too, start it with `./nuqs serve --allow 192.168.1.0/24`.
- One scan runs at a time. Every scan and account is saved in `nuqs.db`, so they're still there after a restart, and the CLI and the web UI share the same history.

## Other commands

```bash
./nuqs user reset-password <username>   # issue a one-time password reset code
./nuqs checks                           # list the built-in checks
./nuqs version                          # print the version
```
