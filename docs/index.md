# Nuqs

Nuqs is a non-overengineered, open-source vulnerability assessment tool. It uses Nmap to find hosts and open ports, then runs small checks on each service to find real problems.

It is designed to be simple to use, feature-rich and reliable. Every finding includes the evidence behind it.

## What it does today

- Finds hosts and open services with Nmap
- Runs 9 checks: open Telnet, missing web security headers, anonymous FTP login, Redis and MongoDB with no password, SSH login with no password, SSH password login, weak SSH algorithms, old TLS versions
- Shows every finding with **evidence** (what we actually saw) and a **fix**
- Prints a readable report or JSON

It's small on purpose. This is the core, and everything else gets built on top of it. See the [roadmap](roadmap.md) for what's coming.

## Quick start

```bash
go build -o nuqs ./cmd/nuqs
./nuqs scan 192.168.1.1
```

More in [Getting started](getting-started.md).

## Where to go next

| I want to... | Read |
|---|---|
| Run a scan | [Getting started](getting-started.md) |
| Understand the code | [How it works](how-it-works.md) and [Architecture](architecture.md) |
| Add a new check | [Writing a check](writing-a-check.md) |
| Run or write tests | [Testing](testing.md) |
| See the plan | [Roadmap](roadmap.md) and [What's done](progress.md) |
| Know why we made a choice | [Decisions](design/decisions.md) |

Our research on how Nessus works lives in a separate repo, [nessus-dissection](https://github.com/PremadeS/nessus-dissection).
