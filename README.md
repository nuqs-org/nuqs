<!-- The front page of the repo: what Nuqs is and how to start. -->

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-light.svg">
    <img src="docs/assets/logo.svg" width="88" alt="Nuqs logo">
  </picture>
</p>

<h1 align="center">Nuqs</h1>

<p align="center">
  A non-overengineered, open-source vulnerability assessment tool built on Nmap.<br>
  Simple, reliable and trust-worthy   
</p>

<p align="center">
  <a href="https://github.com/nuqs-org/nuqs/actions/workflows/ci.yml"><img src="https://github.com/nuqs-org/nuqs/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://nuqs-org.github.io/nuqs/"><img src="https://github.com/nuqs-org/nuqs/actions/workflows/docs.yml/badge.svg" alt="Docs"></a>
  <img src="https://img.shields.io/github/go-mod/go-version/nuqs-org/nuqs" alt="Go version">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License"></a>
</p>

<p align="center">
  <a href="https://nuqs-org.github.io/nuqs/"><b>Docs</b></a> ·
  <a href="#quick-start"><b>Quick start</b></a> ·
  <a href="docs/roadmap.md"><b>Roadmap</b></a> ·
  <a href="https://nuqs.duckdns.org"><b>Chat</b></a>
</p>

---

## Quick start

You need Go 1.27+ and Nmap.

```bash
go build -o nuqs ./cmd/nuqs
./nuqs scan 192.168.1.1
./nuqs scan --json -p 21,23,80,443 192.168.1.0/24 > report.json
```

> [!IMPORTANT]
> Only scan networks you own or have permission to scan.

## What's here

| Folder | What |
|---|---|
| `cmd/nuqs` | the `nuqs` binary |
| `internal/` | the core: targets, Nmap, engine, checks interface, output, CLI |
| `checks/` | built-in checks, one folder each |
| `test/integration` | full scan test with the real Nmap |
| `docs/` | the website, including the [roadmap](docs/roadmap.md) and [what's done](docs/progress.md) |

The full map (diagram plus every file) is on the [website](https://nuqs-org.github.io/nuqs/architecture/). It's rebuilt from the code on every docs build.

## Develop

```bash
go test -race ./...                                  # unit tests
go test -tags integration ./test/integration         # needs nmap
golangci-lint run                                    # lint, also checks every public thing has a doc comment
go run ./tools/archdiagram                           # build the architecture page locally (the docs build does this too)
./scripts/docs.sh                                    # docs website at http://127.0.0.1:8000 (installs what it needs)
```

Adding a check? See [Writing a check](docs/writing-a-check.md). Everything else: [Contributing](docs/contributing.md). Found a security bug? See [Security](SECURITY.md).

## Research

How Nessus works under the hood, measured and written up before we started: [PremadeS/nessus-dissection](https://github.com/PremadeS/nessus-dissection).

---

<p align="center"><sub>Apache 2.0 · Nuqs Org</sub></p>
