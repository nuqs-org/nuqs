# How it works

## The flow

```text
targets ──► target.Parse ──► Nmap ──► hosts + services ──► checks ──► findings ──► report
            (validate)       (nmap)                        (engine)               (output)
```

1. **Validate targets.** We reject anything that isn't an IP, network, range or hostname. This also stops tricks like passing `-oN file` as a target.
2. **Find hosts with Nmap.** We run `nmap -sT -sV --open` and read its XML while it runs. Nmap writes each host when it's done with it, plus a progress update every 2 seconds, so we get those as they happen instead of at the end. The CLI and the web UI turn those updates into one steady percent and time left (see `internal/progress`). Nmap does all the low-level packet work.
3. **Pick checks.** Each check says which services it cares about (by port or Nmap service name). We only run a check where it applies.
4. **Run checks in parallel.** Each check gets its own timeout. If a check errors, hangs or even panics, it's recorded and the scan keeps going.
5. **Report.** Findings are sorted worst first, with evidence and a fix.

## Where the code lives

See [Architecture](architecture.md). It shows every package, what it does, what it uses, and every file in the repo. It's generated from the code on every docs build, so it's always right.

## Rules we keep

- **Simple first.** If it can be simple, it should be simple.
- **No hidden magic.** Checks are listed by hand in `checks/checks.go`, there's no auto-registration.
- **Standard library only** for now, zero dependencies. Less to audit, less to break.
- **Errors aren't findings.** A check that couldn't connect never reports "vulnerable".
- **Evidence for everything.** Every finding says what we saw, so people can trust it.
- **Confidence for everything.** Every finding is `confirmed` (we saw it happen) or `inferred` (only from a version number, or Nmap guessed the service from the port).
- **Same input, same output.** Reports are sorted the same way every time.
