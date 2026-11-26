# Contributing

## The flow

1. Pick a task from the [roadmap](roadmap.md) and open an issue (or comment on one) so nobody does it twice.
2. Make a branch from `master`, like `feat/redis-check` or `fix/ftp-timeout`.
3. Write the code **and** the tests **and** the doc comments.
4. Run `make test` and `make lint` before pushing. CI runs the same targets.
5. Open a PR. Keep it small, one thing per PR. Fill in the **test plan**: what to run and what the reviewer should see.
6. One teammate reviews it by following the test plan. CI must be green before merging.

## Common commands

The `Makefile` holds the commands used both locally and in CI. Run `make` (or `make help`) to see the full list.

| Command | What it does |
|---|---|
| `make build` | Build the `nuqs` binary (`nuqs.exe` on Windows) |
| `make test` | Run unit tests with `-race` and check total coverage is at least 85% |
| `make lint` | Run `golangci-lint` (including doc comment checks) |
| `make docs` | Build the docs site strictly into `site/` (use `make docs-serve` for live preview) |
| `make lab` | Run the Docker loopback lab and compare against `lab/expected-report.json` |
| `make integration` | Run the real-Nmap integration test |

On Windows, `make build`, `make test`, `make vet`, `make lint` and `make clean` work in both Git Bash / MSYS2 and native PowerShell or CMD (with `mingw32-make`). `make docs` and `make lab` need Bash (Git Bash, MSYS2 or WSL).

## Keep it simple

If it can be simple, it should be simple. Before adding a library, a config option or an abstraction, ask "do we need this right now?". Usually the answer is no.

## Docs

- Every public function, type and package needs a doc comment. CI checks this.
- Every file starts with a one-line description of what's in it. The [Architecture](architecture.md) page shows these next to each file. A test fails if a Go file is missing one, for other files it's optional but nice.

| File type | How to write the description |
|---|---|
| Go | `// Tests the engine: timeouts, panics and sorting.` on the first line, then a **blank line**, then `package ...`. The blank line matters, without it Go treats the comment as the package description. A file that holds the package doc comment doesn't need one. |
| YAML, shell, `.gitignore` | `# What this file does.` on the first line (after `#!/usr/bin/env bash` in scripts) |
| `go.mod` | `// What this file does.` on the first line |
| Markdown, XML | `<!-- What this file does. -->` at the top |
- Comments explain **why**, the code already shows what.
- Keep docs short and plain, like you're explaining it to a teammate. Use commas, not semicolons.
- The API pages on the website are generated from these comments, so you never edit them by hand.
- If you change how something works, update the matching page in `docs/` in the same PR.

## Commit messages

Short and clear, like `add redis-no-auth check` or `fix ftp check hanging on silent servers`.
