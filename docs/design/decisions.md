# Decisions

Why we built Nuqs the way we did. If you want to change one of these, open an issue first.

## Go, not C or Rust

| Option | Why or why not |
|---|---|
| **Go** ✅ | Built for programs that mostly wait on the network, which is what a scanner does. One binary, built-in testing, fuzzing and race detection. Easy to learn for the whole team. Tools like Nuclei and naabu are written in Go, so we can learn from them. |
| Rust | Faster and even safer, but much slower to write. Our speed comes from design, not raw CPU, so it isn't worth the cost for a 4-month project. |
| C | No. A scanner reads untrusted data all day, and in C every parsing bug can become a security hole in the security tool itself. |

**"Don't we need low-level control?"** Not in our code. The low-level work (raw packets, SYN scans, OS detection) is done by **Nmap**, which is written in C/C++. Our code waits on the network most of the time. Nessus itself shows this: its core is C/C++, but almost everything else runs in its own slow script language, and it's still slow because of how it's designed (it looks at 345,000 plugins for every host), not because of the language. If we ever need a very fast packet engine, we'll write just that part in Rust or C as a separate program.

## Nmap as a separate program

We run the `nmap` binary and read its XML. We don't bundle it or link to it, because Nmap's license doesn't allow that in our case. Users install Nmap themselves.

## One core, many front ends

```text
nuqs scan   ─┐
nuqs serve  ─┼──► engine (targets → nmap → checks → findings)
web UI      ─┘
```

The CLI, the API and the web UI never contain scan logic. They only call the engine. That way all three always behave the same.

## Standard library only, plus SQLite

The core has one dependency. Every dependency is code we have to trust and keep updated, so we add one only when it saves real work, and write the reason down here.

### SQLite with modernc.org/sqlite (week 2)

Scans, history and diffs need a database that survives restarts, can be shared by the CLI and the server at the same time, and doesn't need its own server.

- **SQLite** is one file next to Nuqs, nothing to install or run. It handles the CLI and the server writing at the same time (WAL mode), and it's the most tested database there is.
- **`modernc.org/sqlite`** is SQLite translated to pure Go. `go build` still needs no C compiler, so cross-compiling for every OS keeps working. The well known alternative, `mattn/go-sqlite3`, needs cgo.
- We use it through Go's own `database/sql`, so only one line in `internal/store` knows which driver it is.
- A JSON file was the other option. It's fine for a few records, but history and diffs need to search findings across many scans, and we'd end up writing our own locking and indexes.

## Checks are listed by hand

`checks/checks.go` has a plain list of every check. No magic auto-registration. It's easy to see what runs, and a test makes sure nobody forgets to add a new check to the list.

## Errors are never findings

If a check can't connect or times out, it reports an error, never "vulnerable". False positives destroy trust, and trust is how we beat Nessus.

## AI helps, it never decides

Nuqs has two optional AI helpers, and it works fully without either.

- **Defence model:** writes exact fix steps for a host. It only suggests, Nuqs never runs what it writes, and its answer is always marked as AI-written.
- **Verifier model:** when the user clicks "Verify", it plans extra checks to prove a finding is real. But the AI's opinion is never the proof. A finding only becomes "confirmed" when one of our safe, read-only tools returns hard evidence, and everything it did is saved so the user can read it.

Both use a local model (Ollama) by default, so scan data doesn't leave the machine. Users can point them at any OpenAI-compatible endpoint instead.

## One set of tools for the API, MCP and the verifier

The REST API, the MCP server (`nuqs mcp`) and the verifier all use the same small set of safe actions in `internal/tools`. We write and test each action once, and all three behave the same. AI assistants can only scan addresses on the allowed-targets list, and scans ask for confirmation. MCP uses the official Go MCP SDK, which will be our second dependency.

## Docs from code comments

We asked for Doxygen at first, but Doxygen doesn't support Go. Go has its own standard for doc comments, which we use instead. CI turns them into the API pages of the website, and the linter fails the build if any public function, type or package is missing one.

## Website on GitHub Pages

Free, runs from our repo, and updates on every push to the default branch. The address is `nuqs-org.github.io/nuqs`. We can move to a custom domain later without changing anything else.

## Web UI, not a desktop app

The UI is a web page served by the `nuqs` binary. It works on every OS, from any machine on the network, and on a server with no screen. A Qt app would be a second UI in C++ to build and test, for no real gain. If people want a desktop app later, we wrap the same web UI with Wails, so there's still only one UI.
