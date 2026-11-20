# Testing

We don't compromise on tests. Everything has to work from the start, and CI blocks any PR that breaks something.

## Run the tests

```bash
go test ./...                 # all unit tests
go test -race ./...           # same, with the race detector (CI does this)
go test -cover ./...          # with coverage per package
```

Unit tests never need Nmap or the internet. Checks are tested against small fake servers that run inside the test.

## Integration test

This one runs the real Nmap against two local fake servers with known problems, and makes sure we find exactly those problems.

```bash
go test -tags integration -v ./test/integration
```

It skips itself if Nmap isn't installed. CI always runs it.

## End-to-end lab report

With Go, Nmap, Python 3 and Docker Compose installed, run `./scripts/lab.sh`.
The script builds the CLI and the FTP image from the checkout, starts the
three services, and waits for them to be ready. The first build downloads the
pinned images and the Alpine vsftpd package. Keep these loopback ports free.

| Service | Port | Expected finding |
| --- | --- | --- |
| vsftpd | 12121 | Medium. The empty public service accepts the anonymous handshake and prohibits file transfers. |
| BusyBox telnetd | 12323 | Medium. The listener negotiates Telnet and closes the session without starting a shell. |
| nginx | 18080 | Low. The static page omits the three HTTP security headers checked by Nuqs. |

Nuqs uses real Nmap discovery and its built-in check registry. Expect three
findings, zero check errors, and a match with the checked-in
`lab/expected-report.json`. The comparison validates the scan
timestamps and substitutes two fixed values. It also drops Nmap's product
guess for the Telnet server, because Nmap names BusyBox on some runs only.
Changes to the inventory, findings or errors produce a unified diff. Review that diff before updating
the expected report. Before discovery, the runner checks for an FTP greeting
on the published port. If the job fails, it prints the FTP container state,
port mapping and recent logs before removing the containers.

## Fuzz tests

Anything that reads untrusted input has a fuzz test. Fuzzing throws millions of random inputs at it to find crashes.

```bash
go test ./internal/target -run='^$' -fuzz=FuzzParse -fuzztime=30s
go test ./internal/nmap   -run='^$' -fuzz=FuzzParse -fuzztime=30s
```

If fuzzing finds a crash, Go saves the input under `testdata/fuzz/`. Commit that file with the fix so it's tested forever.

## What CI checks

Every push and PR runs:

| Check | Fails when |
|---|---|
| `gofmt` | code isn't formatted |
| `go vet` and `golangci-lint` | common bugs, or a public function, type or package has no doc comment |
| Unit tests with `-race` | any test fails or there's a data race |
| Coverage | total coverage drops below **85%** |
| Fuzz (short) | a fuzz target crashes in 30 seconds |
| Integration | the real Nmap scan doesn't find what it should |
| Lab report | the built CLI’s report for the lab differs from the saved JSON |
| Build | the binary doesn't build or `nuqs version` fails |
| govulncheck | a known vulnerability affects our code or Go version |
| Docs | the website doesn't build (broken links and so on) |
| Architecture | the diagram generator disagrees with `go list` about how packages connect |

## Rules for tests

- Every bug fix comes with a test that fails without the fix.
- Every check has positive, negative and "server misbehaves" tests.
- Tests must be fast and never touch the real network.
- Table-driven tests are preferred, they're easy to extend.
