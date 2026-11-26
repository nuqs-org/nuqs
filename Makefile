# Build, test, lint, docs and lab commands shared by local dev and CI.

GO            ?= go
GOFMT         ?= gofmt
GOLANGCI_LINT ?= golangci-lint
BASH          ?= bash
VERSION       ?= dev
LDFLAGS       := -X main.version=$(VERSION)
PKGS          ?= ./...
MIN_COV       ?= 85

ifeq ($(OS),Windows_NT)
BIN           ?= nuqs.exe
ifeq ($(shell echo %OS%),Windows_NT)
USING_CMD     := 1
endif
else
BIN           ?= nuqs
endif

EMPTY         :=
INDENT        := $(EMPTY)  $(EMPTY)

.DEFAULT_GOAL := help

.PHONY: help build test coverage integration fmt fmt-check vet lint docs docs-serve lab lab-update clean

help:
	$(info Common targets:)
	$(info $(INDENT)make build        build $(BIN) (override VERSION=v0.1.0 if needed))
	$(info $(INDENT)make test         run unit tests with -race and check coverage >= $(MIN_COV)%)
	$(info $(INDENT)make integration  run the real-Nmap integration test)
	$(info $(INDENT)make fmt          format all Go files with gofmt)
	$(info $(INDENT)make fmt-check    fail if any Go file needs gofmt)
	$(info $(INDENT)make vet          run go vet on normal and integration packages)
	$(info $(INDENT)make lint         run golangci-lint)
	$(info $(INDENT)make docs         build the docs site strictly into site/)
	$(info $(INDENT)make docs-serve   preview the docs site locally at http://127.0.0.1:8000)
	$(info $(INDENT)make lab          run the Docker loopback lab and compare against expected JSON)
	$(info $(INDENT)make lab-update   refresh lab/expected-report.json from the lab)
	$(info $(INDENT)make clean        remove build, coverage and docs build outputs)
	@:

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/nuqs

test:
	$(GO) test -race -coverprofile=coverage.out $(PKGS)
	@$(MAKE) --no-print-directory coverage

coverage:
ifdef USING_CMD
	@powershell -NoProfile -Command "$$line = (& $(GO) tool cover '-func=coverage.out' | Select-String '^total:').Line; if (-not $$line) { [Console]::Error.WriteLine('Could not read total coverage'); exit 1 }; $$t = [double](($$line -split '\s+')[-1].TrimEnd([char]37)); Write-Host ('Total coverage: ' + $$t.ToString('0.0', [System.Globalization.CultureInfo]::InvariantCulture) + [char]37); if ($$t -lt $(MIN_COV)) { [Console]::Error.WriteLine('Coverage dropped below $(MIN_COV)' + [char]37); exit 1 }"
else
	@total=$$($(GO) tool cover -func=coverage.out | awk '/^total:/ {sub("%","",$$3); print $$3}'); \
	if [ -z "$$total" ]; then echo "Could not read total coverage"; exit 1; fi; \
	echo "Total coverage: $${total}%"; \
	awk -v t="$$total" -v min="$(MIN_COV)" 'BEGIN { exit (t+0 >= min+0) ? 0 : 1 }' || { echo "Coverage dropped below $(MIN_COV)%"; exit 1; }
endif

integration:
	$(GO) test -tags integration -v -count=1 ./test/integration

fmt:
	$(GOFMT) -w .

fmt-check:
ifdef USING_CMD
	@powershell -NoProfile -Command "$$u = & $(GOFMT) -l .; if ($$LASTEXITCODE -ne 0) { exit $$LASTEXITCODE }; if ($$u) { Write-Host 'These files need gofmt:'; $$u; exit 1 }"
else
	@unformatted=$$($(GOFMT) -l .) || exit 1; \
	if [ -n "$$unformatted" ]; then \
		echo "These files need gofmt:"; echo "$$unformatted"; exit 1; \
	fi
endif

vet:
	$(GO) vet ./...
	$(GO) vet -tags integration ./...

lint:
	$(GOLANGCI_LINT) run

docs:
	$(BASH) scripts/docs.sh build

docs-serve:
	$(BASH) scripts/docs.sh

lab:
	$(BASH) scripts/lab.sh

lab-update:
	$(BASH) scripts/lab.sh --update

clean:
ifdef USING_CMD
	@powershell -NoProfile -Command "foreach ($$p in '$(BIN)','coverage.out','lab-report.json','site') { if (Test-Path $$p) { Remove-Item -Recurse -Force $$p } }"
else
	rm -rf $(BIN) coverage.out lab-report.json site
endif
