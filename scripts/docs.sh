#!/usr/bin/env bash
# Builds the docs website. The first run installs what it needs into .venv.
#
#   ./scripts/docs.sh          preview at http://127.0.0.1:8000 (reloads on save)
#   ./scripts/docs.sh build    build into site/, the same way CI does
set -euo pipefail
cd "$(dirname "$0")/.."

# Pick Python and the right venv bin folder (Unix uses bin/, Windows uses Scripts/).
python_bin=python3
if ! "$python_bin" --version >/dev/null 2>&1; then
  python_bin=python
fi
venv_bin=.venv/bin
if [ -d .venv/Scripts ]; then
  venv_bin=.venv/Scripts
fi

# Install (or update) the docs tools when requirements.txt is new or changed.
if [ ! -f .venv/.installed ] || [ docs/requirements.txt -nt .venv/.installed ]; then
  echo "Installing docs tools into .venv (only needed once)..."
  "$python_bin" -m venv .venv
  if [ -d .venv/Scripts ]; then
    venv_bin=.venv/Scripts
  fi
  "$venv_bin/pip" install --quiet --upgrade pip
  "$venv_bin/pip" install --quiet -r docs/requirements.txt
  touch .venv/.installed
fi

go run ./tools/apidocs
go run ./tools/archdiagram

if [ "${1:-serve}" = "build" ]; then
  "$venv_bin/mkdocs" build --strict
else
  "$venv_bin/mkdocs" serve
fi
