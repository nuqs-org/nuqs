#!/usr/bin/env bash
# Builds Nuqs and compares its report for the loopback lab services with the golden file.
#
#   ./scripts/lab.sh            compare with lab/expected-report.json
#   ./scripts/lab.sh --update   write the new report there instead (review the diff before committing)
#
# Set LAB_OUT=some/file.json to also keep a copy of the normalized report.
set -euo pipefail
cd "$(dirname "$0")/.."

update=false
[[ "${1:-}" == "--update" ]] && update=true

workdir=$(mktemp -d)
compose=(docker compose -f lab/docker-compose.yml -p "nuqs-lab-$$")
cleanup() {
  local result=$1 teardown=0
  if (( result != 0 )); then
    echo "Lab failed (exit $result). Service state and logs before teardown:" >&2
    "${compose[@]}" ps --all >&2 || true
    "${compose[@]}" logs --no-color --tail 50 >&2 || true
  fi
  "${compose[@]}" down --rmi local || teardown=$?
  rm -r -- "$workdir" || teardown=$?
  exit "$((result != 0 ? result : teardown))"
}
trap 'cleanup "$?"' EXIT

# A throwaway certificate for the TLS service, readable by its nginx user.
export LAB_TLS_DIR="$workdir/tls"
mkdir -m 755 "$LAB_TLS_DIR"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
  -keyout "$LAB_TLS_DIR/key.pem" -out "$LAB_TLS_DIR/cert.pem" 2>/dev/null
chmod 644 "$LAB_TLS_DIR"/*.pem

go build -o "$workdir/nuqs" ./cmd/nuqs
"${compose[@]}" up -d --build --wait --wait-timeout 120
python3 - <<'PY'
import socket
import sys

try:
    with socket.create_connection(("127.0.0.1", 12121), timeout=3) as conn:
        with conn.makefile("rb") as stream:
            greeting = stream.readline(512)
except OSError as err:
    sys.exit(f"FTP greeting check on 127.0.0.1:12121 failed: {err}")
if not greeting.startswith(b"220 "):
    sys.exit(f"Expected FTP 220 greeting on 127.0.0.1:12121, received {greeting!r}")
print("FTP greeting received on 127.0.0.1:12121 before discovery")
PY
"$workdir/nuqs" scan --json -Pn -p 12121,12222,12323,12717,16379,18080,18443 127.0.0.1 > "$workdir/report.json"
go run ./lab < "$workdir/report.json" > "$workdir/normalized.json"
[[ -n "${LAB_OUT:-}" ]] && cp "$workdir/normalized.json" "$LAB_OUT"
if $update; then
  cp "$workdir/normalized.json" lab/expected-report.json
  echo "Wrote lab/expected-report.json, review it with: git diff lab/expected-report.json"
  exit 0
fi
diff -u lab/expected-report.json "$workdir/normalized.json"
echo "Lab report matches lab/expected-report.json"
