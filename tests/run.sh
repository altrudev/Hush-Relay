#!/usr/bin/env bash
# Hush Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev) and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
# Run the full test suite against a throwaway relay.
#   ./tests/run.sh               # PHP relay: core tests (needs php + node 20+)
#   ./tests/run.sh --go          # Go relay instead (needs go 1.22+)
#   add --e2e for the multi-browser test (needs python3 + playwright + chromium)
set -euo pipefail
cd "$(dirname "$0")/.."

IMPL=php; E2E=0
for arg in "$@"; do case "$arg" in --go) IMPL=go;; --e2e) E2E=1;; esac; done
PORT="${PORT:-8099}"
TMP="$(mktemp -d)"
export HUSH_DATA="$TMP/data"
if [ "$IMPL" = go ]; then
  echo "== go build, vet, unit tests"
  test -z "$(gofmt -l cmd web)" && echo "  ok   gofmt" || { echo "  FAIL gofmt: $(gofmt -l cmd web)"; exit 1; }
  go vet ./... && echo "  ok   go vet"
  go test ./... 2>&1 | sed 's/^/  /'
  go build -o "$TMP/hush-relay" ./cmd/hush-relay && echo "  ok   build"
  "$TMP/hush-relay" -addr "localhost:$PORT" -data "$HUSH_DATA" >"$TMP/server.log" 2>&1 &
else
  export PHP_CLI_SERVER_WORKERS=16
  php -S "localhost:$PORT" -t web scripts/router.php >"$TMP/server.log" 2>&1 &
fi
PID=$!
trap 'kill $PID 2>/dev/null; rm -rf "$TMP"' EXIT
for _ in $(seq 50); do curl -s -o /dev/null "http://localhost:$PORT/index.html" && break; sleep 0.1; done

echo "== syntax"
{ command -v php >/dev/null && php -l web/relay.php >/dev/null && echo "  ok   relay.php"; } || [ "$IMPL" = go ]
node --check web/app.js && echo "  ok   app.js"
bash -n scripts/*.sh && echo "  ok   shell scripts"

echo "== core"
RELAY="http://localhost:$PORT/relay.php" node tests/core.test.js

echo "== server hardening"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://localhost:$PORT/relay.php?a=put&box=0123456789abcdef0123456789abcdef" --data-binary @web/icon.svg)
[ "$code" = 200 ] && echo "  ok   relay accepts mail" || { echo "  FAIL relay put ($code)"; exit 1; }
for p in data/ data/recover/ .htaccess scripts/router.php embed.go; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/$p")
  [ "$code" = 404 ] && echo "  ok   /$p not served" || { echo "  FAIL /$p returned $code"; exit 1; }
done
[ -z "$(ls -A web | grep -x data || true)" ] && echo "  ok   no data written inside web/" || { echo "  FAIL data inside web/"; exit 1; }
curl -s -D - -o /dev/null "http://localhost:$PORT/index.html" | grep -qi "frame-ancestors 'none'" && echo "  ok   pages refuse to be framed" || { echo "  FAIL no frame-ancestors header"; exit 1; }
# New recovery slots are rate limited per client (5 per day).
codes=""
for i in 1 2 3 4 5 6 7; do
  l=$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n'); t=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
  codes="$codes $(curl -s -o /dev/null -w '%{http_code}' -X POST "http://localhost:$PORT/relay.php?a=rput" -d "{\"l\":\"$l\",\"t\":\"$t\",\"d\":\"abc\"}")"
done
echo "$codes" | grep -q 429 && echo "  ok   new recovery slots rate limited ($codes )" || { echo "  FAIL slot rate limit ($codes )"; exit 1; }
# Behind a proxy, limits apply per real client: the 7th+ live connection from one client gets 429,
# while another client behind the same proxy is unaffected.
live() { curl -s -o /dev/null -w '%{http_code} ' -H "X-Forwarded-For: $1" -X POST "http://localhost:$PORT/relay.php?a=get&wait=4" -d "{\"s\":\"$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')\"}"; }
burst=$( (for i in 1 2 3 4 5 6 7 8; do live 198.51.100.7 & done; wait) )
sleep 0.3; otherip=$(live 203.0.113.9)
echo "$burst" | grep -q 429 && [ "$otherip" = "200 " ] && echo "  ok   live connections capped per client behind a proxy ($burst| other client: $otherip)" || { echo "  FAIL per-client live cap ($burst| other: $otherip)"; exit 1; }
if [ "$IMPL" = go ]; then
  # A data folder inside a served folder must be refused at startup.
  if "$TMP/hush-relay" -addr "localhost:$((PORT+1))" -web web -data web/data >"$TMP/refuse.log" 2>&1; then echo "  FAIL started with data inside web/"; exit 1; fi
  grep -q "inside the served folder" "$TMP/refuse.log" && [ ! -d web/data ] && echo "  ok   relay refuses to run with an exposed data folder" || { echo "  FAIL: $(cat "$TMP/refuse.log")"; exit 1; }
  # Graceful shutdown: a waiting long-poll is answered with [] and the process exits cleanly.
  "$TMP/hush-relay" -addr "localhost:$((PORT+2))" -data "$TMP/data2" >"$TMP/stop.log" 2>&1 &
  SPID=$!; sleep 0.5
  sec=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
  sbox=$(printf '%s' "$sec" | sha256sum | cut -c1-32)
  curl -s -o /dev/null -X POST "http://localhost:$((PORT+2))/relay.php?a=put&box=$sbox" --data-binary @web/icon.svg
  ids=$(curl -s -X POST "http://localhost:$((PORT+2))/relay.php?a=get" -d "{\"s\":\"$sec\"}" | grep -o '"id":"[0-9a-f]*"' | cut -d'"' -f4)
  curl -s -o /dev/null -X POST "http://localhost:$((PORT+2))/relay.php?a=ack" -d "{\"s\":\"$sec\",\"ids\":[\"$ids\"]}"
  ( curl -s -X POST "http://localhost:$((PORT+2))/relay.php?a=get&wait=15" -d "{\"s\":\"$sec\"}" > "$TMP/lp.out"; echo "rc=$?" >> "$TMP/lp.out" ) &
  LP=$!; sleep 0.6; kill -TERM $SPID; wait $LP; wait $SPID; rc=$?
  grep -q '^\[\]' "$TMP/lp.out" && grep -q 'rc=0' "$TMP/lp.out" && [ $rc = 0 ] && echo "  ok   graceful shutdown answers waiting long-polls" || { echo "  FAIL shutdown: $(cat "$TMP/lp.out") exit=$rc"; exit 1; }
  for p in relay.php embed.go .htaccess; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/$p")
    [ "$code" = 405 ] || [ "$code" = 404 ] && echo "  ok   GET /$p gives $code" || { echo "  FAIL /$p returned $code"; exit 1; }
  done
else
# Requests that really come from outside cannot spoof X-Forwarded-For (only loopback proxies are trusted).
grep -q "preg_match('/^(127" web/relay.php && echo "  ok   forwarded addresses trusted only from local proxies" || { echo "  FAIL proxy trust check missing"; exit 1; }
# Without the router or HUSH_DATA, php -S must refuse rather than expose web/data.
env -u HUSH_DATA php -S "localhost:$((PORT+1))" -t web >/dev/null 2>&1 &
PID2=$!
sleep 0.5
body=$(curl -s -X POST "http://localhost:$((PORT+1))/relay.php?a=get" -d '{}')
kill $PID2 2>/dev/null
echo "$body" | grep -q "HUSH_DATA" && [ ! -d web/data ] && echo "  ok   relay refuses to run with an exposed data folder" || { echo "  FAIL exposed data folder not refused: $body"; rm -rf web/data; exit 1; }
fi

if [ "$E2E" = 1 ]; then
  echo "== browsers"
  # The earlier stages used up this client's rate limits; start from a clean slate.
  if [ "$IMPL" = go ]; then
    kill $PID 2>/dev/null; wait $PID 2>/dev/null || true
    "$TMP/hush-relay" -addr "localhost:$PORT" -data "$HUSH_DATA" >>"$TMP/server.log" 2>&1 &
    PID=$!
    for _ in $(seq 50); do curl -s -o /dev/null "http://localhost:$PORT/index.html" && break; sleep 0.1; done
  else
    rm -rf "$HUSH_DATA/limits"
  fi
  BASE="http://localhost:$PORT/index.html" python3 tests/e2e.py
fi
echo "All tests passed."
