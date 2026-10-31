#!/usr/bin/env bash
# Hush Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev) and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
# Run the app and relay with PHP's built-in server.
# Good for a spare Android phone (Termux), a Raspberry Pi, or a small VPS.
#
#   ./scripts/serve.sh            # listens on 127.0.0.1:8080
#   PORT=9000 HOST=0.0.0.0 ./scripts/serve.sh
#
# Put a tunnel (Cloudflare Tunnel, Tailscale Funnel) or an HTTPS reverse proxy
# in front of it: browsers only allow the app's crypto on https:// or localhost.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8080}"
# Each open app holds one request for up to 20s (live mode), so allow many workers.
export PHP_CLI_SERVER_WORKERS="${PHP_CLI_SERVER_WORKERS:-32}"
# Keep relay data outside the web folder.
export HUSH_DATA="${HUSH_DATA:-$HOME/.hush-relay-data}"
mkdir -p "$HUSH_DATA" && chmod 700 "$HUSH_DATA"

command -v php >/dev/null || { echo "PHP not found. Termux: pkg install php   Debian/Ubuntu: sudo apt install php-cli" >&2; exit 1; }
echo "Hush Relay on http://$HOST:$PORT/   (data: $HUSH_DATA, workers: $PHP_CLI_SERVER_WORKERS)"
exec php -S "$HOST:$PORT" -t web scripts/router.php
