#!/usr/bin/env bash
# Hush Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev) and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
# Publish the Hush web app (not the relay) to IPFS with Kubo.
# Usage: ./publish-ipfs.sh https://your-host/hush/relay.php
set -euo pipefail

RELAY="${1:?usage: $0 https://your-host/path/relay.php}"
[[ "$RELAY" =~ ^https://[A-Za-z0-9._~:/?=\&%-]+$ ]] || { echo "Relay must be a plain https:// URL" >&2; exit 1; }
command -v ipfs >/dev/null || { echo "Install Kubo first: https://docs.ipfs.tech/install/command-line/" >&2; exit 1; }

SRC="$(cd "$(dirname "$0")" && pwd)"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

cp "$SRC"/{index.html,app.js,sw.js,manifest.json,icon.svg} "$OUT"/ && cp -r "$SRC/vendor" "$OUT"/
printf 'window.HUSH_CONFIG = { relay: "%s" };\n' "$RELAY" > "$OUT/config.js"

CID="$(ipfs add -r -Q --cid-version=1 "$OUT")"
echo "CID: $CID"
echo
echo "Test it:  https://$CID.ipfs.dweb.link/"
echo
echo "For a stable address (keeps users' keys across updates), set a DNS TXT record:"
echo "  _dnslink.hush.example.com  TXT  \"dnslink=/ipfs/$CID\""
echo "then open https://hush-example-com.ipns.dweb.link/ (dots in the domain become dashes)."
echo
echo "Keep this CID online: leave your Kubo node running, or pin it with a pinning service."
