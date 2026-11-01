# Changelog

## 0.4.0 (2026-11-01): Go relay and Tor onion services
- New Go relay: one self-contained binary with the app built in, Go standard library only
  - Same API and data layout as `relay.php`; the two can share a data folder
  - In-memory long-poll wake-ups: 3,000 simultaneous live connections tested at about 80 MB
  - Builds for Linux (x86, ARM, ARMv7), Android, Windows, macOS and FreeBSD
  - Anti-framing headers, dotfile/data/source protection, refuses a data folder inside the served folder
- Tor onion-service mode (`-onion`): limits apply per mailbox because Tor hides client addresses
- Independent review of the Go relay: 4 confirmed issues and 9 smaller ones fixed with regression tests
  (onion limit bypass via forwarded headers, a lock stall on recovery lookups, memory exhaustion via large
  deliveries on small devices, abrupt shutdown); deliveries are now streamed and capped at about 2 MiB
- Both relays read a single configurable forwarded-address header (`X-Forwarded-For` by default)
- App accepts v3 `.onion` relay addresses over `http://`
- Self-hosting guide: Go relay, Tor onion service, hardened systemd unit
- Tests: Go unit tests (race detector), shared suite and four-browser run against both relays

## 0.3.0 (2026-10-31): first public release
- Live delivery (long-polling), messages arrive in about a second
- QR invites; scan with the camera or from a picture
- Move an account to a new device by QR, confirmed with a 12-digit code
- 6-word recovery backed by an encrypted slot on the relay
- Double Ratchet with forward secrecy, sealed sender, size padding
- Encrypted backup files (passphrase)
- IPFS publishing script; app refuses to run on shared-origin path gateways
- `serve.sh` + router for PHP's built-in server (phones, Pis, VPS)
- Two rounds of adversarial review; 20 issues fixed with regression tests (see SECURITY.md)
- Test suite: crypto core, relay API, server hardening, four-browser end-to-end
