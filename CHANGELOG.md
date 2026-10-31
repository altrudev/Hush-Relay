# Changelog

## 0.3.0 (2026-10-31): first public release
- Live delivery (long-polling), messages arrive in about a second
- QR invites; scan with the camera or from a picture
- Move an account to a new device by QR, confirmed with an 8-digit code
- 6-word recovery backed by an encrypted slot on the relay
- Double Ratchet with forward secrecy, sealed sender, size padding
- Encrypted backup files (passphrase)
- IPFS publishing script; app refuses to run on shared-origin path gateways
- `serve.sh` + router for PHP's built-in server (phones, Pis, VPS)
- Two rounds of adversarial review; 20 issues fixed with regression tests (see SECURITY.md)
- Test suite: crypto core, relay API, server hardening, four-browser end-to-end
