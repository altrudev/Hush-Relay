# About Hush Relay

**Hush Relay** is a small, open-source, self-hostable messaging project designed around browser-side encryption and a minimal PHP mailbox service. It can run as an installable progressive web app (PWA) and does not require accounts, phone numbers, an app store, a frontend build step, or a centrally operated service.

## Purpose

Make it practical for people to host their own message relay and inspect the source of the client and server. The application handles identity keys, message encryption, contact management, verification, recovery, and device transfer in the browser. The PHP relay stores and retrieves encrypted envelopes; it is not intended to know message plaintext.

## Components

| Component | Implementation | Function |
|---|---|---|
| Browser app | HTML, JavaScript, WebCrypto, service worker | Local keys, encryption, contacts, PWA interface |
| Relay | PHP 7.4+ | Encrypted mailbox storage, long-poll delivery, expiration and quotas |
| Self-hosting | Shell scripts, PHP CLI or web hosting | Local development, VPS, Android/Termux, shared hosting |
| Protocol | Documented in `docs/PROTOCOL.md` | Ratchet, envelopes, recovery and linking |
| Tests | Node.js and shell; optional Python Playwright | Deterministic crypto/relay checks, hardening and browser scenarios |

## What it does not promise

**Experimental — no independent professional cryptographic audit.** Passing tests and prior internal reviews are not evidence of production-grade security. Hush Relay is not a substitute for mature, independently audited secure-messaging software where failure could expose people to harm.

The relay can observe metadata such as IP addresses, mailbox destinations, time and approximate padded message size. The server delivering the web app can modify the JavaScript it provides, so independently pinning and reviewing deployed client code matters. See [SECURITY.md](SECURITY.md) for the threat model, outstanding risks and disclosure policy.

Other current limitations include one active device per account, no background push notifications, and device-local message history.

## Getting started

Run `./scripts/serve.sh` from a clone and open `http://localhost:8080` in two browsers. A public deployment needs a stable HTTPS endpoint. Follow the [README](README.md) and [self-hosting guide](docs/SELF-HOSTING.md) before exposing a relay.

## Governance and ownership

- **Project:** Hush Relay
- **Repository:** https://github.com/altrudev/Hush-Relay
- **Creator and maintainer:** Valentyn (Val) Rukhaylo / [ALTRU.dev](https://altru.dev)
- **Initial public version:** 0.3.0 (2026-10-31)
- **License:** GNU AGPL v3.0 or later for original project code; separate third-party notices for bundled libraries
- **Contributions:** See [CONTRIBUTING.md](CONTRIBUTING.md)
- **Security reports:** See [SECURITY.md](SECURITY.md); never report exploitable vulnerabilities publicly

No organization, foundation or third-party service is implied to sponsor, audit, or endorse this software.
