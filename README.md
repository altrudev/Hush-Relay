# Hush Relay

**A small, self-hostable, end-to-end encrypted messenger. No accounts, no phone numbers, no app store, no build step.**

Hush Relay is two pieces:

- **The app** is a web page (a PWA) made of plain HTML and JavaScript. You open it in a browser and can install it to your home screen. All encryption happens there.
- **The relay** is a dumb mailbox. It stores encrypted envelopes until the recipient picks them up, and it can't read them or see who sent them. It comes in two interchangeable versions: a **single Go binary** with the app built in (standard library only, no dependencies) and **one PHP file** for shared hosting.

You can run the whole thing on a spare Android phone, a $5 VPS, a Raspberry Pi or ordinary shared hosting, optionally as a **Tor onion service** with no domain or open ports. You can also publish the app on IPFS.

> ⚠️ **Status: experimental and not independently audited.** The design uses standard building blocks (a Signal-style Double Ratchet on WebCrypto), but it has only had two rounds of internal adversarial review ([audit log](SECURITY.md#audit-log)), not one by outside cryptographers. Use it for everyday privacy, learning and experiments. **If your safety depends on your messages** (activists, journalists, sources, people facing a hostile government), use [Signal](https://signal.org) or [SimpleX](https://simplex.chat) instead. See [SECURITY.md](SECURITY.md).

## Features

- **End-to-end encryption with forward secrecy:** a Double Ratchet, so a stolen device can't decrypt messages captured earlier.
- **A sealed sender:** the relay can't tell who sent a message. Messages are padded to fixed sizes, so the relay learns only a coarse length.
- **Live delivery:** messages arrive in under a second while the app is open, and wait up to 14 days on the relay while you're offline.
- **No sign-up:** your identity is a key generated on your device. You add contacts by QR code or invite link.
- **Safety numbers** to check that nobody is in the middle. Strangers who message you arrive as *requests* until you reply.
- **Move your account by QR:** scan a one-time code from your old device and approve after matching a 12-digit code.
- **6 recovery words:** an encrypted backup kept on your relay, so you can get your account back on any device. The relay can't open it.
- **Different relays talk to each other:** each person can use a different relay, in any country.
- **No dependencies:** vanilla JS and WebCrypto in the browser; a Go relay built only on the standard library (or one PHP file). Three small vendored libraries handle QR codes and the wordlist.

## Quick start (local, 1 minute)

```bash
git clone https://github.com/altrudev/Hush-Relay.git hush-relay
cd hush-relay
go build -o hush-relay ./cmd/hush-relay && ./hush-relay     # Go 1.22+
# or, with PHP 7.4+:  ./scripts/serve.sh
```

Open http://localhost:8080 in two different browsers (or one normal and one private window). Create an account in each, open **Settings** in one, and paste its invite link into the other. Then chat.

## Put it on the internet

Browsers only allow the app's encryption on `https://` (or `localhost`), so a public relay needs HTTPS. Pick one:

| Where | Effort | Notes |
|---|---|---|
| **Tor onion service** (any Linux device or phone) | Medium | No domain, tunnel company or open ports; the location stays hidden. [Guide](docs/SELF-HOSTING.md#tor-onion-service) |
| **Spare Android phone** (Termux + Cloudflare Tunnel) | Medium | Free and always on while plugged in. [Guide](docs/SELF-HOSTING.md#android-phone) |
| **VPS** (Debian/Ubuntu + Caddy) | Medium | Most reliable, about $5/month. [Guide](docs/SELF-HOSTING.md#vps) |
| **Shared hosting** (cPanel, Apache, PHP) | Easy | Upload the `web/` folder. [Guide](docs/SELF-HOSTING.md#shared-hosting) |
| **App on IPFS**, relay anywhere above | Advanced | Anyone can mirror the app. [Guide](docs/SELF-HOSTING.md#ipfs) |

The relay address gets baked into every invite, so **keep it stable.** A tunnel URL that changes on every restart will break your contacts' links.

## Using it

1. **Create an account.** Pick a display name. The relay field is pre-filled.
2. **Add someone.** In **Settings**, show your invite QR or copy the link. They tap **Scan** (or paste the link).
3. **Verify.** Open the chat and compare the safety number in person or on a call, then tap **Numbers match**.
4. **Turn on recovery words** in **Settings** and write the 6 words down. They're the only thing you need to recover your account.
5. **New phone?** On it, choose *Link from my other device*. On the old one, tap **Scan**, check the 12-digit code matches and approve. The account moves over, and the old device signs out.

## Repository layout

```
cmd/hush-relay/ Go relay: one binary, app built in, standard library only
web/            the app (and the PHP relay)
  index.html    UI
  app.js        crypto core + app logic (also loadable in Node for tests)
  relay.php     the PHP mailbox relay (same API and data layout as the Go one)
  embed.go      tells the Go build which app files to include
  config.js     optional default relay URL (used for IPFS builds)
  sw.js         offline support
  vendor/       qrcode-generator (MIT), jsQR (Apache-2.0), BIP39 wordlist (MIT)
scripts/
  serve.sh      run app + relay with PHP's built-in server
  router.php    keeps the data folder private under php -S
  publish-ipfs.sh
tests/
  run.sh        full test suite against a throwaway relay
  core.test.js  crypto, ratchet, relay API, recovery, linking
  e2e.py        multi-browser test (Playwright)
docs/
  SELF-HOSTING.md  PROTOCOL.md
```

## Documentation

- [Project overview, scope and status](ABOUT.md)
- [Protocol and threat assumptions](docs/PROTOCOL.md)
- [Self-hosting and deployment](docs/SELF-HOSTING.md)
- [Security limitations and vulnerability reporting](SECURITY.md)
- [Contributing and local test procedure](CONTRIBUTING.md)
- [Third-party attribution and licensing](LICENSES.md)
- [Release history](CHANGELOG.md)

## Tests

```bash
./tests/run.sh --go     # Go relay: gofmt, vet, unit tests (race-safe), then the shared suite (needs go + node 20+)
./tests/run.sh          # PHP relay (needs php + node 20+)
# add --e2e for four real browsers (pip install playwright && playwright install chromium)
```

## Limits

- **One active device per account.** Linking moves an account; it doesn't add a second device.
- **Message history stays on the device that received it.**
- **The relay operator sees metadata:** IP addresses, timing, size bucket and which mailbox gets mail. They can't see content or senders.
- **The web delivery problem:** whoever serves the app's files could serve modified code. Pin an IPFS CID or self-host the app if that matters to you.
- **No push notifications.** Live delivery works while the app is open.

## Contributing

Issues and pull requests are welcome, especially security review. Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Copyright © 2026 Valentyn Rukhaylo (ALTRU.dev) and contributors.

Original Hush Relay code and documentation are licensed under the **GNU Affero General Public License v3.0 or later** (SPDX: `AGPL-3.0-or-later`). The complete license is in [LICENSE](LICENSE). For hosted modified versions, AGPL section 13 may require providing the corresponding source to network users; see [LICENSES.md](LICENSES.md) for an overview. AGPL permits commercial use provided its terms are followed.

Vendored components remain under their respective MIT or Apache-2.0 terms, detailed in [LICENSES.md](LICENSES.md) and the accompanying notice files. No trademark rights or separate proprietary license are granted by this repository.

Developed and maintained by [Val Rukhaylo / ALTRU.dev](https://altru.dev).
