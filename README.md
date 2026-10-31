# Hush Relay

**A small, self-hostable, end-to-end encrypted messenger. No accounts, no phone numbers, no app store, no build step.**

Hush Relay is two pieces:

- **The app** is a web page (a PWA) made of plain HTML and JavaScript. You open it in a browser and can install it to your home screen. All encryption happens there.
- **The relay** is one PHP file that acts as a dumb mailbox. It stores encrypted envelopes until the recipient picks them up, and it can't read them or see who sent them.

You can run the whole thing on a spare Android phone, a $5 VPS, a Raspberry Pi or ordinary shared hosting. You can also publish the app on IPFS.

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
- **Plain files:** vanilla JS, WebCrypto and one PHP file. Three small vendored libraries handle QR codes and the wordlist.

## Quick start (local, 1 minute)

```bash
git clone https://github.com/altrudev/Hush-Relay.git hush-relay
cd hush-relay
./scripts/serve.sh
```

Open http://localhost:8080 in two different browsers (or one normal and one private window). Create an account in each, open **Settings** in one, and paste its invite link into the other. Then chat.

You need PHP 7.4 or newer (`sudo apt install php-cli`; on Termux, `pkg install php`).

## Put it on the internet

Browsers only allow the app's encryption on `https://` (or `localhost`), so a public relay needs HTTPS. Pick one:

| Where | Effort | Notes |
|---|---|---|
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
web/            everything you deploy
  index.html    UI
  app.js        crypto core + app logic (also loadable in Node for tests)
  relay.php     the mailbox relay
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

## Tests

```bash
./tests/run.sh          # needs php + node 20+
./tests/run.sh --e2e    # also four real browsers (pip install playwright && playwright install chromium)
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

Copyright © 2026 Valentyn Rukhaylo ([ALTRU.dev](https://altru.dev)) and contributors.

Hush Relay is free software under the [GNU Affero General Public License v3.0 or later](LICENSE). If you run a modified version for others (including as a hosted relay or app), you must offer them your changed source code.

Bundled third-party code keeps its own license: [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) (MIT), [jsQR](https://github.com/cozmo/jsQR) (Apache-2.0, see `web/vendor/LICENSE-jsQR.txt`), BIP39 English wordlist via [@scure/bip39](https://github.com/paulmillr/scure-bip39) (MIT, see `web/vendor/LICENSE-bip39-wordlist.txt`).

Made by [ALTRU.dev](https://altru.dev), Code for Humanity.
