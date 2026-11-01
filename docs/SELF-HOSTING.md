# Self-hosting Hush Relay

There are two interchangeable relays. Both speak the same API and use the same data folder layout, so you can switch between them without losing mail.

| | Go relay (`hush-relay`) | PHP relay (`web/relay.php`) |
|---|---|---|
| Install | One file, nothing else | PHP 7.4+ and a web server |
| App included | Yes, built in | Upload `web/` alongside it |
| Live connections | Thousands (tested: 3,000 at about 80 MB) | One PHP worker each (32 by default) |
| Best for | Phones, Pis, VPS, Tor onion services | Shared hosting (cPanel) |

Every option ends the same way: a stable `https://` (or `.onion`) address serving the app, with the relay writing to a private data folder.

## Go relay (recommended)

Build it once (Go 1.22+), or download a release binary for your device:

```bash
go build -trimpath -ldflags "-s -w" -o hush-relay ./cmd/hush-relay
# other devices: GOOS=linux GOARCH=arm64 (Pi, most phones) · GOARCH=arm GOARM=7 (older Pis) · GOOS=windows
./hush-relay                      # http://127.0.0.1:8080, data in ~/.hush-relay-data
```

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `-addr` | `HUSH_ADDR` | `127.0.0.1:8080` | Listen address. Keep it on 127.0.0.1 behind a proxy, tunnel or onion service. |
| `-data` | `HUSH_DATA` | `~/.hush-relay-data` | Pending mail and recovery backups (created with mode 0700). |
| `-web` | `HUSH_WEB` | built in | Serve the app from a folder instead (for example a custom `config.js`). |
| `-trusted-proxies` | `HUSH_TRUSTED_PROXIES` | none | Proxy IPs on other machines allowed to report client addresses. |
| `-onion` | `HUSH_ONION=1` | off | Tor mode: limits apply per mailbox, because Tor hides client addresses. |
| `-forwarded-header` | `HUSH_FORWARDED_HEADER` | `X-Forwarded-For` | Header your proxy uses for the client address. Use `CF-Connecting-IP` behind Cloudflare Tunnel. |
| `-path` | `HUSH_PATH` | none | Private path for the app, relay and calls, e.g. `/k7q4mxp2/`. Every other address shows a plain front page. |
| `-cover` | `HUSH_COVER` | built in | Your own HTML file for that front page. |
| `-join-code` | `HUSH_JOIN_CODE` | none | Invite-only mode: only people with the code can get mail on this relay. It travels inside your invites. |
| `-new-path` | | | Print a random `-path` and `-join-code` to use, then exit. |

It answers at `/relay.php` (so invites made for the PHP relay keep working) and at `/relay`. It refuses to start if the data folder is inside a served folder.

It protects small devices on its own: at most 128 uploads or deliveries are handled at once (short bursts wait, then get "busy, retry"), each fetch returns at most about 2 MiB of mail (the app collects the rest automatically), and on shutdown (Ctrl-C or `systemctl stop`) waiting connections are answered before it exits.

### Private setup (recommended)

Run your relay so that it looks like an ordinary website to everyone except the people you invite:

```bash
./hush-relay -new-path
#   -path /k7q4mxp2ab/ -join-code 3f9c1e7a5b2d8c40
./hush-relay -path /k7q4mxp2ab/ -join-code 3f9c1e7a5b2d8c40
```

- **The front page** (`https://relay.example.com/`) shows a plain "nothing here" page; any other address gives a normal 404. The app lives at `https://relay.example.com/k7q4mxp2ab/`. Open that, create your profile, and share invites from there.
- **The join code** makes the relay invite-only. Your invites carry it, so people you invite never type it; strangers who find the address can't create a mailbox or store anything. Changing the code later doesn't remove people who already joined.
- **Calls** go through the same HTTPS connection (`…/k7q4mxp2ab/live`), so to your network provider a call looks like any other secure connection to your server, much like a mainstream chat app talking to its servers. No peer-to-peer traffic, no extra ports.
- Treat the path as a shared secret, not a password: it hides the app from scanners and casual visitors. Real protection comes from the encryption and the join code.

**Calls and bandwidth.** A video call uses about 0.7 Mbit/s in each direction per person, all through the relay (so the relay's upload carries both directions of every call). A home connection or the smallest VPS handles a few calls at once. Calls need the Go relay; on the PHP relay the call buttons stay hidden.

**Moving from the PHP relay:** stop PHP, point `-data` at the same folder (your old `HUSH_DATA`), start `hush-relay`. Waiting mail and recovery backups carry over.

## PHP relay settings

**Choosing where the data lives.** The PHP relay stores mail in a data folder. By default that's `web/data/`, protected by an `.htaccess` file that only Apache honours. Anywhere else, point it outside the web folder in one of two ways:

- set the environment variable `HUSH_DATA=/path/outside/web`, or
- create `web/relay.config.php` containing `<?php define('HUSH_DATA', '/path/outside/web');`

`scripts/serve.sh` already does this for you (it uses `~/.hush-relay-data`).

**Built-in abuse limits** (both relays; for PHP, edit the constants at the top of `relay.php`): 120 deliveries per minute per client, 5 new recovery backups per client per day, 500 messages or 8 MiB waiting per mailbox, 6 live connections per client. The relay also stops accepting data when less than 256 MiB of disk is free. Limits use the real client address: requests from a proxy or tunnel on the same machine (Cloudflare Tunnel, Caddy, nginx) are trusted to report it automatically. A proxy on another machine needs `HUSH_TRUSTED_PROXIES=<its IP>`. Only one header is read: `X-Forwarded-For` by default, or the one named in `HUSH_FORWARDED_HEADER` (use `CF-Connecting-IP` behind Cloudflare Tunnel).

**Live mode and capacity.** Every open copy of the app keeps one request waiting at the relay for up to 20 seconds. The Go relay handles this without tuning. For the PHP relay, make sure your server allows enough simultaneous PHP workers: `serve.sh` defaults to 32, and shared hosts often cap this lower.



---

## Tor onion service

An onion service gives your relay a `.onion` address with **no domain, no tunnel company and no open ports**, and hides where the relay physically is. Tor connects outward, so it works behind any home router. The address is unlisted: only people you give it to can find it.

On any Linux device (old laptop, Raspberry Pi, VPS):

```bash
sudo apt install tor
# add to /etc/tor/torrc:
#   HiddenServiceDir /var/lib/tor/hush/
#   HiddenServicePort 80 127.0.0.1:8080
sudo systemctl restart tor
sudo cat /var/lib/tor/hush/hostname      # your address: <56 characters>.onion
./hush-relay -onion -join-code <code>    # listens on 127.0.0.1:8080 (hush-relay -new-path makes a code)
```

- **Back up `/var/lib/tor/hush/`.** It holds the onion address's private key: lose it and the address is gone; leak it and someone else can impersonate your relay.
- **Add `-join-code` too.** Behind Tor every visitor looks the same, so limits can't tell people apart; the join code is what keeps strangers from using your relay (and from opening call rooms).
- **Always use `-onion`.** Behind Tor every visitor appears as 127.0.0.1. Without it, one abusive visitor could use up the limits for everyone. With it, limits apply per mailbox and forwarded-address headers from visitors are ignored.
- **Who can reach it:** people open `http://<address>.onion/` in **Tor Browser** (desktop or Android). Tor encrypts and authenticates the connection, and the app accepts v3 onion relay addresses.
- **Limit to know about:** Tor Browser forgets site data when it closes, which includes your identity keys. Turn on **recovery words** and sign back in with them each session, or offer both an onion address and a normal `https://` address so people can choose. A native client with Tor built in is on the roadmap to remove this limit.
- The "Safest" security level in Tor Browser turns JavaScript off, so the app can't run at that level.
- Not yet tested end to end in Tor Browser by the maintainers; reports welcome.

## Android app

People you invite can use the web app in any browser, or install the **Hush Relay Android app** (not in any app store):

1. Download `hush-relay-<version>.apk` from the [releases page](https://github.com/altrudev/Hush-Relay/releases) and check it against the published SHA-256 and signing-certificate fingerprint.
2. Open it on the phone and allow installing from that source when Android asks.
3. On the welcome screen, paste the invite link someone sent you (or share the link to the Hush Relay app from your messenger), then create your profile.

The app is the same code as the web app, bundled inside the APK so nothing is downloaded to run it; it only connects to the relays you use. It blocks screenshots and hides chats from the recent-apps preview, keeps your keys in app storage that other apps can't read, and excludes them from Android cloud backups. Like the web app, it receives messages while it's open; there are no push notifications yet.

**Building it yourself** (no Gradle; the plain Android SDK tools):

```bash
./android/build.sh            # signed release APK in android/out/, plus a .sha256 file
./android/build.sh --debug    # debug build: remote WebView inspector on, screenshots allowed
```

It needs a JDK 17+, Android build-tools 34+ and one platform (35+). The first release build creates a signing key at `~/.hush-relay/release.jks` (or `HUSH_KEYSTORE`). **Back that key up**: Android only installs updates signed with the same key. `tests/android/run.sh` runs a two-person test (app plus a browser, with a video call) on an emulator.

## Android phone as the relay

A spare phone on a charger and Wi-Fi works well for friends and family.

1. Install **Termux** from [F-Droid](https://f-droid.org/packages/com.termux/). The Play Store build is outdated.
2. In Termux, either download the `linux-arm64` release binary (no other packages needed) or build it:
   ```bash
   pkg update && pkg install golang git cloudflared
   git clone https://github.com/altrudev/Hush-Relay.git hush-relay && cd hush-relay
   go build -o ~/hush-relay ./cmd/hush-relay
   termux-wake-lock            # keep running with the screen off
   ~/hush-relay                # serves on 127.0.0.1:8080
   ```
   The PHP relay also works on a phone (`pkg install php`, then `./scripts/serve.sh`).
   For an onion address instead of a tunnel: `pkg install tor`, add the two `HiddenService` lines above to `$PREFIX/etc/tor/torrc` (with `HiddenServiceDir $HOME/.tor-hush`), run `tor`, and start `~/hush-relay -onion`.
3. **Give it a stable public address** with a [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/). This needs a domain on Cloudflare. In a second Termux session:
   ```bash
   cloudflared tunnel login
   cloudflared tunnel create hush
   cloudflared tunnel route dns hush relay.example.com
   cloudflared tunnel run --url http://127.0.0.1:8080 hush
   ```
   Your app is now at `https://relay.example.com/`.

   `cloudflared tunnel --url http://127.0.0.1:8080` also works for a quick test, but its random address changes on every restart, which breaks invites.
4. In Android settings, turn off battery optimization for Termux. Optionally install **Termux:Boot** and add a script in `~/.termux/boot/` that starts both commands after a reboot.

**Phone security:**
- Use a phone that still gets security updates (or runs LineageOS), with a screen lock and encryption on.
- Use it only for this.
- The phone holds only encrypted mail, but whoever gets the phone can see the metadata (who has mail and when).

## VPS

Any small Debian/Ubuntu server works. Caddy provides HTTPS automatically.

```bash
sudo apt install caddy
sudo useradd -r -m -d /opt/hush hush
sudo install -o root -g root -m 755 hush-relay /usr/local/bin/hush-relay   # the Go binary
```

`/etc/systemd/system/hush-relay.service`:
```ini
[Unit]
Description=Hush Relay
After=network.target
[Service]
User=hush
ExecStart=/usr/local/bin/hush-relay -addr 127.0.0.1:8080 -data /opt/hush/data -path /k7q4mxp2ab/ -join-code 3f9c1e7a5b2d8c40
Restart=always
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/hush/data
PrivateTmp=true
[Install]
WantedBy=multi-user.target
```

(PHP alternative: `sudo apt install php-cli git`, clone the repo, and use `ExecStart=/opt/hush/hush-relay/scripts/serve.sh` with `Environment=HUSH_DATA=/opt/hush/data`.)

`/etc/caddy/Caddyfile`:
```
relay.example.com {
    reverse_proxy 127.0.0.1:8080
    header Content-Security-Policy "frame-ancestors 'none'"
    log {
        output discard     # don't keep IP logs you don't need
    }
}
```

```bash
sudo systemctl enable --now hush-relay && sudo systemctl reload caddy
```

## Shared hosting

On cPanel or any Apache with PHP 7.4+:

1. Upload the **contents** of `web/` to a folder, for example `public_html/hush/`.
2. Recommended: create `relay.config.php` next to `relay.php` that points `HUSH_DATA` to a folder outside `public_html`.
3. Open `https://yourdomain/hush/`.

Shared hosts limit simultaneous PHP processes. This is fine for small groups; for more users, use a VPS. Ask your host to turn off access logs for that folder if you can.

**nginx users:** if you serve `web/` directly with PHP-FPM, keep `HUSH_DATA` outside the web root (the relay refuses to run otherwise), and add `add_header Content-Security-Policy "frame-ancestors 'none'";`.

## IPFS

IPFS can host the **app** (static files), not the relay. Anyone can mirror the app, and its content address proves it hasn't been altered.

```bash
./scripts/publish-ipfs.sh https://relay.example.com/relay.php   # needs Kubo (ipfs)
```

The script bakes your relay address into `config.js` and prints a CID.

Browser storage, which holds the keys, is tied to the exact web address. A new CID URL is a new address, so for real use set up DNSLink:

1. Add a DNS TXT record: `_dnslink.app.example.com TXT "dnslink=/ipfs/<cid>"`.
2. Open `https://app-example-com.ipns.dweb.link/` (dots become dashes) or your own gateway on that domain.
3. Update the record on each release. The address stays the same, so users keep their accounts.

Path-style gateway URLs (`…/ipfs/<cid>/`) share one origin with every IPFS site, so the app refuses to run there.

Keep the CID online by running Kubo (it works on a phone too) or a pinning service.
