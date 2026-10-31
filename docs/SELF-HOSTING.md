# Self-hosting Hush Relay

Every option ends the same way: a stable `https://` address serving the `web/` folder, with `relay.php` able to write to a private data folder.

**Choosing where the data lives.** The relay stores mail in a data folder. By default that's `web/data/`, protected by an `.htaccess` file that only Apache honours. Anywhere else, point it outside the web folder in one of two ways:

- set the environment variable `HUSH_DATA=/path/outside/web`, or
- create `web/relay.config.php` containing `<?php define('HUSH_DATA', '/path/outside/web');`

`scripts/serve.sh` already does this for you (it uses `~/.hush-relay-data`).

**Built-in abuse limits** (edit the constants at the top of `relay.php`): 120 deliveries per minute per client, 5 new recovery backups per client per day, 500 messages or 8 MiB waiting per mailbox, 6 live connections per client. The relay also stops accepting data when less than 256 MiB of disk is free. Limits use the real client address: requests from a proxy or tunnel on the same machine (Cloudflare Tunnel, Caddy, nginx) are trusted to report it automatically. A proxy on another machine needs `HUSH_TRUSTED_PROXIES=<its IP>`.

**Live mode and capacity.** Every open copy of the app keeps one request waiting at the relay for up to 20 seconds. Make sure your server allows enough simultaneous PHP workers: `serve.sh` defaults to 32, and shared hosts often cap this lower.

---

## Android phone

A spare phone on a charger and Wi-Fi works well for friends and family.

1. Install **Termux** from [F-Droid](https://f-droid.org/packages/com.termux/). The Play Store build is outdated.
2. In Termux:
   ```bash
   pkg update && pkg install php git cloudflared
   git clone https://github.com/altrudev/Hush-Relay.git hush-relay && cd hush-relay
   termux-wake-lock            # keep running with the screen off
   ./scripts/serve.sh          # serves on 127.0.0.1:8080
   ```
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
sudo apt install php-cli git caddy
sudo useradd -r -m -d /opt/hush hush
sudo -u hush git clone https://github.com/altrudev/Hush-Relay.git /opt/hush/hush-relay
```

`/etc/systemd/system/hush-relay.service`:
```ini
[Unit]
Description=Hush Relay
After=network.target
[Service]
User=hush
WorkingDirectory=/opt/hush/hush-relay
Environment=HUSH_DATA=/opt/hush/data
ExecStart=/opt/hush/hush-relay/scripts/serve.sh
Restart=always
[Install]
WantedBy=multi-user.target
```

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
