# Security

## Status

Hush Relay is **experimental and has not been audited by an independent security firm.** It went through two rounds of internal review: an adversarial code review with working exploit scripts, fixes, then a second review of those fixes (see the audit log below). That is not a substitute for expert review.

Use it for everyday privacy, learning and experiments. If a bug could put you or the people you talk to at risk (activists, journalists, sources, people facing a hostile government), use [Signal](https://signal.org) or [SimpleX](https://simplex.chat).

## Reporting a vulnerability

Please report privately through GitHub's **Report a vulnerability** button (the Security tab of this repository). Don't open a public issue. Include steps to reproduce if you can. Fixed issues are listed in the audit log below, with credit if you want it.

## What it is designed to protect

| Threat | Protection |
|---|---|
| Relay operator reading messages | End-to-end encryption (Double Ratchet, AES-256-GCM) |
| Relay operator learning who sent a message | Sealed sender: a fresh ephemeral key per envelope |
| Relay operator learning exact message length | Padding to 1, 4, 16 or 32 KiB |
| Someone who later steals a device reading past captured traffic | Forward secrecy for message bodies (see limit 1) |
| Forged or tampered messages | Authenticated encryption bound to both identities and the header |
| Replayed messages or replayed old sessions | Ratchet counters, single-use session ids, authenticated timestamps |
| Relay operator opening or replacing the recovery backup | 66-bit random words, PBKDF2 600k, token-guarded slot |
| Unsolicited senders posing as your contacts | Unknown senders arrive as *requests*, marked unverified; safety numbers |
| Abuse of a public relay | Per-client rate limits (real client address, also behind a proxy or tunnel), per-mailbox quotas, disk floor, expiry |

## Known limits (by design, for now)

1. **No prekeys.** Until a contact replies, the first messages of a session depend on both identity keys. Someone who records traffic and later steals an identity key can read those first messages and learn the sender of any recorded envelope. Ongoing conversations have forward secrecy.
2. **Key-compromise impersonation.** Someone who steals your identity key can pose as anyone *to you*.
3. **The relay sees metadata:** IP addresses, timing, which mailbox receives mail, the size bucket, and whether mail is waiting. Use a relay you trust, Tor, or a tunnel that hides client IPs if this matters.
4. **Web delivery.** Whoever serves the app's files can serve modified code. Pin an IPFS CID, self-host the app, or check `app.js` against a tagged release.
5. **Shared origins.** Browser storage is per origin. Don't host the app on an origin that also runs other people's code (for example, a shared cPanel domain with other apps).
6. **Device linking** uses a 12-digit comparison code (about 40 bits) inside a 10-minute window. Compare the code; never approve a request you didn't start.
7. **Invites are not signed.** If someone intercepts your invite, they can swap the mailbox in it, though not the key. Verify safety numbers once.
8. **One device per account.** Recovering or linking while another copy is still active leads to lost messages. Erase the old copy.
9. **No independent cryptographic review yet.**

## Deployment checklist

- Serve over HTTPS. Browsers refuse the crypto APIs otherwise.
- Keep `HUSH_DATA` outside the web root unless you're on Apache with `.htaccess` enabled (`AllowOverride`); the relay can't detect an Apache that ignores `.htaccess`. Elsewhere, the relay refuses to start when the data folder is inside the web root.
- Behind a proxy on another machine, list it in `HUSH_TRUSTED_PROXIES` so limits apply per real client. Local proxies and tunnels are trusted automatically.
- Keep anti-framing headers on: `web/.htaccess` (Apache) and `scripts/router.php` (`php -S`) send them. On Caddy or nginx, add `Content-Security-Policy: frame-ancestors 'none'`.
- Turn off access logs you don't need.
- Behind a Tor onion service, run the Go relay with `-onion`; otherwise every visitor shares one client identity for rate limits. Back up the onion service's key folder and keep it private.
- Keep the host patched. For a phone relay, use a device that still gets security updates.

## Audit log

### 2026-10-31: internal adversarial review (pre-release)

A separate reviewer was given only the code and a threat model. It wrote proof-of-concept exploits for the issues it found. Every confirmed issue below was fixed and has a regression test in `tests/`.

| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 | High | Data folder could be served by URL on nginx, Caddy or `php -S` | `HUSH_DATA` / `relay.config.php`; refuses to run when exposed; hardened router |
| 2 | Medium-high | A malicious relay could replay an old session opening and break or re-route a conversation | Single-use session ids, authenticated timestamps, replay floor after restore, newest session wins |
| 3 | Medium | An oversized relay URL or contact spam could silently stop recovery-backup updates | Strict relay URL validation; unknown senders become requests excluded from backups; sync errors shown |
| 4 | Medium | Unauthenticated writes could fill the disk | Rate limits, per-mailbox quotas, free-disk floor, expiry of stale slots and temp files |
| 5 | Low | `http://localhost:@evil.com` passed relay validation | URL parsing with exact protocol/host checks |
| 6 | Low | Array query parameters caused a 500 error | Type checks on every parameter |
| 7 | Medium | Scanning a crafted invite silently re-routed an existing contact | Confirmation before any change to a known contact |
| 8 | Medium | A web link could open the "move account" screen; pages could be framed | URL link requests ignored on existing accounts; frame-busting and `frame-ancestors` |
| 9 | Medium-low | 8-digit link code; the new device accepted any account | 12-digit code; the new device confirms which account it is receiving |
| 10 | Medium-low | Idle long-polls could tie up every relay worker | Concurrent long-polls capped per client; unused mailboxes answer quickly |
| 11 | Low | A stranger could use a contact's display name | Message requests, unverified tags, safety numbers |
| 12 | Low | Messages lost to a local storage error were deleted from the relay | Kept on the relay and retried |
| 13 | Low | Imported account bundles weren't consistency-checked | Mailbox, key and relay checks on import |

### 2026-10-31: second review (of the fixes)

The same reviewer re-tested every fix. The replay, cryptography, input, invite, link and import fixes held, and simultaneous session starts still converge. It found 7 further issues, now fixed with regression tests:

| # | Severity | Finding | Fix |
|---|---|---|---|
| 14 | High | Behind a tunnel or proxy, every user shared one rate-limit identity, so one attacker could block delivery for all; capped apps also polled in a tight loop | Real client address from local proxies (`CF-Connecting-IP`, `X-Forwarded-For`); `429` + `Retry-After`; client never polls faster than every 1.5 s |
| 15 | Medium | A contact's new device with a slow clock could leave the conversation stuck on the old session | Sessions chosen by arrival, not timestamps; a reset on a freshly opened session always takes over |
| 16 | Medium-low | After recovering with words, replay protection only reached back to the last backup sync | Replay floor set to the moment of recovery |
| 17 | Low | A far-future timestamp could freeze a contact's mailbox updates | Timestamps clamped to local time plus allowed skew |
| 18 | Low | A data folder elsewhere under the document root passed the exposure check | Also checked against the server's document root |
| 19 | Low | The largest allowed account didn't fit the relay's limits | Limits raised; a worst-case 500-contact account is tested |
| 20 | Low | Message requests could fill the contact limit and block real new contacts | Requests capped separately (200, oldest dropped); a Delete button for requests |
