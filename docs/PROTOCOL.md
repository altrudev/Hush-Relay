# Hush Relay protocol (v3)

All cryptography uses the browser's WebCrypto API: ECDH P-256, HKDF-SHA-256, HMAC-SHA-256, AES-256-GCM and PBKDF2-SHA-256. Encodings are base64url without padding unless noted.

## Identity and mailbox

- **Identity key:** an ECDH P-256 key pair generated on the device. The public key (65-byte raw, base64url) is the identity.
- **Mailbox:** `secret` = 32 random bytes as hex, and `box` = first 32 hex characters of `SHA-256(secret)`. Anyone may deliver to `box`; reading and deleting require `secret`, which is only ever sent in a POST body.
- **Contact id:** the first 32 hex characters of `SHA-256(rawPub)`. A different key is a different contact.
- **Safety number:** `SHA-256(pubA ‖ pubB)` with the two keys sorted. The first 40 hex characters are shown in groups of 5.
- **Invite:** `https://<app>/#i=` followed by `base64url(JSON {p: pub, b: box, r: relayURL, n: name})`. It travels in the URL fragment, so it never reaches a server.

## Envelope (what the relay stores)

```
ephPub (65) | iv (12) | AES-GCM(K_outer, pad(JSON inner), AD = ephPub)
K_outer = HKDF(ECDH(eph, recipientIdentity), salt = 0^32, info = "hush/v2/outer")
inner   = { v: 2, f: senderPub, b: senderBox, r: senderRelay, n: senderName,
            s: sessionId, h: {dh, pn, n}, c: ratchetCiphertext }
```

`pad` adds trailing spaces up to 1, 4, 16 or 32 KiB. A fresh ephemeral key per message hides the sender from the relay. The relay sees only the recipient's box, the time and the size bucket.

## Double Ratchet

The construction follows Signal's Double Ratchet specification, without header encryption (the outer layer already hides headers from the relay).

- **Session root:** `HKDF(ECDH(idSelf, idPeer), salt = sessionId, info = "hush/v2/root")`. `sessionId` is 16 random bytes chosen by whoever starts the session. Only the two identity holders can derive the root, which is what authenticates the sender.
- **Initiator:** generates a ratchet key `DHs`, sets `DHr` to the peer's identity key, then runs `RK, CKs = KDF_RK(root, ECDH(DHs, peerId))`.
- **Responder:** uses its identity key as its first `DHs` and creates the session when the first message for an unknown `sessionId` arrives.
- **KDF_RK:** `HKDF(dhOut, salt = RK, info = "hush/v2/rk")` produces 64 bytes, giving the new `RK` and a chain key.
- **KDF_CK:** `next = HMAC(CK, 0x02)` and `mk = HMAC(CK, 0x01)`.
- **Message encryption:** AES-GCM with `mk`, a random 12-byte IV, and `AD = senderPub "|" recipientPub ‖ JSON(header)`.
- **Out-of-order messages:** up to 200 skipped keys per step, 500 stored in total.
- **Failure handling:** decryption runs on a copy of the state, and the state is saved only if it succeeds.
- **Several sessions per contact:** sessions are keyed by `sessionId`. Receiving on a session makes it the active one, and the 4 most recent are kept, so two people starting at the same time converge.

Message bodies are JSON: `{t: "msg", id, txt, ts}` or `{t: "reset", id, ts}`. A reset is sent after an account moves to a new device, because ratchet state never travels.

## Relay API (all POST, at `/relay.php`; the Go relay also answers at `/relay`)

| Action | Request | Result |
|---|---|---|
| `?a=put&box=<32hex>` | raw envelope bytes (93 bytes to 256 KiB) | `{ok}`; at most 500 pending per box |
| `?a=get&wait=<0..20>` | `{"s": secret}` | `[{id, d: base64}]`, waiting up to `wait` seconds for mail |
| `?a=ack` | `{"s": secret, "ids": [...]}` | deletes delivered mail |
| `?a=rput` | `{"l": 32hex, "t": 64hex, "d": b64url}` | stores a recovery slot; an existing slot needs the same `t` |
| `?a=rget` | `{"l"}` | `{d}` or 404 |
| `?a=rdel` | `{"l", "t"}` | deletes a slot |

Undelivered mail expires after 14 days. The relay keeps `sha256(t)`, never `t`.

## Recovery words

- **The words:** 6 random words from the BIP39 English list, which is 66 bits.
- **Key derivation:** `PBKDF2(words, salt = "hush/recovery/v1", 600 000 iterations)` produces 80 bytes, split into the locator `l` (16 bytes, hex), the write token `t` (32 bytes, hex) and the key `k` (32 bytes).
- **The slot:** it holds `AES-GCM(k, JSON account, AD = "hush-recovery:" + l)`, re-uploaded whenever the contact list changes.
- **The account bundle:** `{v: 3, me: {jwk, pub, secret, box, name, relay, rec}, contacts: [{pub, box, relay, name, verified, blocked}]}`. When importing, the device checks that the private key actually matches `pub`.

## Moving to a new device

1. The new device creates an ephemeral key pair `E` and a temporary mailbox. It shows `https://<app>/#link=` followed by `base64url({r, b, e: E.pub})` as a QR code. It also shows the 12-digit code `SHA-256(E.pub)[0..16 hex] mod 10^12`.
2. The old device scans the QR, shows the same code, and waits for the user to approve.
3. The old device seals `{t: "link", data: accountBundle, ack: {r, b: ackBox}}` to `E.pub` with the envelope's outer layer, delivers it, and waits up to 2 minutes for any message in `ackBox`.
4. The new device opens the bundle, imports it, sends the acknowledgement, and sends `reset` to every contact.
5. The old device erases itself only after the acknowledgement arrives.

## Encrypted backup file

`HUSH3.` + `b64url(salt)` + `.` + `b64url(AES-GCM(PBKDF2(passphrase, salt, 600 000), bundle, AD = "hush-backup"))`
