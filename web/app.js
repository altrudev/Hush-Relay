'use strict';
// Hush Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev) and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
/* Hush Relay v0.3 — end-to-end encrypted 1:1 messenger. Vanilla JS, WebCrypto only.
 *
 * What a relay stores:
 *   ephPub(65) | iv(12) | AES-GCM(K_outer, padded JSON inner)
 *   K_outer = HKDF(ECDH(ephemeral, recipientIdentity))
 *   inner   = { v:2, f: senderIdentityPub, b: senderBox, r: senderRelay, n: senderName,
 *               s: sessionId, h: ratchetHeader, c: ciphertext }
 * The outer layer hides sender and ratchet headers from the relay. Bodies use a
 * Signal-style Double Ratchet (forward secrecy + post-compromise healing).
 * Each session's root secret = HKDF(ECDH(identityA, identityB), sessionId), so
 * only the real holder of the sender's identity key can produce a message that
 * decrypts — that is the sender authentication.
 */

const enc = new TextEncoder(), dec = new TextDecoder();
const ALG = { name: 'ECDH', namedCurve: 'P-256' };
const MAX_SKIP = 200;

const rand = n => crypto.getRandomValues(new Uint8Array(n));
const u8 = b => new Uint8Array(b);
const hex = b => Array.from(u8(b), x => x.toString(16).padStart(2, '0')).join('');
function b64e(buf) {
  const a = u8(buf); let s = '';
  for (let i = 0; i < a.length; i += 0x8000) s += String.fromCharCode.apply(null, a.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64d(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}
const sha = async d => hex(await crypto.subtle.digest('SHA-256', typeof d === 'string' ? enc.encode(d) : d));
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let i = 0;
  for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
}
const isBox = b => typeof b === 'string' && /^[0-9a-f]{32}$/.test(b);
// A relay address must be a plain https URL (http only for local testing), short, with no credentials.
function isRelay(r) {
  if (typeof r !== 'string' || r.length > 256 || /[\s"'<>\\]/.test(r)) return false;
  let u; try { u = new URL(r); } catch { return false; }
  if (u.username || u.password || u.hash || u.search) return false;
  if (u.protocol === 'https:') return true;
  const localApp = typeof location === 'undefined' || /^(localhost|127\.0\.0\.1)$/.test(location.hostname);
  return u.protocol === 'http:' && /^(localhost|127\.0\.0\.1)$/.test(u.hostname) && localApp;
}
const MAX_CLOCK_SKEW = 10 * 60000;

// ---------- primitives ----------
const importPub = raw => crypto.subtle.importKey('raw', typeof raw === 'string' ? b64d(raw) : raw, ALG, true, []);
const dh = async (priv, pubB64) => u8(await crypto.subtle.deriveBits({ name: 'ECDH', public: await importPub(pubB64) }, priv, 256));
async function hkdf(ikm, salt, info, bytes) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return u8(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('hush/v2/' + info) }, k, bytes * 8));
}
async function hmac(key, byte) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return u8(await crypto.subtle.sign('HMAC', k, new Uint8Array([byte])));
}
const aesKey = (raw, use) => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, [use]);
async function aesEnc(raw, pt, ad) {
  const iv = rand(12);
  return concat(iv, u8(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: ad }, await aesKey(raw, 'encrypt'), pt)));
}
async function aesDec(raw, data, ad) {
  return u8(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12), additionalData: ad }, await aesKey(raw, 'decrypt'), data.slice(12)));
}
async function genKP() {
  const kp = await crypto.subtle.generateKey(ALG, false, ['deriveBits']);
  return { priv: kp.privateKey, pub: b64e(await crypto.subtle.exportKey('raw', kp.publicKey)) };
}
// Pad to fixed buckets so the relay learns only a coarse size class.
function pad(str) {
  const b = enc.encode(str);
  const L = [1024, 4096, 16384, 32768].find(x => x >= b.length) || b.length;
  const out = new Uint8Array(L).fill(0x20); out.set(b); return out; // trailing spaces are valid JSON
}

// ---------- identity ----------
async function newIdentity(name, relay) {
  const kp = await crypto.subtle.generateKey(ALG, true, ['deriveBits']); // extractable only so it can go into an encrypted backup
  const pub = b64e(await crypto.subtle.exportKey('raw', kp.publicKey));
  const secret = hex(rand(32));
  const box = (await sha(secret)).slice(0, 32);
  return { priv: kp.privateKey, pub, secret, box, name, relay };
}
const contactId = async pubB64 => (await sha(b64d(pubB64))).slice(0, 32);
async function safetyNumber(pubA, pubB) {
  const [x, y] = [pubA, pubB].sort();
  return (await sha(concat(b64d(x), b64d(y)))).slice(0, 40).match(/.{5}/g).join(' ');
}

// ---------- Double Ratchet ----------
async function kdfRK(rk, dhOut) { const o = await hkdf(dhOut, rk, 'rk', 64); return [o.slice(0, 32), o.slice(32)]; }
async function kdfCK(ck) { return [await hmac(ck, 2), await hmac(ck, 1)]; } // [next chain key, message key]
async function rootSecret(me, peerPub, sid) { return hkdf(await dh(me.priv, peerPub), b64d(sid), 'root', 32); }

async function initInitiator(me, peerPub) {
  const sid = b64e(rand(16));
  const DHs = await genKP();
  const [RK, CKs] = await kdfRK(await rootSecret(me, peerPub, sid), await dh(DHs.priv, peerPub));
  return { sid, DHs, DHr: peerPub, RK, CKs, CKr: null, Ns: 0, Nr: 0, PN: 0, skipped: {}, ts: Date.now() };
}
async function initResponder(me, peerPub, sid) {
  return { sid, DHs: { priv: me.priv, pub: me.pub }, DHr: null, RK: await rootSecret(me, peerPub, sid),
    CKs: null, CKr: null, Ns: 0, Nr: 0, PN: 0, skipped: {}, ts: Date.now() };
}
async function ratchetEncrypt(st, pt, ad) {
  const [ck, mk] = await kdfCK(st.CKs); st.CKs = ck;
  const h = { dh: st.DHs.pub, pn: st.PN, n: st.Ns }; st.Ns++;
  return { h, c: await aesEnc(mk, pt, concat(ad, enc.encode(JSON.stringify(h)))) };
}
async function skipKeys(st, until) {
  if (!st.CKr) return;
  if (until - st.Nr > MAX_SKIP) throw new Error('too many skipped messages');
  while (st.Nr < until) {
    const [ck, mk] = await kdfCK(st.CKr); st.CKr = ck;
    st.skipped[st.DHr + ':' + st.Nr] = mk; st.Nr++;
  }
  const keys = Object.keys(st.skipped);
  for (const k of keys.slice(0, Math.max(0, keys.length - 500))) delete st.skipped[k];
}
// Works on a copy; the caller commits the returned state only if decryption succeeded.
async function ratchetDecrypt(st0, h, c, ad) {
  const st = { ...st0, skipped: { ...st0.skipped } };
  const fullAd = concat(ad, enc.encode(JSON.stringify({ dh: h.dh, pn: h.pn, n: h.n })));
  const sk = h.dh + ':' + h.n;
  if (st.skipped[sk]) { const mk = st.skipped[sk]; delete st.skipped[sk]; return [st, await aesDec(mk, c, fullAd)]; }
  if (h.dh !== st.DHr) {
    await skipKeys(st, h.pn);
    st.PN = st.Ns; st.Ns = 0; st.Nr = 0; st.DHr = h.dh;
    [st.RK, st.CKr] = await kdfRK(st.RK, await dh(st.DHs.priv, st.DHr));
    st.DHs = await genKP();
    [st.RK, st.CKs] = await kdfRK(st.RK, await dh(st.DHs.priv, st.DHr));
  }
  await skipKeys(st, h.n);
  const [ck, mk] = await kdfCK(st.CKr); st.CKr = ck; st.Nr++;
  return [st, await aesDec(mk, c, fullAd)];
}

// ---------- envelope ----------
async function sealOuter(obj, toPub) {
  const eph = await genKP(), ephRaw = b64d(eph.pub);
  const key = await hkdf(await dh(eph.priv, toPub), new Uint8Array(32), 'outer', 32);
  return concat(ephRaw, await aesEnc(key, pad(JSON.stringify(obj)), ephRaw));
}
async function openOuter(me, bytes) {
  const ephRaw = bytes.slice(0, 65);
  const key = await hkdf(await dh(me.priv, b64e(ephRaw)), new Uint8Array(32), 'outer', 32);
  return JSON.parse(dec.decode(await aesDec(key, bytes.slice(65), ephRaw)));
}

// c = contact object { pub, sessions:{}, active }. Mutates c.sessions; caller persists c.
async function encryptFor(me, c, msg) {
  let st = c.active && c.sessions[c.active];
  if (!st || !st.CKs) {
    st = await initInitiator(me, c.pub);
    st.mine = true;
    c.sessions[st.sid] = st; c.active = st.sid;
    c.usedSids = [...(c.usedSids || []), st.sid].slice(-300);
  }
  const { h, c: ct } = await ratchetEncrypt(st, enc.encode(JSON.stringify(msg)), enc.encode(me.pub + '|' + c.pub));
  st.ts = Date.now();
  return sealOuter({ v: 2, f: me.pub, b: me.box, r: me.relay, n: me.name, s: st.sid, h, c: b64e(ct) }, c.pub);
}
async function decryptFrom(me, c, inner) {
  const h = inner.h;
  if (!h || typeof h.dh !== 'string' || !Number.isInteger(h.n) || !Number.isInteger(h.pn) || h.n < 0 || h.pn < 0 ||
      typeof inner.s !== 'string' || typeof inner.c !== 'string') throw new Error('bad header');
  const isNew = !c.sessions[inner.s];
  // A session id is only ever started once: a relay replaying an old opening message is refused.
  if (isNew && (c.usedSids || []).includes(inner.s)) throw new Error('replayed session');
  const st = c.sessions[inner.s] || await initResponder(me, c.pub, inner.s);
  const [ns, pt] = await ratchetDecrypt(st, h, b64d(inner.c), enc.encode(c.pub + '|' + me.pub));
  const msg = JSON.parse(dec.decode(pt));
  if (typeof msg !== 'object' || msg === null || !Number.isFinite(msg.ts)) throw new Error('bad message');
  // Opening messages from before this copy of the account existed are replays.
  if (isNew && msg.ts < (c.floor || 0) - MAX_CLOCK_SKEW) throw new Error('stale session');
  // Commit only now that the message is authentic and fresh.
  const cur = c.active && c.sessions[c.active];
  ns.ts = Date.now(); ns.got = true;
  c.sessions[inner.s] = ns;
  c.opened = null;
  if (isNew) {
    c.usedSids = [...(c.usedSids || []), inner.s].slice(-300);
    c.opened = inner.s; // the UI acts on resets only for freshly opened sessions
    // A freshly opened session from the peer becomes the one we answer on. The single exception keeps
    // two people who both started a session at the same moment from swapping forever: if our own
    // session has not been answered yet, both sides keep whichever session id sorts first.
    const tie = cur && cur.mine && !cur.got;
    c.active = tie && c.active < inner.s ? c.active : inner.s;
  } else if (!cur) c.active = inner.s;
  c.lastTs = Math.max(c.lastTs || 0, Math.min(msg.ts, Date.now() + MAX_CLOCK_SKEW));
  const ids = Object.keys(c.sessions).sort((a, b) => c.sessions[b].ts - c.sessions[a].ts);
  for (const id of ids.slice(4)) if (id !== c.active) delete c.sessions[id];
  return msg;
}

// ---------- account bundles (identity + contact list, never ratchet state) ----------
async function backupData(me, contacts) {
  return {
    v: 3,
    me: { jwk: await crypto.subtle.exportKey('jwk', me.priv), pub: me.pub, secret: me.secret, box: me.box,
          name: me.name, relay: me.relay, rec: me.rec || null },
    at: Date.now(),
    // Unanswered message requests are left out, so strangers cannot bloat the backup.
    contacts: contacts.filter(c => !c.request).slice(0, 500)
      .map(c => ({ pub: c.pub, box: c.box, relay: c.relay, name: c.name, verified: !!c.verified, blocked: !!c.blocked }))
  };
}
async function restoreData(data) {
  if (!data || !data.me || !data.me.jwk) throw new Error('not a Hush account');
  const { jwk, ...rest } = data.me;
  const priv = await crypto.subtle.importKey('jwk', jwk, ALG, true, ['deriveBits']);
  // Prove the private key matches the claimed public key before trusting the bundle.
  const probe = await genKP();
  const a = await dh(priv, probe.pub), b = await dh(probe.priv, rest.pub);
  if (hex(a) !== hex(b)) throw new Error('key mismatch');
  if (typeof rest.secret !== 'string' || !/^[0-9a-f]{64}$/.test(rest.secret) || (await sha(rest.secret)).slice(0, 32) !== rest.box)
    throw new Error('mailbox mismatch');
  if (!isRelay(rest.relay)) throw new Error('bad relay address');
  rest.name = String(rest.name || '').slice(0, 40);
  return { me: { ...rest, priv }, contacts: Array.isArray(data.contacts) ? data.contacts.slice(0, 1000) : [], at: Number(data.at) || Date.now() };
}

// Passphrase-protected backup file
async function passKey(pass, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits']);
  return u8(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 }, k, 256));
}
async function exportBackup(me, contacts, pass) {
  const salt = rand(16);
  const data = await backupData(me, contacts);
  return 'HUSH3.' + b64e(salt) + '.' + b64e(await aesEnc(await passKey(pass, salt), enc.encode(JSON.stringify(data)), enc.encode('hush-backup')));
}
async function importBackup(text, pass) {
  const [tag, s, d] = String(text).trim().split('.');
  if (!/^HUSH[23]$/.test(tag) || !s || !d) throw new Error('not a Hush backup');
  return restoreData(JSON.parse(dec.decode(await aesDec(await passKey(pass, b64d(s)), b64d(d), enc.encode('hush-backup')))));
}

// Recovery words: 6 random BIP39 words = 66 bits. PBKDF2 turns them into
// a slot locator, a write token and an encryption key. The relay sees only the
// locator and sha256(token), so even its host cannot open or replace the backup.
const WORDS = typeof module !== 'undefined' ? require('./vendor/words.js') : self.HUSH_WORDS;
function genWords() {
  return Array.from(crypto.getRandomValues(new Uint16Array(6)), n => WORDS[n & 2047]).join(' ');
}
function normWords(text) {
  const parts = String(text).toLowerCase().split(/[^a-z]+/).filter(Boolean);
  if (parts.length !== 6) throw new Error('Enter exactly 6 words');
  return parts.map(p => {
    if (WORDS.includes(p)) return p;
    const m = p.length >= 4 ? WORDS.filter(w => w.startsWith(p.slice(0, 4))) : [];
    if (m.length === 1) return m[0];
    throw new Error('"' + p + '" is not one of the recovery words');
  }).join(' ');
}
async function recoveryKeys(words) {
  const k = await crypto.subtle.importKey('raw', enc.encode(normWords(words)), 'PBKDF2', false, ['deriveBits']);
  const o = u8(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode('hush/recovery/v1'), iterations: 600000 }, k, 640));
  return { l: hex(o.slice(0, 16)), t: hex(o.slice(16, 48)), k: b64e(o.slice(48, 80)) };
}
async function sealRecovery(rec, data) {
  return b64e(await aesEnc(b64d(rec.k), enc.encode(JSON.stringify(data)), enc.encode('hush-recovery:' + rec.l)));
}
async function openRecovery(rec, d) {
  return JSON.parse(dec.decode(await aesDec(b64d(rec.k), b64d(d), enc.encode('hush-recovery:' + rec.l)))); // raw bundle; adopt() verifies it
}

// Short code shown on both devices during linking, so a swapped QR is noticed.
async function linkCode(pub) {
  // 12 digits (~40 bits): grinding a matching key inside the 10-minute window is impractical.
  const h = await sha(b64d(pub));
  return String(BigInt('0x' + h.slice(0, 16)) % 1000000000000n).padStart(12, '0').replace(/(\d{4})(\d{4})(\d{4})/, '$1 $2 $3');
}

if (typeof module !== 'undefined') module.exports = {
  newIdentity, encryptFor, decryptFrom, sealOuter, openOuter, genKP, safetyNumber, contactId,
  backupData, restoreData, exportBackup, importBackup, genWords, normWords, recoveryKeys, sealRecovery, openRecovery,
  linkCode, isRelay, b64e, b64d, hex, rand, sha
};

// ---------- storage ----------
let db;
function openDB() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('hush2', 1);
    r.onupgradeneeded = () => {
      const d = r.result;
      d.createObjectStore('kv');
      d.createObjectStore('contacts', { keyPath: 'id' });
      d.createObjectStore('messages', { keyPath: 'id', autoIncrement: true }).createIndex('contact', 'contact');
    };
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
function tx(store, mode, fn) {
  return new Promise((res, rej) => {
    const t = db.transaction(store, mode), req = fn(t.objectStore(store));
    t.oncomplete = () => res(req && req.result);
    t.onerror = () => rej(t.error);
  });
}
const kvGet = k => tx('kv', 'readonly', s => s.get(k));
const kvSet = (k, v) => tx('kv', 'readwrite', s => s.put(v, k));
const saveContact = c => tx('contacts', 'readwrite', s => s.put(c));
const dropContact = id => tx('contacts', 'readwrite', s => s.delete(id));
const putMessage = m => tx('messages', 'readwrite', s => s.put(m));
const messagesFor = id => tx('messages', 'readonly', s => s.index('contact').getAll(id));

// ---------- app ----------
if (typeof document !== 'undefined') (() => {
  const $ = s => document.querySelector(s);
  const TP = { 'Content-Type': 'text/plain' };
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  let me = null, current = null, started = false, paused = false;
  const contacts = new Map(), seen = new Set(), locks = new Map();
  // Serialize ratchet work per contact so sends and receives never interleave.
  const lock = (id, fn) => { const p = (locks.get(id) || Promise.resolve()).then(fn); locks.set(id, p.catch(() => {})); return p; };

  const views = ['vSetup', 'vPair', 'vList', 'vScan', 'vLink', 'vChat', 'vSettings'];
  function show(v, title) {
    for (const x of views) $('#' + x).hidden = x !== v;
    $('#title').textContent = title || 'Hush Relay';
    $('#back').hidden = !me || v === 'vList';
    $('#settingsBtn').hidden = v !== 'vList';
    if (v !== 'vChat') current = null;
    if (v !== 'vScan') stopScanner();
  }
  const status = t => { $('#status').textContent = t || ''; };
  const defaultRelay = () => (window.HUSH_CONFIG && window.HUSH_CONFIG.relay) || new URL('relay.php', location.href).href;
  const fromStd = d => Uint8Array.from(atob(d), ch => ch.charCodeAt(0));
  const parseHashData = (text, key) => {
    const m = String(text).match(new RegExp('#' + key + '=([A-Za-z0-9_-]+)'));
    return m ? JSON.parse(dec.decode(b64d(m[1]))) : null;
  };

  // ----- QR -----
  const scripts = {};
  const loadScript = src => scripts[src] || (scripts[src] = new Promise((res, rej) => {
    const s = document.createElement('script'); s.src = src; s.onload = res; s.onerror = rej; document.head.append(s);
  }));
  async function renderQR(img, text) {
    await loadScript('vendor/qrcode.js');
    const q = qrcode(0, 'L'); q.addData(text); q.make();
    img.src = q.createDataURL(6, 3);
  }
  let detector;
  async function decodeQR(src, w, h) {
    if (detector === undefined) {
      detector = null;
      try { if ('BarcodeDetector' in self && (await BarcodeDetector.getSupportedFormats()).includes('qr_code')) detector = new BarcodeDetector({ formats: ['qr_code'] }); } catch {}
    }
    if (detector) { try { const r = await detector.detect(src); if (r[0]) return r[0].rawValue; } catch {} }
    await loadScript('vendor/jsQR.js');
    const s = Math.min(1, 1000 / Math.max(w, h)), cw = Math.round(w * s), ch = Math.round(h * s);
    const cv = document.createElement('canvas'); cv.width = cw; cv.height = ch;
    const ctx = cv.getContext('2d', { willReadFrequently: true }); ctx.drawImage(src, 0, 0, cw, ch);
    const r = self.jsQR(ctx.getImageData(0, 0, cw, ch).data, cw, ch);
    return r ? r.data : null;
  }
  let camera = null;
  async function openScanner() {
    show('vScan', 'Scan QR code');
    $('#scanNote').textContent = 'Point the camera at a Hush QR code, or choose a picture of one.';
    const v = $('#scanVideo');
    try {
      camera = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
      v.srcObject = camera; v.hidden = false; await v.play(); scanTick();
    } catch { v.hidden = true; $('#scanNote').textContent = 'Camera not available. Choose a picture of the QR code instead.'; }
  }
  function stopScanner() { if (camera) { camera.getTracks().forEach(t => t.stop()); camera = null; } }
  async function scanTick() {
    if (!camera) return;
    const v = $('#scanVideo');
    if (v.videoWidth) {
      const t = await decodeQR(v, v.videoWidth, v.videoHeight);
      if (t && camera) { stopScanner(); return handleCode(t); }
    }
    setTimeout(scanTick, 300);
  }
  async function handleCode(text) {
    try {
      if (/#link=/.test(text)) return await showLinkRequest(text);
      if (/#i=/.test(text)) { const c = await addFromInvite(text); return openChat(c.id); }
      throw new Error('That is not a Hush code');
    } catch (e) { alert(e.message); show('vList'); renderList(); }
  }

  // ----- contacts -----
  function newContact(id, p, b, r, n) {
    return { id, pub: p, box: b, relay: r, name: String(n || 'Unknown').slice(0, 40), unread: 0, ts: Date.now(),
      verified: false, blocked: false, sessions: {}, active: null };
  }
  const inviteLink = () => location.origin + location.pathname + '#i=' + b64e(enc.encode(JSON.stringify({ p: me.pub, b: me.box, r: me.relay, n: me.name })));
  async function addFromInvite(text) {
    const o = parseHashData(text, 'i');
    if (!o) throw new Error('That does not look like an invite link');
    if (o.p === me.pub) throw new Error('That is your own invite');
    if (!isBox(o.b) || !isRelay(o.r)) throw new Error('Invite is incomplete');
    await importPub(o.p);
    const id = await contactId(o.p);
    let c = contacts.get(id);
    if (c) {
      if (c.blocked) {
        if (!confirm(c.name + ' is blocked. Unblock them?')) return c;
        c.blocked = false;
      }
      // Invites are not signed, so an invite never silently re-routes an existing contact.
      if ((c.box !== o.b || c.relay !== o.r) &&
          confirm('This invite has a different mailbox for ' + c.name + ' than the one you have. Only switch if they told you they moved. Switch?')) {
        c.box = o.b; c.relay = o.r;
      }
      c.request = false;
    } else { c = newContact(id, o.p, o.b, o.r, o.n); contacts.set(id, c); }
    await saveContact(c); scheduleSync();
    return c;
  }
  async function checkRelay(url) {
    try {
      const r = await fetch(url + '?a=get', { method: 'POST', headers: TP, body: '{}' });
      return r.status === 400 && /^bad/.test((await r.json()).error);
    } catch { return false; }
  }

  // ----- list -----
  function renderList() {
    const ul = $('#contactList'); ul.textContent = '';
    const arr = [...contacts.values()].filter(c => !c.blocked).sort((a, b) => b.ts - a.ts);
    $('#empty').hidden = arr.length > 0;
    for (const c of arr) {
      const li = document.createElement('li'); li.className = 'contact';
      const nm = document.createElement('span'); nm.className = 'nm'; nm.textContent = c.name;
      li.append(nm);
      const tag = c.request ? 'request' : !c.verified ? 'unverified' : '';
      if (tag) { const t = document.createElement('span'); t.className = 'tag'; t.textContent = tag; li.append(t); }
      if (c.unread) { const b = document.createElement('span'); b.className = 'badge'; b.textContent = c.unread; li.append(b); }
      li.onclick = () => openChat(c.id);
      ul.append(li);
    }
  }

  // ----- chat -----
  async function openChat(id) {
    const c = contacts.get(id); if (!c) return;
    show('vChat', c.name); current = id;
    if (c.unread) { c.unread = 0; await saveContact(c); }
    await renderBanner(c);
    await renderMsgs();
  }
  async function renderBanner(c) {
    const el = $('#banner'); el.textContent = '';
    const sn = document.createElement('code'); sn.textContent = await safetyNumber(me.pub, c.pub);
    const p = document.createElement('div');
    p.textContent = c.request
      ? 'Message request from someone not in your contacts. Names can be faked: compare this safety number before trusting it. Replying accepts the request.'
      : c.verified ? 'Verified. Safety number:' : 'Compare this safety number with ' + c.name + ' in person or by call before trusting this chat:';
    el.append(p, sn);
    const row = document.createElement('div'); row.className = 'row'; row.style.margin = '0';
    if (!c.verified) {
      const v = document.createElement('button'); v.textContent = 'Numbers match';
      v.onclick = async () => { c.verified = true; await saveContact(c); scheduleSync(); renderBanner(c); };
      row.append(v);
    }
    if (c.request) {
      const del = document.createElement('button'); del.textContent = 'Delete request';
      del.onclick = async () => { contacts.delete(c.id); await dropContact(c.id); show('vList'); renderList(); };
      row.append(del);
    }
    const bl = document.createElement('button'); bl.textContent = 'Block';
    bl.onclick = async () => { if (!confirm('Block ' + c.name + '?')) return; c.blocked = true; await saveContact(c); scheduleSync(); show('vList'); renderList(); };
    row.append(bl);
    el.append(row);
  }
  async function renderMsgs() {
    if (!current) return;
    const ol = $('#msgs'); ol.textContent = '';
    const list = (await messagesFor(current)).sort((a, b) => a.id - b.id);
    for (const m of list) {
      const li = document.createElement('li');
      li.className = 'm ' + m.dir + (m.state === 'failed' ? ' failed' : '');
      li.textContent = m.txt;
      if (m.dir !== 'sys') {
        const s = document.createElement('small');
        s.textContent = new Date(m.ts).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' }) +
          (m.dir === 'out' ? ' · ' + (m.state === 'failed' ? 'failed, tap to retry' : m.state) : '');
        li.append(s);
      }
      if (m.state === 'failed') li.onclick = () => deliver(contacts.get(m.contact), m);
      ol.append(li);
    }
    ol.scrollTop = ol.scrollHeight;
  }

  async function post(c, msg) {
    const blob = await lock(c.id, async () => { const b = await encryptFor(me, c, msg); await saveContact(c); return b; });
    const r = await fetch(c.relay + '?a=put&box=' + c.box, { method: 'POST', headers: TP, body: blob });
    return r.ok;
  }
  async function deliver(c, m) {
    m.state = 'sending'; await putMessage(m); renderMsgs();
    try { m.state = (await post(c, { t: 'msg', id: m.mid, txt: m.txt, ts: m.ts })) ? 'sent' : 'failed'; }
    catch (e) { console.warn(e); m.state = 'failed'; }
    await putMessage(m); renderMsgs();
  }
  async function send(text) {
    const c = contacts.get(current); if (!c || !text.trim()) return;
    if (c.request) { c.request = false; scheduleSync(); renderBanner(c); }
    const m = { contact: c.id, dir: 'out', txt: text, ts: Date.now(), mid: hex(rand(8)), state: 'sending' };
    m.id = await putMessage(m);
    c.ts = m.ts; await saveContact(c);
    await deliver(c, m);
  }

  // ----- receive (live) -----
  async function receive(bytes) {
    const inner = await openOuter(me, bytes);
    if (inner.v !== 2 || typeof inner.f !== 'string' || inner.f === me.pub) throw new Error('unsupported message');
    const id = await contactId(inner.f);
    await lock(id, async () => {
      let c = contacts.get(id), isNew = false;
      if (c && c.blocked) return;
      if (!c) {
        if (!isBox(inner.b) || !isRelay(inner.r)) throw new Error('bad sender data');
        await importPub(inner.f);
        c = newContact(id, inner.f, inner.b, inner.r, inner.n); isNew = true;
        c.request = true; // a stranger: shown as a request until you reply or accept
      }
      const msg = await decryptFrom(me, c, inner); // throws unless the sender really holds that identity key
      // Only the newest live session may change where we send replies (a replay can't re-route us).
      if (!isNew && c.active === inner.s && isBox(inner.b) && isRelay(inner.r)) {
        c.box = inner.b; c.relay = inner.r;
      }
      if (isNew) {
        // Strangers can't crowd out real contacts: at most 200 open requests, oldest dropped first.
        const reqs = [...contacts.values()].filter(x => x.request).sort((a, b) => a.ts - b.ts);
        for (const old of reqs.slice(0, Math.max(0, reqs.length - 199))) { contacts.delete(old.id); await dropContact(old.id); }
        if ([...contacts.values()].filter(x => !x.request).length >= 5000) return;
      }
      contacts.set(id, c);
      if (msg.t === 'msg' && typeof msg.txt === 'string') {
        const key = id + ':' + msg.id;
        if (!seen.has(key)) {
          seen.add(key);
          await putMessage({ contact: id, dir: 'in', txt: msg.txt.slice(0, 4000), ts: Date.now(), mid: msg.id });
          c.ts = Date.now();
          if (current !== id) c.unread = (c.unread || 0) + 1;
        }
      } else if (msg.t === 'reset' && c.opened === inner.s) {
        // The contact moved to a new device: this new session replaces all earlier ones.
        c.active = inner.s;
        for (const s of Object.keys(c.sessions)) if (s !== inner.s) delete c.sessions[s];
        await putMessage({ contact: id, dir: 'sys', txt: c.name + ' signed in on a new device. Anything sent to them just before may be lost.', ts: Date.now() });
      }
      await saveContact(c);
      if (!c.request) scheduleSync();
    });
  }

  // Live mode: the relay holds each request open until mail arrives (up to 20s).
  async function pollOnce(wait) {
    try {
      const r = await fetch(me.relay + '?a=get&wait=' + wait, { method: 'POST', headers: TP, body: JSON.stringify({ s: me.secret }) });
      if (r.status === 429) { await sleep(1000 * (Number(r.headers.get('Retry-After')) || 5)); return true; }
      if (!r.ok) throw new Error(r.status);
      const items = await r.json();
      if (paused || !me) return true; // leave mail on the relay during an account transfer
      const done = [];
      const STORAGE_ERRORS = ['QuotaExceededError', 'UnknownError', 'AbortError', 'TransactionInactiveError', 'InvalidStateError'];
      for (const it of items) {
        try { await receive(fromStd(it.d)); done.push(it.id); }
        catch (e) {
          // Undecryptable or forged mail is discarded; a local storage failure keeps it on the relay to retry.
          if (STORAGE_ERRORS.includes(e && e.name)) { console.warn('storage error, will retry', e); continue; }
          done.push(it.id); console.warn('dropped message', e);
        }
      }
      if (done.length) {
        await fetch(me.relay + '?a=ack', { method: 'POST', headers: TP, body: JSON.stringify({ s: me.secret, ids: done }) });
        if (current) renderMsgs(); else if (!$('#vList').hidden) renderList();
      }
      status('');
      return true;
    } catch { status('Relay unreachable — retrying'); return false; }
  }
  async function liveLoop() {
    let backoff = 2000;
    while (me) {
      if (paused || document.visibilityState !== 'visible') { await sleep(1000); continue; }
      const t0 = Date.now();
      if (await pollOnce(20)) backoff = 2000;
      else { await sleep(backoff); backoff = Math.min(backoff * 2, 60000); }
      const gap = Date.now() - t0;
      if (gap < 1500) await sleep(1500 - gap); // never poll in a tight loop
    }
  }

  // ----- recovery words -----
  let syncTimer = null;
  function scheduleSync() { if (me && me.rec) { clearTimeout(syncTimer); syncTimer = setTimeout(syncRecovery, 2000); } }
  async function syncRecovery() {
    if (!me || !me.rec) return false;
    try {
      const d = await sealRecovery(me.rec, await backupData(me, [...contacts.values()]));
      const r = await fetch(me.relay + '?a=rput', { method: 'POST', headers: TP, body: JSON.stringify({ l: me.rec.l, t: me.rec.t, d }) });
      if (!r.ok) throw new Error('relay answered ' + r.status);
      if (me.recError) { me.recError = null; await kvSet('me', me); }
      return true;
    } catch (e) {
      console.warn('recovery sync failed', e);
      me.recError = String(e.message || e); await kvSet('me', me);
      status('Recovery backup could not be updated — see Settings');
      return false;
    }
  }
  function renderRecovery() {
    const on = !!(me && me.rec);
    $('#recOn').hidden = !on; $('#recOff').hidden = on; $('#recNew').hidden = true;
    $('#recErr').textContent = on && me.recError ? 'Last update failed: ' + me.recError + '. It retries when your contacts change.' : '';
  }
  let draftWords = null;
  $('#recStart').onclick = () => {
    draftWords = genWords();
    $('#recWords').textContent = draftWords;
    $('#recConfirm').value = '';
    $('#recOff').hidden = true; $('#recNew').hidden = false;
  };
  $('#recSave').onclick = async () => {
    let typed;
    try { typed = normWords($('#recConfirm').value); } catch (e) { return alert(e.message); }
    if (typed !== draftWords) return alert('Those words do not match. Check the order and spelling.');
    status('Setting up recovery…');
    const rec = await recoveryKeys(draftWords);
    const old = me.rec; me.rec = rec;
    if (!(await syncRecovery())) {
      const why = me.recError || ''; me.rec = old; me.recError = null; status('');
      return alert(/429/.test(why) ? 'Your relay limits how many new recovery backups can be created per day. Try again tomorrow.'
        : 'Could not save the recovery backup to your relay (' + why + '). Try again.');
    }
    await kvSet('me', me); draftWords = null; status(''); renderRecovery();
  };
  $('#recCancel').onclick = () => { draftWords = null; renderRecovery(); };
  $('#recDisable').onclick = async () => {
    if (!confirm('Turn off recovery words? Your backup on the relay will be deleted.')) return;
    try { await fetch(me.relay + '?a=rdel', { method: 'POST', headers: TP, body: JSON.stringify({ l: me.rec.l, t: me.rec.t }) }); } catch {}
    me.rec = null; await kvSet('me', me); renderRecovery();
  };
  $('#recoverBtn').onclick = async () => {
    const relay = $('#relayIn').value.trim() || defaultRelay();
    let rec;
    try { status('Checking words…'); rec = await recoveryKeys($('#recoverWords').value); }
    catch (e) { status(''); return alert(e.message); }
    try {
      const r = await fetch(relay + '?a=rget', { method: 'POST', headers: TP, body: JSON.stringify({ l: rec.l }) });
      if (r.status === 404) throw new Error('No account found for those words on this relay. Check the words and the relay address above.');
      if (!r.ok) throw new Error('Relay error ' + r.status);
      const data = await openRecovery(rec, (await r.json()).d);
      data.me.rec = rec;
      await adopt(data);
    } catch (e) { alert(e.message); }
    status('');
  };

  // ----- device linking -----
  // New device: show a one-time QR holding a fresh public key and a mailbox to drop the account into.
  let pairing = null;
  $('#pairBtn').onclick = async () => {
    const relay = $('#relayIn').value.trim() || defaultRelay();
    if (!isRelay(relay)) return alert('Relay must be an https:// URL');
    const kp = await genKP(), secret = hex(rand(32)), box = (await sha(secret)).slice(0, 32);
    const url = location.origin + location.pathname + '#link=' + b64e(enc.encode(JSON.stringify({ r: relay, b: box, e: kp.pub })));
    const my = pairing = { kp, until: Date.now() + 10 * 60000 };
    show('vPair', 'Link this device');
    $('#pairLink').value = url;
    $('#pairCode').textContent = await linkCode(kp.pub);
    renderQR($('#pairQR'), url);
    while (pairing === my && Date.now() < my.until) {
      try {
        const r = await fetch(relay + '?a=get&wait=20', { method: 'POST', headers: TP, body: JSON.stringify({ s: secret }) });
        if (!r.ok) { await sleep(3000); continue; }
        for (const it of await r.json()) {
          let bundle;
          try { bundle = await openOuter(kp, fromStd(it.d)); } catch { continue; }
          if (pairing !== my || !bundle || bundle.t !== 'link') continue;
          const who = bundle.data && bundle.data.me ? String(bundle.data.me.name || '?').slice(0, 40) : '?';
          const n = bundle.data && Array.isArray(bundle.data.contacts) ? bundle.data.contacts.length : 0;
          if (!confirm('Sign in as "' + who + '" with ' + n + ' contact(s)? Only continue if this is your own account.')) continue;
          pairing = null;
          fetch(relay + '?a=ack', { method: 'POST', headers: TP, body: JSON.stringify({ s: secret, ids: [it.id] }) }).catch(() => {});
          try { await adopt(bundle.data); }
          catch (e) { alert('Could not sign in: ' + e.message); show('vSetup'); return; }
          if (bundle.ack && isRelay(bundle.ack.r) && isBox(bundle.ack.b))
            fetch(bundle.ack.r + '?a=put&box=' + bundle.ack.b, { method: 'POST', headers: TP, body: rand(96) }).catch(() => {});
          return;
        }
      } catch { await sleep(3000); }
    }
    if (pairing === my) { pairing = null; alert('This link request expired. Start again.'); show('vSetup'); }
  };
  $('#pairCancel').onclick = () => { pairing = null; show('vSetup'); };
  $('#pairCopy').onclick = async () => { try { await navigator.clipboard.writeText($('#pairLink').value); status('Copied'); setTimeout(() => status(''), 1500); } catch { $('#pairLink').select(); } };

  // Old device: approve, send the account, wait for the new device to confirm, then sign out.
  let pendingLink = null;
  async function showLinkRequest(text) {
    const o = parseHashData(text, 'link');
    if (!o || !isRelay(o.r) || !isBox(o.b) || typeof o.e !== 'string') throw new Error('That link request is damaged');
    await importPub(o.e);
    pendingLink = o;
    show('vLink', 'Move account');
    $('#linkCode').textContent = await linkCode(o.e);
  }
  $('#linkCancel').onclick = () => { pendingLink = null; show('vList'); renderList(); };
  $('#linkApprove').onclick = async () => {
    const o = pendingLink; if (!o) return;
    pendingLink = null; paused = true;
    $('#linkApprove').disabled = true; status('Sending account…');
    const ackSecret = hex(rand(32)), ackBox = (await sha(ackSecret)).slice(0, 32);
    try {
      const bundle = { t: 'link', data: await backupData(me, [...contacts.values()]), ack: { r: me.relay, b: ackBox } };
      const r = await fetch(o.r + '?a=put&box=' + o.b, { method: 'POST', headers: TP, body: await sealOuter(bundle, o.e) });
      if (!r.ok) throw new Error('the relay refused it (' + r.status + ')');
      status('Waiting for the new device to confirm…');
      const until = Date.now() + 120000;
      while (Date.now() < until) {
        const g = await fetch(me.relay + '?a=get&wait=20', { method: 'POST', headers: TP, body: JSON.stringify({ s: ackSecret }) });
        const items = g.ok ? await g.json() : [];
        if (items.length) {
          await fetch(me.relay + '?a=ack', { method: 'POST', headers: TP, body: JSON.stringify({ s: ackSecret, ids: items.map(i => i.id) }) }).catch(() => {});
          return wipe('Your account moved to the new device. This device is now signed out.');
        }
        if (!g.ok) await sleep(2000);
      }
      throw new Error('the new device did not confirm');
    } catch (e) {
      paused = false; status(''); $('#linkApprove').disabled = false;
      alert('Transfer not confirmed: ' + e.message + '. This device stays signed in. If the new device signed in anyway, erase one of them.');
      show('vList'); renderList();
    }
  };

  // Take over an account bundle (link, recovery words or backup file).
  async function adopt(data) {
    const r = await restoreData(data);
    me = r.me; await kvSet('me', me);
    for (const x of r.contacts) {
      if (!isBox(x.box) || !isRelay(x.relay)) continue;
      try { await importPub(x.pub); } catch { continue; }
      const c = newContact(await contactId(x.pub), x.pub, x.box, x.relay, x.name);
      c.verified = !!x.verified; c.blocked = !!x.blocked;
      c.floor = Date.now(); // opening messages from before this copy of the account are replays
      contacts.set(c.id, c); await saveContact(c);
    }
    start();
    // Ratchet state never travels; tell each contact to switch to a fresh session.
    for (const c of contacts.values()) if (!c.blocked) post(c, { t: 'reset', id: hex(rand(8)), ts: Date.now() }).catch(() => {});
  }
  function wipe(msg) {
    me = null; db.close();
    const req = indexedDB.deleteDatabase('hush2');
    req.onsuccess = req.onerror = req.onblocked = () => { if (msg) alert(msg); location.replace(location.pathname); };
  }

  // ----- wiring -----
  $('#back').onclick = () => { show('vList'); renderList(); };
  $('#scanBtn').onclick = openScanner;
  $('#scanFile').onchange = async e => {
    const f = e.target.files[0]; e.target.value = ''; if (!f) return;
    try {
      const bmp = await createImageBitmap(f);
      const t = await decodeQR(bmp, bmp.width, bmp.height);
      if (!t) return alert('No QR code found in that picture');
      stopScanner(); handleCode(t);
    } catch { alert('Could not read that picture'); }
  };
  $('#scanCancel').onclick = () => { show('vList'); renderList(); };
  $('#settingsBtn').onclick = async () => {
    show('vSettings', 'Settings');
    const link = inviteLink();
    $('#inviteLink').value = link;
    renderQR($('#inviteQR'), link);
    $('#myFp').textContent = (await contactId(me.pub)).match(/.{4}/g).join(' ');
    $('#myRelay').textContent = me.relay;
    renderRecovery();
  };
  $('#copyBtn').onclick = async () => { try { await navigator.clipboard.writeText($('#inviteLink').value); status('Copied'); setTimeout(() => status(''), 1500); } catch { $('#inviteLink').select(); } };
  $('#shareBtn').onclick = () => navigator.share ? navigator.share({ text: $('#inviteLink').value }).catch(() => {}) : $('#copyBtn').click();
  $('#exportBtn').onclick = async () => {
    const p1 = $('#bp1').value, p2 = $('#bp2').value;
    if (p1.length < 12) return alert('Use a passphrase of at least 12 characters');
    if (p1 !== p2) return alert('Passphrases do not match');
    status('Encrypting backup…');
    try {
      const text = await exportBackup(me, [...contacts.values()], p1);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([text], { type: 'application/octet-stream' }));
      a.download = 'hush-backup-' + new Date().toISOString().slice(0, 10) + '.hush';
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 10000);
      $('#bp1').value = $('#bp2').value = '';
      status('');
    } catch (e) { status(''); alert('Backup failed: ' + e.message); }
  };
  $('#wipeBtn').onclick = () => {
    if (confirm('Erase your identity, contacts and messages from this device? Without recovery words or a backup this cannot be undone.')) wipe();
  };
  $('#addBtn').onclick = () => { const v = $('#addIn').value; $('#addIn').value = ''; handleCode(v); };
  $('#composer').onsubmit = e => { e.preventDefault(); const t = $('#txt').value; $('#txt').value = ''; send(t); };
  $('#txt').onkeydown = e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); $('#composer').requestSubmit(); } };
  $('#createBtn').onclick = async () => {
    const name = $('#nameIn').value.trim(), relay = $('#relayIn').value.trim();
    if (!name) return alert('Enter a name');
    if (!isRelay(relay)) return alert('Relay must be an https:// URL');
    status('Checking relay…');
    const ok = await checkRelay(relay); status('');
    if (!ok && !confirm('That relay did not answer like a Hush relay. Use it anyway?')) return;
    me = await newIdentity(name, relay);
    await kvSet('me', me);
    start();
  };
  $('#restoreBtn').onclick = async () => {
    const f = $('#restoreFile').files[0], pass = $('#restorePass').value;
    if (!f || !pass) return alert('Choose a backup file and enter its passphrase');
    status('Decrypting backup…');
    let data;
    try {
      const [tag, s, d] = (await f.text()).trim().split('.');
      if (!/^HUSH[23]$/.test(tag)) throw 0;
      data = JSON.parse(dec.decode(await aesDec(await passKey(pass, b64d(s)), b64d(d), enc.encode('hush-backup'))));
    } catch { status(''); return alert('Could not open the backup: wrong passphrase or damaged file'); }
    try { await adopt(data); } catch (e) { alert(e.message); }
    status('');
  };

  async function handleHash() {
    const h = location.hash;
    if (!/^#(i|link)=/.test(h)) return;
    history.replaceState(null, '', location.pathname);
    if (/^#link=/.test(h)) return alert('To move your account, open Scan in the app and scan the code shown on the new device.');
    handleCode(h);
  }

  function start() {
    show('vList'); renderList(); handleHash();
    if (started) return; started = true;
    liveLoop();
  }

  (async () => {
    // Refuse to run inside another site's frame (clickjacking).
    if (window.top !== window.self) { document.body.textContent = 'Hush Relay cannot run inside another page.'; return; }
    // IPFS path gateways (gateway.example/ipfs/<cid>/) put every IPFS site on one origin,
    // so any of them could read this app's storage. Only run on an origin of our own.
    if (/^\/(ipfs|ipns)\//.test(location.pathname)) {
      document.body.textContent = 'Open Hush from its own domain or a subdomain gateway (https://<cid>.ipfs.dweb.link/). ' +
        'Path-style IPFS gateways share storage with every other IPFS site, which would expose your keys.';
      return;
    }
    if (!window.isSecureContext || !crypto.subtle) { document.body.textContent = 'Hush needs HTTPS.'; return; }
    db = await openDB();
    me = await kvGet('me');
    for (const c of (await tx('contacts', 'readonly', s => s.getAll())) || []) contacts.set(c.id, c);
    if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
    if (me) return start();
    $('#relayIn').value = defaultRelay();
    show('vSetup');
    if (/^#link=/.test(location.hash)) {
      history.replaceState(null, '', location.pathname);
      alert('This is a request to move an account onto a new device. Open it (or scan it) on the device that already has your account.');
    }
  })();
})();
