// Hush Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev) and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

func newTestRelay(t *testing.T, onion bool) (*Relay, http.Handler) {
	t.Helper()
	r, err := NewRelay(t.TempDir(), []string{"10.0.0.9"}, onion)
	if err != nil {
		t.Fatal(err)
	}
	site := fstest.MapFS{
		"index.html":    {Data: []byte("<!doctype html>app")},
		"app.js":        {Data: []byte("x")},
		"vendor/q.js":   {Data: []byte("q")},
		".htaccess":     {Data: []byte("secret")},
		"relay.php":     {Data: []byte("<?php")},
		"data/x/1.m":    {Data: []byte("mail")},
		"embed.go":      {Data: []byte("package web")},
		"notes.md":      {Data: []byte("#")},
		"sub/.hidden":   {Data: []byte("h")},
		"img/a.svg":     {Data: []byte("<svg/>")},
		"manifest.json": {Data: []byte("{}")},
	}
	return r, newMux(r, site)
}

type call struct {
	method, url, body, remote string
	hdr                       map[string]string
}

func do(h http.Handler, c call) (*httptest.ResponseRecorder, map[string]any) {
	if c.method == "" {
		c.method = http.MethodPost
	}
	req := httptest.NewRequest(c.method, c.url, strings.NewReader(c.body))
	if c.remote != "" {
		req.RemoteAddr = c.remote
	}
	for k, v := range c.hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec, m
}

func secret(n int) string   { return fmt.Sprintf("%064x", n) }
func boxOf(s string) string { return sha256hex(s)[:32] }
func blob(n int) string     { return strings.Repeat("e", n) }

func TestPutGetAckRoundTrip(t *testing.T) {
	_, h := newTestRelay(t, false)
	s := secret(1)
	if rec, _ := do(h, call{url: "/relay.php?a=put&box=" + boxOf(s), body: blob(100)}); rec.Code != 200 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	rec, _ := do(h, call{url: "/relay.php?a=get", body: `{"s":"` + s + `"}`})
	var items []envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &items); err != nil || len(items) != 1 || len(items[0].ID) != 22 {
		t.Fatalf("get: %s", rec.Body)
	}
	do(h, call{url: "/relay.php?a=ack", body: `{"s":"` + s + `","ids":["` + items[0].ID + `"]}`})
	rec, _ = do(h, call{url: "/relay.php?a=get", body: `{"s":"` + s + `"}`})
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("after ack want [] got %s", rec.Body)
	}
}

func TestValidationMatchesPHP(t *testing.T) {
	_, h := newTestRelay(t, false)
	cases := []struct {
		c    call
		code int
		err  string
	}{
		{call{method: "GET", url: "/relay.php"}, 405, ""},
		{call{url: "/relay.php?a=get", body: "{}"}, 400, "bad s"},
		{call{url: "/relay.php?a=get", body: `{"s":"` + strings.Repeat("AB", 32) + `"}`}, 400, "bad s"},
		{call{url: "/relay.php?a=nope", body: `{"s":"` + secret(1) + `"}`}, 400, "bad action"},
		{call{url: "/relay.php?a=put&box[]=1", body: blob(100)}, 400, "bad box"},
		{call{url: "/relay.php?a=put&box=" + boxOf(secret(1)) + "&box=" + boxOf(secret(2)), body: blob(100)}, 400, "bad box"},
		{call{url: "/relay.php?a=put&box=" + boxOf(secret(1)), body: blob(80)}, 413, "bad size"},
		{call{url: "/relay.php?a=put&box=" + boxOf(secret(1)), body: blob(maxBlob + 1)}, 413, "bad size"},
		{call{url: "/relay.php?a=rget", body: `{"l":"zz"}`}, 400, "bad l"},
		{call{url: "/relay.php?a=rput", body: `{"l":"` + secret(1)[:32] + `"}`}, 400, "bad t"},
		{call{url: "/relay.php?a=rput", body: `{"l":"` + secret(1)[:32] + `","t":"` + secret(2) + `","d":"a b"}`}, 400, "bad data"},
	}
	for i, tc := range cases {
		rec, m := do(h, tc.c)
		if rec.Code != tc.code || (tc.err != "" && m["error"] != tc.err) {
			t.Errorf("case %d (%s): got %d %v, want %d %q", i, tc.c.url, rec.Code, m, tc.code, tc.err)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "*" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("case %d: missing relay headers", i)
		}
	}
}

func TestLongPollWakesOnPut(t *testing.T) {
	_, h := newTestRelay(t, false)
	s := secret(3)
	do(h, call{url: "/relay.php?a=put&box=" + boxOf(s), body: blob(100)}) // box becomes known
	rec, _ := do(h, call{url: "/relay.php?a=get", body: `{"s":"` + s + `"}`})
	var items []envelope
	_ = json.Unmarshal(rec.Body.Bytes(), &items)
	do(h, call{url: "/relay.php?a=ack", body: `{"s":"` + s + `","ids":["` + items[0].ID + `"]}`})

	done := make(chan time.Duration)
	start := time.Now()
	go func() {
		do(h, call{url: "/relay.php?a=get&wait=10", body: `{"s":"` + s + `"}`})
		done <- time.Since(start)
	}()
	time.Sleep(300 * time.Millisecond)
	do(h, call{url: "/relay.php?a=put&box=" + boxOf(s), body: blob(100)})
	select {
	case d := <-done:
		if d > 2*time.Second {
			t.Fatalf("long-poll woke after %v", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("long-poll did not wake on put")
	}
}

func TestUnknownMailboxDoesNotHoldConnection(t *testing.T) {
	_, h := newTestRelay(t, false)
	start := time.Now()
	do(h, call{url: "/relay.php?a=get&wait=20", body: `{"s":"` + secret(99) + `"}`})
	if d := time.Since(start); d > 4*time.Second || d < 2*time.Second {
		t.Fatalf("unknown mailbox waited %v, want about 3s", d)
	}
}

func TestLiveConnectionsCappedPerClient(t *testing.T) {
	_, h := newTestRelay(t, false)
	codes := make(chan int, 10)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := secret(100 + i)
			rec, _ := do(h, call{url: "/relay.php?a=get&wait=2", body: `{"s":"` + s + `"}`, remote: "198.51.100.7:5000"})
			codes <- rec.Code
		}(i)
	}
	wg.Wait()
	close(codes)
	n429 := 0
	for c := range codes {
		if c == 429 {
			n429++
		}
	}
	if n429 != 2 {
		t.Fatalf("want 2 refused live connections, got %d", n429)
	}
	if rec, _ := do(h, call{url: "/relay.php?a=get&wait=1", body: `{"s":"` + secret(200) + `"}`, remote: "203.0.113.9:5000"}); rec.Code != 200 {
		t.Fatalf("other client refused: %d", rec.Code)
	}
}

func TestForwardedHeadersTrustedOnlyFromProxies(t *testing.T) {
	r, _ := newTestRelay(t, false)
	mk := func(remote, xff string) string {
		req := httptest.NewRequest("POST", "/relay.php", nil)
		req.RemoteAddr = remote
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		ip, _ := r.clientIP(req)
		return ip
	}
	if got := mk("198.51.100.7:1", "1.2.3.4"); got != "198.51.100.7" {
		t.Errorf("outside client spoofed XFF: %s", got)
	}
	if got := mk("127.0.0.1:1", "9.9.9.9, 1.2.3.4"); got != "1.2.3.4" {
		t.Errorf("local proxy: want last hop, got %s", got)
	}
	if got := mk("10.0.0.9:1", "5.6.7.8"); got != "5.6.7.8" {
		t.Errorf("configured proxy: got %s", got)
	}
	if got := mk("[::1]:1", "not-an-ip"); got != "::1" {
		t.Errorf("bad XFF should fall back: %s", got)
	}
}

func TestPutRateLimit(t *testing.T) {
	_, h := newTestRelay(t, false)
	ok, refused := 0, 0
	for i := 0; i < putsPerMin+5; i++ {
		rec, _ := do(h, call{url: "/relay.php?a=put&box=" + boxOf(secret(i)), body: blob(100), remote: "198.51.100.7:1"})
		if rec.Code == 200 {
			ok++
		} else if rec.Code == 429 {
			refused++
		}
	}
	if ok != putsPerMin || refused != 5 {
		t.Fatalf("ok=%d refused=%d", ok, refused)
	}
}

func TestOnionModeLimitsPerMailbox(t *testing.T) {
	_, h := newTestRelay(t, true)
	// Behind Tor every request is from 127.0.0.1 with no forwarded header.
	for i := 0; i < 200; i++ { // many different senders' mail all reaches different boxes
		if rec, _ := do(h, call{url: "/relay.php?a=put&box=" + boxOf(secret(i)), body: blob(100), remote: "127.0.0.1:1"}); rec.Code != 200 {
			t.Fatalf("onion put %d refused: %d", i, rec.Code)
		}
	}
	box := boxOf(secret(5000))
	refused := 0
	for i := 0; i < onionPutsPerBoxMin+3; i++ {
		if rec, _ := do(h, call{url: "/relay.php?a=put&box=" + box, body: blob(100), remote: "127.0.0.1:1"}); rec.Code == 429 {
			refused++
		}
	}
	if refused != 3 {
		t.Fatalf("per-box onion limit: refused %d", refused)
	}
	// Live connections: capped per mailbox, not shared by everyone on 127.0.0.1.
	var wg sync.WaitGroup
	codes := make([]int, 6)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec, _ := do(h, call{url: "/relay.php?a=get&wait=1", body: `{"s":"` + secret(300+i) + `"}`, remote: "127.0.0.1:1"})
			codes[i] = rec.Code
		}(i)
	}
	wg.Wait()
	for i, c := range codes {
		if c != 200 {
			t.Fatalf("onion user %d refused (%d): limits must not be shared across mailboxes", i, c)
		}
	}
}

func TestMailboxQuota(t *testing.T) {
	r, h := newTestRelay(t, false)
	box := boxOf(secret(7))
	var wg sync.WaitGroup
	for i := 0; i < maxPerBox+20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			do(h, call{url: "/relay.php?a=put&box=" + box, body: blob(100), remote: fmt.Sprintf("198.51.%d.%d:1", i/250, i%250)})
		}(i)
	}
	wg.Wait()
	if ids, _ := r.pending(box); len(ids) != maxPerBox {
		t.Fatalf("concurrent puts stored %d, want exactly %d", len(ids), maxPerBox)
	}
}

func TestRecoverySlots(t *testing.T) {
	_, h := newTestRelay(t, false)
	l, tok := secret(1)[:32], secret(2)
	if rec, _ := do(h, call{url: "/relay.php?a=rput", body: `{"l":"` + l + `","t":"` + tok + `","d":"abc_-1"}`}); rec.Code != 200 {
		t.Fatalf("rput %d", rec.Code)
	}
	if rec, _ := do(h, call{url: "/relay.php?a=rput", body: `{"l":"` + l + `","t":"` + secret(3) + `","d":"evil"}`}); rec.Code != 403 {
		t.Fatalf("overwrite with wrong token: %d", rec.Code)
	}
	if _, m := do(h, call{url: "/relay.php?a=rget", body: `{"l":"` + l + `"}`}); m["d"] != "abc_-1" {
		t.Fatalf("rget %v", m)
	}
	if rec, _ := do(h, call{url: "/relay.php?a=rdel", body: `{"l":"` + l + `","t":"` + secret(3) + `"}`}); rec.Code != 403 {
		t.Fatalf("rdel with wrong token: %d", rec.Code)
	}
	do(h, call{url: "/relay.php?a=rdel", body: `{"l":"` + l + `","t":"` + tok + `"}`})
	if rec, _ := do(h, call{url: "/relay.php?a=rget", body: `{"l":"` + l + `"}`}); rec.Code != 404 {
		t.Fatalf("after rdel: %d", rec.Code)
	}
	// New slots: 5 per client per day.
	refused := 0
	for i := 0; i < 7; i++ {
		rec, _ := do(h, call{url: "/relay.php?a=rput", body: fmt.Sprintf(`{"l":"%032x","t":"%s","d":"x"}`, 1000+i, tok), remote: "198.51.100.7:1"})
		if rec.Code == 429 {
			refused++
		}
	}
	if refused != 2 {
		t.Fatalf("slot rate limit refused %d, want 2", refused)
	}
}

func TestSharesDataWithPHPRelay(t *testing.T) {
	r, h := newTestRelay(t, false)
	s := secret(42)
	box := boxOf(s)
	// Mail written by relay.php: <data>/<box>/<10-digit time><12 hex>.m
	_ = os.MkdirAll(filepath.Join(r.data, box), 0o700)
	_ = os.WriteFile(filepath.Join(r.data, box, "1793500000"+"a1b2c3d4e5f6"+".m"), []byte(blob(100)), 0o600)
	// A slot written by relay.php
	l := secret(1)[:32]
	php, _ := json.Marshal(map[string]string{"h": sha256hex(secret(2)), "d": "phpdata"})
	_ = os.WriteFile(filepath.Join(r.recover, l+".json"), php, 0o600)

	rec, _ := do(h, call{url: "/relay.php?a=get", body: `{"s":"` + s + `"}`})
	if !strings.Contains(rec.Body.String(), `"1793500000a1b2c3d4e5f6"`) {
		t.Fatalf("PHP-written mail not delivered: %s", rec.Body)
	}
	if _, m := do(h, call{url: "/relay.php?a=rget", body: `{"l":"` + l + `"}`}); m["d"] != "phpdata" {
		t.Fatalf("PHP slot not read: %v", m)
	}
	if rec, _ := do(h, call{url: "/relay.php?a=rput", body: `{"l":"` + l + `","t":"` + secret(2) + `","d":"new"}`}); rec.Code != 200 {
		t.Fatalf("PHP slot token not honoured: %d", rec.Code)
	}
}

func TestSweep(t *testing.T) {
	r, _ := newTestRelay(t, false)
	box := boxOf(secret(1))
	dir := filepath.Join(r.data, box)
	_ = os.MkdirAll(dir, 0o700)
	old := time.Now().Add(-ttl - time.Hour)
	for _, n := range []string{"1000000000aaaaaaaaaaaa.m", "x.m.tmp"} {
		p := filepath.Join(dir, n)
		_ = os.WriteFile(p, []byte("x"), 0o600)
		_ = os.Chtimes(p, old, old)
	}
	fresh := filepath.Join(r.data, boxOf(secret(2)))
	_ = os.MkdirAll(fresh, 0o700)
	_ = os.WriteFile(filepath.Join(fresh, "1900000000bbbbbbbbbbbb.m"), []byte("x"), 0o600)
	slot := filepath.Join(r.recover, secret(3)[:32]+".json")
	_ = os.WriteFile(slot, []byte("{}"), 0o600)
	so := time.Now().Add(-slotTTL - time.Hour)
	_ = os.Chtimes(slot, so, so)
	r.allow("put", "k", time.Minute, 1)
	r.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	r.Sweep()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("expired mailbox not removed")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("fresh mail removed")
	}
	if _, err := os.Stat(slot); !os.IsNotExist(err) {
		t.Error("stale slot not removed")
	}
	if len(r.counts) != 0 {
		t.Errorf("expired rate windows kept: %d", len(r.counts))
	}
}

func TestStaticFiles(t *testing.T) {
	_, h := newTestRelay(t, false)
	want := map[string]int{
		"/": 200, "/index.html": 200, "/app.js": 200, "/vendor/q.js": 200, "/img/a.svg": 200,
		"/.htaccess": 404, "/relay.php": 405, "/data/x/1.m": 404, "/embed.go": 404,
		"/notes.md": 404, "/sub/.hidden": 404, "/missing": 404, "/../app.js": 200,
		"/vendor/../.htaccess": 404, "/%2e%2e/relay.php": 404,
	}
	for p, code := range want {
		req := httptest.NewRequest("GET", "/", nil)
		req.URL.Path = p
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != code {
			t.Errorf("GET %s = %d, want %d", p, rec.Code, code)
		}
		if p == "/" && (rec.Header().Get("Content-Security-Policy") != "frame-ancestors 'none'" || rec.Header().Get("X-Frame-Options") != "DENY") {
			t.Error("anti-framing headers missing")
		}
	}
	rec, _ := do(h, call{method: "POST", url: "/index.html"})
	if rec.Code != 405 {
		t.Errorf("POST to a static file = %d", rec.Code)
	}
	req := httptest.NewRequest("GET", "/app.js", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("app.js content type %q", ct)
	}
	b, _ := io.ReadAll(rec.Body)
	if !bytes.Equal(b, []byte("x")) {
		t.Errorf("app.js body %q", b)
	}
}

func TestDataInsideWebRefused(t *testing.T) {
	dir := t.TempDir()
	if _, err := siteFS(dir, filepath.Join(dir, "data")); err == nil {
		t.Fatal("data inside web folder accepted")
	}
	if _, err := siteFS(dir, filepath.Join(filepath.Dir(dir), "elsewhere")); err != nil {
		t.Fatalf("data outside web refused: %v", err)
	}
	if _, err := siteFS(filepath.Join(dir, "web"), filepath.Join(dir, "web..data")); err != nil {
		t.Fatalf("sibling with similar name refused: %v", err)
	}
}
