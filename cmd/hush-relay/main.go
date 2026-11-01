// Hush Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev) and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command hush-relay serves the Hush Relay app and its mailbox relay from a
// single self-contained binary. It uses only the Go standard library.
//
//	hush-relay                         # http://127.0.0.1:8080, data in ~/.hush-relay-data
//	hush-relay -addr 127.0.0.1:9000 -data /srv/hush
//	hush-relay -onion                  # behind a Tor onion service
//
// Put an HTTPS proxy, a tunnel or a Tor onion service in front of it: browsers
// only allow the app's cryptography on https://, .onion (Tor Browser) or localhost.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/altrudev/Hush-Relay/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	home, _ := os.UserHomeDir()
	addr := flag.String("addr", envOr("HUSH_ADDR", "127.0.0.1:8080"), "listen address (keep it on 127.0.0.1 behind a proxy, tunnel or onion service)")
	data := flag.String("data", envOr("HUSH_DATA", filepath.Join(home, ".hush-relay-data")), "data folder for pending mail and recovery slots")
	webDir := flag.String("web", os.Getenv("HUSH_WEB"), "serve the app from this folder instead of the built-in copy")
	trusted := flag.String("trusted-proxies", os.Getenv("HUSH_TRUSTED_PROXIES"), "comma-separated proxy IPs allowed to report client addresses (local ones are trusted automatically)")
	onion := flag.Bool("onion", os.Getenv("HUSH_ONION") == "1", "Tor onion-service mode: limits apply per mailbox because Tor hides client addresses")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("hush-relay", version)
		return
	}

	site, err := siteFS(*webDir, *data)
	if err != nil {
		log.Fatal(err)
	}
	relay, err := NewRelay(*data, strings.Split(*trusted, ","), *onion)
	if err != nil {
		log.Fatalf("data folder: %v", err)
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           newMux(relay, site),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      maxWait*time.Second + 20*time.Second, // long-polls hold for up to 20 s
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			relay.Sweep()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	mode := ""
	if *onion {
		mode = ", onion mode"
	}
	log.Printf("hush-relay %s on http://%s/ (data: %s%s)", version, ln.Addr(), *data, mode)
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// siteFS returns the app files: the built-in copy, or a folder on disk. A data
// folder inside a served folder is refused so mail can never be fetched by URL.
func siteFS(dir, data string) (fs.FS, error) {
	if dir == "" {
		return web.Files, nil
	}
	absWeb, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	absData, err := filepath.Abs(data)
	if err != nil {
		return nil, err
	}
	if rel, err := filepath.Rel(absWeb, absData); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("data folder %s is inside the served folder %s; choose another -data", absData, absWeb)
	}
	return os.DirFS(absWeb), nil
}

// newMux routes the relay API and the app. The relay answers at /relay.php so
// invites and builds made for the PHP relay keep working, and at /relay.
func newMux(relay *Relay, site fs.FS) http.Handler {
	static := newStatic(site)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/relay.php", "/relay":
			relay.ServeHTTP(w, req)
		default:
			static.ServeHTTP(w, req)
		}
	})
}

type staticFiles struct {
	fs   fs.FS
	etag map[string]string
}

func newStatic(site fs.FS) *staticFiles {
	s := &staticFiles{fs: site, etag: map[string]string{}}
	_ = fs.WalkDir(site, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, err := fs.ReadFile(site, p); err == nil {
				h := sha256.Sum256(b)
				s.etag[p] = `"` + hex.EncodeToString(h[:8]) + `"`
			}
		}
		return nil
	})
	return s
}

func notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("Not found\n"))
}

func (s *staticFiles) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "frame-ancestors 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	p := path.Clean("/" + req.URL.Path)
	if strings.HasSuffix(p, "/") {
		p += "index.html"
	}
	name := strings.TrimPrefix(p, "/")
	if name == "" {
		name = "index.html"
	}
	// Never serve dotfiles, data folders, server code or Go sources.
	for _, seg := range strings.Split(name, "/") {
		if strings.HasPrefix(seg, ".") || seg == "data" {
			notFound(w)
			return
		}
	}
	switch path.Ext(name) {
	case ".php", ".go", ".sh", ".md":
		notFound(w)
		return
	}
	f, err := s.fs.Open(name)
	if err != nil {
		notFound(w)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		notFound(w)
		return
	}
	ctype := mime.TypeByExtension(path.Ext(name))
	switch path.Ext(name) {
	case ".js":
		ctype = "text/javascript; charset=utf-8"
	case ".json":
		ctype = "application/json"
	case ".svg":
		ctype = "image/svg+xml"
	case "":
		ctype = "application/octet-stream"
	}
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	h.Set("Content-Type", ctype)
	h.Set("Cache-Control", "no-cache")
	if tag, ok := s.etag[name]; ok {
		h.Set("ETag", tag)
	}
	rs, ok := f.(interface {
		Read([]byte) (int, error)
		Seek(int64, int) (int64, error)
	})
	if !ok {
		notFound(w)
		return
	}
	http.ServeContent(w, req, name, info.ModTime(), rs)
}
