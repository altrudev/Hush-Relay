// Hush Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev) and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package web embeds the Hush Relay app so the Go relay is a single file.
// Only the files listed here are served; relay.php and server config are not.
package web

import "embed"

//go:embed index.html app.js sw.js config.js manifest.json icon.svg vendor/*.js vendor/*.txt
var Files embed.FS
