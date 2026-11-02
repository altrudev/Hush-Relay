# Licensing and third-party notices

## Hush Relay original materials

Copyright © 2026 Valentyn Rukhaylo (ALTRU.dev).

Unless a file specifically identifies a separate license, original source code and documentation written for Hush Relay are licensed under the **GNU Affero General Public License, version 3 or any later version** (SPDX identifier: `AGPL-3.0-or-later`). The authoritative full license text appears in [LICENSE](LICENSE).

This is **free software**, including for commercial purposes, subject to the license conditions. You may use, study, copy and modify it under the AGPL terms. Source distribution and providing access to modified hosted software can trigger obligations under the license, including the network-use provisions of section 13. Read the complete license before distributing or operating a modified service. This summary is informational and is not a substitute for the license text or legal advice.

The AGPL license does **not** give permission to use the ALTRU.dev name or logos as endorsements or trademarks. No alternative proprietary license is granted through this repository.

## Bundled third-party material

The project includes third-party assets under their original license terms, **not** relicensed as Hush Relay original code.

| Local files | Upstream origin | License | Preserved notice |
|---|---|---|---|
| `web/vendor/qrcode.js` | [qrcode-generator by Kazuhiko Arase](https://github.com/kazuhikoarase/qrcode-generator) | MIT | [LICENSE-qrcode-generator.txt](web/vendor/LICENSE-qrcode-generator.txt) and the source header |
| `web/vendor/jsQR.js` | [jsQR](https://github.com/cozmo/jsQR) | Apache License 2.0 | [LICENSE-jsQR.txt](web/vendor/LICENSE-jsQR.txt) |
| `web/vendor/words.js` | BIP39 English wordlist sourced from [@scure/bip39](https://github.com/paulmillr/scure-bip39) | MIT | [LICENSE-bip39-wordlist.txt](web/vendor/LICENSE-bip39-wordlist.txt) |

The Go relay binary (`cmd/hush-relay`) embeds the web app, including these files and their notice files, so a shared binary redistributes them too. The relay itself uses only the Go standard library (BSD-3-Clause, © The Go Authors), which is compiled into the binary.

When redistributing the code or a binary, keep the relevant license text and copyright notices. These notices cover the identified bundled material and do not imply endorsement by its upstream authors.

## Warranty disclaimer

Hush Relay comes **WITHOUT ANY WARRANTY**, to the extent allowed by applicable law; see sections 15–17 of [LICENSE](LICENSE). The software is experimental, has not undergone an independent professional security audit, and should not be relied on for high-risk communications.

## Copyright and provenance

The creator credit above applies to original Hush Relay contributions, not to the works of third-party authors. Contributors retain the applicable copyright rights to their submissions, subject to the terms under which contributions are made.
