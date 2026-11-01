#!/usr/bin/env bash
# Hush Relay — Copyright (C) 2026 Valentyn Rukhaylo (ALTRU.dev) and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Build the Android app with the plain SDK tools: no Gradle, no libraries.
#   ./android/build.sh            signed release APK  -> android/out/hush-relay-<version>.apk
#   ./android/build.sh --debug    debuggable build (remote WebView inspector on)
#
# Needs: JDK 17+, Android SDK build-tools (34+) and one platform (android-35+).
#   ANDROID_HOME   SDK folder            (default ~/Android/Sdk or ~/.local/android-sdk)
#   HUSH_KEYSTORE  release signing key   (default ~/.hush-relay/release.jks, made on first run)
#   HUSH_KEYPASS   its password          (asked for if not set)
# Keep the keystore safe and backed up: updates must be signed with the same key,
# or Android refuses to install them over the old app.
set -euo pipefail

DEBUG=false; [[ "${1:-}" == "--debug" ]] && DEBUG=true
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$HERE")"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
for d in "$SDK" "$HOME/Android/Sdk" "$HOME/.local/android-sdk"; do [[ -n "$d" && -d "$d/build-tools" ]] && { SDK="$d"; break; }; done
[[ -d "$SDK/build-tools" ]] || { echo "Android SDK not found; set ANDROID_HOME" >&2; exit 1; }
BT="$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)"
PLATFORM="$(ls -d "$SDK"/platforms/android-* | sort -V | tail -1)/android.jar"
VERSION="$(sed -n 's/.*android:versionName="\([^"]*\)".*/\1/p' "$HERE/AndroidManifest.xml")"
echo "SDK $(basename "$BT"), $(basename "$(dirname "$PLATFORM")"), version $VERSION"

B="$HERE/build"; OUT="$HERE/out"
rm -rf "$B"; mkdir -p "$B"/{res,gen,classes,assets/www/vendor} "$OUT"

# The app: the same files the relay serves (no service worker needed inside the APK).
cp "$ROOT"/web/{index.html,app.js,call.js,worklet.js,config.js,manifest.json,icon.svg} "$B/assets/www/"
cp "$ROOT"/web/vendor/*.js "$ROOT"/web/vendor/*.txt "$B/assets/www/vendor/"
cp "$ROOT"/LICENSE "$B/assets/www/LICENSE.txt"

mkdir -p "$B/gen/dev/altru/hushrelay"
cat > "$B/gen/dev/altru/hushrelay/BuildConfig.java" <<EOF
package dev.altru.hushrelay;
public final class BuildConfig { public static final boolean DEBUG = $DEBUG; }
EOF

"$BT/aapt2" compile --dir "$HERE/res" -o "$B/res.zip"
DBG=(); $DEBUG && DBG=(--debug-mode)
"$BT/aapt2" link -o "$B/base.apk" -I "$PLATFORM" --manifest "$HERE/AndroidManifest.xml" \
  -A "$B/assets" --java "$B/gen" --min-sdk-version 26 --target-sdk-version 35 "${DBG[@]}" "$B/res.zip"

javac -nowarn -Xlint:-options --release 11 -classpath "$PLATFORM" -d "$B/classes" \
  $(find "$HERE/src" "$B/gen" -name '*.java')
"$BT/d8" --min-api 26 --lib "$PLATFORM" $($DEBUG || echo --release) --output "$B" $(find "$B/classes" -name '*.class')
(cd "$B" && zip -qj base.apk classes.dex)
"$BT/zipalign" -f -p 4 "$B/base.apk" "$B/aligned.apk"

if $DEBUG; then
  KS="$B/debug.jks"; PASS=android
  keytool -genkeypair -keystore "$KS" -storepass "$PASS" -keypass "$PASS" -alias debug -keyalg EC -groupname secp256r1 \
    -validity 365 -dname "CN=Hush Relay debug" >/dev/null 2>&1
  APK="$OUT/hush-relay-$VERSION-debug.apk"
else
  KS="${HUSH_KEYSTORE:-$HOME/.hush-relay/release.jks}"
  PASS="${HUSH_KEYPASS:-}"
  if [[ -z "$PASS" ]]; then read -rsp "Keystore password: " PASS; echo; fi
  if [[ ! -f "$KS" ]]; then
    mkdir -p "$(dirname "$KS")"; chmod 700 "$(dirname "$KS")"
    keytool -genkeypair -keystore "$KS" -storepass "$PASS" -keypass "$PASS" -alias hush -keyalg EC -groupname secp256r1 \
      -validity 10000 -dname "CN=Hush Relay" >/dev/null
    chmod 600 "$KS"
    echo "New signing key: $KS  (back it up; future updates need it)"
  fi
  APK="$OUT/hush-relay-$VERSION.apk"
fi
"$BT/apksigner" sign --ks "$KS" --ks-pass "pass:$PASS" --key-pass "pass:$PASS" --out "$APK" "$B/aligned.apk"
"$BT/apksigner" verify "$APK"
rm -f "$APK.idsig"
( cd "$OUT" && sha256sum "$(basename "$APK")" > "$(basename "$APK").sha256" )
echo "Built $APK"
echo "Signing certificate SHA-256 (publish this so people can check their download):"
"$BT/apksigner" verify --print-certs "$APK" | sed -n 's/.*SHA-256 digest: //p'
