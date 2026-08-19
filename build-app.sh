#!/bin/bash
#
# Builds HDWatcher.app — compiles the Swift package, assembles the bundle,
# generates the icon and code-signs the result.
#
# Usage:
#   ./build-app.sh                    release build, ad-hoc signature
#   ./build-app.sh --debug            debug build
#   ./build-app.sh --sign "Developer ID Application: Your Name (TEAMID)"
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

CONFIG="release"
IDENTITY=""           # resolved below
INSTALL=0

# Pixel Worship. The organisation's certificate is named after the person, not
# the company — "Apple Development: Matthew Mourlam (2QHZSWALA4)" — while the
# cert named matt@pixelworship.co belongs to a separate personal team.
TEAM_ID="BM46YKWLTV"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)   CONFIG="debug"; shift ;;
        --sign)    IDENTITY="$2"; shift 2 ;;
        --install) INSTALL=1; shift ;;
        -h|--help)
            sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

# Prefer a real Pixel Worship identity, falling back to ad-hoc so the build
# always works on a machine without the certificates installed.
if [[ -z "$IDENTITY" ]]; then
    IDENTITY=$(security find-identity -v -p codesigning \
        | grep "Developer ID Application" | grep "$TEAM_ID" \
        | head -1 | sed -E 's/.*"(.*)"/\1/' || true)
fi
if [[ -z "$IDENTITY" ]]; then
    IDENTITY=$(security find-identity -v -p codesigning \
        | grep "Apple Development: Matthew Mourlam (2QHZSWALA4)" \
        | head -1 | sed -E 's/.*"(.*)"/\1/' || true)
fi
if [[ -z "$IDENTITY" ]]; then
    echo "note: no Pixel Worship signing identity found; using an ad-hoc signature"
    IDENTITY="-"
fi

APP_NAME="HDWatcher"
BUILD_DIR="$ROOT/build"
APP="$BUILD_DIR/$APP_NAME.app"
CONTENTS="$APP/Contents"
MACOS_DIR="$CONTENTS/MacOS"
RESOURCES_DIR="$CONTENTS/Resources"

echo "==> Compiling ($CONFIG)"
swift build -c "$CONFIG" --product "$APP_NAME"
swift build -c "$CONFIG" --product hdwatcherd
BIN_PATH="$(swift build -c "$CONFIG" --product "$APP_NAME" --show-bin-path)"
BINARY="$BIN_PATH/$APP_NAME"
AGENT_BINARY="$BIN_PATH/hdwatcherd"

for required in "$BINARY" "$AGENT_BINARY"; do
    if [[ ! -f "$required" ]]; then
        echo "error: expected binary at $required" >&2
        exit 1
    fi
done

echo "==> Assembling bundle"
rm -rf "$APP"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR" "$CONTENTS/Library/LaunchDaemons"
cp "$BINARY" "$MACOS_DIR/$APP_NAME"
# The recording daemon ships inside the bundle; SMAppService registers it from
# Contents/Library/LaunchDaemons and launchd resolves BundleProgram relative to
# the app.
cp "$AGENT_BINARY" "$MACOS_DIR/hdwatcherd"
cp "$ROOT/Resources/co.pixelworship.hdwatcher.daemon.plist" \
   "$CONTENTS/Library/LaunchDaemons/"
cp "$ROOT/Resources/Info.plist" "$CONTENTS/Info.plist"
printf 'APPL????' > "$CONTENTS/PkgInfo"

echo "==> Generating icon"
ICON_WORK="$BUILD_DIR/icon"
rm -rf "$ICON_WORK"
mkdir -p "$ICON_WORK"
if swift "$ROOT/Scripts/make-icon.swift" "$ICON_WORK" >/dev/null 2>&1; then
    iconutil -c icns "$ICON_WORK/AppIcon.iconset" -o "$RESOURCES_DIR/AppIcon.icns"
    echo "    icon written"
else
    echo "    warning: icon generation failed; continuing without one" >&2
fi

echo "==> Signing (identity: $IDENTITY)"
SIGN_ARGS=(--force --deep --sign "$IDENTITY"
           --entitlements "$ROOT/Resources/HDWatcher.entitlements")
# The hardened runtime is required for notarisation, but an ad-hoc signature
# combined with it produces an app Gatekeeper will not launch.
if [[ "$IDENTITY" != "-" ]]; then
    SIGN_ARGS+=(--options runtime --timestamp)
else
    SIGN_ARGS+=(--timestamp=none)
fi
# The nested agent has to be signed before the app that contains it.
codesign "${SIGN_ARGS[@]}" "$MACOS_DIR/hdwatcherd" 2>&1 | sed 's/^/    /'
codesign "${SIGN_ARGS[@]}" "$APP" 2>&1 | sed 's/^/    /'

codesign --verify --verbose=2 "$APP" 2>&1 | sed 's/^/    /'
codesign -dv --verbose=2 "$APP" 2>&1 | grep -E "TeamIdentifier|Authority=Apple Development|Authority=Developer ID" | sed 's/^/    /'

echo "==> Built $APP"
du -sh "$APP" | sed 's/^/    /'

if [[ $INSTALL -eq 1 ]]; then
    echo "==> Installing to /Applications"
    rm -rf "/Applications/$APP_NAME.app"
    cp -R "$APP" "/Applications/$APP_NAME.app"
    echo "    installed"
fi

cat <<EOF

Next steps
----------
  open "$APP"

For HDWatcher to see the whole drive it needs Full Disk Access:
  System Settings > Privacy & Security > Full Disk Access > add HDWatcher.app

To use the privileged recording daemon the app must live in /Applications
(macOS will not run root code from a user-writable location):
  ./build-app.sh --install
then enable it in Settings > Background and approve it as an administrator.
The daemon binary needs its own Full Disk Access entry:
  Contents/MacOS/hdwatcherd

Without it the app still runs, but macOS hides protected locations
(Mail, Messages, other apps' containers) from the watcher.

Signing notes
-------------
  Team: $TEAM_ID (Pixel Worship)
  Xcode project: open HDWatcher.xcodeproj (generated from project.yml
  with xcodegen; run "xcodegen generate" after adding files).

  Only "Apple Development" certificates are installed for this team, which
  are fine for running locally. Distributing to other Macs needs a
  "Developer ID Application" certificate from the Pixel Worship team,
  then notarisation:

    xcrun notarytool submit HDWatcher.zip --keychain-profile <profile> --wait
    xcrun stapler staple build/HDWatcher.app
EOF
