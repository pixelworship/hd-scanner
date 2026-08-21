#!/bin/bash
#
# Installs the HDWatcher recording daemon as a plain system LaunchDaemon.
#
# Why this exists. The app registers the daemon with SMAppService, which is the
# modern, sanctioned route — but it keeps its registration in macOS's Background
# Task Management database, and that registration is tied to the app's code
# signature and to an approval the user grants in Login Items. Rebuild the app
# and the signature changes; install a system update and the approval can be
# withdrawn. Either way the daemon quietly stops starting at boot, which is the
# one thing it exists to do.
#
# This installs it the old way instead: the binary in a stable root-owned
# location, a plist in /Library/LaunchDaemons, bootstrapped into the system
# domain. It survives reboots, app rebuilds and OS updates, and it needs
# administrator rights exactly once — now.
#
#   sudo ./install-daemon.sh              install or update
#   sudo ./install-daemon.sh --uninstall  remove it again
#
set -euo pipefail

LABEL="co.pixelworship.hdwatcher.daemon"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
TARGET_DIR="/usr/local/libexec"
TARGET="$TARGET_DIR/hdwatcherd"
APP="/Applications/HDWatcher.app"
SOURCE="$APP/Contents/MacOS/hdwatcherd"

if [[ $EUID -ne 0 ]]; then
    echo "This needs administrator rights:" >&2
    echo "  sudo $0 $*" >&2
    exit 1
fi

uninstall() {
    echo "==> Removing $LABEL"
    launchctl bootout "system/$LABEL" 2>/dev/null || true
    rm -f "$PLIST"
    rm -f "$TARGET"
    echo "    removed. The audit log in /Library/Application Support is untouched."
}

if [[ "${1:-}" == "--uninstall" ]]; then
    uninstall
    exit 0
fi

if [[ ! -x "$SOURCE" ]]; then
    echo "Could not find the daemon at $SOURCE." >&2
    echo "Install HDWatcher.app into /Applications first (./build-app.sh --install)." >&2
    exit 1
fi

echo "==> Installing the recording daemon"

# The binary is copied out of the app bundle so that rebuilding, replacing or
# even deleting the app does not stop the daemon from starting at boot.
install -d -o root -g wheel -m 755 "$TARGET_DIR"
# Stop the running copy before replacing the file it is executing.
launchctl bootout "system/$LABEL" 2>/dev/null || true
install -o root -g wheel -m 755 "$SOURCE" "$TARGET"
echo "    binary: $TARGET"

cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>Program</key>
    <string>$TARGET</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>10</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>LowPriorityIO</key>
    <true/>
    <key>Nice</key>
    <integer>5</integer>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
</dict>
</plist>
PLIST_EOF

chown root:wheel "$PLIST"
chmod 644 "$PLIST"
echo "    plist:  $PLIST"

# launchd refuses to load a service that is on the disabled list, which is where
# a previous bootout with -w or an earlier failure can leave it.
launchctl enable "system/$LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
launchctl kickstart -k "system/$LABEL" 2>/dev/null || true

sleep 2
if launchctl print "system/$LABEL" >/dev/null 2>&1; then
    pid=$(launchctl print "system/$LABEL" | awk '/^\tpid = /{print $3}')
    echo "    running as pid ${pid:-unknown}"
    echo
    echo "Done. It will start again at every boot, before anyone logs in."
    echo "Give it Full Disk Access so it can see the whole drive:"
    echo "  System Settings > Privacy & Security > Full Disk Access > + > $TARGET"
    echo "  (press Cmd-Shift-G in the file picker and paste that path)"
else
    echo "The service did not start. Check the daemon's own log:" >&2
    echo "  sudo tail -20 '/Library/Application Support/co.pixelworship.hdwatcher/agent.log'" >&2
    exit 1
fi
