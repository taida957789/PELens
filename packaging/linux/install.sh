#!/bin/sh
# Install PELens for the current user (~/.local) or, with PREFIX=/usr/local, system-wide.
set -e
here=$(cd "$(dirname "$0")" && pwd)
prefix=${PREFIX:-$HOME/.local}
install -Dm755 "$here/pelens" "$prefix/bin/pelens"
install -Dm755 "$here/pelens-cli" "$prefix/bin/pelens-cli"
install -Dm644 "$here/share/applications/pelens.desktop" "$prefix/share/applications/pelens.desktop"
for s in 256 512; do
    install -Dm644 "$here/share/icons/hicolor/${s}x${s}/apps/pelens.png" "$prefix/share/icons/hicolor/${s}x${s}/apps/pelens.png"
done
command -v update-desktop-database > /dev/null && update-desktop-database "$prefix/share/applications" || true
command -v gtk-update-icon-cache > /dev/null && gtk-update-icon-cache -q "$prefix/share/icons/hicolor" || true
echo "PELens installed to $prefix/bin (make sure it is on your PATH)"
