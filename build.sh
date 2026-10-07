#!/bin/bash
# Build PuTTYgen.app ke folder build/.
set -euo pipefail
cd "$(dirname "$0")"

APP=build/PuTTYgen.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

echo "• Kompilasi Swift"
swiftc -O -parse-as-library \
  -target "$(uname -m)-apple-macos13.0" \
  -framework Cocoa -framework WebKit \
  Sources/*.swift -o "$APP/Contents/MacOS/PuTTYgen"

echo "• Menyalin resource"
cp Info.plist "$APP/Contents/"
cp -R web "$APP/Contents/Resources/web"

if [ ! -f assets/AppIcon.icns ]; then
  echo "• Membuat ikon"
  swift assets/make-icon.swift assets >/dev/null
  iconutil -c icns assets/AppIcon.iconset -o assets/AppIcon.icns
  rm -rf assets/AppIcon.iconset
fi
cp assets/AppIcon.icns "$APP/Contents/Resources/"

# Sertakan puttygen di dalam app supaya tetap jalan tanpa Homebrew.
PG="$(command -v puttygen || true)"
if [ -n "$PG" ]; then
  echo "• Menyertakan puttygen dari $PG"
  cp "$(readlink -f "$PG")" "$APP/Contents/Resources/puttygen"
  chmod 755 "$APP/Contents/Resources/puttygen"
else
  echo "! puttygen tidak ditemukan — app akan mencari /opt/homebrew/bin/puttygen saat dijalankan"
fi

echo "• Tanda tangan ad-hoc"
codesign --force --deep --sign - "$APP" >/dev/null 2>&1 || true

echo "Selesai: $APP"
