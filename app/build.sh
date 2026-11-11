#!/bin/zsh
set -euo pipefail
cd "${0:A:h}"
repo="${PWD:h}"
app="$repo/build/AIDT VPN.app"
if [[ -e "$app" ]]; then
    print -u2 "Build output already exists: $app. Move it aside before rebuilding."
    exit 1
fi
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources/vpn/scripts"
cp "$repo/dev.command" "$repo/audit.command" "$repo/vpn" "$app/Contents/Resources/vpn/"
cp "$repo"/scripts/*.py "$app/Contents/Resources/vpn/scripts/"
xcrun swiftc main.swift -O -framework AppKit -o "$app/Contents/MacOS/AIDTVPN"
cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>AIDTVPN</string>
<key>CFBundleIdentifier</key><string>com.cskwork.aidt-vpn-menubar</string>
<key>CFBundleName</key><string>AIDT VPN</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSUIElement</key><true/>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
plutil -lint "$app/Contents/Info.plist"
codesign --force --sign - "$app"
codesign --verify --deep --strict "$app"
"$app/Contents/MacOS/AIDTVPN" --check
