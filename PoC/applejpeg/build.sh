#!/usr/bin/env bash
# Build the open-source MOON Probe and package an unsigned IPA.
# macOS only: requires Xcode command line tools with the iPhoneOS SDK.
set -euo pipefail

cd "$(dirname "$0")/../.."

SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
APP="build/MOONProbe.app"

rm -rf "$APP"
mkdir -p "$APP"

xcrun --sdk iphoneos clang \
  -arch arm64 \
  -miphoneos-version-min=15.0 \
  -isysroot "$SDK" \
  -fobjc-arc -fblocks -O2 \
  -c PoC/applejpeg/moonprobe.m \
  -o build/moonprobe.o

xcrun --sdk iphoneos clang \
  -arch arm64 \
  -miphoneos-version-min=15.0 \
  -isysroot "$SDK" \
  -o "$APP/moonprobe" \
  build/moonprobe.o \
  -framework UIKit \
  -framework Foundation \
  -framework IOKit \
  -framework IOSurface

cp PoC/applejpeg/Info.plist "$APP/Info.plist"
chmod +x "$APP/moonprobe"

python3 scripts/package_ipa.py "$APP" build/MOONProbe-unsigned.ipa

echo
echo "Built: build/MOONProbe-unsigned.ipa"
echo "Sign it with Sideloadly/AltStore/Xcode before installing."
