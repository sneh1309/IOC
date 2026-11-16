#!/bin/bash
# Aletheia - prepare the USB stick on YOUR Mac (not the client's). Run once:
#   bash "/Volumes/EVIDENCE/aletheia/setup/setup_usb_mac.command"
# Downloads official portable Python (python-build-standalone) for Apple Silicon + Intel Macs,
# verifies SHA-256 and unpacks next to the tool. Installs nothing on this Mac.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAG=20260718; VER=3.12.13
MIRRORS=("https://github.com/astral-sh/python-build-standalone/releases/download/$TAG"
         "https://releases.astral.sh/github/python-build-standalone/releases/download/$TAG")
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
echo "Aletheia USB setup - target folder: $ROOT"
for m in "${MIRRORS[@]}"; do curl -fsSL "$m/SHA256SUMS" -o "$TMP/SHA256SUMS" 2>/dev/null && break || true; done
for ARCH in aarch64 x86_64; do
  NAME="cpython-$VER+$TAG-$ARCH-apple-darwin-install_only_stripped.tar.gz"
  echo "Downloading Python $VER for $ARCH Macs ..."
  OK=0
  for m in "${MIRRORS[@]}"; do
    if curl -fSL --progress-bar "$m/${NAME/+/%2B}" -o "$TMP/$NAME"; then OK=1; break; fi
  done
  [ $OK = 1 ] || { echo "Download failed for $ARCH"; exit 1; }
  HASH="$(shasum -a 256 "$TMP/$NAME" | cut -d' ' -f1)"
  if [ -s "$TMP/SHA256SUMS" ] && grep -q "$NAME" "$TMP/SHA256SUMS"; then
    EXP="$(grep "$NAME" "$TMP/SHA256SUMS" | head -1 | cut -d' ' -f1)"
    [ "$EXP" = "$HASH" ] || { echo "SHA-256 MISMATCH - download rejected"; exit 1; }
    echo "  SHA-256 verified: $HASH"
  else
    echo "  SHA-256 (record this): $HASH  [official checksum list not reachable]"
  fi
  mkdir -p "$TMP/x-$ARCH"; tar -xzf "$TMP/$NAME" -C "$TMP/x-$ARCH"
  rm -rf "$ROOT/python-$ARCH"
  cp -R "$TMP/x-$ARCH/python" "$ROOT/python-$ARCH" 2>/dev/null || cp -RL "$TMP/x-$ARCH/python" "$ROOT/python-$ARCH"
  [ -e "$ROOT/python-$ARCH/bin/python3.12" ] || { echo "Unpack failed for $ARCH"; exit 1; }
  echo "  Installed to $ROOT/python-$ARCH"
done
xattr -dr com.apple.quarantine "$ROOT" 2>/dev/null || true
echo; echo "DONE. The USB is ready. On the client's Mac follow the User Guide, Step 2 onwards."
