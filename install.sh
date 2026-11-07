#!/bin/sh
# Installs the wardenbroker CLI from GitHub Releases, verifying its SHA-256.
#
#   curl -fsSL https://raw.githubusercontent.com/MeLlamoPablo/WardenBroker/master/install.sh | sh
#
# WARDENBROKER_VERSION      a release tag such as v0.1.0 (default: latest)
# WARDENBROKER_INSTALL_DIR  where to put the binary (default: ~/.local/bin)
# Re-run it to update.
set -eu

repo=MeLlamoPablo/WardenBroker
version=${WARDENBROKER_VERSION:-latest}
dir=${WARDENBROKER_INSTALL_DIR:-$HOME/.local/bin}
if [ "$version" = latest ]; then
  base=https://github.com/$repo/releases/latest/download
else
  base=https://github.com/$repo/releases/download/$version
fi
base=${WARDENBROKER_DOWNLOAD_URL:-$base} # tests only

fail() { echo "wardenbroker install: $*" >&2; exit 1; }

case $(uname -s) in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "unsupported OS $(uname -s); download a binary from https://github.com/$repo/releases" ;;
esac
case $(uname -m) in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "unsupported architecture $(uname -m); download a binary from https://github.com/$repo/releases" ;;
esac
asset=wardenbroker-$os-$arch

fetch() {
  if command -v curl >/dev/null 2>&1; then curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else fail "needs curl or wget"; fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else fail "needs sha256sum or shasum to verify the download"; fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

fetch "$base/$asset" "$tmp/$asset" || fail "could not download $base/$asset"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "could not download $base/SHA256SUMS"
expected=$(awk -v f="$asset" '$2 == f { print $1 }' "$tmp/SHA256SUMS")
[ -n "$expected" ] || fail "$asset is not listed in SHA256SUMS"
[ "$(sha256 "$tmp/$asset")" = "$expected" ] || fail "checksum mismatch for $asset"

mkdir -p "$dir"
chmod 755 "$tmp/$asset"
mv "$tmp/$asset" "$dir/wardenbroker"
echo "Installed wardenbroker $("$dir/wardenbroker" version) to $dir/wardenbroker"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Note: $dir is not on your PATH." ;;
esac
