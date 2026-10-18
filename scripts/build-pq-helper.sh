#!/bin/bash
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_ROOT="${PQ_BUILD_ROOT:-$ROOT/.build/pq-helper}"
CARGO_BIN="${PQ_CARGO_BIN:-cargo}"
mkdir -p "$BUILD_ROOT/tools" "$ROOT/helpers/pq-negotiator/bin"
if [ -z "${PROTOC:-}" ]; then
  ZIP="$BUILD_ROOT/tools/protoc.zip"
  curl --fail --location --silent --show-error --retry 2 \
    https://github.com/protocolbuffers/protobuf/releases/download/v36.2/protoc-36.2-osx-universal_binary.zip -o "$ZIP"
  printf '%s  %s\n' 83d0dc80672f53486f54299bca6177159f9cad1fd54d4d3143eeea53c4423e1b "$ZIP" | shasum -a 256 --check
  mkdir -p "$BUILD_ROOT/tools/protoc"
  unzip -oq "$ZIP" -d "$BUILD_ROOT/tools/protoc"
  chmod +x "$BUILD_ROOT/tools/protoc/bin/protoc"
  export PROTOC="$BUILD_ROOT/tools/protoc/bin/protoc"
fi
export MACOSX_DEPLOYMENT_TARGET=13.0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$BUILD_ROOT/target}"
"$CARGO_BIN" test --manifest-path "$ROOT/helpers/pq-negotiator/Cargo.toml" --locked --release
"$CARGO_BIN" build --manifest-path "$ROOT/helpers/pq-negotiator/Cargo.toml" --locked --release
cp "$CARGO_TARGET_DIR/release/mullvad-pq-negotiator" "$ROOT/helpers/pq-negotiator/bin/mullvad-pq-negotiator"
chmod 755 "$ROOT/helpers/pq-negotiator/bin/mullvad-pq-negotiator"
"$ROOT/helpers/pq-negotiator/bin/mullvad-pq-negotiator" --version
