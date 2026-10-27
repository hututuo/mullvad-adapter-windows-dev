#!/bin/bash
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CARGO_BIN="${QUIC_CARGO_BIN:-cargo}"
export CARGO_TARGET_DIR="${QUIC_TARGET_DIR:-$ROOT/helpers/quic-carrier/target}"
export MACOSX_DEPLOYMENT_TARGET=13.0
"$CARGO_BIN" test --manifest-path "$ROOT/helpers/quic-carrier/Cargo.toml" --locked
"$CARGO_BIN" build --manifest-path "$ROOT/helpers/quic-carrier/Cargo.toml" --locked --release
mkdir -p "$ROOT/helpers/quic-carrier/bin"
cp "$CARGO_TARGET_DIR/release/mullvad-quic-carrier" "$ROOT/helpers/quic-carrier/bin/mullvad-quic-carrier"
chmod 755 "$ROOT/helpers/quic-carrier/bin/mullvad-quic-carrier"
"$ROOT/helpers/quic-carrier/bin/mullvad-quic-carrier" --version-json
