#!/bin/zsh
set -euo pipefail

ROOT="${0:A:h}"
APP="$HOME/Applications/Mullvad Adapter.app"
BACKUP_DIR="${MULLVAD_ADAPTER_BACKUP_DIR:-$ROOT/../../../backups/$(date +%Y%m%d-%H%M%S)-mullvad-ui}"
STAGING="$APP.candidate-$$"
PREVIOUS="$APP.previous-$$"
CONTENTS="$STAGING/Contents"
MACOS="$CONTENTS/MacOS"

cd "$ROOT"
xcrun swift build -c release
BIN_DIR="$(xcrun swift build -c release --show-bin-path)"

mkdir -p "$MACOS"
cp "$BIN_DIR/MullvadAdapterUI" "$MACOS/MullvadAdapterUI"
cp "$ROOT/Info.plist" "$CONTENTS/Info.plist"
chmod 755 "$MACOS/MullvadAdapterUI"

/usr/bin/codesign --force --deep --sign - "$STAGING"
/usr/bin/codesign --verify --deep --strict "$STAGING"

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
if [[ -d "$APP" ]]; then
    mv "$APP" "$PREVIOUS"
fi
if ! mv "$STAGING" "$APP"; then
    [[ ! -d "$PREVIOUS" ]] || mv "$PREVIOUS" "$APP"
    exit 1
fi
if [[ -d "$PREVIOUS" ]]; then
    if [[ -e "$BACKUP_DIR/installed-ui.app" ]]; then
        # Keep the original rollback baseline across iterations of one task.
        rm -rf -- "$PREVIOUS"
    else
        mv "$PREVIOUS" "$BACKUP_DIR/installed-ui.app"
    fi
fi

echo "$APP"
