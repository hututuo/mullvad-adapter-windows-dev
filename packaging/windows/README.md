# Windows packaging gate

Standalone development executables require their matching runtime and are not complete installation packages. Source SHA is included in CI artifact names. The candidate builder includes the pinned Mihomo engine, licenses/source provenance, architecture/size/SHA256, signature status and offline WebView2 support. Acceptance of installation and real connections is recorded separately from packaging.

Before enabling `desktop/src-tauri/tauri.conf.json` bundling:

1. Add the separately installed ordinary-user agent and explicit start/stop entry. Never tie agent lifetime to the UI, or modify external Clash on exit.
2. Verify Windows PE architecture and all runtime dependencies. Avoid a package that requires cargo, Node, Ruby or protoc on the user's machine.
3. Implement versioned staging, hash/schema validation, exact prior-product/config rollback and locked-file failures. Preserve corrupt data and do not lower protection.
4. Test offline clean Windows 11 x64 with absent WebView2 and with installed WebView2, install/start/close/reopen/stop/uninstall preserving data, then upgrade failure rollback.
5. Run authorized physical-route/WG/SS/multihop and PQ acceptance against the exact candidate. Build/CI cannot substitute for it.

The candidate config requests NSIS current-user mode and `offlineInstaller` for WebView2, following the [Tauri Windows installer documentation](https://v2.tauri.app/distribute/windows-installer/). Signing/release are separate gates.

## Complete candidate assembly

On a Windows x64 build host with the repository's locked Node/Rust dependencies,
run `python packaging/windows/build_candidate.py --source-sha FULL_SHA --output NEW_DIRECTORY --target-dir DEDICATED_CACHE`.
The script builds the agent with the exact SHA, stages the checksum-pinned official
Mihomo, pins that runtime manifest into the desktop binary, and enables NSIS only
for this candidate. All five runtime files map to `runtime/` next to the installed
UI. The installer embeds offline WebView2 and builds with a static MSVC CRT.
Build tools are not installed on the user's machine. No installer is executed,
no signing key is read, and no release/feed is published by this script.

The `windows-shared-core` manual dispatch input `build_candidate` enables this
job after the existing checks. `candidate.json` records the full SHA, platform,
architecture, file sizes/hashes and unsigned status. Installation, interaction,
upgrade, egress and recovery remain `NOT_RUN` until independently tested. An
existing output directory is refused; it is never deleted or replaced. Preserve
the previous installer for rollback and disconnect/stop the owned backend before
replacing its runtime. User state lives outside the installation directory.

`desktop` is the restored compiler output; `packaged_desktop` is the expected
installed NSIS payload. The pinned bundler changes `__TAURI_BUNDLE_TYPE_VAR_UNK`
to the equal-length `__TAURI_BUNDLE_TYPE_VAR_NSS` before packaging, then restores
the original file. The builder refuses an absent or ambiguous marker instead of
silently predicting a hash. See the pinned [bundler implementation](https://github.com/tauri-apps/tauri/blob/tauri-bundler-v2.10.1/crates/tauri-bundler/src/bundle.rs).
