# macOS candidate installation

This arm64 candidate contains a compiled SwiftUI app and Ruby daemon source, plus a compiled arm64 PQ negotiator. No Rust/protobuf toolchain is needed at runtime. No Swift compiler or package build is needed to run the app. It is unsigned and is not a public release.

The daemon currently requires an existing configured installation: Ruby 3.0 or newer (the regression suite uses modern Ruby syntax), Clash Verge with `verge-mihomo`, a local Mullvad WireGuard template/device identity, and the existing launchd service. The default core path is `/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo`. A clean-machine installer that provisions these components is not included or verified. Do not treat this archive as a standalone VPN installer.

After extracting, the `payload/` directory contains the app, `install.sh`, `install-daemon.rb`, `verify-candidate.rb`, and `daemon/`, together with `helpers/pq-negotiator/` (binary, source, lockfile and GPL license). Open the app directly from this directory for UI inspection, or explicitly authorize installation before using `install.sh`, which replaces the user Applications copy. Opening the normal app connects to the existing local daemon; older daemons do not provide the new city API. For an isolated city design preview, launch the executable with `--preview-cities`.

The daemon installer is an upgrade tool. From the extracted `payload/` directory, `ruby install-daemon.rb --check` checks source and regressions without changing the installation. A real candidate acceptance run uses `verify-candidate.rb` and a relay not owned by production; it creates real tunnels and therefore requires separate authorization. Installation then requires its exact-source canary report and a new backup directory:

```sh
ruby verify-candidate.rb --relay UNUSED_RELAY --post-quantum --output LOCAL_CANARY_DIRECTORY
ruby install-daemon.rb --install --canary-report LOCAL_CANARY_DIRECTORY/acceptance.json --backup-dir LOCAL_BACKUP_DIRECTORY
ruby install-daemon.rb --rollback LOCAL_BACKUP_DIRECTORY
```

An upgrade stops and restarts the adapter and can interrupt existing connections. Preserve user configuration, WireGuard identity, city state, and the original backup. Cloud checks and package assembly do not certify this upgrade, real egress, old-data migration, or recovery timing.

The daemon installer verifies the packaged helper identity and binds installation to a protected canary report containing both daemon and helper SHA256. It copies the helper adjacent to the installed daemon and preserves any previous helper in the same backup. Disable required multihop/PQ through the current app before manually rolling back to an older daemon that may not understand those policies. Cloud binaries have their own hashes: a local-source canary does not certify a different cloud helper binary.
