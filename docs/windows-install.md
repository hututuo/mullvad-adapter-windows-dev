# Windows candidate installation

Use the complete unsigned x64 `setup.exe` from a candidate build and verify its
SHA256 against `candidate.json`. A source checkout or standalone development UI
executable is not the installation package. The NSIS wrapper is a 32-bit installer
which installs the x64 desktop, agent and official pinned Mihomo. It embeds
Microsoft's offline x64 WebView2 installer. The supported runtime is Windows 11
x64; users do not need Python, Node, Cargo, Ruby or a compiler.

The manifest's `desktop` describes the compiler output; `packaged_desktop`
describes the installed executable. Tauri's pinned NSIS bundler changes its
bundle-type marker for packaging and restores the compiler output afterward.
Use `packaged_desktop` when checking the installed UI. The runtime manifest and
its payload hashes stay identical through installation.

The desktop starts an ordinary-user backend and verifies its source SHA and
runtime hashes. Closing the window hides it; quitting the interface from the tray
leaves the backend running. Disconnect closes the owned tunnel while retaining
the local proxy front on REJECT. Management logout clears the account session,
and does not revoke the device or erase its private key.
The diagnostics page and tray action “停止后台并退出” requests shutdown and waits on the retained server
process handle for a clean exit. An uncertain stop is reported and cannot silently
restart the backend. It does not kill processes by name or change external Clash.

On first setup, enter the port of an available local external proxy for official
API access, log in to the existing Mullvad account, and create a local device.
Private keys are generated locally and held in DPAPI. Registration sends only
the public key. Activate the created device while disconnected, choose up to
three favorite cities and connect. Other devices' private keys cannot be fetched
from Mullvad. A submitted registration with an unknown result must be reconciled
before retry; do not create another device to work around an API timeout.
If a device activation cannot confirm its local identity commit, the running
host clears its old in-memory identity and blocks new connections. Stop the
backend normally and reopen it to reconcile the durable identity; the original
identity backup and generated private key remain in protected storage. Device
revocation confirmations include the exact device ID and public key so duplicate
device names do not identify a destructive target on their own.

System traffic interception remains with the external Clash/Mihomo application.
The Windows **Clash 接入** page supports detecting and integrating the current
Clash Verge Rev profile with private backup, validation and undo; see
[Clash connection](clash-connect.md) for controller prerequisites and limits.
Its local adapter entry is SOCKS5 at `127.0.0.1` and the adapter's displayed front
port, with UDP enabled. The adapter never silently falls back to DIRECT. Local
SOCKS egress, external Clash TUN integration, physical interruption and installation
are distinct tests; consult the candidate's verification record for actual results.
Windows protection options whose backend is unsupported are blocked explicitly.
Manual city ICMP results remain visible while tiny background maintenance batches
update candidate hints. Logs distinguish those batches and include bounded city
and result counts; ICMP non-response is not a tunnel failure.
Periodic connection checks refresh the displayed measurements and their logged
results. DNS timeout, unavailable transport, rejected validation and a hostname
HTTPS check skipped after DNS failure are distinct bounded outcomes. A degraded
but live original path is preserved and checked again rather than forcing an
IP change; it is not reported as fully ready.

New cache, report and log files use an explicit protected DACL for the durable
current-user SID, so SSH-created files remain usable after a desktop login.
Existing ACLs are preserved; an unreadable legacy cache reports a specific
access error instead of silently appearing empty. Back up affected public cache
or log files before repairing their permissions; do not repair the key store
or change the user profile ACL.

User state and rotated logs live in `%LOCALAPPDATA%/MullvadAdapter-Windows/`, outside
the installed files. Keep the previous complete installer for rollback. Before
an upgrade or rollback, disconnect and stop the current backend; never overwrite
a locked runtime or delete the state directory. A private key should not be pasted
into diagnostics, Git, a command line, or a bug report. The diagnostics action
writes public state and bounded events to a file and copies its path.

The candidate manifest's `NOT_RUN` installation, upgrade and recovery fields are
build defaults. Cloud build success cannot establish those results. Signing,
publication and update-feed changes are separate gates.
