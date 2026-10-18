# Design

Use a dedicated portable crate and Tauri worker. Detect Verge profile/script and
existing local controller (Windows named pipe preferred, loopback HTTP otherwise);
expose allowlisted summaries, never runtime credentials. A pipe transport wraps
the pinned ureq HTTP parser with bounded nonblocking Windows byte I/O. It sends
no HTTP secret, opens no TCP bridge and never silently falls back from a failed
pipe. A blank controller and an unsafe address are different closed errors.
Snapshot hashing binds each explicit apply to its inputs. An OS advisory lock
serializes this feature's writers; optimistic byte checks detect external edits.
Private exact backups precede any script write. Pinned Mihomo validates staged
YAML before activation; bounded local-controller payload reload and selector readback
separate saved, active and tunnel states. Managed script wrappers are additive
and preserve the existing main. Undo checks ownership, retains archives and never
restores a revoked device identity. See docs/clash-connect.md for supported paths,
runtime divergence checks and the limits of external-writer coordination.
