# Windows process ownership primitive

`windows_process::OwnedProcess` is an internal, unconnected platform building block.
It is not exposed by the mock agent or renderer. A future engine adapter must first
verify a packaged executable's hash/version, write private transient configuration,
and supply its bounded graceful-shutdown operation. This module does not accept or
log secrets, create a tunnel, install a service, or change networking.

The implementation creates a private unnamed kill-on-close Job Object, creates the
child suspended with PROC_THREAD_ATTRIBUTE_JOB_LIST, then resumes its main thread.
Job membership is atomic with creation on Windows10+, including abrupt owner death
between CreateProcess return and ResumeThread. No create-then-assign gap remains. Ownership stays in process/job handles, never a PID
lookup. Descendants cannot request breakaway from this job. Windows nested-job
restrictions are returned as startup errors rather than bypassed.

Ordinary launches allowlist one NUL handle for all stdio. The explicit secret-input
entry adds only a short-lived read-only stdin duplicate; stdout/stderr remain NUL.
Engine/PQ output capture is deliberately not available yet; adding it requires
a bounded secret-safe channel. See RUNTIME_INPUT.md for the separate private
transient file and crash-cleanup contract. The generic fixture-oriented spawn inherits its parent environment; production
engine integration must use the explicit sanitized entry described below.

Root wait and force-stop fallback are capped at 30 seconds. Force-stop completion
requires both root termination and zero active processes in the owned job tree.
Dropping ownership closes the kill-on-close job without an unbounded destructor
wait. This is process containment, not a security sandbox against hostile binaries.

Windows-only tests launch the test executable as an isolated child fixture and
cover suspended ownership, force stop, descendant cleanup, owner drop, path and
quoting validation, abrupt pre-resume owner exit, unrelated-process preservation
and rejection of an unrelated inheritable sentinel handle. Seven ignored fixture functions are child entry points, not
skipped acceptance assertions. Real Mihomo/PQ supervision and graceful engine
shutdown remain integration gates.

References: [Microsoft Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
[CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw),
[Atomic process/job creation](https://devblogs.microsoft.com/oldnewthing/20230209-00/?p=107812/).

## Explicit engine environment

`spawn_sanitized` reconstructs a five-entry Unicode environment rather than
inheriting the parent's environment. PATH is the Windows API-reported system
directory; SystemRoot and windir come from GetSystemWindowsDirectoryW, not environment
variables. TEMP/TMP point to the caller's trusted private runtime directory.
CLASH_* overrides, proxy variables, credentials, arbitrary search paths and
per-drive current-directory entries are not inherited. Keys are sorted and the
block has the required double-NUL ending and CREATE_UNICODE_ENVIRONMENT flag.
The prior generic `spawn` remains available for internal fixtures; production
engine integration must choose `spawn_sanitized`. Executable/hash and trusted
runtime directory validation remain caller responsibilities. The secret-input entry uses this same environment policy; no entry launches
Mihomo without an explicit caller.

Native regression launches a separate poisoned-parent fixture, so shared test
runner environment is never modified. It overrides CLASH/proxy/synthetic-secret
and OS-path variables, then checks the sanitized grandchild's exact five keys
and reconstructed paths. This requires exact-SHA Windows execution; Linux only
checks signatures.

A checked private-input spawn accepts a nonblocking preflight under SPAWN_LOCK
immediately before CreateProcessW. It must not call spawn recursively or do
network I/O. Rejection unwinds temporary handles/input without creating a child;
this closes the queue-delay window for cancellation and freshness checks. It
cannot interrupt CreateProcess after entry. A native actual-thread test holds
the gate, expires a deadline or cancels, then verifies deferred preflight, the
exact refusal, gate release and input cleanup without any process creation.
