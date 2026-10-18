# Windows private staged store primitive

This module is an internal platform primitive, not yet wired to account, identity,
policy owners, the agent IPC, or the installer. It uses the typed record codec and
current-user DPAPI before writing any file. Plaintext is not written to disk.
Caller input and explicit borrowed plaintext copies remain caller responsibilities.

## Directory and ownership contract

The caller must supply a dedicated absolute local directory beneath an already
trusted current-user application directory. UNC/extended paths are rejected;
parent directory discovery, recursive creation, ancestor/reparse validation and
installer integration remain separate gates. This primitive does not secure an
attacker-controlled parent path. Network filesystems are outside its contract.

New objects receive a protected DACL with exactly one full-access ACE for the
current user and that user's owner SID. Existing objects must already match;
permissions are never repaired automatically. Handles reject reparse points and
wrong object types. The directory handle denies delete-sharing, and an exclusive
`.store-lock` handle persists until all store clones and prepared writes are gone.
This is cooperative single-owner exclusion, not isolation from malicious code
already running as the same user, administrators, or SYSTEM.

Only account.dpapi, identity.dpapi and policy.dpapi are committed record names.
The dedicated directory reserves `.pending-<UUID>` for abandoned staged files.
On open, the exclusive owner validates and removes only that exact staged-name
shape with the expected file type and private ACL. Other names are preserved.
Failure to validate or reclaim a reserved staged file aborts opening the store.

## Write and read boundary

Prepare encodes and encrypts, creates an exclusive unique staged file, writes and
flushes its ciphertext, then closes the staged handle. Failure/abort closes the
handle before best-effort cleanup. Committing performs a same-directory replace
rename after validating any existing target through the same ACL/DPAPI/codec
read path (only a missing filename permits first creation); the successful rename is the filesystem commit point. Failure leaves the
old committed record in place in the tested local filesystem scenarios. This is
not a filesystem-independent or power-loss durability guarantee. No directory
fsync or disk-controller guarantee is claimed. Drop cleanup can fail; a later
exclusive open retries abandoned staged-file cleanup.

The domain transaction owner MUST revalidate its current token/epoch and retain
its serialization authority across final rename and in-memory publication. This
module supplies no transaction token validation, cancellation gate, or shared
memory update by itself. It must not be used as proof that a policy transaction
is integrated. Disk I/O is synchronous and has no hard kernel-I/O deadline.

Reads enforce a ciphertext size cap and object ACL/type, unprotect with DPAPI,
then validate record kind, format, size and checksum before exposing a borrowed
payload. Corrupt records fail closed and are not regenerated or overwritten.
The checksum is corruption detection, not a keyed authenticity mechanism or
account/policy semantic validation. Cross-user recovery and schema migration
remain unimplemented.

## Test boundary

Windows tests use only uniquely named temporary directories and synthetic bytes.
They cover private ACL acceptance, exclusive lifetime, staged versus committed
reads, abort, failed replacement, malformed/wrong-kind records, rejection of an
insecure preexisting directory/target, replacement refusal for damaged records, injected pre-flush failure, and abrupt process
exit after flush. The crash fixture exits without running destructors; reopening
must retain the previous commit and reclaim only reserved abandoned files.

Linux checks compile the Windows signatures but do not execute these tests.
Actual Windows CI execution, cross-user denial, real AppData path integration,
domain transaction races, power interruption and installation are separate gates.
