# Private transient stdin for an owned engine

This internal primitive is not wired to the mock agent or real engine launcher.
Persistent account/identity/policy data still uses typed DPAPI storage. This
separate runtime directory holds transient plaintext input, not persistent
settings. Callers supply a dedicated directory below an already trusted local
current-user parent. Parent discovery/ancestor validation is still a gate.

New runtime objects use the same current-user owner/protected one-ACE DACL and
reparse/type checks as PrivateStore, factored into a shared internal helper with
no changed store behavior. Existing insecure objects fail closed rather than
receiving permission repairs. The directory denies delete sharing; a dedicated
exclusive .runtime-lock lease remains held through prepared input and the owned
process. Unknown filenames are never reclaimed. On a safe exclusive startup,
only exact .input-UUID names with matching ACL/type are reclaimed; errors fail
opening rather than being silently skipped. Unclean power loss is not assumed
to honor ordinary process-close cleanup.

Input is nonempty and capped at16KiB. It is written directly from a borrowed
secret buffer into a CREATE_NEW private file with TEMPORARY/DELETE_ON_CLOSE,
then rewound and retained only through a read-only non-inheritable duplicate.
The file object is not reopened by pathname. It contains plaintext while alive:
this is neither a no-disk claim nor secure erase, paging or power-loss assurance.
Kernel/file I/O is synchronous; call outside the actor. Errors close handles and
ordinary final close removes the transient file without a secret path in logs.

spawn_with_secret_input consumes the prepared stream, uses its private runtime
as working/TEMP directory and reconstructs the sanitized environment. Only a
short-lived read-only stdin duplicate and NUL stdout/stderr enter the explicit
handle allowlist. Atomic Job ownership and suspended creation stay unchanged.
All agent process creation must use this serialized entry point while the stdin
duplicate is briefly inheritable; arbitrary third-party process launch code is
outside that guarantee. Input remains owned until the process owner is dropped.
On abrupt parent death, Job kill closes child handles and kernel deletion applies.
No destructor waits unboundedly; explicit stop still checks the whole job tree.

The future Mihomo integration will use -f - so Go reads inherited stdin rather
than opening a delete-on-close pathname. Go's ordinary Windows open share mode
omits FILE_SHARE_DELETE, which would conflict with direct path reopening. This
change does not itself execute Mihomo, verify vendor hashes or establish routing.

Standard-library test child launches share the same spawn gate because Rust1.85
uses broad handle inheritance. A concurrent eight-pair regression keeps unrelated
standard children alive while secret-input owners exit and requires immediate
input reclamation; this is not a mutation proof of every scheduling interleaving.

Windows assertions cover length bounds, read-only access, lease retention,
ordinary last-close deletion, owned child stdin/denied writes, abrupt owner exit
with a live child holding stdin, reserved-file startup reclamation, preservation
of unrelated names and insecure-root refusal. All bytes are synthetic. Native
exact-SHA execution is required; Linux only checks Win32 signatures.

References:
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
- https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle
- https://go.dev/src/syscall/syscall_windows.go
