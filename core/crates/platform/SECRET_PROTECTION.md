# Current-user DPAPI primitive

`windows_secret` is not wired to accounts, IPC, files, or the UI. It supplies only
current-user DPAPI protect/unprotect for the next private-store implementation.
No real account or key is used by its tests.

- Never sets `CRYPTPROTECT_LOCAL_MACHINE`; it sets `CRYPTPROTECT_UI_FORBIDDEN` and
  uses a null prompt structure. A fixed versioned purpose value is additional
  entropy, not a password, key, or replacement for current-user protection.
- Rejects empty or oversized inputs. Plaintext is bounded to64KiB; protected input
  to80KiB. Errors remain explicit; corrupt data is not replaced or regenerated.
- `Secret` cannot be cloned, debug-formatted or serialized by the type. It exposes
  borrowed bytes only for explicit internal use. The OS-owned plaintext buffer is
  overwritten through volatile writes with a compiler fence, then `LocalFree`d.
  Callers remain responsible for erasing their input/copies and keeping plaintext
  out of logs, command arguments, reports and ordinary snapshots.
- DPAPI does not defend against malicious code already running as the same user or
  an administrator, and memory erasure does not promise protection against swap,
  crash dumps or copies made elsewhere. Roaming Windows profiles have documented
  portability exceptions; this is not a hardware-binding promise.

Native tests use synthetic strings to check roundtrip, tamper rejection, malformed
and oversized inputs, exact64KiB roundtrip and purpose mismatch. Cross-user failure, file ACLs, private directories, atomic
commit/recovery, deletion and real account/identity integration remain separate
acceptance gates. DPAPI success is not sufficient application-format validation:
Microsoft documents that some corrupted inputs may succeed with corrupted output;
the future store must validate format/version and semantic integrity before use.
Windows-native tests must pass for the exact implementation SHA.

References: [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata),
[CryptUnprotectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata).
