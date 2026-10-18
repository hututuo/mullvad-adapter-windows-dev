//! Private staged ciphertext files. Not yet connected to account or policy owners.
use super::windows_private::*;
use super::{
    storage_record::{self, RecordKind},
    windows::{boot_id, Identity},
    windows_secret::{self, Secret},
};
use sha2::{Digest, Sha256};
use std::{
    io,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    sync::Arc,
};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*};
const MAX_FILE: usize = 81920;
struct Lease {
    root: PathBuf,
    sid: String,
    _directory: Handle,
    _lock: Handle,
}
#[derive(Clone)]
pub struct PrivateStore(Arc<Lease>);
impl PrivateStore {
    /// Parent directory must already be a trusted current-user application path.
    /// No recursive parent creation or permission repair of existing data occurs.
    pub fn open(root: &Path) -> io::Result<Self> {
        if !local_root(root) {
            return Err(invalid());
        }
        let sid = Identity::current()?.sid_for_storage().to_owned();
        let descriptor = Descriptor::new(&sid)?;
        let attributes = descriptor.attributes();
        let root_w = path_wide(root)?;
        if unsafe { CreateDirectoryW(root_w.as_ptr(), &attributes) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
                return Err(error);
            }
        }
        let directory = checked(unsafe {
            CreateFileW(
                root_w.as_ptr(),
                READ_CONTROL | FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        })?;
        require_private(directory.0, &sid, true)?;
        let lock = checked(unsafe {
            CreateFileW(
                path_wide(&root.join(".store-lock"))?.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                &attributes,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        })?;
        require_private(lock.0, &sid, false)?;
        let store = Self(Arc::new(Lease {
            root: root.to_owned(),
            sid,
            _directory: directory,
            _lock: lock,
        }));
        store.reclaim_staged()?;
        Ok(store)
    }
    fn reclaim_staged(&self) -> io::Result<()> {
        for entry in std::fs::read_dir(&self.0.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(id) = name.strip_prefix(".pending-") else {
                continue;
            };
            if id.len() != 36
                || !id.bytes().enumerate().all(|(i, b)| {
                    if [8, 13, 18, 23].contains(&i) {
                        b == b'-'
                    } else {
                        b.is_ascii_hexdigit()
                    }
                })
            {
                continue;
            }
            let path = path_wide(&entry.path())?;
            let file = checked(unsafe {
                CreateFileW(
                    path.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT,
                    null_mut(),
                )
            })?;
            require_private(file.0, &self.0.sid, false)?;
            drop(file);
            if unsafe { DeleteFileW(path.as_ptr()) } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
    pub fn prepare(&self, kind: RecordKind, payload: &[u8]) -> io::Result<PreparedWrite> {
        self.prepare_checked(kind, payload, || Ok(()))
    }
    fn prepare_checked<F: FnOnce() -> io::Result<()>>(
        &self,
        kind: RecordKind,
        payload: &[u8],
        before_flush: F,
    ) -> io::Result<PreparedWrite> {
        let record = storage_record::encode(kind, payload)?;
        let encrypted = windows_secret::protect(record.expose())?;
        drop(record);
        self.stage_ciphertext(kind, &encrypted, before_flush)
    }
    fn stage_ciphertext<F: FnOnce() -> io::Result<()>>(
        &self,
        kind: RecordKind,
        encrypted: &[u8],
        before_flush: F,
    ) -> io::Result<PreparedWrite> {
        let pending = self.0.root.join(format!(".pending-{}", boot_id()?));
        let descriptor = Descriptor::new(&self.0.sid)?;
        let attributes = descriptor.attributes();
        let file = checked(unsafe {
            CreateFileW(
                path_wide(&pending)?.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        })?;
        let mut staged = PreparedWrite {
            lease: self.0.clone(),
            pending,
            kind,
            committed: false,
            file: Some(file),
        };
        let file = staged.file.as_ref().unwrap().0;
        require_private(file, &self.0.sid, false)?;
        let mut offset = 0;
        while offset < encrypted.len() {
            let mut written = 0;
            if unsafe {
                WriteFile(
                    file,
                    encrypted[offset..].as_ptr(),
                    (encrypted.len() - offset) as u32,
                    &mut written,
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "private store write stalled",
                ));
            }
            offset += written as usize;
        }
        before_flush()?;
        if unsafe { FlushFileBuffers(file) } == 0 {
            return Err(io::Error::last_os_error());
        }
        staged.file.take();
        Ok(staged)
    }
    pub fn load(&self, kind: RecordKind) -> io::Result<StoredValue> {
        let encrypted = self.read_ciphertext(kind.filename())?;
        Self::decode(kind, &encrypted)
    }
    fn decode(kind: RecordKind, encrypted: &[u8]) -> io::Result<StoredValue> {
        let secret = windows_secret::unprotect(&encrypted)?;
        let payload = storage_record::decode(kind, secret.expose())?;
        let payload_start = secret.expose().len() - payload.len();
        Ok(StoredValue {
            secret,
            payload_start,
        })
    }
    /// Maintainer recovery access, with the same ACL/envelope validation as fixed
    /// records. This does not restore, delete or change the active identity.
    pub fn load_archive(&self, kind: RecordKind, digest: &str) -> io::Result<StoredValue> {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid());
        }
        let name = format!(
            "archive-{}-{digest}.dpapi",
            kind.filename().trim_end_matches(".dpapi")
        );
        let encrypted = self.read_ciphertext(&name)?;
        if format!("{:x}", Sha256::digest(&encrypted)) != digest {
            return Err(invalid());
        }
        Self::decode(kind, &encrypted)
    }
    /// Preserve a validated record before an explicitly requested replacement.
    /// Names depend only on ciphertext. Archives retain the original private ACL,
    /// envelope and bytes; no plaintext or credentials enter filenames or logs.
    /// A crash before publication leaves the fixed record untouched. Existing
    /// conflicting or unsafe archives are never replaced or silently repaired.
    pub fn archive(&self, kind: RecordKind) -> io::Result<()> {
        let encrypted = self.read_ciphertext(kind.filename())?;
        let secret = windows_secret::unprotect(&encrypted)?;
        storage_record::decode(kind, secret.expose())?;
        drop(secret);
        let name = format!(
            "archive-{}-{:x}.dpapi",
            kind.filename().trim_end_matches(".dpapi"),
            Sha256::digest(&encrypted)
        );
        match self.read_ciphertext(&name) {
            Ok(existing) if existing == encrypted => return Ok(()),
            Ok(_) => return Err(invalid()),
            Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => {}
            Err(e) => return Err(e),
        }
        let mut staged = self.stage_ciphertext(kind, &encrypted, || Ok(()))?;
        // No REPLACE_EXISTING: an external entry created after the check wins.
        if unsafe {
            MoveFileExW(
                path_wide(&staged.pending)?.as_ptr(),
                path_wide(&self.0.root.join(&name))?.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        staged.committed = true;
        if self.read_ciphertext(&name)? != encrypted {
            return Err(invalid());
        }
        Ok(())
    }
    // Only fixed RecordKind names and internally derived archive names reach here.
    fn read_ciphertext(&self, name: &str) -> io::Result<Vec<u8>> {
        let file = checked(unsafe {
            CreateFileW(
                path_wide(&self.0.root.join(name))?.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        })?;
        require_private(file.0, &self.0.sid, false)?;
        let mut metadata: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.0, &mut metadata) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if metadata.nNumberOfLinks != 1 {
            return Err(invalid());
        }
        let mut len = 0;
        if unsafe { GetFileSizeEx(file.0, &mut len) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if len <= 0 || len as u64 > MAX_FILE as u64 {
            return Err(invalid());
        }
        let mut encrypted = vec![0; len as usize];
        let mut offset = 0;
        while offset < encrypted.len() {
            let mut read = 0;
            if unsafe {
                ReadFile(
                    file.0,
                    encrypted[offset..].as_mut_ptr(),
                    (encrypted.len() - offset) as u32,
                    &mut read,
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated private record",
                ));
            }
            offset += read as usize;
        }
        Ok(encrypted)
    }
}
pub struct StoredValue {
    secret: Secret,
    payload_start: usize,
}
impl StoredValue {
    pub fn expose(&self) -> &[u8] {
        &self.secret.expose()[self.payload_start..]
    }
}
/// A staged file is never a committed snapshot. Keep the actor's transaction
/// state lock/token authority held across commit AND its in-memory publication.
pub struct PreparedWrite {
    lease: Arc<Lease>,
    pending: PathBuf,
    kind: RecordKind,
    committed: bool,
    file: Option<Handle>,
}
impl PreparedWrite {
    pub fn commit(mut self) -> io::Result<()> {
        // An explicit write must not silently repair/replace an invalid existing
        // object. Only a genuinely absent fixed filename permits first creation.
        // The caller retains its transaction authority across this check/rename.
        match PrivateStore(self.lease.clone()).load(self.kind) {
            Ok(previous) => drop(previous),
            Err(error) if error.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => {}
            Err(error) => return Err(error),
        }
        if unsafe {
            MoveFileExW(
                path_wide(&self.pending)?.as_ptr(),
                path_wide(&self.lease.root.join(self.kind.filename()))?.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        self.committed = true;
        Ok(())
    }
}
impl Drop for PreparedWrite {
    fn drop(&mut self) {
        self.file.take();
        if !self.committed {
            if let Ok(path) = path_wide(&self.pending) {
                unsafe {
                    DeleteFileW(path.as_ptr());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!("adapter-store-{}", boot_id().unwrap())))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn archives_preserve_ciphertext_recover_and_fail_closed_on_unsafe_entries() {
        let temp = Temp::new();
        let store = PrivateStore::open(&temp.0).unwrap();
        let kind = RecordKind::DeviceDraft;
        let payload = b"synthetic draft material";
        store.prepare(kind, payload).unwrap().commit().unwrap();
        let original = std::fs::read(temp.0.join(kind.filename())).unwrap();
        let digest = format!("{:x}", Sha256::digest(&original));
        let path = temp.0.join(format!("archive-device-draft-{digest}.dpapi"));
        store.archive(kind).unwrap();
        store.archive(kind).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(store.load_archive(kind, &digest).unwrap().expose(), payload);
        assert!(!original.windows(payload.len()).any(|v| v == payload));
        assert!(store.load_archive(kind, "../invalid").is_err());
        std::fs::write(&path, b"partial archive").unwrap();
        assert!(store.archive(kind).is_err());
        assert_eq!(
            std::fs::read(temp.0.join(kind.filename())).unwrap(),
            original
        );
        std::fs::write(&path, &original).unwrap();
        let alias = temp.0.join("test-hardlink.dpapi");
        std::fs::hard_link(&path, &alias).unwrap();
        assert!(store.archive(kind).is_err());
        std::fs::remove_file(alias).unwrap();
        store.archive(kind).unwrap();
        store
            .prepare(kind, b"new synthetic draft")
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(store.load_archive(kind, &digest).unwrap().expose(), payload);
        assert_eq!(std::fs::read(&path).unwrap(), original);
        drop(store);
    }
    #[test]
    fn only_absolute_local_disk_paths_are_accepted() {
        for path in [r"C:\Users\fixture\store", "C:/Users/fixture/store"] {
            assert!(local_root(Path::new(path)), "{path}");
        }
        for path in [
            r"\\server\share\store",
            "//server/share/store",
            r"/\server\share\store",
            r"\\?\C:\store",
            r"\\.\C:\store",
            r"C:store",
            r"\store",
            "store",
            r"C:\Users\fixture\..\store",
        ] {
            assert!(!local_root(Path::new(path)), "{path}");
        }
    }
    #[test]
    fn staged_writes_are_private_exclusive_and_not_committed_until_rename() {
        let temp = Temp::new();
        let store = PrivateStore::open(&temp.0).unwrap();
        assert!(PrivateStore::open(&temp.0).is_err());
        store
            .prepare(RecordKind::Identity, b"old synthetic value")
            .unwrap()
            .commit()
            .unwrap();
        let pending = store
            .prepare(RecordKind::Identity, b"new synthetic value")
            .unwrap();
        assert_eq!(
            store.load(RecordKind::Identity).unwrap().expose(),
            b"old synthetic value"
        );
        let bytes = std::fs::read(temp.0.join(RecordKind::Identity.filename())).unwrap();
        assert!(!bytes.windows(19).any(|x| x == b"old synthetic value"));
        drop(pending);
        assert_eq!(
            store.load(RecordKind::Identity).unwrap().expose(),
            b"old synthetic value"
        );
        store
            .prepare(RecordKind::Identity, b"new synthetic value")
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(
            store.load(RecordKind::Identity).unwrap().expose(),
            b"new synthetic value"
        );
    }
    #[test]
    fn prepared_write_retains_exclusive_store_lifetime() {
        let temp = Temp::new();
        let store = PrivateStore::open(&temp.0).unwrap();
        let pending = store
            .prepare(RecordKind::Account, b"synthetic account")
            .unwrap();
        drop(store);
        assert!(PrivateStore::open(&temp.0).is_err());
        pending.commit().unwrap();
        let reopened = PrivateStore::open(&temp.0).unwrap();
        assert_eq!(
            reopened.load(RecordKind::Account).unwrap().expose(),
            b"synthetic account"
        );
    }
    #[test]
    fn rename_failure_preserves_old_commit_and_cleans_pending() {
        let temp = Temp::new();
        let store = PrivateStore::open(&temp.0).unwrap();
        store
            .prepare(RecordKind::Policy, b"old policy")
            .unwrap()
            .commit()
            .unwrap();
        let blocker = checked(unsafe {
            CreateFileW(
                path_wide(&temp.0.join(RecordKind::Policy.filename()))
                    .unwrap()
                    .as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        })
        .unwrap();
        assert!(store
            .prepare(RecordKind::Policy, b"new policy")
            .unwrap()
            .commit()
            .is_err());
        assert_eq!(
            store.load(RecordKind::Policy).unwrap().expose(),
            b"old policy"
        );
        assert!(!std::fs::read_dir(&temp.0).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".pending-")));
        drop(blocker);
    }
    #[test]
    fn corrupt_or_wrong_kind_records_are_not_replaced() {
        let temp = Temp::new();
        let store = PrivateStore::open(&temp.0).unwrap();
        store
            .prepare(RecordKind::Identity, b"synthetic identity")
            .unwrap()
            .commit()
            .unwrap();
        let path = temp.0.join(RecordKind::Identity.filename());
        let wrong = storage_record::encode(RecordKind::Account, b"synthetic account").unwrap();
        for invalid in [
            b"corrupt ciphertext".to_vec(),
            windows_secret::protect(wrong.expose()).unwrap(),
            windows_secret::protect(b"not an inner record").unwrap(),
        ] {
            std::fs::write(&path, &invalid).unwrap();
            assert!(store.load(RecordKind::Identity).is_err());
            assert!(store
                .prepare(RecordKind::Identity, b"replacement")
                .unwrap()
                .commit()
                .is_err());
            assert_eq!(std::fs::read(&path).unwrap(), invalid);
            assert!(!std::fs::read_dir(&temp.0).unwrap().any(|e| e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".pending-")));
        }
    }
    #[test]
    fn invalid_existing_target_is_not_replaced_or_repaired() {
        let temp = Temp::new();
        let store = PrivateStore::open(&temp.0).unwrap();
        let path = temp.0.join(RecordKind::Account.filename());
        // A directory occupying the committed filename must never be replaced.
        std::fs::create_dir(&path).unwrap();
        assert!(store
            .prepare(RecordKind::Account, b"replacement")
            .unwrap()
            .commit()
            .is_err());
        assert!(path.is_dir());
        std::fs::remove_dir(&path).unwrap();
        // Moving an ordinary inherited-ACL file retains its original ACL.
        let outside = Temp::new();
        std::fs::create_dir(&outside.0).unwrap();
        let original = outside.0.join("insecure");
        let record = storage_record::encode(RecordKind::Account, b"original").unwrap();
        let encrypted = windows_secret::protect(record.expose()).unwrap();
        std::fs::write(&original, &encrypted).unwrap();
        std::fs::rename(&original, &path).unwrap();
        assert!(store
            .prepare(RecordKind::Account, b"replacement")
            .unwrap()
            .commit()
            .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), encrypted);
    }
    #[test]
    fn insecure_existing_directory_is_rejected_without_permission_repair() {
        let temp = Temp::new();
        std::fs::create_dir(&temp.0).unwrap();
        std::fs::write(temp.0.join("user-file"), b"untouched").unwrap();
        assert!(PrivateStore::open(&temp.0).is_err());
        assert_eq!(
            std::fs::read(temp.0.join("user-file")).unwrap(),
            b"untouched"
        );
    }
    #[test]
    #[ignore = "child-only abrupt exit fixture"]
    fn fixture_exit_after_flush() {
        let path = PathBuf::from(std::env::var("ADAPTER_TEST_STORE_ROOT").unwrap());
        let store = PrivateStore::open(&path).unwrap();
        let _pending = store
            .prepare(RecordKind::Identity, b"uncommitted synthetic value")
            .unwrap();
        std::process::exit(73);
    }
    #[test]
    fn abrupt_exit_after_flush_preserves_commit_and_reclaims_only_owned_pending() {
        let temp = Temp::new();
        {
            let store = PrivateStore::open(&temp.0).unwrap();
            store
                .prepare(RecordKind::Identity, b"committed synthetic value")
                .unwrap()
                .commit()
                .unwrap();
            std::fs::write(temp.0.join(".pending-user-note"), b"keep").unwrap();
        }
        let mut child = crate::windows_process::spawn_fixture(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "windows_store::tests::fixture_exit_after_flush",
                    "--ignored",
                ])
                .env("ADAPTER_TEST_STORE_ROOT", &temp.0),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("store crash fixture timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.code(), Some(73));
        assert_eq!(
            std::fs::read_dir(&temp.0)
                .unwrap()
                .filter(|e| e
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".pending-"))
                .count(),
            2
        );
        let reopened = PrivateStore::open(&temp.0).unwrap();
        assert_eq!(
            reopened.load(RecordKind::Identity).unwrap().expose(),
            b"committed synthetic value"
        );
        assert_eq!(
            std::fs::read(temp.0.join(".pending-user-note")).unwrap(),
            b"keep"
        );
        assert_eq!(
            std::fs::read_dir(&temp.0)
                .unwrap()
                .filter(|e| e
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".pending-"))
                .count(),
            1
        );
    }
    #[test]
    fn pre_flush_failure_drops_open_handle_before_pending_cleanup() {
        let temp = Temp::new();
        let store = PrivateStore::open(&temp.0).unwrap();
        store
            .prepare(RecordKind::Policy, b"old policy")
            .unwrap()
            .commit()
            .unwrap();
        assert!(store
            .prepare_checked(RecordKind::Policy, b"new policy", || Err(io::Error::other(
                "injected write-stage failure"
            )))
            .is_err());
        assert_eq!(
            store.load(RecordKind::Policy).unwrap().expose(),
            b"old policy"
        );
        assert!(!std::fs::read_dir(&temp.0).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".pending-")));
    }
}
