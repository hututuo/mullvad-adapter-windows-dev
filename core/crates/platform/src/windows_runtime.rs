//! Secret transient stdin files, never ordinary persistent settings.
use super::{
    windows::{boot_id, Identity},
    windows_private::*,
};
use std::{
    io,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    sync::Arc,
};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*, System::Threading::*};
const MAX_INPUT: usize = 16384;
struct Lease {
    root: PathBuf,
    sid: String,
    _directory: Handle,
    _lock: Handle,
}
#[derive(Clone)]
pub struct PrivateRuntime(Arc<Lease>);
/// Owns a read-only, non-inheritable handle; explicit launch consumes this value.
/// The private delete-on-close file may contain plaintext while handles are alive.
pub struct SecretInput {
    file: Handle,
    lease: Arc<Lease>,
}
impl PrivateRuntime {
    /// Only a dedicated directory beneath an already trusted local parent is valid.
    pub fn open(root: &Path) -> io::Result<Self> {
        if !local_root(root) {
            return Err(invalid());
        }
        let sid = Identity::current()?.sid_for_storage().to_owned();
        let descriptor = Descriptor::new(&sid)?;
        let attributes = descriptor.attributes();
        let path = path_wide(root)?;
        if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
                return Err(error);
            }
        }
        let directory = checked(unsafe {
            CreateFileW(
                path.as_ptr(),
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
                path_wide(&root.join(".runtime-lock"))?.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                &attributes,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        })?;
        require_private(lock.0, &sid, false)?;
        let result = Self(Arc::new(Lease {
            root: root.to_owned(),
            sid,
            _directory: directory,
            _lock: lock,
        }));
        result.reclaim()?;
        Ok(result)
    }
    pub fn path(&self) -> &Path {
        &self.0.root
    }
    fn reclaim(&self) -> io::Result<()> {
        for entry in std::fs::read_dir(&self.0.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(id) = name.strip_prefix(".input-") else {
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
                    GENERIC_READ | DELETE,
                    FILE_SHARE_READ | FILE_SHARE_DELETE,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT,
                    null_mut(),
                )
            })?;
            require_private(file.0, &self.0.sid, false)?;
            // This directory's exclusive lease excludes cooperative active owners.
            if unsafe { DeleteFileW(path.as_ptr()) } == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
    pub fn prepare_input(&self, plaintext: &[u8]) -> io::Result<SecretInput> {
        if plaintext.is_empty() || plaintext.len() > MAX_INPUT {
            return Err(invalid());
        }
        let descriptor = Descriptor::new(&self.0.sid)?;
        let attributes = descriptor.attributes();
        let path = self.0.root.join(format!(".input-{}", boot_id()?));
        let file = checked(unsafe {
            CreateFileW(
                path_wide(&path)?.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | DELETE,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        })?;
        require_private(file.0, &self.0.sid, false)?;
        let mut offset = 0;
        while offset < plaintext.len() {
            let mut written = 0;
            if unsafe {
                WriteFile(
                    file.0,
                    plaintext[offset..].as_ptr(),
                    (plaintext.len() - offset) as u32,
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
                    "transient input write stalled",
                ));
            }
            offset += written as usize;
        }
        // Same file object and offset will be inherited as stdin; no path reopen.
        if unsafe { SetFilePointerEx(file.0, 0, null_mut(), FILE_BEGIN) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut read = null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                file.0,
                GetCurrentProcess(),
                &mut read,
                GENERIC_READ,
                0,
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let read = checked(read)?;
        drop(file);
        Ok(SecretInput {
            file: read,
            lease: self.0.clone(),
        })
    }
}
impl SecretInput {
    pub(crate) fn directory(&self) -> &Path {
        &self.lease.root
    }
    /// Scope this duplicate only across allowlisted CreateProcess. All agent
    /// process creation must use that serialized owner entry point.
    pub(crate) fn inheritable_read(&self) -> io::Result<Handle> {
        let mut read = null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                self.file.0,
                GetCurrentProcess(),
                &mut read,
                GENERIC_READ,
                1,
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        checked(read)
    }
}

#[cfg(test)]
mod tests {
    use super::super::windows_process::OwnedProcess;
    use super::*;
    use std::{
        io::Read,
        time::{Duration, Instant},
    };
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("adapter-runtime-{}", boot_id().unwrap()));
            std::fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn names(path: &Path) -> Vec<String> {
        std::fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|s| s.starts_with(".input-"))
            .collect()
    }
    const SYNTHETIC: &[u8] = b"synthetic-secret-input-fixture";
    #[test]
    fn bounded_readonly_input_holds_exclusion_and_deletes_on_final_close() {
        let temp = Temp::new();
        let path = temp.0.join("runtime");
        let runtime = PrivateRuntime::open(&path).unwrap();
        assert!(runtime.prepare_input(&[]).is_err());
        assert!(runtime.prepare_input(&vec![0; MAX_INPUT + 1]).is_err());
        let input = runtime.prepare_input(&vec![7; MAX_INPUT]).unwrap();
        let mut size = 0;
        assert_ne!(unsafe { GetFileSizeEx(input.file.0, &mut size) }, 0);
        assert_eq!(size, MAX_INPUT as i64);
        let mut written = 0;
        assert_eq!(
            unsafe { WriteFile(input.file.0, b"x".as_ptr(), 1, &mut written, null_mut()) },
            0
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(ERROR_ACCESS_DENIED as i32)
        );
        assert_eq!(names(&path).len(), 1);
        drop(runtime);
        assert!(PrivateRuntime::open(&path).is_err());
        drop(input);
        let _runtime = PrivateRuntime::open(&path).unwrap();
        assert!(names(&path).is_empty());
    }
    #[test]
    #[ignore = "child-only secret stdin fixture"]
    fn fixture_read_input() {
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        std::io::stdin()
            .take((MAX_INPUT + 1) as u64)
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(&bytes[..], SYNTHETIC);
        let handle = unsafe {
            windows_sys::Win32::System::Console::GetStdHandle(
                windows_sys::Win32::System::Console::STD_INPUT_HANDLE,
            )
        };
        let mut written = 0;
        assert_eq!(
            unsafe { WriteFile(handle, b"x".as_ptr(), 1, &mut written, null_mut()) },
            0
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(ERROR_ACCESS_DENIED as i32)
        );
    }
    #[test]
    fn owned_process_reads_input_without_a_secret_path_and_cleans_after_drop() {
        let temp = Temp::new();
        let path = temp.0.join("runtime");
        let runtime = PrivateRuntime::open(&path).unwrap();
        let input = runtime.prepare_input(SYNTHETIC).unwrap();
        let child = OwnedProcess::spawn_with_secret_input(
            &std::env::current_exe().unwrap(),
            &[
                "--exact".into(),
                "windows_runtime::tests::fixture_read_input".into(),
                "--ignored".into(),
            ],
            input,
        )
        .unwrap();
        assert_eq!(child.wait(Duration::from_secs(5)).unwrap(), Some(0));
        assert_eq!(names(&path).len(), 1);
        drop(child);
        assert!(names(&path).is_empty());
    }
    #[test]
    #[ignore = "child-only live stdin holder"]
    fn fixture_hold_input() {
        std::thread::sleep(Duration::from_secs(60));
    }
    #[test]
    #[ignore = "child-only abrupt input owner exit"]
    fn fixture_crash_input_owner() {
        let runtime =
            PrivateRuntime::open(&std::env::current_dir().unwrap().join("runtime")).unwrap();
        let input = runtime.prepare_input(SYNTHETIC).unwrap();
        let _child = OwnedProcess::spawn_with_secret_input(
            &std::env::current_exe().unwrap(),
            &[
                "--exact".into(),
                "windows_runtime::tests::fixture_hold_input".into(),
                "--ignored".into(),
            ],
            input,
        )
        .unwrap();
        unsafe {
            ExitProcess(73);
        }
    }
    #[test]
    fn abrupt_owner_exit_reclaims_live_child_input_via_job_and_kernel_handles() {
        let temp = Temp::new();
        let path = temp.0.join("runtime");
        let owner = OwnedProcess::spawn(
            &std::env::current_exe().unwrap(),
            &[
                "--exact".into(),
                "windows_runtime::tests::fixture_crash_input_owner".into(),
                "--ignored".into(),
            ],
            &temp.0,
        )
        .unwrap();
        assert_eq!(owner.wait(Duration::from_secs(5)).unwrap(), Some(73));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !names(&path).is_empty() {
            assert!(
                Instant::now() < deadline,
                "input remains after owner/child exit"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let _runtime = PrivateRuntime::open(&path).unwrap();
    }
    #[test]
    fn concurrent_standard_fixture_spawn_does_not_retain_secret_stdin() {
        struct ChildGuard(std::process::Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
            }
        }
        for _ in 0..8 {
            let temp = Temp::new();
            let path = temp.0.join("runtime");
            let runtime = PrivateRuntime::open(&path).unwrap();
            let input = runtime.prepare_input(SYNTHETIC).unwrap();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let other = barrier.clone();
            let reader = std::thread::spawn(move || {
                other.wait();
                let process = OwnedProcess::spawn_with_secret_input(
                    &std::env::current_exe().unwrap(),
                    &[
                        "--exact".into(),
                        "windows_runtime::tests::fixture_read_input".into(),
                        "--ignored".into(),
                    ],
                    input,
                )
                .unwrap();
                assert_eq!(process.wait(Duration::from_secs(5)).unwrap(), Some(0));
                drop(process);
            });
            barrier.wait();
            let mut unrelated = ChildGuard(
                crate::windows_process::spawn_fixture(
                    std::process::Command::new(std::env::current_exe().unwrap()).args([
                        "--exact",
                        "windows_runtime::tests::fixture_hold_input",
                        "--ignored",
                    ]),
                )
                .unwrap(),
            );
            reader.join().unwrap();
            assert_eq!(unrelated.0.try_wait().unwrap(), None);
            assert!(
                names(&path).is_empty(),
                "unrelated standard child retained secret stdin"
            );
            unrelated.0.kill().unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while unrelated.0.try_wait().unwrap().is_none() {
                assert!(Instant::now() < deadline, "fixture cleanup timeout");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    #[test]
    fn failed_child_start_closes_prepared_input_without_touching_other_files() {
        let temp = Temp::new();
        let path = temp.0.join("runtime");
        let runtime = PrivateRuntime::open(&path).unwrap();
        std::fs::write(path.join("unrelated"), b"retain").unwrap();
        let input = runtime.prepare_input(SYNTHETIC).unwrap();
        assert!(
            OwnedProcess::spawn_with_secret_input(&path.join("missing.exe"), &[], input).is_err()
        );
        assert!(names(&path).is_empty());
        assert_eq!(std::fs::read(path.join("unrelated")).unwrap(), b"retain");
    }
    #[test]
    fn reserved_insecure_stale_file_is_rejected_without_deletion() {
        let temp = Temp::new();
        let path = temp.0.join("runtime");
        let runtime = PrivateRuntime::open(&path).unwrap();
        let stale = path.join(format!(".input-{}", boot_id().unwrap()));
        // Ordinary creation lacks the exact protected per-object owner DACL.
        std::fs::write(&stale, b"preserve on validation error").unwrap();
        drop(runtime);
        assert!(PrivateRuntime::open(&path).is_err());
        assert_eq!(
            std::fs::read(stale).unwrap(),
            b"preserve on validation error"
        );
    }
    #[test]
    fn startup_reclaims_only_reserved_private_files_and_rejects_insecure_roots() {
        let temp = Temp::new();
        let path = temp.0.join("runtime");
        let runtime = PrivateRuntime::open(&path).unwrap();
        let descriptor = Descriptor::new(&runtime.0.sid).unwrap();
        let attributes = descriptor.attributes();
        let stale = path.join(format!(".input-{}", boot_id().unwrap()));
        let file = checked(unsafe {
            CreateFileW(
                path_wide(&stale).unwrap().as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                &attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        })
        .unwrap();
        drop(file);
        std::fs::write(path.join("unrelated"), b"retain").unwrap();
        drop(runtime);
        let _runtime = PrivateRuntime::open(&path).unwrap();
        assert!(!stale.exists());
        assert_eq!(std::fs::read(path.join("unrelated")).unwrap(), b"retain");
        let insecure = temp.0.join("insecure");
        std::fs::create_dir(&insecure).unwrap();
        assert!(PrivateRuntime::open(&insecure).is_err());
    }
}
