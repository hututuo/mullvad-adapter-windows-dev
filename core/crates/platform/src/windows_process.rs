//! Handle-owned process trees. Not connected to the mock IPC or a live engine.
//! Processes remain suspended until assigned to a kill-on-close job. Explicit
//! handle lists isolate secret input; worker output yields only bounded labels.
use std::{
    io,
    mem::{size_of, zeroed},
    path::Path,
    ptr::{null, null_mut},
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::*,
    System::{JobObjects::*, Threading::*},
};

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
fn checked(h: HANDLE) -> io::Result<Handle> {
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(Handle(h))
    }
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "invalid process specification")
}
fn quote(s: &str) -> String {
    let mut result = String::from("\"");
    let mut slashes = 0;
    for c in s.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        result.extend(std::iter::repeat('\\').take(if c == '"' {
            slashes * 2 + 1
        } else {
            slashes
        }));
        slashes = 0;
        result.push(c);
    }
    result.extend(std::iter::repeat('\\').take(slashes * 2));
    result.push('"');
    result
}
fn sanitized_environment(directory: &Path) -> io::Result<Vec<u16>> {
    use std::path::{Component, Prefix};
    use windows_sys::Win32::System::SystemInformation::{
        GetSystemDirectoryW, GetSystemWindowsDirectoryW,
    };
    if !directory.is_absolute()
        || !matches!(directory.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)))
        || directory
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(invalid());
    }
    let directory = directory
        .to_str()
        .filter(|s| !s.contains('\0'))
        .ok_or_else(invalid)?;
    fn os_directory(query: unsafe extern "system" fn(*mut u16, u32) -> u32) -> io::Result<String> {
        let mut buffer = vec![0u16; 32768];
        let count = unsafe { query(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
        if count == 0 {
            return Err(io::Error::last_os_error());
        }
        if count >= buffer.len() {
            return Err(invalid());
        }
        String::from_utf16(&buffer[..count]).map_err(|_| invalid())
    }
    let windows = os_directory(GetSystemWindowsDirectoryW)?;
    let system = os_directory(GetSystemDirectoryW)?;
    let entries = [
        ("PATH", system.as_str()),
        ("SystemRoot", windows.as_str()),
        ("TEMP", directory),
        ("TMP", directory),
        ("windir", windows.as_str()),
    ];
    // Case-insensitive sorted keys, NUL per entry plus final NUL: Unicode block.
    let mut block = Vec::new();
    for (key, value) in entries {
        block.extend(format!("{key}={value}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    if block.len() > 32767 {
        return Err(invalid());
    }
    Ok(block)
}
struct Attributes(Vec<usize>);
impl Attributes {
    fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.0.as_mut_ptr().cast()
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.pointer());
        }
    }
}

static SPAWN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn spawn_fixture(
    command: &mut std::process::Command,
) -> io::Result<std::process::Child> {
    // Rust 1.85 std::Command uses broad inheritance. Share the same gate as the
    // transient stdin duplicate; never hold it while waiting for a child.
    let _gate = SPAWN_LOCK
        .lock()
        .map_err(|_| io::Error::other("process creation gate poisoned"))?;
    command.spawn()
}

pub struct OwnedProcess {
    job: Handle,
    process: Handle,
    _input: Option<super::windows_runtime::SecretInput>,
    output: super::engine_output::Monitor,
}
impl OwnedProcess {
    pub fn output_snapshot(&self) -> super::engine_output::Snapshot {
        self.output.snapshot()
    }
    pub fn controller_owner(&self) -> io::Result<super::windows_controller_owner::ControllerOwner> {
        super::windows_controller_owner::ControllerOwner::duplicate(self.process.0)
    }
    /// Internal platform primitive: callers must separately verify the packaged
    /// executable/hash and use private transient configuration, never raw keys in args.
    pub fn spawn(executable: &Path, args: &[String], directory: &Path) -> io::Result<Self> {
        Self::spawn_before_resume(executable, args, directory, |_| {})
    }
    /// Engine launch boundary: inherit no environment variables, including proxy,
    /// CLASH_* overrides, credentials or caller-controlled executable search paths.
    /// The trusted private runtime directory is used for TEMP/TMP. No config/secret
    /// belongs in these environment entries or in process arguments.
    pub fn spawn_sanitized(
        executable: &Path,
        args: &[String],
        directory: &Path,
    ) -> io::Result<Self> {
        let environment = sanitized_environment(directory)?;
        Self::spawn_configured(
            executable,
            args,
            directory,
            Some(&environment),
            None,
            None,
            || Ok(()),
            |_| {},
        )
    }
    /// Consume one prepared secret stream. Only its read-only duplicate becomes
    /// child stdin, all output remains NUL, and no secret pathname is in argv.
    pub fn spawn_with_secret_input(
        executable: &Path,
        args: &[String],
        input: super::windows_runtime::SecretInput,
    ) -> io::Result<Self> {
        Self::spawn_with_secret_input_checked(executable, args, input, || Ok(()))
    }
    /// Repeated nonblocking checks while queued, then under the gate immediately
    /// before CreateProcess. Must be repeatable, not spawn or perform network I/O.
    /// A rejected preflight creates no process; an in-flight OS call is not cancellable.
    pub fn spawn_with_secret_input_checked(
        executable: &Path,
        args: &[String],
        input: super::windows_runtime::SecretInput,
        preflight: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Self> {
        let directory = input.directory().to_owned();
        let environment = sanitized_environment(&directory)?;
        Self::spawn_configured(
            executable,
            args,
            &directory,
            Some(&environment),
            Some(input),
            None,
            preflight,
            |_| {},
        )
    }
    /// Inherit only this supplied device lease, secret stdin, NUL input and the
    /// closed-label output pipe. Peer exclusion lasts until the child exits.
    pub fn spawn_with_secret_input_and_peer_checked(
        executable: &Path,
        args: &[String],
        input: super::windows_runtime::SecretInput,
        peer: &super::windows::PeerLease,
        preflight: impl FnMut() -> io::Result<()>,
    ) -> io::Result<Self> {
        let directory = input.directory().to_owned();
        let environment = sanitized_environment(&directory)?;
        Self::spawn_configured(
            executable,
            args,
            &directory,
            Some(&environment),
            Some(input),
            Some(peer),
            preflight,
            |_| {},
        )
    }
    fn spawn_before_resume<F: FnOnce(HANDLE)>(
        executable: &Path,
        args: &[String],
        directory: &Path,
        before_resume: F,
    ) -> io::Result<Self> {
        Self::spawn_configured(
            executable,
            args,
            directory,
            None,
            None,
            None,
            || Ok(()),
            before_resume,
        )
    }
    fn spawn_configured<F: FnOnce(HANDLE)>(
        executable: &Path,
        args: &[String],
        directory: &Path,
        environment: Option<&[u16]>,
        input: Option<super::windows_runtime::SecretInput>,
        peer: Option<&super::windows::PeerLease>,
        mut preflight: impl FnMut() -> io::Result<()>,
        before_resume: F,
    ) -> io::Result<Self> {
        if !executable.is_absolute() || !directory.is_absolute() || args.len() > 128 {
            return Err(invalid());
        }
        let exe = executable.to_str().ok_or_else(invalid)?;
        let cwd = directory.to_str().ok_or_else(invalid)?;
        if exe.contains('\0') || cwd.contains('\0') || args.iter().any(|x| x.contains('\0')) {
            return Err(invalid());
        }
        let command = std::iter::once(exe)
            .chain(args.iter().map(String::as_str))
            .map(quote)
            .collect::<Vec<_>>()
            .join(" ");
        let mut command = wide(&command);
        if command.len() > 32767 {
            return Err(invalid());
        }
        let exe = wide(exe);
        let cwd = wide(cwd);
        // Keep the briefly inheritable secret duplicate scoped to serialized
        // allowlisted process creation. All agent process launches use this gate.
        let _spawn_gate = super::launch_gate::acquire(&SPAWN_LOCK, &mut preflight)?;
        let stdin = input
            .as_ref()
            .map(|input| input.inheritable_read())
            .transpose()?;
        unsafe {
            let job = checked(CreateJobObjectW(null(), null()))?;
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let sa = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: null_mut(),
                bInheritHandle: 1,
            };
            let stdio = checked(CreateFileW(
                wide("NUL").as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &sa,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            ))?;
            // Attribute lpValue buffers must outlive DeleteProcThreadAttributeList
            // on success AND every early return. Reverse local-drop order matters.
            let inherited_peer = peer.map(|p| p.inheritable_duplicate()).transpose()?;
            // Only device workers have a closed-label sink. Raw output never
            // reaches parent stdio or files; front and ordinary children use NUL.
            let output = peer
                .map(|_| super::engine_output::windows::Output::open())
                .transpose()?;
            let mut inherited = vec![stdio.0];
            if let Some(output) = &output {
                inherited.push(output.raw_writer());
            }
            if let Some(peer) = &inherited_peer {
                inherited.push(peer.raw());
            }
            if let Some(stdin) = &stdin {
                inherited.push(stdin.0);
            }
            let mut jobs = [job.0];
            let mut bytes = 0;
            InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut bytes);
            if bytes == 0 || bytes > 65536 {
                return Err(io::Error::last_os_error());
            }
            let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
            if InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 2, 0, &mut bytes) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut attributes = Attributes(storage);
            if UpdateProcThreadAttribute(
                attributes.pointer(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                inherited.as_mut_ptr().cast(),
                inherited.len() * size_of::<HANDLE>(),
                null_mut(),
                null(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            if UpdateProcThreadAttribute(
                attributes.pointer(),
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                jobs.as_mut_ptr().cast(),
                size_of::<HANDLE>(),
                null_mut(),
                null(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut startup: STARTUPINFOEXW = zeroed();
            startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = stdin.as_ref().map_or(stdio.0, |handle| handle.0);
            startup.StartupInfo.hStdOutput = output.as_ref().map_or(stdio.0, |o| o.raw_writer());
            startup.StartupInfo.hStdError = startup.StartupInfo.hStdOutput;
            startup.lpAttributeList = attributes.pointer();
            let mut info: PROCESS_INFORMATION = zeroed();
            preflight()?;
            if CreateProcessW(
                exe.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                1,
                CREATE_SUSPENDED
                    | CREATE_NO_WINDOW
                    | EXTENDED_STARTUPINFO_PRESENT
                    | if environment.is_some() {
                        CREATE_UNICODE_ENVIRONMENT
                    } else {
                        0
                    },
                environment.map_or(null(), |block| block.as_ptr().cast()),
                cwd.as_ptr(),
                &startup.StartupInfo,
                &mut info,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let process = Handle(info.hProcess);
            let thread = Handle(info.hThread);
            // JOB_LIST assigns ownership during CreateProcess, including the
            // suspended interval; abrupt parent death cannot strand an orphan.
            before_resume(process.0);
            if ResumeThread(thread.0) == u32::MAX {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                job,
                process,
                _input: input,
                output: output
                    .as_ref()
                    .map_or_else(super::engine_output::Monitor::default, |o| {
                        o.monitor.clone()
                    }),
            })
        }
    }
    pub fn wait(&self, timeout: Duration) -> io::Result<Option<u32>> {
        let millis = timeout.as_millis().min(30_000) as u32;
        unsafe {
            match WaitForSingleObject(self.process.0, millis) {
                WAIT_OBJECT_0 => {
                    let mut code = 0;
                    if GetExitCodeProcess(self.process.0, &mut code) == 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(Some(code))
                    }
                }
                WAIT_TIMEOUT => Ok(None),
                _ => Err(io::Error::last_os_error()),
            }
        }
    }
    fn accounting(&self) -> io::Result<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION> {
        unsafe {
            let mut info = zeroed();
            if QueryInformationJobObject(
                self.job.0,
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                null_mut(),
            ) == 0
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(info)
            }
        }
    }
    /// Force-stop fallback after the caller's bounded graceful-shutdown attempt.
    /// Completion requires the entire owned job tree to be empty, not only root exit.
    pub fn terminate(&self, timeout: Duration) -> io::Result<()> {
        if unsafe { TerminateJobObject(self.job.0, 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let deadline = std::time::Instant::now() + timeout.min(Duration::from_secs(30));
        loop {
            if self.accounting()?.ActiveProcesses == 0 && self.wait(Duration::ZERO)?.is_some() {
                return Ok(());
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "owned process tree stop timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(10).min(deadline - now));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn child_retains_peer_exclusion_after_parent_lease_is_dropped() {
        use sha2::{Digest, Sha256};
        let fingerprint: [u8; 32] =
            Sha256::digest(super::super::windows::boot_id().unwrap().as_bytes()).into();
        let peer = super::super::windows::PeerLease::acquire(&fingerprint).unwrap();
        assert!(super::super::windows::PeerLease::acquire(&fingerprint).is_err());
        let path = std::env::temp_dir().join(format!(
            "adapter-peer-{}",
            super::super::windows::boot_id().unwrap()
        ));
        let runtime = super::super::windows_runtime::PrivateRuntime::open(&path).unwrap();
        let input = runtime.prepare_input(b"synthetic-fixture-only").unwrap();
        let child = OwnedProcess::spawn_with_secret_input_and_peer_checked(
            &std::env::current_exe().unwrap(),
            &[
                "--exact".into(),
                "windows_process::tests::fixture_wait".into(),
                "--ignored".into(),
            ],
            input,
            &peer,
            || Ok(()),
        )
        .unwrap();
        drop(peer);
        assert!(
            matches!(super::super::windows::PeerLease::acquire(&fingerprint), Err(e) if e.kind() == io::ErrorKind::AlreadyExists)
        );
        child.terminate(Duration::from_secs(5)).unwrap();
        assert!(super::super::windows::PeerLease::acquire(&fingerprint).is_ok());
        drop(child);
        drop(runtime);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    #[ignore = "child-only environment fixture"]
    fn fixture_clean_environment() {
        let keys: std::collections::BTreeSet<_> = std::env::vars_os()
            .map(|(key, _)| key.to_string_lossy().to_ascii_uppercase())
            .collect();
        assert_eq!(
            keys,
            ["PATH", "SYSTEMROOT", "TEMP", "TMP", "WINDIR"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(std::env::var_os("TEMP").unwrap(), cwd.as_os_str());
        assert_eq!(std::env::var_os("TMP").unwrap(), cwd.as_os_str());
        assert_eq!(std::env::var_os("SystemRoot"), std::env::var_os("windir"));
        use windows_sys::Win32::System::SystemInformation::{
            GetSystemDirectoryW, GetSystemWindowsDirectoryW,
        };
        let mut system = [0u16; 32768];
        let system_len =
            unsafe { GetSystemDirectoryW(system.as_mut_ptr(), system.len() as u32) } as usize;
        assert!(system_len > 0 && system_len < system.len());
        let mut windows = [0u16; 32768];
        let windows_len =
            unsafe { GetSystemWindowsDirectoryW(windows.as_mut_ptr(), windows.len() as u32) }
                as usize;
        assert!(windows_len > 0 && windows_len < windows.len());
        let system = String::from_utf16(&system[..system_len]).unwrap();
        let windows = String::from_utf16(&windows[..windows_len]).unwrap();
        let expected: std::collections::BTreeMap<String, String> = [
            ("PATH".into(), system),
            ("SYSTEMROOT".into(), windows.clone()),
            ("TEMP".into(), cwd.to_str().unwrap().into()),
            ("TMP".into(), cwd.to_str().unwrap().into()),
            ("WINDIR".into(), windows),
        ]
        .into_iter()
        .collect();
        let actual: std::collections::BTreeMap<_, _> = std::env::vars()
            .map(|(key, value)| (key.to_ascii_uppercase(), value))
            .collect();
        assert_eq!(actual, expected);
    }
    #[test]
    #[ignore = "child-only poisoned-parent environment fixture"]
    fn fixture_poisoned_environment_parent() {
        // This isolated test process, never the shared test runner, changes env.
        std::env::set_var("CLASH_EXTERNAL_CONTROLLER", "synthetic-invalid");
        std::env::set_var("HTTP_PROXY", "http://127.0.0.1:1");
        std::env::set_var("ADAPTER_SYNTHETIC_SECRET_SENTINEL", "never-inherit");
        std::env::set_var("SystemRoot", "synthetic-invalid");
        std::env::set_var("PATH", "synthetic-invalid");
        std::env::set_var("windir", "synthetic-invalid");
        std::env::set_var("TEMP", "synthetic-invalid");
        std::env::set_var("TMP", "synthetic-invalid");
        let exe = std::env::current_exe().unwrap();
        let child = OwnedProcess::spawn_sanitized(
            &exe,
            &[
                "--exact".into(),
                "windows_process::tests::fixture_clean_environment".into(),
                "--ignored".into(),
            ],
            exe.parent().unwrap(),
        )
        .unwrap();
        assert_eq!(child.wait(Duration::from_secs(5)).unwrap(), Some(0));
    }
    #[test]
    fn sanitized_spawn_omits_parent_overrides_and_reconstructs_os_paths() {
        let exe = std::env::current_exe().unwrap();
        let child = OwnedProcess::spawn(
            &exe,
            &[
                "--exact".into(),
                "windows_process::tests::fixture_poisoned_environment_parent".into(),
                "--ignored".into(),
            ],
            exe.parent().unwrap(),
        )
        .unwrap();
        assert_eq!(child.wait(Duration::from_secs(10)).unwrap(), Some(0));
        assert!(sanitized_environment(Path::new(r"\\server\share\runtime")).is_err());
        assert!(sanitized_environment(Path::new(r"C:\runtime\..\other")).is_err());
    }
    #[test]
    #[ignore = "fixture process only; launched by ownership tests"]
    fn fixture_wait() {
        std::thread::sleep(Duration::from_secs(60));
    }
    #[test]
    #[ignore = "fixture process only; launched by ownership tests"]
    fn fixture_tree() {
        let mut child = spawn_fixture(
            std::process::Command::new(std::env::current_exe().unwrap()).args([
                "--exact",
                "windows_process::tests::fixture_wait",
                "--ignored",
            ]),
        )
        .unwrap();
        let _ = child.wait();
    }
    #[test]
    fn termination_reclaims_descendants_in_the_owned_job() {
        let exe = std::env::current_exe().unwrap();
        let child = OwnedProcess::spawn(
            &exe,
            &[
                "--exact".into(),
                "windows_process::tests::fixture_tree".into(),
                "--ignored".into(),
            ],
            exe.parent().unwrap(),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while child.accounting().unwrap().ActiveProcesses < 2 {
            assert!(
                std::time::Instant::now() < deadline,
                "fixture descendant did not start"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        child.terminate(Duration::from_secs(5)).unwrap();
        assert_eq!(child.accounting().unwrap().ActiveProcesses, 0);
    }
    fn fixture() -> OwnedProcess {
        let exe = std::env::current_exe().unwrap();
        OwnedProcess::spawn(
            &exe,
            &[
                "--exact".into(),
                "windows_process::tests::fixture_wait".into(),
                "--ignored".into(),
            ],
            exe.parent().unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn suspended_assignment_and_bounded_owned_stop() {
        let child = fixture();
        assert_eq!(child.wait(Duration::from_millis(50)).unwrap(), None);
        child.terminate(Duration::from_secs(5)).unwrap();
        assert_eq!(child.wait(Duration::ZERO).unwrap(), Some(1));
    }
    #[test]
    fn closing_owner_job_kills_child_without_pid_lookup() {
        let child = fixture();
        let mut duplicate = null_mut();
        assert_ne!(
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    child.process.0,
                    GetCurrentProcess(),
                    &mut duplicate,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            },
            0
        );
        let duplicate = checked(duplicate).unwrap();
        drop(child);
        assert_eq!(
            unsafe { WaitForSingleObject(duplicate.0, 5000) },
            WAIT_OBJECT_0
        );
    }
    #[test]
    fn input_validation_and_quoting() {
        assert!(OwnedProcess::spawn(Path::new("relative.exe"), &[], Path::new(".")).is_err());
        assert_eq!(quote("a b\\"), "\"a b\\\\\"");
        assert_eq!(quote("a\"b"), "\"a\\\"b\"");
    }
    #[test]
    #[ignore = "crash fixture only; launched by ownership test"]
    fn fixture_crash_before_resume() {
        let exe = std::env::current_exe().unwrap();
        let parent: u32 = std::env::var("ADAPTER_TEST_PARENT_PID")
            .unwrap()
            .parse()
            .unwrap();
        let output = std::env::var("ADAPTER_TEST_DUPLICATE_PATH").unwrap();
        let _ = OwnedProcess::spawn_before_resume(
            &exe,
            &[
                "--exact".into(),
                "windows_process::tests::fixture_wait".into(),
                "--ignored".into(),
            ],
            exe.parent().unwrap(),
            |process| {
                let parent =
                    checked(unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, parent) }).unwrap();
                let mut duplicate = null_mut();
                assert_ne!(
                    unsafe {
                        DuplicateHandle(
                            GetCurrentProcess(),
                            process,
                            parent.0,
                            &mut duplicate,
                            0,
                            0,
                            DUPLICATE_SAME_ACCESS,
                        )
                    },
                    0
                );
                std::fs::write(&output, (duplicate as usize).to_string()).unwrap();
                // ExitProcess closes kernel handles but deliberately skips Rust Drop.
                std::process::exit(71);
            },
        );
        panic!("fixture did not exit during suspended interval");
    }
    #[test]
    fn abrupt_owner_death_before_resume_reclaims_atomic_job_child() {
        let exe = std::env::current_exe().unwrap();
        let output = std::env::temp_dir().join(format!(
            "adapter-job-crash-{}",
            crate::windows::boot_id().unwrap()
        ));
        let mut owner = spawn_fixture(
            std::process::Command::new(&exe)
                .args([
                    "--exact",
                    "windows_process::tests::fixture_crash_before_resume",
                    "--ignored",
                ])
                .env("ADAPTER_TEST_PARENT_PID", std::process::id().to_string())
                .env("ADAPTER_TEST_DUPLICATE_PATH", &output),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = owner.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                let _ = owner.kill();
                let _ = owner.wait();
                panic!("crash fixture timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.code(), Some(71));
        let handle: usize = std::fs::read_to_string(&output).unwrap().parse().unwrap();
        std::fs::remove_file(output).unwrap();
        let child = checked(handle as HANDLE).unwrap();
        let result = unsafe { WaitForSingleObject(child.0, 5000) };
        if result != WAIT_OBJECT_0 {
            // Preserve the regression failure while reclaiming its suspended fixture.
            unsafe {
                TerminateProcess(child.0, 1);
                WaitForSingleObject(child.0, 5000);
            }
        }
        assert_eq!(result, WAIT_OBJECT_0);
    }
    #[test]
    fn startup_failure_and_stop_leave_unrelated_process_untouched() {
        let exe = std::env::current_exe().unwrap();
        let unrelated = fixture();
        assert!(OwnedProcess::spawn(
            &exe.with_file_name("missing-adapter-fixture.exe"),
            &[],
            exe.parent().unwrap()
        )
        .is_err());
        assert_eq!(unrelated.wait(Duration::ZERO).unwrap(), None);
        let owned = fixture();
        owned.terminate(Duration::from_secs(5)).unwrap();
        assert_eq!(unrelated.wait(Duration::ZERO).unwrap(), None);
        unrelated.terminate(Duration::from_secs(5)).unwrap();
    }
    #[test]
    #[ignore = "handle probe fixture only"]
    fn fixture_try_signal_sentinel() {
        let handle: usize = std::env::var("ADAPTER_TEST_SENTINEL_HANDLE")
            .unwrap()
            .parse()
            .unwrap();
        // If this were the inherited event it would signal the parent sentinel.
        // A recycled unrelated numeric value cannot signal that specific object.
        unsafe {
            SetEvent(handle as HANDLE);
        }
    }
    #[test]
    #[ignore = "isolated inheritance fixture only"]
    fn fixture_inheritance() {
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        let sentinel = checked(unsafe { CreateEventW(&sa, 1, 0, null()) }).unwrap();
        // This fixture has its own process/environment, no parallel parent mutation.
        std::env::set_var(
            "ADAPTER_TEST_SENTINEL_HANDLE",
            (sentinel.0 as usize).to_string(),
        );
        let exe = std::env::current_exe().unwrap();
        let child = OwnedProcess::spawn(
            &exe,
            &[
                "--exact".into(),
                "windows_process::tests::fixture_try_signal_sentinel".into(),
                "--ignored".into(),
            ],
            exe.parent().unwrap(),
        )
        .unwrap();
        assert_eq!(child.wait(Duration::from_secs(5)).unwrap(), Some(0));
        assert_eq!(unsafe { WaitForSingleObject(sentinel.0, 0) }, WAIT_TIMEOUT);
    }
    #[test]
    fn unrelated_inheritable_handle_is_not_inherited() {
        let exe = std::env::current_exe().unwrap();
        let child = OwnedProcess::spawn(
            &exe,
            &[
                "--exact".into(),
                "windows_process::tests::fixture_inheritance".into(),
                "--ignored".into(),
            ],
            exe.parent().unwrap(),
        )
        .unwrap();
        assert_eq!(child.wait(Duration::from_secs(10)).unwrap(), Some(0));
    }
    #[test]
    fn queued_secret_spawn_cancellation_releases_input_without_waiting_for_gate() {
        let root = std::env::temp_dir().join(format!(
            "adapter-preflight-{}",
            super::super::windows::boot_id().unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        let runtime =
            super::super::windows_runtime::PrivateRuntime::open(&root.join("runtime")).unwrap();
        let input = runtime.prepare_input(b"synthetic bounded input").unwrap();
        let missing = root.join("never-created.exe");
        let gate = SPAWN_LOCK.lock().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let e = OwnedProcess::spawn_with_secret_input_checked(&missing, &[], input, || {
                Err(io::ErrorKind::Interrupted.into())
            })
            .err()
            .unwrap();
            tx.send(e.kind()).unwrap();
        });
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).unwrap(),
            io::ErrorKind::Interrupted
        );
        drop(gate);
        worker.join().unwrap();
        assert!(!std::fs::read_dir(runtime.path()).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".input-")));
        drop(runtime);
        std::fs::remove_dir_all(root).unwrap();
    }
}
