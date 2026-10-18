//! Local user/session-scoped Windows IPC. This currently hosts mock commands only.
//! DACL and identity checks are independent from any renderer capability.
use std::{
    ffi::c_void,
    io::{self, Read, Write},
    ptr::null_mut,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{Com::CoCreateGuid, Pipes::*, Threading::*},
};

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn error() -> io::Error {
    io::Error::last_os_error()
}
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
impl Handle {
    fn checked(value: HANDLE) -> io::Result<Self> {
        if value.is_null() || value == INVALID_HANDLE_VALUE {
            Err(error())
        } else {
            Ok(Self(value))
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Identity {
    sid: String,
    session: u32,
    scope: String,
}
fn token_information(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<usize>> {
    let mut size = 0;
    unsafe {
        GetTokenInformation(token, class, null_mut(), 0, &mut size);
    }
    if size == 0 || size > 65536 {
        return Err(error());
    }
    let mut value = vec![
        0usize;
        (size as usize + std::mem::size_of::<usize>() - 1)
            / std::mem::size_of::<usize>()
    ];
    if unsafe { GetTokenInformation(token, class, value.as_mut_ptr().cast(), size, &mut size) } == 0
    {
        return Err(error());
    }
    Ok(value)
}
fn identity(token: HANDLE) -> io::Result<Identity> {
    let user = token_information(token, TokenUser)?;
    let sid = unsafe { (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(error());
    }
    let mut size = 0;
    unsafe {
        while *text.add(size) != 0 {
            size += 1;
        }
    }
    let result = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, size) });
    unsafe {
        LocalFree(text.cast());
    }
    let session = token_information(token, TokenSessionId)?;
    Ok(Identity {
        sid: result,
        scope: "Mock".into(),
        session: unsafe { *session.as_ptr().cast::<u32>() },
    })
}
impl Identity {
    pub(crate) fn sid_for_storage(&self) -> &str {
        &self.sid
    }

    pub fn current() -> io::Result<Self> {
        let mut token = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(error());
        }
        identity(Handle::checked(token)?.0)
    }
    pub fn with_scope(mut self, scope: &str) -> io::Result<Self> {
        if scope.is_empty()
            || scope.len() > 64
            || !scope
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid_mock_scope",
            ));
        }
        self.scope = scope.into();
        Ok(self)
    }
    fn same_user_session(&self, other: &Self) -> bool {
        self.sid == other.sid && self.session == other.session
    }
    pub fn pipe_name(&self) -> String {
        format!(
            r"\\.\pipe\MullvadAdapter.{}.{}.{}",
            self.scope, self.sid, self.session
        )
    }
}
struct Security(*mut c_void);
impl Drop for Security {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
impl Security {
    fn new(owner: &Identity) -> io::Result<Self> {
        // Protected DACL: only this user. Connection impersonation additionally checks session.
        let sddl = wide(&format!("D:P(A;;GA;;;{})", owner.sid));
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(error());
        }
        Ok(Self(descriptor))
    }
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }
}
/// Hold for the entire host lifetime. Never inherited by UI/engine children.
pub struct SingleInstance(Handle);
impl SingleInstance {
    pub fn acquire(owner: &Identity) -> io::Result<Self> {
        let security = Security::new(owner)?;
        let attributes = security.attributes();
        let name = wide(&format!(
            r"Local\MullvadAdapter.{}.{}.{}",
            owner.scope, owner.sid, owner.session
        ));
        let handle = unsafe { CreateMutexW(&attributes, 0, name.as_ptr()) };
        let last = unsafe { GetLastError() };
        let handle = Handle::checked(handle)?;
        if last == ERROR_ALREADY_EXISTS {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "agent_already_running",
            ));
        }
        Ok(Self(handle))
    }
    pub fn is_held(&self) -> bool {
        !self.0 .0.is_null()
    }
}
/// Machine-wide presence lease for one tunnel device. Session/scope changes
/// cannot authorize a second worker with the same fingerprint. No thread owns
/// this mutex; exclusivity is the atomic creation of the named kernel object.
pub struct PeerLease(Handle);
// Kernel handles are thread independent; no mutex ownership or wait is used.
unsafe impl Send for PeerLease {}
impl PeerLease {
    pub fn acquire(fingerprint: &[u8; 32]) -> io::Result<Self> {
        let owner = Identity::current()?;
        let security = Security::new(&owner)?;
        let attributes = security.attributes();
        let digest: String = fingerprint.iter().map(|b| format!("{b:02x}")).collect();
        let name = wide(&format!(r"Global\MullvadAdapter.Peer.{digest}"));
        unsafe {
            SetLastError(0);
        }
        let handle = unsafe { CreateMutexW(&attributes, 0, name.as_ptr()) };
        let last = unsafe { GetLastError() };
        let handle = Handle::checked(handle)?;
        if last == ERROR_ALREADY_EXISTS {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "device_peer_in_use",
            ));
        }
        Ok(Self(handle))
    }
    /// Duplicate only under OwnedProcess's allowlisted spawn gate. The engine
    /// retains this object across parent crash until its own process exits.
    pub(crate) fn inheritable_duplicate(&self) -> io::Result<InheritedPeer> {
        let mut value = null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                self.0 .0,
                GetCurrentProcess(),
                &mut value,
                0,
                1,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(error());
        }
        Ok(InheritedPeer(Handle::checked(value)?))
    }
}
pub(crate) struct InheritedPeer(Handle);
impl InheritedPeer {
    pub(crate) fn raw(&self) -> HANDLE {
        self.0 .0
    }
}
pub fn boot_id() -> io::Result<String> {
    let mut guid = windows_sys::core::GUID::from_u128(0);
    if unsafe { CoCreateGuid(&mut guid) } < 0 {
        return Err(io::Error::other("boot_id_unavailable"));
    }
    Ok(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7]
    ))
}
/// A single bounded connection. PIPE_NOWAIT avoids unbounded blocking ReadFile/WriteFile.
/// The entire session deadline includes handshake, framing and output backpressure.
pub struct Pipe {
    handle: Handle,
    deadline: Instant,
    server: bool,
}
/// Retained server handle; no termination rights and no PID-based kill.
pub struct ServerExitWaiter(Handle);
impl ServerExitWaiter {
    pub fn confirm(&self, timeout: Duration) -> io::Result<()> {
        if unsafe {
            WaitForSingleObject(self.0 .0, timeout.as_millis().min(u32::MAX as u128) as u32)
        } != WAIT_OBJECT_0
        {
            return Err(io::Error::other("backend_stop_unconfirmed"));
        }
        let mut code = 0;
        if unsafe { GetExitCodeProcess(self.0 .0, &mut code) } == 0 || code != 0 {
            return Err(io::Error::other("backend_stop_unconfirmed"));
        }
        Ok(())
    }
}
impl Pipe {
    pub fn server_exit_waiter(&self) -> io::Result<ServerExitWaiter> {
        if self.server {
            return Err(io::Error::other("client_pipe_required"));
        }
        let mut pid = 0;
        if unsafe { GetNamedPipeServerProcessId(self.handle.0, &mut pid) } == 0 {
            return Err(error());
        }
        Ok(ServerExitWaiter(Handle::checked(unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        })?))
    }
    pub fn accept(owner: &Identity, wait: Duration) -> io::Result<Self> {
        let security = Security::new(owner)?;
        let attributes = security.attributes();
        let name = wide(&owner.pipe_name());
        let handle = Handle::checked(unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                65540,
                65540,
                0,
                &attributes,
            )
        })?;
        let until = Instant::now() + wait;
        loop {
            let connected = unsafe { ConnectNamedPipe(handle.0, null_mut()) } != 0;
            let code = unsafe { GetLastError() };
            if connected || code == ERROR_PIPE_CONNECTED {
                break;
            }
            if code != ERROR_PIPE_LISTENING && code != ERROR_NO_DATA {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
            if Instant::now() >= until {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "accept_timeout"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut pipe = Self {
            handle,
            deadline: Instant::now() + Duration::from_secs(5),
            server: true,
        };
        // Impersonation identifies the last read message, so read a fixed, nonsecret prelude first.
        let mut prelude = [0];
        pipe.read_exact(&mut prelude).map_err(|_| {
            io::Error::new(io::ErrorKind::PermissionDenied, "client_handshake_rejected")
        })?;
        if prelude != [0xA1] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid_prelude",
            ));
        }
        pipe.authorize(owner).map_err(|_| {
            io::Error::new(io::ErrorKind::PermissionDenied, "client_identity_rejected")
        })?;
        Ok(pipe)
    }
    pub fn connect(owner: &Identity, wait: Duration) -> io::Result<Self> {
        let name = wide(&owner.pipe_name());
        let until = Instant::now() + wait;
        let handle = loop {
            let value = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    std::ptr::null_mut(),
                )
            };
            if value != INVALID_HANDLE_VALUE {
                break Handle::checked(value)?;
            }
            let code = unsafe { GetLastError() };
            if code != ERROR_FILE_NOT_FOUND && code != ERROR_PIPE_BUSY {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
            if Instant::now() >= until {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "connect_timeout"));
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let mut process_id = 0;
        if unsafe { GetNamedPipeServerProcessId(handle.0, &mut process_id) } == 0 {
            return Err(error());
        }
        let process = Handle::checked(unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id)
        })?;
        let mut token = null_mut();
        if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } == 0 {
            return Err(error());
        }
        let token = Handle::checked(token)?;
        if !identity(token.0)?.same_user_session(owner) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wrong_server_identity",
            ));
        }
        let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
        if unsafe { SetNamedPipeHandleState(handle.0, &mode, std::ptr::null(), std::ptr::null()) }
            == 0
        {
            return Err(error());
        }
        let mut pipe = Self {
            handle,
            deadline: Instant::now() + Duration::from_secs(5),
            server: false,
        };
        pipe.write_all(&[0xA1])?;
        Ok(pipe)
    }
    fn authorize(&self, owner: &Identity) -> io::Result<()> {
        if unsafe { ImpersonateNamedPipeClient(self.handle.0) } == 0 {
            return Err(error());
        }
        let result = (|| {
            let mut token = null_mut();
            if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
                return Err(error());
            }
            let token = Handle::checked(token)?;
            if !identity(token.0)?.same_user_session(owner) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "wrong_user_or_session",
                ));
            }
            Ok(())
        })();
        // Never continue executing under client identity if revert fails.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
        result
    }
    fn wait(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "session_deadline"));
        }
        std::thread::sleep(Duration::from_millis(2));
        Ok(())
    }
}
impl Read for Pipe {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if Instant::now() >= self.deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "session_deadline"));
            }
            let mut read = 0;
            if unsafe {
                ReadFile(
                    self.handle.0,
                    buffer.as_mut_ptr(),
                    buffer.len().min(65540) as u32,
                    &mut read,
                    null_mut(),
                )
            } != 0
            {
                if read != 0 {
                    return Ok(read as usize);
                }
            } else {
                let code = unsafe { GetLastError() };
                if code == ERROR_BROKEN_PIPE {
                    return Ok(0);
                }
                if code != ERROR_NO_DATA {
                    return Err(io::Error::from_raw_os_error(code as i32));
                }
            }
            self.wait()?;
        }
    }
}
impl Write for Pipe {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if Instant::now() >= self.deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "session_deadline"));
            }
            let mut written = 0;
            if unsafe {
                WriteFile(
                    self.handle.0,
                    buffer.as_ptr(),
                    buffer.len().min(65540) as u32,
                    &mut written,
                    null_mut(),
                )
            } == 0
            {
                return Err(error());
            }
            if written != 0 {
                return Ok(written as usize);
            }
            self.wait()?;
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    } // FlushFileBuffers can wait indefinitely for a client.
}
impl Drop for Pipe {
    fn drop(&mut self) {
        if self.server {
            unsafe {
                DisconnectNamedPipe(self.handle.0);
            }
        }
    }
}

#[cfg(all(test, any(windows, feature = "windows-api-check")))]
mod tests {
    use super::*;
    #[test]
    fn current_user_pipe_exchange_and_single_instance() {
        let owner = Identity::current()
            .unwrap()
            .with_scope(&boot_id().unwrap())
            .unwrap();
        let server_owner = owner.clone();
        let guard = SingleInstance::acquire(&owner).unwrap();
        assert!(guard.is_held());
        assert!(
            matches!(SingleInstance::acquire(&owner),Err(e) if e.kind()==io::ErrorKind::AlreadyExists)
        );
        let server = std::thread::spawn(move || {
            let owner = server_owner;
            let mut pipe = Pipe::accept(&owner, Duration::from_secs(2)).unwrap();
            let mut request = [0; 4];
            pipe.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            pipe.write_all(b"pong").unwrap();
            let mut ack = [0];
            pipe.read_exact(&mut ack).unwrap();
            assert_eq!(ack, [1]);
        });
        let mut client = Pipe::connect(&owner, Duration::from_secs(2)).unwrap();
        client.write_all(b"ping").unwrap();
        let mut response = [0; 4];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"pong");
        client.write_all(&[1]).unwrap();
        server.join().unwrap();
        drop(guard);
        assert!(SingleInstance::acquire(&owner).is_ok());
    }
    #[test]
    fn boot_identifiers_change() {
        assert_ne!(boot_id().unwrap(), boot_id().unwrap());
    }
    #[test]
    fn restrictive_descriptor_has_one_non_inherited_ace() {
        let owner = Identity::current().unwrap();
        let security = Security::new(&owner).unwrap();
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = null_mut();
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(security.0, &mut present, &mut acl, &mut defaulted)
            },
            0
        );
        assert_ne!(present, 0);
        assert!(!acl.is_null());
        assert_eq!(unsafe { (*acl).AceCount }, 1);
    }
    #[test]
    fn anonymous_client_is_connection_local_rejection() {
        let owner = Identity::current()
            .unwrap()
            .with_scope(&boot_id().unwrap())
            .unwrap();
        let server_owner = owner.clone();
        let server = std::thread::spawn(move || {
            let result = Pipe::accept(&server_owner, Duration::from_secs(3));
            assert!(matches!(result,Err(e) if e.kind()==io::ErrorKind::PermissionDenied));
        });
        let name = wide(&owner.pipe_name());
        let deadline = Instant::now() + Duration::from_secs(3);
        let handle = loop {
            let raw = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS,
                    null_mut(),
                )
            };
            if raw != INVALID_HANDLE_VALUE {
                break Handle::checked(raw).unwrap();
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        };
        let mut written = 0;
        assert_ne!(
            unsafe { WriteFile(handle.0, [0xA1u8].as_ptr(), 1, &mut written, null_mut()) },
            0
        );
        server.join().unwrap();
    }
}
