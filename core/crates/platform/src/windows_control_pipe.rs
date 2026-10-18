//! Bounded byte-stream client for an existing local Windows control pipe.
//! No product IPC prelude, impersonation, network forwarding or worker threads.
use std::{
    io::{self, Read, Write},
    ptr::null_mut,
    time::{Duration, Instant},
};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*, System::Pipes::*};

pub struct LocalControlPipe {
    handle: HANDLE,
    lifetime: Instant,
    operation: Instant,
}
// The owned handle is closed once. All byte-stream I/O requires exclusive &mut.
unsafe impl Send for LocalControlPipe {}
unsafe impl Sync for LocalControlPipe {}
impl std::fmt::Debug for LocalControlPipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalControlPipe").finish_non_exhaustive()
    }
}
impl Drop for LocalControlPipe {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
impl LocalControlPipe {
    pub fn connect(name: &str, wait: Duration) -> io::Result<Self> {
        let suffix = name.strip_prefix(r"\\.\pipe\").unwrap_or("");
        if suffix.is_empty()
            || suffix.len() > 200
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            || suffix.contains("..")
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "local_control_pipe_required",
            ));
        }
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let start = Instant::now();
        let until = start + wait.min(Duration::from_secs(1));
        loop {
            if Instant::now() >= until {
                return Err(timeout());
            }
            let handle = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    null_mut(),
                )
            };
            if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
                let pipe = Self {
                    handle,
                    lifetime: start + Duration::from_secs(5),
                    operation: until,
                };
                // Byte mode and nonblocking I/O keep a hung server from holding
                // the native integration worker indefinitely. Never FlushFileBuffers.
                let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
                if unsafe {
                    SetNamedPipeHandleState(handle, &mode, std::ptr::null(), std::ptr::null())
                } == 0
                {
                    return Err(io::Error::last_os_error());
                }
                return Ok(pipe);
            }
            let error = unsafe { GetLastError() };
            if !matches!(error, ERROR_PIPE_BUSY | ERROR_FILE_NOT_FOUND) {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    pub fn set_timeout(&mut self, wait: Duration) {
        self.operation = (Instant::now() + wait.min(Duration::from_secs(5))).min(self.lifetime);
    }
    fn check(&self) -> io::Result<()> {
        if Instant::now() >= self.operation {
            Err(timeout())
        } else {
            Ok(())
        }
    }
}
fn timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "local_control_timeout")
}
impl Read for LocalControlPipe {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.check()?;
            let mut count = 0;
            if unsafe {
                ReadFile(
                    self.handle,
                    bytes.as_mut_ptr(),
                    bytes.len().min(65536) as u32,
                    &mut count,
                    null_mut(),
                )
            } != 0
            {
                if count > 0 {
                    return Ok(count as usize);
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
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
impl Write for LocalControlPipe {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            self.check()?;
            let mut count = 0;
            if unsafe {
                WriteFile(
                    self.handle,
                    bytes.as_ptr(),
                    bytes.len().min(65536) as u32,
                    &mut count,
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if count > 0 {
                return Ok(count as usize);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    #[test]
    fn remote_pipe_is_rejected_and_missing_local_pipe_has_a_deadline() {
        let start = Instant::now();
        assert_eq!(
            LocalControlPipe::connect(r"\\remote\pipe\fixture", Duration::from_secs(1))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let name = format!(r"\\.\pipe\adapter-missing-{}", std::process::id());
        assert_eq!(
            LocalControlPipe::connect(&name, Duration::from_millis(40))
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn stalled_control_pipe_read_times_out_without_a_background_io_thread() {
        let name = format!(r"\\.\pipe\adapter-stalled-{}", std::process::id());
        let server_name = name.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let wide: Vec<u16> = server_name.encode_utf16().chain(Some(0)).collect();
            let handle = unsafe {
                CreateNamedPipeW(
                    wide.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    4096,
                    4096,
                    0,
                    std::ptr::null(),
                )
            };
            assert_ne!(handle, INVALID_HANDLE_VALUE);
            let guard = LocalControlPipe {
                handle,
                lifetime: Instant::now() + Duration::from_secs(2),
                operation: Instant::now() + Duration::from_secs(2),
            };
            tx.send(()).unwrap();
            let until = Instant::now() + Duration::from_secs(2);
            loop {
                let connected = unsafe { ConnectNamedPipe(handle, null_mut()) } != 0;
                let code = unsafe { GetLastError() };
                if connected || code == ERROR_PIPE_CONNECTED {
                    break;
                }
                assert_eq!(code, ERROR_PIPE_LISTENING);
                assert!(Instant::now() < until);
                std::thread::sleep(Duration::from_millis(2));
            }
            // Intentionally withhold a response longer than the client budget.
            std::thread::sleep(Duration::from_millis(160));
            drop(guard);
        });
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let mut client = LocalControlPipe::connect(&name, Duration::from_secs(1)).unwrap();
        client.set_timeout(Duration::from_millis(40));
        let start = Instant::now();
        assert_eq!(
            client.read(&mut [0; 16]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(client);
        server.join().unwrap();
    }
}
