//! Bounded, closed labels from untrusted engine output. Never retain raw logs.
use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc,
};
use zeroize::{Zeroize, Zeroizing};

const LINE_CAP: usize = 4096;
const TOTAL_CAP: usize = 1024 * 1024;
const PATTERNS: &[(&str, &[&str])] = &[
    (
        "socket_address_invalid",
        &[
            "requested address is not valid",
            "cannot assign requested address",
            "address not available",
            "请求的地址在其上下文中无效",
        ],
    ),
    (
        "socket_argument_invalid",
        &["invalid argument", "无效的参数"],
    ),
    (
        "socket_permission_denied",
        &[
            "permission denied",
            "access denied",
            "forbidden by its access permissions",
        ],
    ),
    (
        "network_unreachable",
        &[
            "network is unreachable",
            "unreachable network",
            "no route to host",
        ],
    ),
    (
        "io_timeout",
        &[
            "i/o timeout",
            "context deadline exceeded",
            "connection timed out",
        ],
    ),
    (
        "connection_refused",
        &["connection refused", "actively refused"],
    ),
    ("connection_reset", &["connection reset", "forcibly closed"]),
    ("bind_failed", &["bind:", "cannot bind", "failed to bind"]),
    (
        "udp_error",
        &[
            "write udp",
            "read udp",
            "wsasendto",
            "wsarecvfrom",
            "sendmsg",
        ],
    ),
    (
        "handshake_initiation_started",
        &["sending handshake initiation"],
    ),
    (
        "handshake_send_failed",
        &["failed to send handshake initiation"],
    ),
    ("udp_receive_failed", &["failed to receive"]),
    (
        "handshake_response_received",
        &["receiving handshake response"],
    ),
    ("unclassified_warning", &[]),
];
#[derive(Default)]
struct State {
    mask: AtomicU32,
    warnings: AtomicU32,
    truncated: AtomicBool,
}
#[derive(Clone, Default)]
pub(crate) struct Monitor(Arc<State>);
#[derive(Clone, Copy, Debug, Default)]
pub struct Snapshot {
    mask: u32,
    pub warning_lines: u32,
    pub truncated: bool,
}
impl Snapshot {
    pub fn signals(&self) -> Vec<&'static str> {
        PATTERNS
            .iter()
            .enumerate()
            .filter_map(|(i, (label, _))| (self.mask & (1 << i) != 0).then_some(*label))
            .collect()
    }
}
impl Monitor {
    pub(crate) fn snapshot(&self) -> Snapshot {
        Snapshot {
            mask: self.0.mask.load(Ordering::Acquire),
            warning_lines: self.0.warnings.load(Ordering::Acquire),
            truncated: self.0.truncated.load(Ordering::Acquire),
        }
    }
}
struct Decoder {
    monitor: Monitor,
    line: Zeroizing<Vec<u8>>,
    bytes: usize,
    overflow: bool,
}
fn contains(bytes: &[u8], text: &str) -> bool {
    bytes
        .windows(text.len())
        .any(|part| part.eq_ignore_ascii_case(text.as_bytes()))
}
impl Decoder {
    fn new(monitor: Monitor) -> Self {
        Self {
            monitor,
            line: Zeroizing::new(Vec::with_capacity(LINE_CAP)),
            bytes: 0,
            overflow: false,
        }
    }
    fn finish_line(&mut self) {
        if !self.overflow {
            let warning = ["level=warning", "level=error", "[warning]", "[error]"]
                .iter()
                .any(|s| contains(&self.line, s));
            let handshake = [
                "sending handshake initiation",
                "receiving handshake response",
                "failed to receive",
            ]
            .iter()
            .any(|s| contains(&self.line, s));
            if !warning && !handshake {
                self.line.zeroize();
                self.line.clear();
                return;
            }
            let mut mask = 0;
            for (i, (_, needles)) in PATTERNS.iter().enumerate() {
                if needles.iter().any(|s| contains(&self.line, s)) {
                    mask |= 1 << i;
                }
            }
            if mask == 0 {
                mask = 1 << (PATTERNS.len() - 1);
            }
            self.monitor.0.mask.fetch_or(mask, Ordering::Release);
            if warning {
                let _ = self.monitor.0.warnings.fetch_update(
                    Ordering::Release,
                    Ordering::Relaxed,
                    |n| Some(n.saturating_add(1)),
                );
            }
        }
        self.line.zeroize();
        self.line.clear();
        self.overflow = false;
    }
    fn push(&mut self, input: &[u8]) {
        for &byte in input {
            self.bytes = self.bytes.saturating_add(1);
            if self.bytes > TOTAL_CAP {
                self.monitor.0.truncated.store(true, Ordering::Release);
                self.line.zeroize();
                self.line.clear();
                continue; // Keep draining the pipe after the classification cap.
            }
            if byte == b'\n' {
                self.finish_line();
            } else if self.line.len() < LINE_CAP && !self.overflow {
                self.line.push(byte);
            } else {
                self.overflow = true;
                self.monitor.0.truncated.store(true, Ordering::Release);
            }
        }
    }
}

#[cfg(any(windows, feature = "windows-api-check"))]
pub(crate) mod windows {
    use super::*;
    use std::{io, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::*, Security::SECURITY_ATTRIBUTES, Storage::FileSystem::ReadFile,
        System::Pipes::CreatePipe,
    };
    struct Handle(HANDLE);
    unsafe impl Send for Handle {}
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    pub(crate) struct Output {
        writer: Handle,
        pub(crate) monitor: Monitor,
    }
    impl Output {
        pub(crate) fn raw_writer(&self) -> HANDLE {
            self.writer.0
        }
        pub(crate) fn open() -> io::Result<Self> {
            let mut reader = null_mut();
            let mut writer = null_mut();
            let attrs = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: null_mut(),
                bInheritHandle: 1,
            };
            if unsafe { CreatePipe(&mut reader, &mut writer, &attrs, 16384) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let reader = Handle(reader);
            let writer = Handle(writer);
            if unsafe { SetHandleInformation(reader.0, HANDLE_FLAG_INHERIT, 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let monitor = Monitor::default();
            let sink = monitor.clone();
            std::thread::Builder::new()
                .name("engine-output-labels".into())
                .spawn(move || {
                    let mut decoder = Decoder::new(sink);
                    let mut scratch = Zeroizing::new([0u8; 4096]);
                    loop {
                        let mut count = 0;
                        if unsafe {
                            ReadFile(
                                reader.0,
                                scratch.as_mut_ptr(),
                                scratch.len() as u32,
                                &mut count,
                                null_mut(),
                            )
                        } == 0
                            || count == 0
                        {
                            break;
                        }
                        decoder.push(&scratch[..count as usize]);
                        scratch.zeroize();
                    }
                    decoder.finish_line();
                    drop(reader);
                })?;
            Ok(Self { writer, monitor })
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fragmented_untrusted_lines_produce_closed_labels_without_secret_text() {
        let monitor = Monitor::default();
        let mut decoder = Decoder::new(monitor.clone());
        decoder.push(b"time=x level=warning msg=\"write udp ");
        decoder.push(b"requested address is not valid in its context; private-key=SECRET\"\n");
        assert_eq!(
            monitor.snapshot().signals(),
            ["socket_address_invalid", "udp_error"]
        );
        assert_eq!(monitor.snapshot().warning_lines, 1);
        assert!(decoder.line.is_empty());
        assert!(!format!("{:?}", monitor.snapshot()).contains("SECRET"));
    }
    #[test]
    fn handshake_start_is_not_a_successful_send_and_debug_receive_errors_are_visible() {
        let monitor = Monitor::default();
        let mut decoder = Decoder::new(monitor.clone());
        decoder.push(b"level=debug msg=\"[WG] Sending handshake initiation\"\n");
        assert_eq!(
            monitor.snapshot().signals(),
            ["handshake_initiation_started"]
        );
        decoder.push(b"level=error msg=\"[WG] Failed to send handshake initiation: write udp invalid argument\"\n");
        decoder.push(b"level=debug msg=\"[WG] Failed to receive IPv4 packet: i/o timeout\"\n");
        assert_eq!(
            monitor.snapshot().signals(),
            [
                "socket_argument_invalid",
                "io_timeout",
                "udp_error",
                "handshake_initiation_started",
                "handshake_send_failed",
                "udp_receive_failed"
            ]
        );
        assert_eq!(monitor.snapshot().warning_lines, 1);
    }
    #[test]
    fn oversized_or_excess_output_is_discarded_but_drain_remains_bounded() {
        let monitor = Monitor::default();
        let mut decoder = Decoder::new(monitor.clone());
        decoder.push(&vec![b'x'; TOTAL_CAP + 20]);
        decoder.push(b"\n");
        assert!(monitor.snapshot().truncated);
        assert!(decoder.line.is_empty());
        assert!(monitor.snapshot().signals().is_empty());
        assert!(decoder.line.capacity() <= LINE_CAP);
    }
}
