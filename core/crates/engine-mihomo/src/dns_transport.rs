//! Fixed inner-DNS TCP probe through an owned local SOCKS5 listener.
use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    time::{Duration, Instant},
};
const BUDGET: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(50);
const QUESTION: &str = "www.gstatic.com";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResult {
    ValidatedA(usize),
    Rejected,
    Cancelled,
    Timeout,
    Unavailable,
}

/// A validated response is one canary only, not tunnel readiness or a commit
/// authorization. The operation owner must still fence the returned evidence.
#[cfg(any(windows, feature = "windows-api-check"))]
pub fn for_worker(
    process: &adapter_platform::windows_process::OwnedProcess,
    network: &adapter_control::owned_lifecycle::BoundNetwork,
    mixed_port: u16,
) -> DnsResult {
    let Ok(owner) = process.controller_owner() else {
        return DnsResult::Unavailable;
    };
    run(
        mixed_port,
        |stream| owner.verify_connected(stream),
        || network.is_cancelled(),
        || owner.is_alive(),
    )
}

pub(crate) fn run(
    port: u16,
    verify: impl Fn(&TcpStream) -> io::Result<()>,
    cancelled: impl Fn() -> bool,
    retained_process_alive: impl Fn() -> bool,
) -> DnsResult {
    let deadline = Instant::now() + BUDGET;
    let checkpoint = || {
        if cancelled() {
            Err(DnsResult::Cancelled)
        } else if Instant::now() >= deadline {
            Err(DnsResult::Timeout)
        } else {
            Ok(())
        }
    };
    let work = || -> Result<usize, DnsResult> {
        checkpoint()?;
        if port < 1024 {
            return Err(DnsResult::Rejected);
        }
        let budget = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(500));
        if budget.is_zero() {
            return Err(DnsResult::Timeout);
        }
        let stream = TcpStream::connect_timeout(
            &SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into(),
            budget,
        )
        .map_err(|_| DnsResult::Unavailable)?;
        verify(&stream).map_err(|_| DnsResult::Rejected)?;
        checkpoint()?;
        let mut socket = BoundedSocket {
            stream,
            deadline,
            cancelled: &cancelled,
        };
        socket.write(&[5, 1, 0])?;
        let mut hello = [0; 2];
        socket.read(&mut hello)?;
        if hello != [5, 0] {
            return Err(DnsResult::Rejected);
        }
        // Fixed IPv4 inner resolver, no hostname lookup and no proxy environment.
        socket.write(&[5, 1, 0, 1, 10, 64, 0, 1, 0, 53])?;
        let mut header = [0; 4];
        socket.read(&mut header)?;
        if header[..3] != [5, 0, 0] {
            return Err(DnsResult::Rejected);
        }
        match header[3] {
            1 => socket.read(&mut [0; 4])?,
            4 => socket.read(&mut [0; 16])?,
            3 => {
                let mut length = [0];
                socket.read(&mut length)?;
                if length[0] == 0 {
                    return Err(DnsResult::Rejected);
                }
                socket.read(&mut vec![0; usize::from(length[0])])?;
            }
            _ => return Err(DnsResult::Rejected),
        }
        socket.read(&mut [0; 2])?;
        let mut random = [0; 2];
        getrandom::fill(&mut random).map_err(|_| DnsResult::Unavailable)?;
        let id = u16::from_be_bytes(random);
        let mut query = Vec::from(random);
        query.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, one question
        query.extend_from_slice(b"\x03www\x07gstatic\x03com\0\0\x01\0\x01");
        socket.write(&(query.len() as u16).to_be_bytes())?;
        socket.write(&query)?;
        let mut length = [0; 2];
        socket.read(&mut length)?;
        let length = usize::from(u16::from_be_bytes(length));
        if length < 12 {
            return Err(DnsResult::Rejected);
        }
        let mut response = vec![0; length];
        socket.read(&mut response)?;
        let count = adapter_probe::dns_answer_count(&response, id, QUESTION);
        checkpoint()?;
        // The original TcpStream was authenticated before writing protocol bytes
        // and is never reconnected or replaced. A normal FIN may already remove
        // the server's ESTABLISHED table row after it sends this complete frame.
        // Requiring that transient row again rejects a legitimate response. Keep
        // the retained process object live, plus nonce/parser/epoch/deadline gates.
        if !retained_process_alive() {
            return Err(DnsResult::Rejected);
        }
        checkpoint()?;
        if count == 0 {
            Err(DnsResult::Rejected)
        } else {
            Ok(count)
        }
    };
    match work() {
        Ok(count) => DnsResult::ValidatedA(count),
        Err(error) => error,
    }
}
struct BoundedSocket<'a, F> {
    stream: TcpStream,
    deadline: Instant,
    cancelled: &'a F,
}
impl<F: Fn() -> bool> BoundedSocket<'_, F> {
    fn budget(&self) -> Result<Duration, DnsResult> {
        if (self.cancelled)() {
            return Err(DnsResult::Cancelled);
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|x| !x.is_zero())
            .map(|x| x.min(POLL))
            .ok_or(DnsResult::Timeout)
    }
    fn read(&mut self, mut output: &mut [u8]) -> Result<(), DnsResult> {
        while !output.is_empty() {
            self.stream
                .set_read_timeout(Some(self.budget()?))
                .map_err(|_| DnsResult::Unavailable)?;
            match self.stream.read(output) {
                Ok(0) => return Err(DnsResult::Unavailable),
                Ok(n) => output = &mut output[n..],
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => return Err(DnsResult::Unavailable),
            }
        }
        self.budget()?;
        Ok(())
    }
    fn write(&mut self, mut input: &[u8]) -> Result<(), DnsResult> {
        while !input.is_empty() {
            self.stream
                .set_write_timeout(Some(self.budget()?))
                .map_err(|_| DnsResult::Unavailable)?;
            match self.stream.write(input) {
                Ok(0) => return Err(DnsResult::Unavailable),
                Ok(n) => input = &input[n..],
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => return Err(DnsResult::Unavailable),
            }
        }
        self.budget()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::TcpListener,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        thread,
    };
    fn blocking_fixture(stream: &TcpStream) {
        // Windows/macOS can inherit the listener's nonblocking mode; Linux does not.
        stream.set_nonblocking(false).unwrap();
    }
    fn fixture(body: impl FnOnce(TcpStream) + Send + 'static) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let join = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(4);
            let stream = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("fixture accept failed: {e}"),
                }
            };
            blocking_fixture(&stream);
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            body(stream);
        });
        (port, join)
    }
    fn handshake(s: &mut TcpStream) {
        let mut hello = [0; 3];
        s.read_exact(&mut hello).unwrap();
        assert_eq!(hello, [5, 1, 0]);
        s.write_all(&[5, 0]).unwrap();
        let mut request = [0; 10];
        s.read_exact(&mut request).unwrap();
        assert_eq!(request, [5, 1, 0, 1, 10, 64, 0, 1, 0, 53]);
        s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
    }
    fn query(s: &mut TcpStream) -> Vec<u8> {
        let mut length = [0; 2];
        s.read_exact(&mut length).unwrap();
        let mut query = vec![0; usize::from(u16::from_be_bytes(length))];
        s.read_exact(&mut query).unwrap();
        query
    }
    #[test]
    fn real_segmented_socks_and_dns_exchange_authenticates_original_socket() {
        let (port, worker) = fixture(|mut s| {
            handshake(&mut s);
            let mut answer = query(&mut s);
            answer[2] = 0x81;
            answer[3] = 0x80;
            answer[7] = 1;
            answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 10]);
            let mut frame = (answer.len() as u16).to_be_bytes().to_vec();
            frame.extend(answer);
            for chunk in frame.chunks(3) {
                s.write_all(chunk).unwrap();
                thread::sleep(Duration::from_millis(1));
            }
            let mut one = [0];
            assert_eq!(s.read(&mut one).unwrap(), 0);
        });
        let checks = AtomicUsize::new(0);
        assert_eq!(
            run(
                port,
                |_| {
                    checks.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
                || false,
                || true
            ),
            DnsResult::ValidatedA(1)
        );
        assert_eq!(checks.load(Ordering::SeqCst), 1);
        worker.join().unwrap();
    }
    #[test]
    fn rejected_owner_receives_no_protocol_bytes() {
        let (port, worker) = fixture(|mut s| {
            let mut one = [0];
            assert_eq!(s.read(&mut one).unwrap(), 0);
        });
        assert_eq!(
            run(
                port,
                |_| Err(io::Error::from(io::ErrorKind::PermissionDenied)),
                || false,
                || true
            ),
            DnsResult::Rejected
        );
        worker.join().unwrap();
    }
    #[test]
    fn invalid_socks_fields_and_header_only_dns_fail() {
        for response in [[4, 0, 0, 1], [5, 1, 0, 1], [5, 0, 1, 1], [5, 0, 0, 9]] {
            let (port, worker) = fixture(move |mut s| {
                let mut hello = [0; 3];
                s.read_exact(&mut hello).unwrap();
                s.write_all(&[5, 0]).unwrap();
                let mut request = [0; 10];
                s.read_exact(&mut request).unwrap();
                s.write_all(&response).unwrap();
            });
            assert_eq!(
                run(port, |_| Ok(()), || false, || true),
                DnsResult::Rejected
            );
            worker.join().unwrap();
        }
        let (port, worker) = fixture(|mut s| {
            handshake(&mut s);
            let q = query(&mut s);
            let mut packet = q[..12].to_vec();
            packet[2] = 0x80;
            packet[7] = 1;
            s.write_all(&12u16.to_be_bytes()).unwrap();
            s.write_all(&packet).unwrap();
        });
        assert_eq!(
            run(port, |_| Ok(()), || false, || true),
            DnsResult::Rejected
        );
        worker.join().unwrap();
    }
    #[test]
    fn cancellation_interrupts_waiting_read_and_closes_connection() {
        let cancel = Arc::new(AtomicBool::new(false));
        let notify = cancel.clone();
        let (port, worker) = fixture(move |mut s| {
            let mut hello = [0; 3];
            s.read_exact(&mut hello).unwrap();
            notify.store(true, Ordering::Release);
            let mut one = [0];
            assert_eq!(s.read(&mut one).unwrap(), 0);
        });
        let started = Instant::now();
        assert_eq!(
            run(port, |_| Ok(()), || cancel.load(Ordering::Acquire), || true),
            DnsResult::Cancelled
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        worker.join().unwrap();
    }
    #[test]
    fn slow_bytes_do_not_reset_total_deadline() {
        let (port, worker) = fixture(|mut s| {
            handshake(&mut s);
            let q = query(&mut s);
            s.write_all(&100u16.to_be_bytes()).unwrap();
            for byte in q.into_iter().cycle().take(20) {
                if s.write_all(&[byte]).is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(250));
            }
        });
        let start = Instant::now();
        assert_eq!(run(port, |_| Ok(()), || false, || true), DnsResult::Timeout);
        assert!(start.elapsed() < Duration::from_millis(2500));
        worker.join().unwrap();
    }
    #[test]
    fn process_proof_lost_after_response_cannot_report_success() {
        let (port, worker) = fixture(|mut s| {
            handshake(&mut s);
            let mut q = query(&mut s);
            q[2] = 0x81;
            q[3] = 0x80;
            q[7] = 1;
            q.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 1]);
            s.write_all(&(q.len() as u16).to_be_bytes()).unwrap();
            s.write_all(&q).unwrap();
            let mut one = [0];
            assert_eq!(s.read(&mut one).unwrap(), 0);
        });
        assert_eq!(
            run(port, |_| Ok(()), || false, || false),
            DnsResult::Rejected
        );
        worker.join().unwrap();
    }
    #[cfg(any(windows, feature = "windows-api-check"))]
    #[test]
    #[ignore = "child-only synthetic local SOCKS/DNS fixture"]
    fn owned_socks_child_fixture() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        std::fs::write(
            "dns-port",
            listener.local_addr().unwrap().port().to_string(),
        )
        .unwrap();
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(2))
                }
                Err(e) => panic!("child accept failed: {e}"),
            }
        };
        blocking_fixture(&stream);
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        handshake(&mut stream);
        let mut q = query(&mut stream);
        q[2] = 0x81;
        q[3] = 0x80;
        q[7] = 1;
        q.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 1]);
        stream.write_all(&(q.len() as u16).to_be_bytes()).unwrap();
        stream.write_all(&q).unwrap();
        if std::path::Path::new("close-after-reply").exists() {
            drop(stream);
            std::fs::write("peer-closed", b"yes").unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !std::path::Path::new("release-child").exists() {
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(5));
            }
        } else {
            let mut one = [0];
            assert_eq!(stream.read(&mut one).unwrap(), 0);
        }
    }

    #[cfg(any(windows, feature = "windows-api-check"))]
    #[test]
    fn actual_process_owner_accepts_its_dns_peer_and_rejects_foreign_listener() {
        actual_owner_fixture(false);
    }
    #[cfg(any(windows, feature = "windows-api-check"))]
    #[test]
    fn native_closed_dns_peer_keeps_original_socket_proof_and_retained_worker_liveness() {
        actual_owner_fixture(true);
    }
    #[cfg(any(windows, feature = "windows-api-check"))]
    fn actual_owner_fixture(close_after_reply: bool) {
        struct Temp(std::path::PathBuf);
        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let root = Temp(std::env::temp_dir().join(format!(
            "adapter-dns-peer-{:032x}",
            u128::from_le_bytes(random)
        )));
        std::fs::create_dir(&root.0).unwrap();
        if close_after_reply {
            std::fs::write(root.0.join("close-after-reply"), b"yes").unwrap();
        }
        let process = adapter_platform::windows_process::OwnedProcess::spawn_sanitized(
            &std::env::current_exe().unwrap(),
            &[
                "--exact".into(),
                "dns_transport::tests::owned_socks_child_fixture".into(),
                "--ignored".into(),
            ],
            &root.0,
        )
        .unwrap();
        let owner = process.controller_owner().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let port = loop {
            if let Ok(text) = std::fs::read_to_string(root.0.join("dns-port")) {
                if let Ok(port) = text.parse::<u16>() {
                    break port;
                }
            }
            assert!(Instant::now() < deadline, "child startup deadline");
            thread::sleep(Duration::from_millis(5));
        };
        let (foreign, other) = fixture(|mut s| {
            let mut one = [0];
            assert_eq!(s.read(&mut one).unwrap(), 0);
        });
        assert_eq!(
            run(
                foreign,
                |s| owner.verify_connected(s),
                || false,
                || owner.is_alive()
            ),
            DnsResult::Rejected
        );
        other.join().unwrap();
        let original = std::sync::Mutex::new(None);
        assert_eq!(
            run(
                port,
                |s| {
                    owner.verify_connected(s)?;
                    if close_after_reply {
                        *original.lock().unwrap() = Some(s.try_clone()?);
                    }
                    Ok(())
                },
                || false,
                || {
                    if close_after_reply {
                        let deadline = Instant::now() + Duration::from_millis(500);
                        while !root.0.join("peer-closed").exists() && Instant::now() < deadline {
                            thread::sleep(Duration::from_millis(2));
                        }
                    }
                    owner.is_alive()
                }
            ),
            DnsResult::ValidatedA(1)
        );
        if close_after_reply {
            assert!(owner.is_alive());
            assert!(owner
                .verify_connected(original.lock().unwrap().as_ref().unwrap())
                .is_err());
            std::fs::write(root.0.join("release-child"), b"yes").unwrap();
        }
        assert_eq!(process.wait(Duration::from_secs(5)).unwrap(), Some(0));
    }
    #[test]
    fn cancelled_or_invalid_request_never_connects() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            run(
                listener.local_addr().unwrap().port(),
                |_| panic!("must not verify"),
                || true,
                || true
            ),
            DnsResult::Cancelled
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            run(53, |_| panic!("must not verify"), || false, || true),
            DnsResult::Rejected
        );
    }

    #[test]
    fn variable_socks_bound_address_forms_remain_bounded_and_supported() {
        for reply in [
            vec![5, 0, 0, 3, 3, b'd', b'n', b's', 0, 53],
            vec![
                5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 53,
            ],
        ] {
            let (port, worker) = fixture(move |mut s| {
                let mut hello = [0; 3];
                s.read_exact(&mut hello).unwrap();
                s.write_all(&[5, 0]).unwrap();
                let mut request = [0; 10];
                s.read_exact(&mut request).unwrap();
                s.write_all(&reply).unwrap();
                let mut q = query(&mut s);
                q[2] = 0x81;
                q[3] = 0x80;
                q[7] = 1;
                q.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 1]);
                s.write_all(&(q.len() as u16).to_be_bytes()).unwrap();
                s.write_all(&q).unwrap();
                let mut one = [0];
                assert_eq!(s.read(&mut one).unwrap(), 0);
            });
            assert_eq!(
                run(port, |_| Ok(()), || false, || true),
                DnsResult::ValidatedA(1)
            );
            worker.join().unwrap();
        }
    }

    fn valid_reply(mut q: Vec<u8>) -> Vec<u8> {
        q[2] = 0x81;
        q[3] = 0x80;
        q[7] = 1;
        q.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 1]);
        q
    }
    #[test]
    fn independent_malicious_dns_never_validates() {
        for case in 0..8 {
            let (port, worker) = fixture(move |mut s| {
                handshake(&mut s);
                let mut r = valid_reply(query(&mut s));
                match case {
                    0 => r[0] ^= 1,
                    1 => r[13] = b'x',
                    2 => r[2] |= 2,
                    3 => r[3] |= 3,
                    4 => r.push(0),
                    5 => {
                        r.pop();
                    }
                    6 => r[7] = 2,
                    7 => {
                        r.resize(65535, 0);
                    }
                    _ => unreachable!(),
                }
                s.write_all(&(r.len() as u16).to_be_bytes()).unwrap();
                s.write_all(&r).unwrap();
                let mut one = [0];
                assert_eq!(s.read(&mut one).unwrap(), 0);
            });
            assert_eq!(
                run(port, |_| Ok(()), || false, || true),
                DnsResult::Rejected,
                "case {case}"
            );
            worker.join().unwrap();
        }
    }
    #[test]
    fn independent_malformed_hello_stops_before_connect() {
        for hello in [[4, 0], [5, 2], [5, 255]] {
            let (port, worker) = fixture(move |mut s| {
                let mut h = [0; 3];
                s.read_exact(&mut h).unwrap();
                for b in hello {
                    s.write_all(&[b]).unwrap();
                    thread::sleep(Duration::from_millis(2));
                }
                let mut one = [0];
                assert_eq!(s.read(&mut one).unwrap(), 0);
            });
            assert_eq!(
                run(port, |_| Ok(()), || false, || true),
                DnsResult::Rejected
            );
            worker.join().unwrap();
        }
    }
    #[test]
    fn final_retained_process_check_cannot_outlive_deadline() {
        let (port, worker) = fixture(|mut s| {
            handshake(&mut s);
            let r = valid_reply(query(&mut s));
            s.write_all(&(r.len() as u16).to_be_bytes()).unwrap();
            s.write_all(&r).unwrap();
            assert_eq!(s.read(&mut [0]).unwrap(), 0);
        });
        assert_eq!(
            run(
                port,
                |_| Ok(()),
                || false,
                || {
                    thread::sleep(Duration::from_millis(2050));
                    true
                }
            ),
            DnsResult::Timeout
        );
        worker.join().unwrap();
    }
    #[test]
    fn final_retained_process_check_cancel_never_validates() {
        let (port, worker) = fixture(|mut s| {
            handshake(&mut s);
            let r = valid_reply(query(&mut s));
            s.write_all(&(r.len() as u16).to_be_bytes()).unwrap();
            s.write_all(&r).unwrap();
            assert_eq!(s.read(&mut [0]).unwrap(), 0);
        });
        let cancel = AtomicBool::new(false);
        assert_eq!(
            run(
                port,
                |_| Ok(()),
                || cancel.load(Ordering::Acquire),
                || {
                    cancel.store(true, Ordering::Release);
                    true
                }
            ),
            DnsResult::Cancelled
        );
        worker.join().unwrap();
    }
    #[test]
    fn independent_zero_length_domain_and_truncated_frame_fail() {
        for case in 0..2 {
            let (port, worker) = fixture(move |mut s| {
                if case == 0 {
                    let mut h = [0; 3];
                    s.read_exact(&mut h).unwrap();
                    s.write_all(&[5, 0]).unwrap();
                    let mut req = [0; 10];
                    s.read_exact(&mut req).unwrap();
                    s.write_all(&[5, 0, 0, 3, 0]).unwrap();
                    let mut one = [0];
                    assert_eq!(s.read(&mut one).unwrap(), 0);
                } else {
                    handshake(&mut s);
                    let _ = query(&mut s);
                    s.write_all(&[255, 255, 0]).unwrap();
                }
            });
            assert_eq!(
                run(port, |_| Ok(()), || false, || true),
                if case == 0 {
                    DnsResult::Rejected
                } else {
                    DnsResult::Unavailable
                }
            );
            worker.join().unwrap();
        }
    }
    #[test]
    fn accepted_nonblocking_socket_is_restored_before_blocking_fixture_io() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        // Model inherited nonblocking even on Linux, where accept clears it.
        peer.set_nonblocking(true).unwrap();
        blocking_fixture(&peer);
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (done_tx, done) = std::sync::mpsc::channel();
        let thread = thread::spawn(move || {
            entered_tx.send(()).unwrap();
            let mut byte = [0];
            let result = peer.read_exact(&mut byte);
            done_tx.send((result, byte)).unwrap();
        });
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            done.recv_timeout(Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        client.write_all(&[42]).unwrap();
        let (result, byte) = done.recv_timeout(Duration::from_secs(1)).unwrap();
        result.unwrap();
        assert_eq!(byte, [42]);
        thread.join().unwrap();
    }
}
