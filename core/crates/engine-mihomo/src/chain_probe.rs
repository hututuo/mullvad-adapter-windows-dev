//! Independent SS UDP qualification. No WG identity, front selection or external
//! Clash mutation. A positive result proves two DNS exchanges and physical UDP
//! carrier evidence only; it is not full chain/WG/HTTPS readiness.
use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream, UdpSocket},
    time::{Duration, Instant},
};

const QUESTION: &str = "one.one.one.one";
const QUESTION_WIRE: &[u8] = b"\x03one\x03one\x03one\x03one\0\0\x01\0\x01";
const RESOLVER: [u8; 4] = [1, 1, 1, 1];
const FRAME_HEADER: [u8; 10] = [0, 0, 0, 1, 1, 1, 1, 1, 0, 53];
const POLL: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeError {
    Cancelled,
    Deadline,
    Resolution,
    Route,
    Configuration,
    Start,
    Owner,
    Udp,
    Cleanup,
}
impl ProbeError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Cancelled => "chain_udp_cancelled",
            Self::Deadline => "chain_udp_deadline",
            Self::Resolution => "chain_udp_resolution_failed",
            Self::Route => "chain_udp_route_unavailable",
            Self::Configuration => "chain_udp_configuration_rejected",
            Self::Start => "chain_udp_start_failed",
            Self::Owner => "chain_udp_owner_unverified",
            Self::Udp => "chain_udp_exchange_failed",
            Self::Cleanup => "cleanup_uncertain",
        }
    }
}
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct UdpProbeResult {
    pub udp_passed: bool,
    pub elapsed_ms: u64,
}

pub fn configuration(
    listener: &crate::Listener<'_>,
    upstream: &crate::chain::UpstreamSs,
    endpoint: Ipv4Addr,
    carrier: &crate::Carrier<'_>,
) -> io::Result<crate::SecretConfig> {
    if !crate::listener_valid(listener)
        || !crate::chain::public_ipv4(endpoint)
        || carrier.port < 1024
        || [listener.mixed_port, listener.controller_port].contains(&carrier.port)
        || carrier.password.len() != 64
        || !carrier.password.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(crate::invalid());
    }
    let mut ss = crate::Proxy::empty("UPSTREAM-SS", "ss", endpoint.to_string(), upstream.port());
    ss.cipher = Some(upstream.cipher().ok_or_else(crate::invalid)?);
    ss.password = Some(upstream.password());
    ss.ip_version = Some("ipv4");
    ss.dialer_proxy = Some("CARRIER");
    let mut inlet = crate::Proxy::empty("CARRIER", "socks5", "127.0.0.1".into(), carrier.port);
    inlet.username = Some("adapter");
    inlet.password = Some(carrier.password);
    inlet.ip_version = Some("ipv4");
    let mut output = crate::config(listener, false, vec![ss, inlet], vec!["UPSTREAM-SS"]);
    output.log_level = "silent";
    crate::encode(&output)
}

/// Run on a bounded I/O worker. Caller verifies the packaged executable/hash and
/// private-runtime ancestors and serializes probe calls. Startup plus data work
/// is capped at 20s (or the caller's earlier deadline); exact resource cleanup
/// has a separate 5s budget per retained process/carrier. No WG lease is acquired.
#[cfg(any(windows, feature = "windows-api-check"))]
pub fn qualify_udp(
    executable: &std::path::Path,
    runtime: &adapter_platform::windows_runtime::PrivateRuntime,
    upstream: &crate::chain::UpstreamSs,
    network: &adapter_control::owned_lifecycle::BoundNetwork,
    deadline: Instant,
) -> Result<UdpProbeResult, ProbeError> {
    use adapter_platform::{egress::windows::snapshot, windows_process::OwnedProcess};
    use std::net::{IpAddr, TcpListener};
    let started = Instant::now();
    let cancelled = || network.is_cancelled();
    let gate = Gate {
        deadline: deadline.min(started + Duration::from_secs(20)),
        cancelled: &cancelled,
    };
    gate.check()?;
    // Reuse the two bounded fresh DNS lanes; no saved-IP shortcut for hostnames.
    // An already in-flight bootstrap lookup can take up to its own 4s ceiling.
    let endpoint =
        crate::chain::resolve_ipv4(upstream, network).map_err(|_| ProbeError::Resolution)?;
    gate.check()?;
    let route = snapshot(network.binding(), IpAddr::V4(endpoint)).map_err(|_| ProbeError::Route)?;
    gate.check()?;
    let mut carrier = crate::carrier::windows::Run::open(&route, upstream.port())
        .map_err(|_| ProbeError::Route)?;
    let mut process: Option<OwnedProcess> = None;
    let result = (|| {
        // Retain both reservations until immediately before spawning; races then
        // fail closed through retained-process listener ownership checks.
        let mixed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| ProbeError::Start)?;
        let controller =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| ProbeError::Start)?;
        let mixed_port = mixed.local_addr().map_err(|_| ProbeError::Start)?.port();
        let controller_port = controller
            .local_addr()
            .map_err(|_| ProbeError::Start)?
            .port();
        let mut random = zeroize::Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *random).map_err(|_| ProbeError::Start)?;
        let secret = zeroize::Zeroizing::new(
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        );
        let listener = crate::Listener {
            mixed_port,
            controller_port,
            controller_secret: &secret,
        };
        let config = configuration(&listener, upstream, endpoint, &carrier.config())
            .map_err(|_| ProbeError::Configuration)?;
        let input = runtime
            .prepare_input(config.expose())
            .map_err(|_| ProbeError::Start)?;
        drop(config);
        let directory = runtime.path().to_str().ok_or(ProbeError::Configuration)?;
        drop((mixed, controller));
        let spawned = OwnedProcess::spawn_with_secret_input_checked(
            executable,
            &["-f".into(), "-".into(), "-d".into(), directory.into()],
            input,
            || {
                gate.check()
                    .and_then(|()| {
                        if route.is_fresh() {
                            Ok(())
                        } else {
                            Err(ProbeError::Route)
                        }
                    })
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::Interrupted, "chain probe preflight rejected")
                    })
            },
        )
        .map_err(|_| ProbeError::Start)?;
        process = Some(spawned);
        let child = process.as_ref().ok_or(ProbeError::Start)?;
        carrier
            .attach(child.controller_owner().map_err(|_| ProbeError::Owner)?)
            .map_err(|_| ProbeError::Owner)?;
        let owner = child.controller_owner().map_err(|_| ProbeError::Owner)?;
        let control = crate::controller::Controller::for_process(child, controller_port, &secret)
            .map_err(|_| ProbeError::Owner)?;
        loop {
            gate.check()?;
            if !owner.is_alive() || !carrier.is_running() {
                return Err(ProbeError::Start);
            }
            match control.check_version() {
                Ok(()) => break,
                Err(crate::controller::ControllerError::Unavailable) => std::thread::sleep(POLL),
                Err(_) => return Err(ProbeError::Owner),
            }
        }
        gate.check()?;
        let window = carrier
            .begin(network.cancellation_monitor())
            .map_err(|_| ProbeError::Route)?;
        let _association = exchanges(
            mixed_port,
            &gate,
            |stream| owner.verify_connected(stream),
            || owner.is_alive(),
        )?;
        gate.check()?;
        // Fresh actual socket send/receive proof in this window, not lifetime
        // packet counters or the successful SOCKS control handshake.
        carrier.verify(window).map_err(|_| ProbeError::Route)?;
        let again =
            snapshot(network.binding(), IpAddr::V4(endpoint)).map_err(|_| ProbeError::Route)?;
        if !route.same_path(&again) {
            return Err(ProbeError::Route);
        }
        gate.check()?;
        Ok(())
    })();
    // Attempt both cleanups even when one fails. Never certify success with an
    // uncertain engine tree or retained physical socket.
    let process_stopped = process
        .as_ref()
        .is_none_or(|p| p.terminate(Duration::from_secs(5)).is_ok());
    let carrier_stopped = carrier.stop_confirmed().is_ok();
    if !process_stopped || !carrier_stopped {
        return Err(ProbeError::Cleanup);
    }
    result?;
    gate.check()?;
    Ok(UdpProbeResult {
        udp_passed: true,
        elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
    })
}

struct Gate<'a> {
    deadline: Instant,
    cancelled: &'a dyn Fn() -> bool,
}
impl Gate<'_> {
    fn check(&self) -> Result<(), ProbeError> {
        if (self.cancelled)() {
            Err(ProbeError::Cancelled)
        } else if Instant::now() >= self.deadline {
            Err(ProbeError::Deadline)
        } else {
            Ok(())
        }
    }
    fn budget(&self) -> Result<Duration, ProbeError> {
        self.check()?;
        Ok(self
            .deadline
            .saturating_duration_since(Instant::now())
            .min(POLL)
            .max(Duration::from_millis(1)))
    }
    fn read(&self, stream: &mut TcpStream, mut bytes: &mut [u8]) -> Result<(), ProbeError> {
        while !bytes.is_empty() {
            stream
                .set_read_timeout(Some(self.budget()?))
                .map_err(|_| ProbeError::Udp)?;
            match stream.read(bytes) {
                Ok(0) => return Err(ProbeError::Udp),
                Ok(n) => bytes = &mut bytes[n..],
                Err(e) if transient(&e) => {}
                Err(_) => return Err(ProbeError::Udp),
            }
        }
        Ok(())
    }
    fn write(&self, stream: &mut TcpStream, mut bytes: &[u8]) -> Result<(), ProbeError> {
        while !bytes.is_empty() {
            stream
                .set_write_timeout(Some(self.budget()?))
                .map_err(|_| ProbeError::Udp)?;
            match stream.write(bytes) {
                Ok(0) => return Err(ProbeError::Udp),
                Ok(n) => bytes = &bytes[n..],
                Err(e) if transient(&e) => {}
                Err(_) => return Err(ProbeError::Udp),
            }
        }
        Ok(())
    }
}
fn transient(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

fn exchanges(
    port: u16,
    gate: &Gate<'_>,
    verify: impl Fn(&TcpStream) -> io::Result<()>,
    live: impl Fn() -> bool,
) -> Result<TcpStream, ProbeError> {
    gate.check()?;
    let mut control = TcpStream::connect_timeout(
        &SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into(),
        gate.budget()?,
    )
    .map_err(|_| ProbeError::Udp)?;
    verify(&control).map_err(|_| ProbeError::Owner)?;
    gate.write(&mut control, &[5, 1, 0])?;
    let mut hello = [0; 2];
    gate.read(&mut control, &mut hello)?;
    if hello != [5, 0] {
        return Err(ProbeError::Udp);
    }
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| ProbeError::Udp)?;
    let local = udp.local_addr().map_err(|_| ProbeError::Udp)?;
    let mut associate = vec![5, 3, 0, 1, 127, 0, 0, 1];
    associate.extend_from_slice(&local.port().to_be_bytes());
    gate.write(&mut control, &associate)?;
    let mut reply = [0; 10];
    gate.read(&mut control, &mut reply)?;
    if reply[..8] != [5, 0, 0, 1, 127, 0, 0, 1] {
        return Err(ProbeError::Udp);
    }
    let relay = SocketAddrV4::new(
        Ipv4Addr::LOCALHOST,
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    if relay.port() == 0 {
        return Err(ProbeError::Udp);
    }
    udp.connect(relay).map_err(|_| ProbeError::Udp)?; // exact response source filtering
    let mut previous = None;
    for _ in 0..2 {
        gate.check()?;
        let mut random = [0u8; 2];
        let mut id = None;
        for _ in 0..8 {
            getrandom::fill(&mut random).map_err(|_| ProbeError::Udp)?;
            let candidate = u16::from_be_bytes(random);
            if previous != Some(candidate) {
                id = Some(candidate);
                break;
            }
        }
        let id = id.ok_or(ProbeError::Udp)?;
        previous = Some(id);
        let mut query = Vec::from(FRAME_HEADER);
        query.extend_from_slice(&id.to_be_bytes());
        query.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        query.extend_from_slice(QUESTION_WIRE);
        udp.set_write_timeout(Some(gate.budget()?))
            .map_err(|_| ProbeError::Udp)?;
        if udp.send(&query).map_err(|_| ProbeError::Udp)? != query.len() {
            return Err(ProbeError::Udp);
        }
        let mut response = [0u8; 4107]; // one-byte lookahead beyond 4096-byte DNS cap
        loop {
            gate.check()?;
            if !live() {
                return Err(ProbeError::Owner);
            }
            udp.set_read_timeout(Some(gate.budget()?))
                .map_err(|_| ProbeError::Udp)?;
            match udp.recv(&mut response) {
                Ok(n) => {
                    if n > 4106
                        || n < 22
                        || response[..10] != FRAME_HEADER
                        || !dns_answer(&response[10..n], id)
                    {
                        return Err(ProbeError::Udp);
                    }
                    break;
                }
                Err(e) if transient(&e) => {}
                Err(_) => return Err(ProbeError::Udp),
            }
        }
    }
    gate.check()?;
    if live() {
        Ok(control)
    } else {
        Err(ProbeError::Owner)
    }
}

fn dns_answer(packet: &[u8], id: u16) -> bool {
    if packet.len() > 4096 || adapter_probe::dns_answer_count(packet, id, QUESTION) == 0 {
        return false;
    }
    // This fixed public canary has no CNAME chain. Require every answer to be
    // its documented public A value as well as the shared strict DNS parser.
    let mut offset = 12 + QUESTION_WIRE.len();
    if packet.get(12..offset) != Some(QUESTION_WIRE) {
        return false;
    }
    let answers = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    if !(1..=2).contains(&answers) {
        return false;
    }
    for _ in 0..answers {
        let Some(end) = answer_name(packet, offset) else {
            return false;
        };
        let Some(record) = packet.get(end..end + 14) else {
            return false;
        };
        if record[..4] != [0, 1, 0, 1]
            || record[8..10] != [0, 4]
            || (record[10..14] != RESOLVER && record[10..14] != [1, 0, 0, 1])
        {
            return false;
        }
        offset = end + 14;
    }
    true
}
fn answer_name(packet: &[u8], offset: usize) -> Option<usize> {
    if packet.get(offset..offset + 2) == Some(&[0xc0, 0x0c]) {
        Some(offset + 2)
    } else {
        let name = &QUESTION_WIRE[..QUESTION_WIRE.len() - 4];
        (packet.get(offset..offset + name.len()) == Some(name)).then_some(offset + name.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::TcpListener,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread,
    };
    fn answer(id: u16) -> Vec<u8> {
        let mut p = Vec::from(id.to_be_bytes());
        p.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        p.extend_from_slice(QUESTION_WIRE);
        p.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 1, 1, 1]);
        p
    }
    #[test]
    fn strict_dns_rejects_wrong_nonce_question_private_answer_fragments_and_tail() {
        let p = answer(17);
        assert!(dns_answer(&p, 17));
        assert!(!dns_answer(&p, 18));
        for length in 0..p.len() {
            assert!(!dns_answer(&p[..length], 17));
        }
        for (at, value) in [(13, b'x'), (2, 0x83), (p.len() - 4, 10)] {
            let mut bad = p.clone();
            bad[at] = value;
            assert!(!dns_answer(&bad, 17));
        }
        let mut bad = p;
        bad.push(0);
        assert!(!dns_answer(&bad, 17));
    }
    fn fixture(
        wrong_id: bool,
        cancel: bool,
        rogue_source: bool,
    ) -> (u16, Arc<AtomicBool>, thread::JoinHandle<Vec<u16>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut hello = [0; 3];
            stream.read_exact(&mut hello).unwrap();
            assert_eq!(hello, [5, 1, 0]);
            stream.write_all(&[5, 0]).unwrap();
            let mut request = [0; 10];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request[..8], &[5, 3, 0, 1, 127, 0, 0, 1]);
            let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
            reply.extend_from_slice(&udp.local_addr().unwrap().port().to_be_bytes());
            stream.write_all(&reply).unwrap();
            let mut ids = vec![];
            for _ in 0..2 {
                let mut query = [0; 4096];
                let (n, source) = udp.recv_from(&mut query).unwrap();
                assert_eq!(&query[..10], &FRAME_HEADER);
                assert_eq!(&query[22..n], QUESTION_WIRE);
                assert_eq!(source.port(), u16::from_be_bytes([request[8], request[9]]));
                let id = u16::from_be_bytes([query[10], query[11]]);
                ids.push(id);
                if cancel {
                    flag.store(true, Ordering::Release);
                    break;
                }
                let mut packet = Vec::from(FRAME_HEADER);
                packet.extend_from_slice(&answer(if wrong_id { id.wrapping_add(1) } else { id }));
                if rogue_source {
                    let rogue = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
                    rogue
                        .send_to(b"foreign source must not be accepted", source)
                        .unwrap();
                }
                udp.send_to(&packet, source).unwrap();
                if wrong_id {
                    break;
                }
            }
            ids
        });
        (port, cancelled, join)
    }
    #[test]
    fn actual_loopback_udp_requires_two_distinct_answers() {
        let (port, cancel, join) = fixture(false, false, true);
        let cancelled = || cancel.load(Ordering::Acquire);
        let gate = Gate {
            deadline: Instant::now() + Duration::from_secs(2),
            cancelled: &cancelled,
        };
        assert!(exchanges(port, &gate, |_| Ok(()), || true).is_ok());
        let ids = join.join().unwrap();
        assert_eq!(ids.len(), 2);
        assert_ne!(ids[0], ids[1]);
    }
    #[test]
    fn wrong_reply_and_mid_exchange_cancel_fail_closed() {
        for (wrong, cancel, expected) in [
            (true, false, ProbeError::Udp),
            (false, true, ProbeError::Cancelled),
        ] {
            let (port, flag, join) = fixture(wrong, cancel, false);
            let cancelled = || flag.load(Ordering::Acquire);
            let gate = Gate {
                deadline: Instant::now() + Duration::from_secs(2),
                cancelled: &cancelled,
            };
            assert_eq!(
                exchanges(port, &gate, |_| Ok(()), || true).unwrap_err(),
                expected
            );
            join.join().unwrap();
        }
    }
    #[test]
    fn owner_rejection_sends_no_protocol_bytes() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
        });
        let gate = Gate {
            deadline: Instant::now() + Duration::from_secs(2),
            cancelled: &|| false,
        };
        assert_eq!(
            exchanges(
                port,
                &gate,
                |_| Err(io::ErrorKind::PermissionDenied.into()),
                || true
            )
            .unwrap_err(),
            ProbeError::Owner
        );
        join.join().unwrap();
    }
    #[test]
    fn expired_and_cancelled_work_has_no_socket_side_effect() {
        let gate = Gate {
            deadline: Instant::now(),
            cancelled: &|| false,
        };
        assert_eq!(
            exchanges(0, &gate, |_| unreachable!(), || unreachable!()).unwrap_err(),
            ProbeError::Deadline
        );
        let gate = Gate {
            deadline: Instant::now() + Duration::from_secs(2),
            cancelled: &|| true,
        };
        assert_eq!(
            exchanges(0, &gate, |_| unreachable!(), || unreachable!()).unwrap_err(),
            ProbeError::Cancelled
        );
    }
    #[test]
    fn graph_has_only_imported_ss_and_authenticated_carrier() {
        let upstream = crate::chain::UpstreamSs::decode(br#"{"name":"fixture","server":"node.example","port":443,"cipher":"aes-128-gcm","password":"synthetic"}"#).unwrap();
        let secret = "a".repeat(64);
        let config = configuration(
            &crate::Listener {
                mixed_port: 17891,
                controller_port: 17892,
                controller_secret: &secret,
            },
            &upstream,
            Ipv4Addr::new(203, 0, 113, 7),
            &crate::Carrier {
                port: 17893,
                password: &secret,
            },
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_slice(config.expose()).unwrap();
        assert_eq!(json["proxies"].as_array().unwrap().len(), 2);
        assert_eq!(json["proxies"][0]["type"], "ss");
        assert_eq!(json["proxies"][0]["dialer-proxy"], "CARRIER");
        assert_eq!(json["proxies"][1]["type"], "socks5");
        assert_eq!(
            json["proxy-groups"][0]["proxies"],
            serde_json::json!(["UPSTREAM-SS"])
        );
        assert_eq!(json["dns"]["enable"], false);
        assert_eq!(json["tun"]["enable"], false);
        assert_eq!(json["log-level"], "silent");
        assert!(!String::from_utf8_lossy(config.expose()).contains("wireguard"));
    }
}
