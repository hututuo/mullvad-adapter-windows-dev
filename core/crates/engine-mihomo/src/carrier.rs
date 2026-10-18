//! One authenticated engine association to one immutable outer relay endpoint.
//! UDP ownership snapshots are admission checks, not packet authentication.
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

const CAP: usize = 65507;
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "carrier_admission_rejected",
    )
}
fn header(remote: SocketAddr) -> Vec<u8> {
    let mut out = vec![0, 0, 0];
    match remote.ip() {
        IpAddr::V4(ip) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&remote.port().to_be_bytes());
    out
}
fn payload<'a>(packet: &'a [u8], remote: SocketAddr) -> io::Result<&'a [u8]> {
    if packet.len() > CAP || packet.len() < 4 || packet[..3] != [0, 0, 0] {
        return Err(denied());
    }
    let (ip, offset) = match packet[3] {
        1 if packet.len() >= 10 => (
            IpAddr::V4(Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7])),
            8,
        ),
        4 if packet.len() >= 22 => {
            let mut bytes = [0; 16];
            bytes.copy_from_slice(&packet[4..20]);
            (IpAddr::V6(Ipv6Addr::from(bytes)), 20)
        }
        _ => return Err(denied()), // No DNS targets, fragments or arbitrary destinations.
    };
    if SocketAddr::new(ip, u16::from_be_bytes([packet[offset], packet[offset + 1]])) != remote
        || packet.len() == offset + 2
    {
        return Err(denied());
    }
    Ok(&packet[offset + 2..])
}
fn credentials(user: &[u8], password: &[u8], expected: &[u8]) -> bool {
    if user != b"adapter" || password.len() != 64 || expected.len() != 64 {
        return false;
    }
    password
        .iter()
        .zip(expected)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(any(windows, feature = "windows-api-check"))]
pub(crate) mod windows {
    use super::*;
    use adapter_control::owned_lifecycle::BoundCancellation;
    use adapter_platform::{
        egress::{windows::snapshot, EgressSnapshot},
        windows_controller_owner::ControllerOwner,
        windows_datagram::{ExchangeWindow, OwnedDatagram, SocketWitness},
    };
    use std::{
        io::{Read, Write},
        net::{SocketAddrV4, TcpListener, TcpStream, UdpSocket},
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            mpsc, Arc,
        },
        thread::{self, JoinHandle},
        time::{Duration, Instant},
    };
    use zeroize::{Zeroize, Zeroizing};

    #[derive(Default)]
    struct Stats {
        accepted: AtomicU64,
        denied: AtomicU64,
        local: AtomicU64,
        invalid: AtomicU64,
        sender_denied: AtomicU64,
        sent: AtomicU64,
        received: AtomicU64,
    }
    #[derive(Clone, Copy, Default, serde::Serialize)]
    pub struct Snapshot {
        pub associations: u64,
        pub admission_denied: u64,
        pub local_packets: u64,
        pub frame_denied: u64,
        pub sender_denied: u64,
        pub physical_sent: u64,
        pub physical_received: u64,
    }
    impl Stats {
        fn snapshot(&self) -> Snapshot {
            Snapshot {
                associations: self.accepted.load(Ordering::Relaxed),
                admission_denied: self.denied.load(Ordering::Relaxed),
                local_packets: self.local.load(Ordering::Relaxed),
                frame_denied: self.invalid.load(Ordering::Relaxed),
                sender_denied: self.sender_denied.load(Ordering::Relaxed),
                physical_sent: self.sent.load(Ordering::Relaxed),
                physical_received: self.received.load(Ordering::Relaxed),
            }
        }
    }
    enum Command {
        Attach(ControllerOwner),
        Begin(BoundCancellation, mpsc::SyncSender<io::Result<u64>>),
        Verify(u64, mpsc::SyncSender<io::Result<Instant>>),
        VerifyActivity(u64, mpsc::SyncSender<io::Result<Instant>>),
    }
    struct Window {
        id: u64,
        monitor: BoundCancellation,
        exchange: ExchangeWindow,
        witness: Option<SocketWitness>,
    }
    struct Association {
        control: TcpStream,
        udp: UdpSocket,
        sender: Option<SocketAddrV4>,
        ownership_checked: Instant,
    }
    pub(crate) struct Run {
        instance: u64,
        port: u16,
        password: Arc<Zeroizing<String>>,
        commands: mpsc::SyncSender<Command>,
        stop: Arc<AtomicBool>,
        alive: Arc<AtomicBool>,
        thread: Option<JoinHandle<io::Result<()>>>,
        stats: Arc<Stats>,
    }
    impl Run {
        pub(crate) fn open(route: &EgressSnapshot, remote_port: u16) -> io::Result<Self> {
            use std::sync::atomic::AtomicU64;
            static NEXT: AtomicU64 = AtomicU64::new(1);
            let instance = NEXT
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .map_err(|_| denied())?;
            let udp = OwnedDatagram::open(route, remote_port)?;
            let baseline = snapshot(route.binding(), route.destination())?;
            if !route.is_fresh() || !route.same_path(&baseline) {
                return Err(denied());
            }
            udp.validate(&baseline)?;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            listener.set_nonblocking(true)?;
            let port = listener.local_addr()?.port();
            let mut random = Zeroizing::new([0u8; 32]);
            getrandom::fill(&mut *random).map_err(|_| denied())?;
            let password = Arc::new(Zeroizing::new(
                random
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
            ));
            let stop = Arc::new(AtomicBool::new(false));
            let alive = Arc::new(AtomicBool::new(true));
            let (commands, receive) = mpsc::sync_channel(4);
            let stats = Arc::new(Stats::default());
            let counters = stats.clone();
            let (secret, cancel, running) = (password.clone(), stop.clone(), alive.clone());
            let thread = thread::Builder::new()
                .name("physical-udp-carrier".into())
                .spawn(move || {
                    let mut udp = udp;
                    let result = forward(
                        &listener,
                        &mut udp,
                        &baseline,
                        remote_port,
                        &secret,
                        &cancel,
                        &receive,
                        &counters,
                    );
                    // Closing this exact socket is mandatory even on forwarding errors.
                    let closed = udp.close_confirmed();
                    running.store(false, Ordering::Release);
                    {
                        let _ = result;
                        closed
                    }
                })?;
            Ok(Self {
                instance,
                port,
                password,
                commands,
                stop,
                alive,
                thread: Some(thread),
                stats,
            })
        }
        pub(crate) fn config(&self) -> crate::Carrier<'_> {
            crate::Carrier {
                port: self.port,
                password: &self.password,
            }
        }
        pub(crate) fn snapshot(&self) -> Snapshot {
            self.stats.snapshot()
        }
        pub(crate) fn instance(&self) -> u64 {
            self.instance
        }
        pub(crate) fn attach(&self, owner: ControllerOwner) -> io::Result<()> {
            self.commands
                .try_send(Command::Attach(owner))
                .map_err(|_| denied())
        }
        pub(crate) fn begin(&self, monitor: BoundCancellation) -> io::Result<u64> {
            let (send, receive) = mpsc::sync_channel(1);
            self.commands
                .try_send(Command::Begin(monitor, send))
                .map_err(|_| denied())?;
            receive
                .recv_timeout(Duration::from_secs(2))
                .map_err(|_| denied())?
        }
        pub(crate) fn verify(&self, id: u64) -> io::Result<Instant> {
            let (send, receive) = mpsc::sync_channel(1);
            self.commands
                .try_send(Command::Verify(id, send))
                .map_err(|_| denied())?;
            receive
                .recv_timeout(Duration::from_millis(500))
                .map_err(|_| denied())?
        }
        pub(crate) fn verify_activity(&self, id: u64) -> io::Result<Instant> {
            let (send, receive) = mpsc::sync_channel(1);
            self.commands
                .try_send(Command::VerifyActivity(id, send))
                .map_err(|_| denied())?;
            receive
                .recv_timeout(Duration::from_millis(500))
                .map_err(|_| denied())?
        }
        pub(crate) fn is_running(&self) -> bool {
            self.alive.load(Ordering::Acquire) && !self.stop.load(Ordering::Acquire)
        }
        pub(crate) fn stop_confirmed(&mut self) -> io::Result<()> {
            self.stop.store(true, Ordering::Release);
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.thread.as_ref().is_some_and(|t| !t.is_finished()) {
                if Instant::now() >= deadline {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                thread::sleep(Duration::from_millis(2));
            }
            if let Some(t) = self.thread.take() {
                t.join()
                    .map_err(|_| io::Error::other("carrier_cleanup_panicked"))??;
            }
            Ok(())
        }
    }
    impl Drop for Run {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
        }
    }

    fn read(
        stream: &mut TcpStream,
        output: &mut [u8],
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> io::Result<()> {
        let mut offset = 0;
        while offset < output.len() {
            if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err(denied());
            }
            stream.set_read_timeout(Some(Duration::from_millis(25)))?;
            match stream.read(&mut output[offset..]) {
                Ok(0) => return Err(denied()),
                Ok(n) => offset += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    fn admit(
        mut stream: TcpStream,
        owner: &ControllerOwner,
        secret: &str,
        cancel: &AtomicBool,
    ) -> io::Result<Association> {
        // No response or authentication exchange before exact retained-peer proof.
        owner.verify_connected(&stream)?;
        stream.set_write_timeout(Some(Duration::from_millis(100)))?;
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut hello = [0; 2];
        read(&mut stream, &mut hello, deadline, cancel)?;
        if hello[0] != 5 || hello[1] == 0 {
            return Err(denied());
        }
        let mut methods = vec![0; hello[1] as usize];
        read(&mut stream, &mut methods, deadline, cancel)?;
        if !methods.contains(&2) {
            return Err(denied());
        }
        stream.write_all(&[5, 2])?;
        let mut auth = [0; 2];
        read(&mut stream, &mut auth, deadline, cancel)?;
        if auth[0] != 1 || auth[1] != 7 {
            return Err(denied());
        }
        let mut user = [0; 7];
        read(&mut stream, &mut user, deadline, cancel)?;
        let mut len = [0; 1];
        read(&mut stream, &mut len, deadline, cancel)?;
        if len[0] != 64 {
            return Err(denied());
        }
        let mut password = Zeroizing::new([0; 64]);
        read(&mut stream, &mut *password, deadline, cancel)?;
        if !credentials(&user, &*password, secret.as_bytes()) || !owner.is_alive() {
            return Err(denied());
        }
        password.zeroize();
        stream.write_all(&[1, 0])?;
        let mut request = [0; 4];
        read(&mut stream, &mut request, deadline, cancel)?;
        if request[..3] != [5, 3, 0] {
            return Err(denied());
        }
        match request[3] {
            1 => {
                let mut address = [0; 6];
                read(&mut stream, &mut address, deadline, cancel)?;
                if address[..4] != [0, 0, 0, 0] && address[..4] != [127, 0, 0, 1] {
                    return Err(denied());
                }
            }
            4 => {
                let mut address = [0; 18];
                read(&mut stream, &mut address, deadline, cancel)?;
                if address[..16] != [0; 16] {
                    return Err(denied());
                }
            }
            _ => return Err(denied()),
        }
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        udp.set_nonblocking(true)?;
        let port = udp.local_addr()?.port();
        let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
        reply.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&reply)?;
        stream.set_nonblocking(true)?;
        Ok(Association {
            control: stream,
            udp,
            sender: None,
            ownership_checked: Instant::now(),
        })
    }
    fn connected(association: &Association, owner: &ControllerOwner) -> bool {
        if !owner.is_alive() {
            return false;
        }
        let mut byte = [0];
        matches!(association.control.peek(&mut byte),Err(e) if e.kind()==io::ErrorKind::WouldBlock)
    }
    fn forward(
        listener: &TcpListener,
        outer: &mut OwnedDatagram,
        baseline: &EgressSnapshot,
        port: u16,
        password: &str,
        cancel: &AtomicBool,
        commands: &mpsc::Receiver<Command>,
        stats: &Stats,
    ) -> io::Result<()> {
        let remote = SocketAddr::new(baseline.destination(), port);
        let return_header = header(remote);
        let mut local = Zeroizing::new(vec![0u8; CAP]);
        let mut incoming = Zeroizing::new(vec![0u8; CAP]);
        let mut owner: Option<ControllerOwner> = None;
        let mut association: Option<Association> = None;
        let mut window: Option<Window> = None;
        let mut next = 0u64;
        let mut current = snapshot(baseline.binding(), baseline.destination())?;
        let mut refreshed = Instant::now();
        let mut valid = current.same_path(baseline) && outer.validate(&current).is_ok();
        while !cancel.load(Ordering::Acquire) {
            // No startup guard owns this transport lifetime. Every proof uses a
            // separate bounded operation monitor and every flow uses fixed bind.
            if refreshed.elapsed() >= Duration::from_millis(200) {
                match snapshot(baseline.binding(), baseline.destination()) {
                    Ok(route) => {
                        valid = route.same_path(baseline) && outer.validate(&route).is_ok();
                        current = route;
                    }
                    Err(_) => valid = false,
                }
                refreshed = Instant::now();
            }
            if !current.is_fresh() {
                valid = false;
            }
            if window.as_ref().is_some_and(|w| w.monitor.is_cancelled()) {
                window = None;
            }
            if let Ok(command) = commands.try_recv() {
                match command {
                    Command::Attach(peer) => {
                        if owner.is_some() {
                            return Err(denied());
                        }
                        owner = Some(peer);
                    }
                    Command::Begin(monitor, reply) => {
                        window = None;
                        // Drain pre-window packets before taking counter baselines.
                        // Preserve established traffic; these are not new evidence.
                        for _ in 0..64 {
                            let n = match outer.receive(&mut incoming) {
                                Ok(Some(n)) => n,
                                _ => break,
                            };
                            stats.received.fetch_add(1, Ordering::Relaxed);
                            if valid {
                                if let (Some(session), Some(peer)) = (&association, &owner) {
                                    if let Some(sender) = session.sender {
                                        if connected(session, peer)
                                            && peer.verify_udp_sender(sender).is_ok()
                                        {
                                            let mut reply = Zeroizing::new(return_header.clone());
                                            reply.extend_from_slice(&incoming[..n]);
                                            let _ = session.udp.send_to(&reply, sender);
                                        }
                                    }
                                }
                            }
                        }
                        incoming.as_mut_slice().zeroize();
                        let result = if !valid || monitor.is_cancelled() {
                            Err(denied())
                        } else {
                            next = next.checked_add(1).ok_or_else(denied)?;
                            window = Some(Window {
                                id: next,
                                monitor,
                                exchange: outer.begin_exchange(),
                                witness: None,
                            });
                            Ok(next)
                        };
                        let _ = reply.try_send(result);
                    }
                    Command::VerifyActivity(id, reply) => {
                        let result = (|| {
                            let w = window
                                .as_ref()
                                .filter(|w| w.id == id && !w.monitor.is_cancelled())
                                .ok_or_else(denied)?;
                            let peer = owner.as_ref().ok_or_else(denied)?;
                            let session = association.as_ref().ok_or_else(denied)?;
                            if !valid || !connected(session, peer) {
                                return Err(denied());
                            }
                            peer.verify_udp_sender(session.sender.ok_or_else(denied)?)?;
                            outer.submitted_window(&w.exchange, &current)
                        })();
                        let _ = reply.try_send(result);
                    }
                    Command::Verify(id, reply) => {
                        let result = (|| {
                            let w = window
                                .as_mut()
                                .filter(|w| w.id == id && !w.monitor.is_cancelled())
                                .ok_or_else(denied)?;
                            let peer = owner.as_ref().ok_or_else(denied)?;
                            let session = association.as_ref().ok_or_else(denied)?;
                            if !valid || !connected(session, peer) {
                                return Err(denied());
                            }
                            peer.verify_udp_sender(session.sender.ok_or_else(denied)?)?;
                            if w.witness.is_none() {
                                w.witness = Some(outer.witness(&w.exchange, &current)?);
                            }
                            let witness = w.witness.as_ref().ok_or_else(denied)?;
                            if !outer.validates(witness, &current) {
                                return Err(denied());
                            }
                            Ok(witness.observed_at())
                        })();
                        let _ = reply.try_send(result);
                    }
                }
            }
            if let Some(peer) = &owner {
                if association.as_ref().is_some_and(|s| !connected(s, peer)) {
                    association = None;
                    window = None;
                }
                match listener.accept() {
                    Ok((stream, _)) if association.is_none() => {
                        match admit(stream, peer, password, cancel) {
                            Ok(session) => {
                                stats.accepted.fetch_add(1, Ordering::Relaxed);
                                association = Some(session);
                            }
                            Err(_) => {
                                stats.denied.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Ok((_stream, _)) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
                if valid {
                    if let Some(session) = &mut association {
                        for _ in 0..16 {
                            let (n, sender) = match session.udp.recv_from(&mut local) {
                                Ok(v) => v,
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                                Err(e) => return Err(e),
                            };
                            stats.local.fetch_add(1, Ordering::Relaxed);
                            let SocketAddr::V4(sender) = sender else {
                                stats.invalid.fetch_add(1, Ordering::Relaxed);
                                continue;
                            };
                            if session.sender.is_some_and(|s| s != sender) {
                                continue;
                            }
                            let Ok(data) = payload(&local[..n], remote) else {
                                stats.invalid.fetch_add(1, Ordering::Relaxed);
                                continue;
                            };
                            if session.sender.is_none()
                                || session.ownership_checked.elapsed() >= Duration::from_secs(1)
                            {
                                if peer.verify_udp_sender(sender).is_err() {
                                    stats.sender_denied.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                                session.ownership_checked = Instant::now();
                            }
                            session.sender = Some(sender);
                            // A full datagram is submitted or dropped on backpressure;
                            // no unbounded packet queue or arbitrary UDP destination.
                            if outer.send(data)? {
                                stats.sent.fetch_add(1, Ordering::Relaxed);
                            }
                            local.as_mut_slice().zeroize();
                        }
                        for _ in 0..16 {
                            match outer.receive(&mut incoming) {
                                Ok(Some(n)) => {
                                    stats.received.fetch_add(1, Ordering::Relaxed);
                                    if let Some(sender) = session.sender {
                                        let known = if session.ownership_checked.elapsed()
                                            < Duration::from_secs(1)
                                        {
                                            true
                                        } else if peer.verify_udp_sender(sender).is_ok() {
                                            session.ownership_checked = Instant::now();
                                            true
                                        } else {
                                            false
                                        };
                                        if known {
                                            let mut reply = Zeroizing::new(Vec::with_capacity(
                                                return_header.len() + n,
                                            ));
                                            reply.extend_from_slice(&return_header);
                                            reply.extend_from_slice(&incoming[..n]);
                                            let _ = session.udp.send_to(&reply, sender);
                                        }
                                    }
                                    incoming.as_mut_slice().zeroize();
                                }
                                Ok(None) => break,
                                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {}
                                Err(e) => return Err(e),
                            }
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(2));
        }
        drop(association);
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use adapter_platform::windows_process::OwnedProcess;
        #[test]
        #[ignore = "child-only owned loopback carrier fixture"]
        fn owned_carrier_client_child() {
            let deadline = Instant::now() + Duration::from_secs(5);
            let port = loop {
                if let Ok(value) = std::fs::read_to_string("carrier-port") {
                    break value.parse::<u16>().unwrap();
                }
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(5));
            };
            let mut control = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
            control
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            control.write_all(&[5, 1, 2]).unwrap();
            let mut reply = [0; 2];
            control.read_exact(&mut reply).unwrap();
            assert_eq!(reply, [5, 2]);
            let mut auth = vec![1, 7];
            auth.extend_from_slice(b"adapter");
            auth.push(64);
            auth.extend_from_slice(&[b'a'; 64]);
            if std::path::Path::new("bad-secret").exists() {
                let last = auth.len() - 1;
                auth[last] = b'b';
            }
            control.write_all(&auth).unwrap();
            if std::path::Path::new("bad-secret").exists() {
                assert_eq!(control.read(&mut reply).unwrap(), 0);
                return;
            }
            control.read_exact(&mut reply).unwrap();
            assert_eq!(reply, [1, 0]);
            control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            let mut bound = [0; 10];
            control.read_exact(&mut bound).unwrap();
            assert_eq!(bound[..8], [5, 0, 0, 1, 127, 0, 0, 1]);
            let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let mut frame = header("192.0.2.10:20484".parse().unwrap());
            frame.extend_from_slice(b"synthetic-ciphertext");
            udp.send_to(
                &frame,
                (
                    Ipv4Addr::LOCALHOST,
                    u16::from_be_bytes([bound[8], bound[9]]),
                ),
            )
            .unwrap();
            while !std::path::Path::new("release-client").exists() {
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(5));
            }
        }
        fn fixture(bad_secret: bool) {
            struct Temp(std::path::PathBuf);
            impl Drop for Temp {
                fn drop(&mut self) {
                    let _ = std::fs::remove_dir_all(&self.0);
                }
            }
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce).unwrap();
            let directory = Temp(std::env::temp_dir().join(format!(
                "adapter-carrier-{:032x}",
                u128::from_le_bytes(nonce)
            )));
            std::fs::create_dir(&directory.0).unwrap();
            if bad_secret {
                std::fs::write(directory.0.join("bad-secret"), b"yes").unwrap();
            }
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let child = OwnedProcess::spawn_sanitized(
                &std::env::current_exe().unwrap(),
                &[
                    "--exact".into(),
                    "carrier::windows::tests::owned_carrier_client_child".into(),
                    "--ignored".into(),
                    "--nocapture".into(),
                ],
                &directory.0,
            )
            .unwrap();
            let owner = child.controller_owner().unwrap();
            // A foreign local process gets zero greeting/capability bytes.
            let mut foreign = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            foreign
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let (stream, _) = listener.accept().unwrap();
            assert!(admit(stream, &owner, &"a".repeat(64), &AtomicBool::new(false)).is_err());
            assert_eq!(foreign.read(&mut [0; 2]).unwrap(), 0);
            std::fs::write(
                directory.0.join("carrier-port"),
                listener.local_addr().unwrap().port().to_string(),
            )
            .unwrap();
            let deadline = Instant::now() + Duration::from_secs(3);
            let stream = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline);
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                }
            };
            let session = admit(stream, &owner, &"a".repeat(64), &AtomicBool::new(false));
            if bad_secret {
                assert!(session.is_err());
            } else {
                let session = session.unwrap();
                session.udp.set_nonblocking(false).unwrap();
                session
                    .udp
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut frame = [0; 128];
                let (n, sender) = session.udp.recv_from(&mut frame).unwrap();
                assert_eq!(
                    payload(&frame[..n], "192.0.2.10:20484".parse().unwrap()).unwrap(),
                    b"synthetic-ciphertext"
                );
                let SocketAddr::V4(sender) = sender else {
                    panic!("fixture sender family")
                };
                owner.verify_udp_sender(sender).unwrap();
                let foreign_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
                let SocketAddr::V4(other) = foreign_udp.local_addr().unwrap() else {
                    panic!("fixture sender family")
                };
                assert!(owner.verify_udp_sender(other).is_err());
                std::fs::write(directory.0.join("release-client"), b"yes").unwrap();
            }
            assert_eq!(child.wait(Duration::from_secs(3)).unwrap(), Some(0));
            child.terminate(Duration::from_secs(2)).unwrap();
        }
        #[test]
        fn native_carrier_admits_only_retained_child_and_its_udp_sender() {
            fixture(false);
        }
        #[test]
        fn native_carrier_rejects_wrong_ephemeral_secret() {
            fixture(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_fixed_destination_and_no_fragment_domain_or_empty_forwarding() {
        for remote in ["192.0.2.10:20484", "[2001:db8::2]:51820"] {
            let remote = remote.parse().unwrap();
            let mut frame = header(remote);
            frame.extend_from_slice(b"encrypted");
            assert_eq!(payload(&frame, remote).unwrap(), b"encrypted");
            let wrong = SocketAddr::new(remote.ip(), remote.port() + 1);
            assert!(payload(&frame, wrong).is_err());
            for index in [0, 1, 2, 3] {
                let mut altered = frame.clone();
                altered[index] = 99;
                assert!(payload(&altered, remote).is_err());
            }
            for n in 0..header(remote).len() + 1 {
                assert!(payload(&frame[..n], remote).is_err());
            }
        }
    }
    #[test]
    fn username_and_full_ephemeral_capability_are_required() {
        let key = b"a".repeat(64);
        assert!(credentials(b"adapter", &key, &key));
        assert!(!credentials(b"other", &key, &key));
        assert!(!credentials(b"adapter", &key[..63], &key));
        let mut wrong = key.clone();
        wrong[63] = b'b';
        assert!(!credentials(b"adapter", &wrong, &key));
    }
}
