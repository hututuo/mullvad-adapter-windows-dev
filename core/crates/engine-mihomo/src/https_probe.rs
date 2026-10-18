//! HTTPS canaries over an owned SOCKS peer; never system DNS or direct fallback.
use std::{
    fmt,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};
use ureq::{
    http::Uri,
    tls::TlsConfig,
    unversioned::{
        resolver::{ResolvedSocketAddrs, Resolver},
        transport::{
            Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, RustlsConnector,
            Transport,
        },
    },
    Agent,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Ip,
    Hostname,
}
impl Target {
    fn host(self) -> &'static str {
        match self {
            Self::Ip => "1.1.1.1",
            Self::Hostname => "www.gstatic.com",
        }
    }
    fn url(self) -> &'static str {
        match self {
            Self::Ip => "https://1.1.1.1/cdn-cgi/trace",
            Self::Hostname => "https://www.gstatic.com/generate_204",
        }
    }
    pub(crate) fn budget(self) -> Duration {
        Duration::from_secs(match self {
            Self::Ip => 8,
            Self::Hostname => 12,
        })
    }
    fn matches(self, uri: &Uri) -> bool {
        uri.to_string() == self.url()
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpsResult {
    Passed(u16),
    Rejected,
    Cancelled,
    Deadline,
}
type Verify = Arc<dyn Fn(&TcpStream) -> io::Result<()> + Send + Sync>;
type Cancel = Arc<dyn Fn() -> bool + Send + Sync>;

#[cfg(any(windows, feature = "windows-api-check"))]
pub fn for_worker(
    process: &adapter_platform::windows_process::OwnedProcess,
    network: &adapter_control::owned_lifecycle::BoundNetwork,
    port: u16,
    target: Target,
) -> HttpsResult {
    let Ok(owner) = process.controller_owner() else {
        return HttpsResult::Rejected;
    };
    let monitor = network.cancellation_monitor();
    run(
        port,
        target,
        Arc::new(move |s| owner.verify_connected(s)),
        Arc::new(move || monitor.is_cancelled()),
        verified_tls(),
        target.budget(),
        || {
            process
                .wait(Duration::ZERO)
                .is_ok_and(|status| status.is_none())
        },
    )
}
#[cfg(any(windows, feature = "windows-api-check"))]
pub(crate) fn verified_tls() -> TlsConfig {
    TlsConfig::builder()
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .build()
}

struct FixedResolver {
    target: Target,
    port: u16,
}
impl fmt::Debug for FixedResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnedSocksResolver")
    }
}
impl Resolver for FixedResolver {
    fn resolve(
        &self,
        uri: &Uri,
        _config: &ureq::config::Config,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        if !self.target.matches(uri) {
            return Err(ureq::Error::HostNotFound);
        }
        // Deliberately no ToSocketAddrs/DefaultResolver. The custom connector
        // uses this local listener; hostname resolution is delegated in SOCKS.
        let mut out = self.empty();
        out.push(SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port).into());
        Ok(out)
    }
}
struct SocksConnector {
    port: u16,
    target: Target,
    deadline: Instant,
    verify: Verify,
    cancel: Cancel,
}
impl fmt::Debug for SocksConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnedSocksHttpsConnector")
    }
}
fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "canary transport rejected")
}
fn remaining(deadline: Instant, cancel: &Cancel) -> io::Result<Duration> {
    if cancel() {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "canary cancelled",
        ));
    }
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "canary deadline"))
}
impl<In: Transport> Connector<In> for SocksConnector {
    type Out = SocksTransport;
    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        if chained.is_some()
            || !self.target.matches(details.uri)
            || details.config.proxy().is_some()
        {
            return Err(denied().into());
        }
        let stream = TcpStream::connect_timeout(
            &SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port).into(),
            remaining(self.deadline, &self.cancel)?.min(Duration::from_millis(500)),
        )?;
        (self.verify)(&stream)?;
        remaining(self.deadline, &self.cancel)?;
        let mut transport = SocksTransport {
            stream,
            deadline: self.deadline,
            cancel: self.cancel.clone(),
            buffers: LazyBuffers::new(4096, 4096),
        };
        transport.write_bytes(&[5, 1, 0])?;
        let mut hello = [0; 2];
        transport.read_bytes(&mut hello)?;
        if hello != [5, 0] {
            return Err(denied().into());
        }
        let mut request = vec![5, 1, 0];
        match self.target {
            Target::Ip => request.extend_from_slice(&[1, 1, 1, 1, 1]),
            Target::Hostname => {
                request.extend_from_slice(&[3, self.target.host().len() as u8]);
                request.extend_from_slice(self.target.host().as_bytes());
            }
        }
        request.extend_from_slice(&443u16.to_be_bytes());
        transport.write_bytes(&request)?;
        let mut header = [0; 4];
        transport.read_bytes(&mut header)?;
        if header[..3] != [5, 0, 0] {
            return Err(denied().into());
        }
        match header[3] {
            1 => transport.read_bytes(&mut [0; 4])?,
            4 => transport.read_bytes(&mut [0; 16])?,
            3 => {
                let mut size = [0];
                transport.read_bytes(&mut size)?;
                if size[0] == 0 {
                    return Err(denied().into());
                }
                transport.read_bytes(&mut vec![0; usize::from(size[0])])?;
            }
            _ => return Err(denied().into()),
        }
        transport.read_bytes(&mut [0; 2])?;
        Ok(Some(transport))
    }
}
struct SocksTransport {
    stream: TcpStream,
    deadline: Instant,
    cancel: Cancel,
    buffers: LazyBuffers,
}
impl fmt::Debug for SocksTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnedSocksTlsStream")
    }
}
impl SocksTransport {
    fn read_some(&mut self, output: &mut [u8]) -> io::Result<usize> {
        loop {
            self.stream.set_read_timeout(Some(
                remaining(self.deadline, &self.cancel)?.min(Duration::from_millis(50)),
            ))?;
            match self.stream.read(output) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue
                }
                result => {
                    remaining(self.deadline, &self.cancel)?;
                    return result;
                }
            }
        }
    }
    fn read_bytes(&mut self, mut output: &mut [u8]) -> io::Result<()> {
        while !output.is_empty() {
            let n = self.read_some(output)?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            output = &mut output[n..];
        }
        Ok(())
    }
    fn write_bytes(&mut self, mut input: &[u8]) -> io::Result<()> {
        while !input.is_empty() {
            self.stream.set_write_timeout(Some(
                remaining(self.deadline, &self.cancel)?.min(Duration::from_millis(50)),
            ))?;
            match self.stream.write(input) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => input = &input[n..],
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        remaining(self.deadline, &self.cancel)?;
        Ok(())
    }
}
impl Transport for SocksTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }
    fn transmit_output(&mut self, amount: usize, _timeout: NextTimeout) -> Result<(), ureq::Error> {
        // Small bounded transport buffer; no credentials are written by probes.
        let data = self.buffers.output()[..amount].to_vec();
        self.write_bytes(&data)?;
        Ok(())
    }
    fn await_input(&mut self, _timeout: NextTimeout) -> Result<bool, ureq::Error> {
        let mut chunk = [0; 4096];
        let capacity = self.buffers.input_append_buf().len().min(chunk.len());
        if capacity == 0 {
            return Err(denied().into());
        }
        let size = self.read_some(&mut chunk[..capacity])?;
        self.buffers.input_append_buf()[..size].copy_from_slice(&chunk[..size]);
        self.buffers.input_appended(size);
        Ok(size > 0)
    }
    fn is_open(&mut self) -> bool {
        false
    }
}
pub(crate) fn run(
    port: u16,
    target: Target,
    verify: Verify,
    cancel: Cancel,
    tls: TlsConfig,
    budget: Duration,
    live: impl Fn() -> bool,
) -> HttpsResult {
    let deadline = Instant::now() + budget;
    if cancel() {
        return HttpsResult::Cancelled;
    }
    if port < 1024 || !live() {
        return HttpsResult::Rejected;
    }
    let config = Agent::config_builder()
        .proxy(None)
        .max_redirects(0)
        .max_idle_connections(0)
        .max_idle_connections_per_host(0)
        .max_response_header_size(8192)
        .timeout_global(Some(budget))
        .timeout_connect(Some(Duration::from_millis(500)))
        .http_status_as_error(false)
        .tls_config(tls)
        .build();
    let connector = SocksConnector {
        port,
        target,
        deadline,
        verify,
        cancel: cancel.clone(),
    }
    .chain(RustlsConnector::default());
    let agent = Agent::with_parts(config, connector, FixedResolver { target, port });
    let result = (|| -> Result<u16, ureq::Error> {
        let mut response = agent
            .get(target.url())
            .header("Connection", "close")
            .call()?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(65537) // one-byte lookahead permits an exactly64KiB body
            .read_to_vec()?;
        if body.len() > 65536 {
            return Err(denied().into());
        }
        Ok(status)
    })();
    if cancel() {
        HttpsResult::Cancelled
    } else if Instant::now() >= deadline {
        HttpsResult::Deadline
    } else if !live() {
        HttpsResult::Rejected
    } else if cancel() {
        HttpsResult::Cancelled
    } else if Instant::now() >= deadline {
        HttpsResult::Deadline
    } else {
        match result {
            Ok(status) if (200..400).contains(&status) => HttpsResult::Passed(status),
            _ => HttpsResult::Rejected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{pki_types::PrivatePkcs8KeyDer, ServerConfig, ServerConnection, StreamOwned};
    use std::{
        net::TcpListener,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        thread,
    };
    use ureq::tls::{Certificate, RootCerts};
    fn tls_fixture(
        target: Target,
        cert_names: Vec<String>,
        body: impl FnOnce(&mut StreamOwned<ServerConnection, TcpStream>) + Send + 'static,
    ) -> (u16, TlsConfig, Arc<AtomicBool>, thread::JoinHandle<()>) {
        let mut params = rcgen::CertificateParams::new(cert_names.clone()).unwrap();
        if cert_names[0] == "expired.test" || cert_names[0] == "future.test" {
            params = rcgen::CertificateParams::new(vec!["www.gstatic.com".into()]).unwrap();
            let year = if cert_names[0] == "expired.test" {
                2000
            } else {
                2100
            };
            params.not_before = rcgen::date_time_ymd(year, 1, 1);
            params.not_after = rcgen::date_time_ymd(year + 1, 1, 1);
        }
        let signing_key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&signing_key).unwrap();
        let key = rcgen::CertifiedKey { cert, signing_key };
        let cert = key.cert.der().clone();
        let roots = RootCerts::new_with_certs(&[Certificate::from_der(cert.as_ref()).to_owned()]);
        let tls = TlsConfig::builder()
            .root_certs(roots)
            .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .build();
        assert!(!tls.disable_verification());
        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert],
                    PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
                )
                .unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let saw = Arc::new(AtomicBool::new(false));
        let recorded = saw.clone();
        let join = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut socket = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            let mut hello = [0; 3];
            if socket.read_exact(&mut hello).is_err() {
                return;
            }
            assert_eq!(hello, [5, 1, 0]);
            socket.write_all(&[5, 0]).unwrap();
            let mut request = [0; 4];
            socket.read_exact(&mut request).unwrap();
            assert_eq!(&request[..3], &[5, 1, 0]);
            match target {
                Target::Ip => {
                    assert_eq!(request[3], 1);
                    let mut ip = [0; 4];
                    socket.read_exact(&mut ip).unwrap();
                    assert_eq!(ip, [1, 1, 1, 1]);
                }
                Target::Hostname => {
                    assert_eq!(request[3], 3);
                    let mut size = [0];
                    socket.read_exact(&mut size).unwrap();
                    let mut host = vec![0; usize::from(size[0])];
                    socket.read_exact(&mut host).unwrap();
                    assert_eq!(host, target.host().as_bytes());
                }
            }
            let mut port = [0; 2];
            socket.read_exact(&mut port).unwrap();
            assert_eq!(u16::from_be_bytes(port), 443);
            socket.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            let mut stream =
                StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), socket);
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte) {
                    Ok(1) => request.push(byte[0]),
                    _ => return,
                };
                assert!(request.len() <= 8192);
            }
            assert_eq!(
                stream.conn.server_name(),
                match target {
                    Target::Ip => None,
                    Target::Hostname => Some("www.gstatic.com"),
                }
            );
            let http = String::from_utf8_lossy(&request).to_ascii_lowercase();
            assert!(http.contains(&format!("host: {}\r\n", target.host())));
            assert!(!http.contains("authorization:"));
            assert!(!http.contains("cookie:"));
            recorded.store(true, Ordering::Release);
            body(&mut stream);
        });
        (port, tls, saw, join)
    }
    fn probe(port: u16, target: Target, tls: TlsConfig, budget: Duration) -> HttpsResult {
        run(
            port,
            target,
            Arc::new(|_| Ok(())),
            Arc::new(|| false),
            tls,
            budget,
            || true,
        )
    }
    #[test]
    fn validated_tls_ip_and_socks_hostname_targets_succeed_without_local_lookup() {
        for target in [Target::Ip, Target::Hostname] {
            let (port, tls, saw, join) =
                tls_fixture(target, vec![target.host().into()], |stream| {
                    stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                        .unwrap();
                    stream.flush().unwrap();
                });
            assert_eq!(
                probe(port, target, tls, Duration::from_secs(2)),
                HttpsResult::Passed(204)
            );
            join.join().unwrap();
            assert!(saw.load(Ordering::Acquire));
        }
    }
    #[test]
    fn untrusted_or_wrong_hostname_certificate_never_sends_http() {
        for untrusted in [false, true] {
            let (port, tls, saw, join) = tls_fixture(
                Target::Hostname,
                vec![if untrusted {
                    "www.gstatic.com"
                } else {
                    "wrong.example"
                }
                .into()],
                |_| panic!("HTTP after invalid TLS"),
            );
            let tls = if untrusted {
                TlsConfig::builder()
                    .unversioned_rustls_crypto_provider(Arc::new(
                        rustls::crypto::ring::default_provider(),
                    ))
                    .build()
            } else {
                tls
            };
            assert_eq!(
                probe(port, Target::Hostname, tls, Duration::from_secs(2)),
                HttpsResult::Rejected
            );
            join.join().unwrap();
            assert!(!saw.load(Ordering::Acquire));
        }
    }
    #[test]
    fn redirect_status_is_not_followed_and_body_limit_is_enforced() {
        for oversize in [false, true] {
            let (port, tls, saw, join) = tls_fixture(
                Target::Ip,
                vec!["1.1.1.1".into()],
                move |stream| {
                    let response = if oversize {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n".as_slice()
                    } else {
                        b"HTTP/1.1 302 Found\r\nLocation: https://unrelated.example/\r\nContent-Length: 0\r\n\r\n".as_slice()
                    };
                    let _ = stream.write_all(response);
                    let _ = stream.flush();
                },
            );
            assert_eq!(
                probe(port, Target::Ip, tls, Duration::from_secs(2)),
                if oversize {
                    HttpsResult::Rejected
                } else {
                    HttpsResult::Passed(302)
                }
            );
            join.join().unwrap();
            assert!(saw.load(Ordering::Acquire));
        }
    }
    #[test]
    fn cancellation_and_total_deadline_interrupt_tls_body_reads() {
        for cancelled in [false, true] {
            let cancel = Arc::new(AtomicBool::new(false));
            let change = cancel.clone();
            let (port, tls, _, join) =
                tls_fixture(Target::Ip, vec!["1.1.1.1".into()], move |stream| {
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n")
                        .unwrap();
                    stream.flush().unwrap();
                    if cancelled {
                        change.store(true, Ordering::Release);
                    }
                    for _ in 0..10 {
                        if stream.write_all(b"x").and_then(|_| stream.flush()).is_err() {
                            return;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                });
            let started = Instant::now();
            let result = run(
                port,
                Target::Ip,
                Arc::new(|_| Ok(())),
                Arc::new(move || cancel.load(Ordering::Acquire)),
                tls,
                Duration::from_millis(400),
                || true,
            );
            assert_eq!(
                result,
                if cancelled {
                    HttpsResult::Cancelled
                } else {
                    HttpsResult::Deadline
                }
            );
            assert!(started.elapsed() < Duration::from_secs(1));
            join.join().unwrap();
        }
    }
    #[test]
    fn final_process_check_cannot_restore_expired_or_cancelled_evidence() {
        for cancel_at_end in [false, true] {
            let flag = Arc::new(AtomicBool::new(false));
            let read = flag.clone();
            let calls = AtomicUsize::new(0);
            let (port, tls, _, join) = tls_fixture(Target::Ip, vec!["1.1.1.1".into()], |stream| {
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .unwrap();
                stream.flush().unwrap();
            });
            let result = run(
                port,
                Target::Ip,
                Arc::new(|_| Ok(())),
                Arc::new(move || read.load(Ordering::Acquire)),
                tls,
                Duration::from_millis(400),
                || {
                    if calls.fetch_add(1, Ordering::SeqCst) == 1 {
                        if cancel_at_end {
                            flag.store(true, Ordering::Release);
                        } else {
                            thread::sleep(Duration::from_millis(450));
                        }
                    }
                    true
                },
            );
            assert_eq!(
                result,
                if cancel_at_end {
                    HttpsResult::Cancelled
                } else {
                    HttpsResult::Deadline
                }
            );
            join.join().unwrap();
        }
    }
    #[cfg(any(windows, feature = "windows-api-check"))]
    #[test]
    #[ignore = "child-only synthetic HTTPS over SOCKS fixture"]
    fn owned_tls_child_fixture() {
        let (port, tls, saw, join) =
            tls_fixture(Target::Hostname, vec!["www.gstatic.com".into()], |stream| {
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .unwrap();
                stream.flush().unwrap();
            });
        let RootCerts::Specific(roots) = tls.root_certs() else {
            panic!("fixture roots");
        };
        std::fs::write("tls-root.der", roots[0].der()).unwrap();
        std::fs::write("tls-port", port.to_string()).unwrap();
        join.join().unwrap();
        assert!(saw.load(Ordering::Acquire));
        let deadline = Instant::now() + Duration::from_secs(20);
        while !std::path::Path::new("client-finished").exists() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
    }
    #[cfg(any(windows, feature = "windows-api-check"))]
    #[test]
    fn actual_owned_tls_child_is_verified_before_socks_and_after_http() {
        struct Temp(std::path::PathBuf);
        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let root = Temp(std::env::temp_dir().join(format!(
            "adapter-tls-peer-{:032x}",
            u128::from_le_bytes(random)
        )));
        std::fs::create_dir(&root.0).unwrap();
        let process = adapter_platform::windows_process::OwnedProcess::spawn_sanitized(
            &std::env::current_exe().unwrap(),
            &[
                "--exact".into(),
                "https_probe::tests::owned_tls_child_fixture".into(),
                "--ignored".into(),
            ],
            &root.0,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let port = loop {
            if let Ok(text) = std::fs::read_to_string(root.0.join("tls-port")) {
                if let Ok(port) = text.parse::<u16>() {
                    break port;
                }
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        };
        let der = std::fs::read(root.0.join("tls-root.der")).unwrap();
        let tls = TlsConfig::builder()
            .root_certs(RootCerts::new_with_certs(&[
                Certificate::from_der(&der).to_owned()
            ]))
            .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .build();
        let owner = process.controller_owner().unwrap();
        assert_eq!(
            run(
                port,
                Target::Hostname,
                Arc::new(move |s| owner.verify_connected(s)),
                Arc::new(|| false),
                tls,
                Target::Hostname.budget(),
                || process
                    .wait(Duration::ZERO)
                    .is_ok_and(|status| status.is_none())
            ),
            HttpsResult::Passed(204)
        );
        std::fs::write(root.0.join("client-finished"), b"done").unwrap();
        assert_eq!(process.wait(Duration::from_secs(5)).unwrap(), Some(0));
    }
    #[test]
    fn complete_body_and_header_bounds_are_enforced_over_tls() {
        for case in 0..4 {
            let (port, tls, _, join) =
                tls_fixture(Target::Ip, vec!["1.1.1.1".into()], move |stream| {
                    let response = match case {
                        0 | 1 => {
                            let size = 65536 + case;
                            let mut response =
                                format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n")
                                    .into_bytes();
                            response.resize(response.len() + size, b'x');
                            response
                        }
                        2 => format!(
                            "HTTP/1.1 200 OK\r\nX-Long: {}\r\nContent-Length: 0\r\n\r\n",
                            "x".repeat(9000)
                        )
                        .into_bytes(),
                        _ => b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n123456789".to_vec(),
                    };
                    let _ = stream.write_all(&response);
                    let _ = stream.flush();
                });
            assert_eq!(
                probe(port, Target::Ip, tls, Duration::from_secs(2)),
                if case == 0 {
                    HttpsResult::Passed(200)
                } else {
                    HttpsResult::Rejected
                },
                "case {case}"
            );
            join.join().unwrap();
        }
    }
    #[test]
    fn resolver_is_fixed_and_owner_refusal_sends_zero_bytes() {
        let resolver = FixedResolver {
            target: Target::Hostname,
            port: 12345,
        };
        let config = Agent::config_builder().build();
        let timeout = NextTimeout {
            after: Duration::from_secs(1).into(),
            reason: ureq::Timeout::Resolve,
        };
        let addresses = resolver
            .resolve(&Target::Hostname.url().parse().unwrap(), &config, timeout)
            .unwrap();
        assert_eq!(addresses.len(), 1);
        assert_eq!(
            addresses[0],
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12345).into()
        );
        for url in [
            "http://www.gstatic.com/generate_204",
            "https://unrelated.example/",
            "https://www.gstatic.com:444/generate_204",
            "https://www.gstatic.com/other",
        ] {
            assert!(resolver
                .resolve(&url.parse().unwrap(), &config, timeout)
                .is_err());
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let join = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut stream = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut one = [0];
            assert_eq!(stream.read(&mut one).unwrap(), 0);
        });
        assert_eq!(
            run(
                port,
                Target::Ip,
                Arc::new(|_| Err(denied())),
                Arc::new(|| false),
                TlsConfig::default(),
                Duration::from_secs(2),
                || true
            ),
            HttpsResult::Rejected
        );
        join.join().unwrap();
    }
    #[test]
    fn independent_expired_future_and_wrong_ip_reject_before_http() {
        for (target, name) in [
            (Target::Hostname, "expired.test"),
            (Target::Hostname, "future.test"),
            (Target::Ip, "8.8.8.8"),
        ] {
            let (port, tls, saw, join) = tls_fixture(target, vec![name.into()], |_| {
                panic!("invalid cert reached HTTP")
            });
            assert_eq!(
                probe(port, target, tls, Duration::from_secs(2)),
                HttpsResult::Rejected
            );
            join.join().unwrap();
            assert!(!saw.load(Ordering::Acquire));
        }
    }
    #[test]
    fn independent_chunked_and_eof_body_bounds() {
        for chunked in [false, true] {
            for size in [65536, 65537] {
                let (port, tls, _, join) =
                    tls_fixture(Target::Ip, vec!["1.1.1.1".into()], move |stream| {
                        let mut response = if chunked {
                            format!(
                                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size:X}\r\n"
                            )
                            .into_bytes()
                        } else {
                            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec()
                        };
                        response.extend(vec![b'x'; size]);
                        if chunked {
                            response.extend(b"\r\n0\r\n\r\n");
                        }
                        let _ = stream.write_all(&response);
                        let _ = stream.flush();
                        stream.conn.send_close_notify();
                        let _ = stream.flush();
                    });
                assert_eq!(
                    probe(port, Target::Ip, tls, Duration::from_secs(2)),
                    if size == 65536 {
                        HttpsResult::Passed(200)
                    } else {
                        HttpsResult::Rejected
                    },
                    "chunked={chunked} size={size}"
                );
                join.join().unwrap();
            }
        }
    }
    #[test]
    fn independent_dead_process_final_fence() {
        let (port, tls, _, join) = tls_fixture(Target::Ip, vec!["1.1.1.1".into()], |stream| {
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                .unwrap();
            stream.flush().unwrap();
        });
        let live_calls = AtomicUsize::new(0);
        assert_eq!(
            run(
                port,
                Target::Ip,
                Arc::new(|_| Ok(())),
                Arc::new(|| false),
                tls,
                Duration::from_secs(2),
                || live_calls.fetch_add(1, Ordering::SeqCst) == 0
            ),
            HttpsResult::Rejected
        );
        join.join().unwrap();
    }
}
