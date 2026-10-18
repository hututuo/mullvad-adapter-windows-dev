//! Fixed loopback controller. Verify connected peer ownership before credentials.
use serde::Deserialize;
use std::{
    fmt,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};
use ureq::{
    http::HeaderValue,
    unversioned::{
        resolver::DefaultResolver,
        transport::{Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, Transport},
    },
    Agent,
};
use zeroize::Zeroizing;
const REQUEST_LIMIT: Duration = Duration::from_secs(2);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerError {
    InvalidInput,
    Unavailable,
    Unauthorized,
    UnexpectedResponse,
    OutcomeUnknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selected {
    Reject,
    SlotA,
    SlotB,
}
impl Selected {
    fn name(self) -> &'static str {
        match self {
            Self::Reject => "REJECT",
            Self::SlotA => "SLOT-A",
            Self::SlotB => "SLOT-B",
        }
    }
}
trait PeerVerifier: Send + Sync {
    fn verify(&self, stream: &TcpStream) -> io::Result<()>;
}
#[cfg(any(windows, feature = "windows-api-check"))]
impl PeerVerifier for adapter_platform::windows_controller_owner::ControllerOwner {
    fn verify(&self, stream: &TcpStream) -> io::Result<()> {
        self.verify_connected(stream)
    }
}
struct VerifiedConnector {
    port: u16,
    verifier: Arc<dyn PeerVerifier>,
}
impl fmt::Debug for VerifiedConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedLoopbackConnector")
    }
}
impl<In: Transport> Connector<In> for VerifiedConnector {
    type Out = VerifiedTransport;
    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        if chained.is_some()
            || details.uri.scheme_str() != Some("http")
            || details.uri.host() != Some("127.0.0.1")
            || details.uri.port_u16() != Some(self.port)
            || details.config.proxy().is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "nonlocal controller request rejected",
            )
            .into());
        }
        if details.timeout.after.is_zero() {
            return Err(ureq::Error::Timeout(details.timeout.reason));
        }
        let budget = details
            .timeout
            .not_zero()
            .map(|v| *v)
            .unwrap_or(Duration::from_millis(500))
            .min(Duration::from_millis(500));
        let start = Instant::now();
        let stream = TcpStream::connect_timeout(
            &SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port)),
            budget,
        )?;
        self.verifier.verify(&stream)?;
        if start.elapsed() >= budget {
            return Err(ureq::Error::Timeout(details.timeout.reason));
        }
        stream.set_nodelay(true)?;
        Ok(Some(VerifiedTransport {
            stream,
            buffers: LazyBuffers::new(4096, 4096),
            deadline: start + REQUEST_LIMIT,
        }))
    }
}
struct VerifiedTransport {
    stream: TcpStream,
    buffers: LazyBuffers,
    deadline: Instant,
}
impl fmt::Debug for VerifiedTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VerifiedLoopbackTransport")
    }
}
impl VerifiedTransport {
    fn remaining(&self, timeout: NextTimeout) -> Result<Duration, ureq::Error> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
            .ok_or(ureq::Error::Timeout(timeout.reason))?;
        if timeout.after.is_zero() {
            return Err(ureq::Error::Timeout(timeout.reason));
        }
        Ok(remaining.min(timeout.not_zero().map(|v| *v).unwrap_or(REQUEST_LIMIT)))
    }
    fn io_error(error: io::Error, timeout: NextTimeout) -> ureq::Error {
        if matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            ureq::Error::Timeout(timeout.reason)
        } else {
            error.into()
        }
    }
}
impl Transport for VerifiedTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }
    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        let mut offset = 0;
        while offset < amount {
            self.stream
                .set_write_timeout(Some(self.remaining(timeout)?))?;
            match self.stream.write(&self.buffers.output()[offset..amount]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "controller write stalled",
                    )
                    .into())
                }
                Ok(n) => offset += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Self::io_error(e, timeout)),
            }
        }
        use zeroize::Zeroize;
        self.buffers.output()[..amount].zeroize();
        Ok(())
    }
    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        loop {
            self.stream
                .set_read_timeout(Some(self.remaining(timeout)?))?;
            match self.stream.read(self.buffers.input_append_buf()) {
                Ok(n) => {
                    self.buffers.input_appended(n);
                    return Ok(n > 0);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Self::io_error(e, timeout)),
            }
        }
    }
    fn is_open(&mut self) -> bool {
        false
    } // never reusable: prove ownership on every call
}
impl Drop for VerifiedTransport {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.buffers.output().zeroize();
    }
}
/// Capability and transport are never exposed to the renderer or Debug output.
pub struct Controller {
    agent: Agent,
    base: String,
    secret: Zeroizing<String>,
}
impl Controller {
    #[cfg(any(windows, feature = "windows-api-check"))]
    pub fn for_process(
        process: &adapter_platform::windows_process::OwnedProcess,
        port: u16,
        secret: &str,
    ) -> Result<Self, ControllerError> {
        let owner = process
            .controller_owner()
            .map_err(|_| ControllerError::Unavailable)?;
        Self::new_verified(port, secret, Arc::new(owner))
    }
    fn new_verified(
        port: u16,
        secret: &str,
        verifier: Arc<dyn PeerVerifier>,
    ) -> Result<Self, ControllerError> {
        if port < 1024 || secret.len() != 64 || !secret.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(ControllerError::InvalidInput);
        }
        let config = Agent::config_builder()
            .proxy(None)
            .max_redirects(0)
            .max_idle_connections(0)
            .max_idle_connections_per_host(0)
            .max_response_header_size(8192)
            .timeout_global(Some(REQUEST_LIMIT))
            .timeout_connect(Some(Duration::from_millis(500)))
            .http_status_as_error(false)
            .build();
        let agent = Agent::with_parts(
            config,
            VerifiedConnector { port, verifier },
            DefaultResolver::default(),
        );
        Ok(Self {
            agent,
            base: format!("http://127.0.0.1:{port}"),
            secret: Zeroizing::new(secret.to_owned()),
        })
    }
    fn authorization(&self) -> Result<HeaderValue, ControllerError> {
        let text = Zeroizing::new(format!("Bearer {}", self.secret.as_str()));
        let mut header = HeaderValue::from_str(&text).map_err(|_| ControllerError::InvalidInput)?;
        header.set_sensitive(true);
        Ok(header)
    }
    fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, ControllerError> {
        let started = Instant::now();
        let mut response = self
            .agent
            .get(format!("{}{path}", self.base))
            .header("Authorization", self.authorization()?)
            .header("Connection", "close")
            .call()
            .map_err(|_| ControllerError::Unavailable)?;
        match response.status().as_u16() {
            200 => {}
            401 | 403 => return Err(ControllerError::Unauthorized),
            _ => return Err(ControllerError::UnexpectedResponse),
        }
        let value = response
            .body_mut()
            .with_config()
            .limit(16384)
            .read_json()
            .map_err(|_| ControllerError::UnexpectedResponse)?;
        if started.elapsed() >= REQUEST_LIMIT {
            return Err(ControllerError::Unavailable);
        }
        Ok(value)
    }
    pub fn check_version(&self) -> Result<(), ControllerError> {
        #[derive(Deserialize)]
        struct Version {
            version: String,
        }
        let result: Version = self.get("/version")?;
        if Some(result.version.as_str())
            != crate::ENGINE_COMPATIBILITY_TARGET.strip_prefix("mihomo-")
        {
            return Err(ControllerError::UnexpectedResponse);
        }
        Ok(())
    }
    pub fn selected(&self) -> Result<Selected, ControllerError> {
        #[derive(Deserialize)]
        struct Group {
            #[serde(rename = "type")]
            kind: String,
            now: String,
            all: Vec<String>,
        }
        let result: Group = self.get("/proxies/OUT")?;
        let mut choices = result.all;
        choices.sort();
        if result.kind != "Selector" || choices != ["REJECT", "SLOT-A", "SLOT-B"] {
            return Err(ControllerError::UnexpectedResponse);
        }
        match result.now.as_str() {
            "REJECT" => Ok(Selected::Reject),
            "SLOT-A" => Ok(Selected::SlotA),
            "SLOT-B" => Ok(Selected::SlotB),
            _ => Err(ControllerError::UnexpectedResponse),
        }
    }
    /// Worker-only graph check. A ready controller is not tunnel readiness.
    pub fn check_worker_graph(&self) -> Result<(), ControllerError> {
        #[derive(Deserialize)]
        struct Group {
            #[serde(rename = "type")]
            kind: String,
            now: String,
            all: Vec<String>,
        }
        let result: Group = self.get("/proxies/OUT")?;
        if result.kind != "Selector" || result.now != "MULLVAD" || result.all != ["MULLVAD"] {
            return Err(ControllerError::UnexpectedResponse);
        }
        Ok(())
    }
    /// One mutation, never automatically reconciled/retried here. Any ambiguous
    /// transport/status outcome requires the owner to query selected() under its
    /// current generation/epoch before deciding whether to retry or roll back.
    pub fn select(&self, choice: Selected) -> Result<(), ControllerError> {
        let body = format!("{{\"name\":\"{}\"}}", choice.name());
        let started = Instant::now();
        let response = self
            .agent
            .put(format!("{}/proxies/OUT", self.base))
            .header("Authorization", self.authorization()?)
            .header("Connection", "close")
            .header("Content-Type", "application/json")
            .send(body.as_bytes())
            .map_err(|_| ControllerError::OutcomeUnknown)?;
        if started.elapsed() >= REQUEST_LIMIT {
            return Err(ControllerError::OutcomeUnknown);
        }
        match response.status().as_u16() {
            204 => Ok(()),
            401 | 403 => Err(ControllerError::Unauthorized),
            400 | 404 => Err(ControllerError::UnexpectedResponse),
            _ => Err(ControllerError::OutcomeUnknown),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::TcpListener,
        sync::atomic::{AtomicUsize, Ordering},
        thread,
    };
    const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    struct Permit(Arc<AtomicUsize>);
    impl PeerVerifier for Permit {
        fn verify(&self, _: &TcpStream) -> io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    struct Deny;
    impl PeerVerifier for Deny {
        fn verify(&self, _: &TcpStream) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "not owned"))
        }
    }
    fn request(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut out = vec![];
        let mut b = [0u8];
        while out.len() < 8192 && !out.ends_with(b"\r\n\r\n") {
            match stream.read(&mut b) {
                Ok(0) => break,
                Ok(_) => out.push(b[0]),
                Err(_) => break,
            }
        }
        out
    }
    fn accept_bounded(listener: &TcpListener) -> TcpStream {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_write_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    return stream;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "accept timeout");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("fixture accept: {e}"),
            }
        }
    }
    fn fixture(response: Vec<u8>) -> (u16, thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let join = thread::spawn(move || {
            let mut stream = accept_bounded(&listener);
            let bytes = request(&mut stream);
            if !response.is_empty() {
                let _ = stream.write_all(&response);
            }
            bytes
        });
        (port, join)
    }
    fn json_response(body: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).into_bytes()
    }
    fn permitted(port: u16) -> (Controller, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Controller::new_verified(port, SECRET, Arc::new(Permit(calls.clone()))).unwrap(),
            calls,
        )
    }
    #[test]
    fn worker_graph_accepts_only_the_single_mullvad_choice() {
        for (body, valid) in [
            (
                r#"{"type":"Selector","now":"MULLVAD","all":["MULLVAD"]}"#,
                true,
            ),
            (
                r#"{"type":"Selector","now":"DIRECT","all":["MULLVAD"]}"#,
                false,
            ),
            (
                r#"{"type":"Selector","now":"MULLVAD","all":["MULLVAD","DIRECT"]}"#,
                false,
            ),
            (
                r#"{"type":"Selector","now":"MULLVAD","all":["MULLVAD","MULLVAD"]}"#,
                false,
            ),
            (
                r#"{"type":"Fallback","now":"MULLVAD","all":["MULLVAD"]}"#,
                false,
            ),
        ] {
            let (port, join) = fixture(json_response(body));
            let (client, _) = permitted(port);
            assert_eq!(client.check_worker_graph().is_ok(), valid);
            let request = String::from_utf8(join.join().unwrap()).unwrap();
            assert!(request.starts_with("GET /proxies/OUT HTTP/1.1"));
        }
    }
    #[test]
    fn authorization_is_sent_only_after_peer_verification_and_is_sensitive() {
        let (port, join) = fixture(json_response("{\"version\":\"v1.19.31\"}"));
        let (client, calls) = permitted(port);
        client.check_version().unwrap();
        let request = String::from_utf8(join.join().unwrap()).unwrap();
        assert!(request.starts_with("GET /version HTTP/1.1"));
        assert!(request
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {SECRET}")));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(client.authorization().unwrap().is_sensitive());
        assert!(!format!("{:?}", client.authorization().unwrap()).contains(SECRET));
    }
    #[test]
    fn rejected_peer_receives_no_http_or_capability_bytes() {
        let (port, join) = fixture(vec![]);
        let client = Controller::new_verified(port, SECRET, Arc::new(Deny)).unwrap();
        assert_eq!(client.check_version(), Err(ControllerError::Unavailable));
        assert!(join.join().unwrap().is_empty());
    }
    #[test]
    fn redirects_and_unauthorized_responses_are_not_followed_or_echoed() {
        for (response,expected) in [(b"HTTP/1.1 302 Found\r\nLocation: https://example.com/\r\nContent-Length: 0\r\n\r\n".to_vec(),ControllerError::UnexpectedResponse),(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n".to_vec(),ControllerError::Unauthorized)] {let(port,join)=fixture(response);let(client,calls)=permitted(port);assert_eq!(client.check_version(),Err(expected));join.join().unwrap();assert_eq!(calls.load(Ordering::SeqCst),1);}
    }
    #[test]
    fn oversize_or_wrong_version_and_selection_fail_closed() {
        for body in [
            "{\"version\":\"unexpected\"}".to_owned(),
            format!("{{\"version\":\"{}\"}}", "x".repeat(17000)),
        ] {
            let (port, join) = fixture(json_response(&body));
            let (client, _) = permitted(port);
            assert_eq!(
                client.check_version(),
                Err(ControllerError::UnexpectedResponse)
            );
            join.join().unwrap();
        }
        let (port, join) = fixture(json_response(
            "{\"type\":\"Selector\",\"now\":\"DIRECT\",\"all\":[\"REJECT\",\"SLOT-A\",\"SLOT-B\"]}",
        ));
        let (client, _) = permitted(port);
        assert_eq!(client.selected(), Err(ControllerError::UnexpectedResponse));
        join.join().unwrap();
    }
    #[test]
    fn valid_selection_decodes_and_mutation_response_loss_is_unknown() {
        let (port, join) = fixture(json_response(
            "{\"type\":\"Selector\",\"now\":\"SLOT-A\",\"all\":[\"SLOT-B\",\"REJECT\",\"SLOT-A\"]}",
        ));
        let (client, _) = permitted(port);
        assert_eq!(client.selected(), Ok(Selected::SlotA));
        join.join().unwrap();
        let (port, join) = fixture(vec![]);
        let (client, calls) = permitted(port);
        assert_eq!(
            client.select(Selected::SlotB),
            Err(ControllerError::OutcomeUnknown)
        );
        let request = join.join().unwrap();
        assert!(request.starts_with(b"PUT /proxies/OUT HTTP/1.1"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn successful_select_and_invalid_secret_have_explicit_results() {
        let (port, join) =
            fixture(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_vec());
        let (client, _) = permitted(port);
        assert_eq!(client.select(Selected::Reject), Ok(()));
        join.join().unwrap();
        assert!(Controller::new_verified(port, "invalid", Arc::new(Deny)).is_err());
    }
    #[test]
    fn slow_peer_verification_never_leaks_headers_after_connect_budget() {
        struct Slow;
        impl PeerVerifier for Slow {
            fn verify(&self, _: &TcpStream) -> io::Result<()> {
                thread::sleep(Duration::from_millis(600));
                Ok(())
            }
        }
        let (port, join) = fixture(vec![]);
        let client = Controller::new_verified(port, SECRET, Arc::new(Slow)).unwrap();
        assert_eq!(client.check_version(), Err(ControllerError::Unavailable));
        assert!(join.join().unwrap().is_empty());
    }
    #[test]
    fn truncated_and_stalled_bodies_are_bounded_failures() {
        let (port, join) = fixture(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}".to_vec());
        let (client, _) = permitted(port);
        assert_eq!(
            client.check_version(),
            Err(ControllerError::UnexpectedResponse)
        );
        join.join().unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let join = thread::spawn(move || {
            let mut stream = accept_bounded(&listener);
            request(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
                .unwrap();
            thread::sleep(Duration::from_secs(3));
        });
        let (client, _) = permitted(port);
        let start = Instant::now();
        assert!(client.check_version().is_err());
        // 500ms is scheduling allowance on shared CI runners, not a transport budget.
        assert!(start.elapsed() < REQUEST_LIMIT + Duration::from_millis(500));
        join.join().unwrap();
    }
    #[test]
    fn segmented_slow_body_does_not_reset_total_request_deadline() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let join = thread::spawn(move || {
            let mut stream = accept_bounded(&listener);
            request(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10000\r\n\r\n")
                .unwrap();
            for _ in 0..10 {
                thread::sleep(Duration::from_millis(400));
                if stream.write_all(b" ").is_err() {
                    break;
                }
            }
        });
        let (client, _) = permitted(port);
        let start = Instant::now();
        assert!(client.check_version().is_err());
        // Data arrives within every per-read timeout; only a total deadline ends this early.
        assert!(start.elapsed() < REQUEST_LIMIT + Duration::from_millis(500));
        join.join().unwrap();
    }
    #[cfg(any(windows, feature = "windows-api-check"))]
    #[test]
    #[ignore = "child-only HTTP ownership fixture"]
    fn fixture_owned_http() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        std::fs::write(
            "http-port.txt",
            listener.local_addr().unwrap().port().to_string(),
        )
        .unwrap();
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let bytes = request(&mut stream);
            if bytes.is_empty() {
                continue;
            }
            let text = String::from_utf8(bytes).unwrap().to_ascii_lowercase();
            assert!(text.contains(&format!("authorization: bearer {SECRET}")));
            stream
                .write_all(&json_response("{\"version\":\"v1.19.31\"}"))
                .unwrap();
        }
    }
    #[cfg(any(windows, feature = "windows-api-check"))]
    #[test]
    fn windows_owned_peer_factory_sends_only_to_the_selected_live_process() {
        use adapter_platform::{windows::boot_id, windows_process::OwnedProcess};
        struct Temp(std::path::PathBuf);
        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        fn start() -> (Temp, OwnedProcess, u16) {
            let temp = Temp(
                std::env::temp_dir().join(format!("adapter-http-owner-{}", boot_id().unwrap())),
            );
            std::fs::create_dir(&temp.0).unwrap();
            let process = OwnedProcess::spawn(
                &std::env::current_exe().unwrap(),
                &[
                    "--exact".into(),
                    "controller::tests::fixture_owned_http".into(),
                    "--ignored".into(),
                ],
                &temp.0,
            )
            .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let port = loop {
                if let Ok(s) = std::fs::read_to_string(temp.0.join("http-port.txt")) {
                    if let Ok(port) = s.parse() {
                        break port;
                    }
                }
                assert!(Instant::now() < deadline, "HTTP fixture startup timeout");
                thread::sleep(Duration::from_millis(10));
            };
            (temp, process, port)
        }
        let (_a, owned, port) = start();
        let (_b, unrelated, _) = start();
        let wrong = Controller::for_process(&unrelated, port, SECRET).unwrap();
        assert_eq!(wrong.check_version(), Err(ControllerError::Unavailable));
        let right = Controller::for_process(&owned, port, SECRET).unwrap();
        right.check_version().unwrap();
        owned.terminate(Duration::from_secs(2)).unwrap();
        assert_eq!(right.check_version(), Err(ControllerError::Unavailable));
        unrelated.terminate(Duration::from_secs(2)).unwrap();
    }
}
