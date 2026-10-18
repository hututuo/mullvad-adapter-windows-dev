//! Independent Windows application host with separately retained mock transports.
//! Live tunnel selection remains gated until its transaction/egress acceptance.
use adapter_control::MockControl;
use adapter_protocol::{Hello, Response, API_MAJOR, API_MINOR};
#[cfg(any(windows, feature = "windows-api-check"))]
mod live_connection;
mod live_device;
mod live_diagnostics;
mod live_identity;
mod live_quick;
mod live_runtime;
mod live_status;
#[cfg(any(windows, feature = "windows-api-check"))]
mod windows_live;
#[cfg(any(windows, feature = "windows-api-check"))]
mod windows_tunnel_check;
fn main() {
    #[cfg(windows)]
    if matches!(
        std::env::args().nth(1).as_deref(),
        Some("--serve" | "--import-identity-stdin" | "--verify-tunnel" | "--verify-bound-tunnel")
    ) {
        let args: Vec<_> = std::env::args().collect();
        let scope = args
            .windows(2)
            .find(|pair| pair[0] == "--scope")
            .map(|pair| pair[1].as_str())
            .unwrap_or("Windows");
        let result = if matches!(
            args[1].as_str(),
            "--verify-tunnel" | "--verify-bound-tunnel"
        ) {
            let relay = args
                .windows(2)
                .find(|p| p[0] == "--relay")
                .map(|p| p[1].as_str())
                .unwrap_or("");
            let mode = args
                .windows(2)
                .find(|p| p[0] == "--transport")
                .map(|p| p[1].as_str())
                .unwrap_or("ipv4");
            requested_port(&args).and_then(|port| {
                windows_tunnel_check::verify(
                    scope,
                    relay,
                    mode,
                    port,
                    args[1] == "--verify-bound-tunnel",
                )
            })
        } else if args[1] == "--serve" {
            windows_live::serve(scope)
        } else {
            windows_live::import_stdin(scope)
        };
        if let Err(error) = result {
            eprintln!("{}", error);
            std::process::exit(1);
        }
        return;
    }

    #[cfg(windows)]
    if std::env::args().nth(1).as_deref() == Some("--mock-pipe") {
        if let Err(error) = run_windows_mock() {
            eprintln!("mock host failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    if std::env::args().nth(1).as_deref() != Some("--mock-stdio") {
        eprintln!("This development skeleton only supports --mock-stdio; no tunnel or platform IPC is available.");
        std::process::exit(2);
    }
    // The Windows host will supply a cryptographically generated OS UUID at startup.
    let boot = format!(
        "mock-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let mut control = MockControl::new(boot.clone());
    let hello = Response::Hello(Hello {
        major: API_MAJOR,
        minor: API_MINOR,
        boot_id: boot,
        build: env!("CARGO_PKG_VERSION").into(),
        mode: "mock_no_tunnel".into(),
        capabilities: vec!["mock_snapshots".into()],
    });
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    if adapter_protocol::write_frame(&mut output, &hello).is_err() {
        return;
    }
    let start = std::time::Instant::now();
    while let Ok(request) = adapter_protocol::read_frame(&mut input) {
        let response = control.handle(
            request,
            start.elapsed().as_millis().min(u64::MAX as u128) as u64,
        );
        if adapter_protocol::write_frame(&mut output, &response).is_err() {
            break;
        }
    }
}

#[cfg(any(test, windows, feature = "windows-api-check"))]
fn requested_port(args: &[String]) -> std::io::Result<Option<u16>> {
    let positions: Vec<_> = args
        .iter()
        .enumerate()
        .filter(|(_, value)| value.as_str() == "--port")
        .map(|(index, _)| index)
        .collect();
    if positions.len() > 1 {
        return Err(std::io::Error::other("invalid_transport_port"));
    }
    let Some(index) = positions.first() else {
        return Ok(None);
    };
    let port = args
        .get(index + 1)
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| std::io::Error::other("invalid_transport_port"))?;
    Ok(Some(port))
}

#[cfg(test)]
mod tunnel_argument_tests {
    use super::*;
    #[test]
    fn explicit_port_requires_one_nonzero_u16_argument() {
        let args = |values: &[&str]| values.iter().map(|v| v.to_string()).collect::<Vec<_>>();
        assert_eq!(requested_port(&args(&["--verify-tunnel"])).unwrap(), None);
        assert_eq!(
            requested_port(&args(&["--verify-tunnel", "--port", "53"])).unwrap(),
            Some(53)
        );
        for values in [
            &["--port"][..],
            &["--port", "0"],
            &["--port", "65536"],
            &["--port", "--scope"],
            &["--port", "53", "--port", "123"],
        ] {
            assert!(requested_port(&args(values)).is_err());
        }
    }
}

#[cfg(windows)]
fn run_windows_mock() -> std::io::Result<()> {
    use adapter_platform::windows::{boot_id, Identity, Pipe, SingleInstance};
    let mut identity = Identity::current()?;
    let args: Vec<_> = std::env::args().collect();
    if args.get(2).map(String::as_str) == Some("--scope") {
        identity = identity.with_scope(
            args.get(3)
                .ok_or_else(|| std::io::Error::other("missing_scope"))?,
        )?;
    }
    let _instance = SingleInstance::acquire(&identity)?;
    let boot = boot_id()?;
    let hello = Response::Hello(Hello {
        major: API_MAJOR,
        minor: API_MINOR,
        boot_id: boot.clone(),
        build: env!("CARGO_PKG_VERSION").into(),
        mode: "mock_no_tunnel".into(),
        capabilities: vec!["mock_snapshots".into()],
    });
    let mut control = MockControl::new(boot);
    let started = std::time::Instant::now();
    loop {
        let mut pipe = match Pipe::accept(&identity, std::time::Duration::from_secs(1)) {
            Ok(pipe) => pipe,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::PermissionDenied
                        | std::io::ErrorKind::InvalidData
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                continue
            }
            Err(error) => return Err(error),
        };
        if adapter_protocol::write_frame(&mut pipe, &hello).is_err() {
            continue;
        }
        let _ = serve_session(&mut pipe, &mut control, || {
            started.elapsed().as_millis().min(u64::MAX as u128) as u64
        });
    }
}

#[cfg(any(windows, test))]
fn serve_session(
    stream: &mut (impl std::io::Read + std::io::Write),
    control: &mut MockControl,
    now: impl Fn() -> u64,
) -> std::io::Result<()> {
    use adapter_protocol::{read_frame, write_frame, Request, ResponseAck};
    for _ in 0..16 {
        let request: Request = read_frame(stream)?;
        let expected_ack = request.request_id.clone();
        let response = control.handle(request, now());
        write_frame(stream, &response)?;
        let ack: ResponseAck = read_frame(stream)?;
        if ack.request_id != expected_ack {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "response_ack_mismatch",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use adapter_protocol::*;
    struct Stream {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl std::io::Read for Stream {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(b)
        }
    }
    impl std::io::Write for Stream {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn all_sixteen_responses_require_matching_ack_before_session_success() {
        let mut input = Vec::new();
        for i in 0..16 {
            let id = format!("request-{i}");
            write_frame(
                &mut input,
                &Request {
                    major: 1,
                    boot_id: "boot".into(),
                    request_id: id.clone(),
                    command: Command::Snapshot,
                },
            )
            .unwrap();
            if i < 15 {
                write_frame(&mut input, &ResponseAck { request_id: id }).unwrap();
            }
        }
        let mut stream = Stream {
            input: std::io::Cursor::new(input.clone()),
            output: Vec::new(),
        };
        assert!(serve_session(&mut stream, &mut MockControl::new("boot".into()), || 0).is_err());
        write_frame(
            &mut input,
            &ResponseAck {
                request_id: "request-15".into(),
            },
        )
        .unwrap();
        let mut stream = Stream {
            input: std::io::Cursor::new(input),
            output: Vec::new(),
        };
        serve_session(&mut stream, &mut MockControl::new("boot".into()), || 0).unwrap();
        let mut output = std::io::Cursor::new(stream.output);
        for _ in 0..16 {
            assert!(matches!(
                read_frame::<Response>(&mut output).unwrap(),
                Response::Snapshot(_)
            ));
        }
    }
}
