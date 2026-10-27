use super::*;
use adapter_platform::windows::{boot_id, Identity, Pipe};
use adapter_protocol::{
    app::{Account, AppCommand, AppReply, AppRequest, Dashboard, Settings, APP_API_MAJOR},
    app_status::StatusReply,
    ResponseAck,
};
use std::{
    io::{self, Read, Write},
    sync::mpsc::{self, SyncSender},
    thread::JoinHandle,
};

const FALLBACK_SOURCE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn fixture_dashboard(boot: &str, source_sha: &str, build: &str, sequence: u64) -> Dashboard {
    Dashboard {
        status_observation: None,
        sequence,
        boot_id: boot.into(),
        build: build.into(),
        source_sha: source_sha.into(),
        status: format!("fixture-public-{sequence}"),
        physical_attachment: "fixture-available".into(),
        settings: Settings::default(),
        quic_available: false,
        front_ready: true,
        front_selected: "fixture-front".into(),
        identity_configured: false,
        device_draft: None,
        device_name: None,
        public_key: None,
        active_relay: None,
        connection: None,
        readiness: Some("fixture-ready".into()),
        cities: vec![],
        metadata_source: "fixture".into(),
        metadata_updated_at: None,
        metadata_refreshing: false,
        metadata_error: None,
        metadata_cache_error: None,
        metadata_changes: None,
        chain_node: None,
        chain_fingerprint: None,
        chain_revision: 0,
        retry_in_seconds: None,
        recovery: None,
        backup_verified_at: None,
        backup_test_id: 0,
        backup_test_status: None,
        backup_test_restored: false,
        account: Account::default(),
        operation: None,
        last_error: None,
        logs_path: "fixture-only-public-path".into(),
        last_report_path: None,
        logging_degraded: false,
        logging_dropped: 0,
        quick_test: None,
        city_candidates: vec![],
    }
}

fn valid_source_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn verify_hello(hello: &AppReply, expected_boot: &str) -> Result<(), String> {
    let (major, boot, build, source) = match hello {
        AppReply::Hello {
            major,
            boot_id,
            build,
            source_sha,
        } => (
            *major,
            boot_id.as_str(),
            build.as_str(),
            source_sha.as_str(),
        ),
        _ => return Err("status endpoint did not send Hello".into()),
    };

    if major != APP_API_MAJOR {
        return Err("status Hello major did not match".into());
    }
    if boot != expected_boot {
        return Err("status Hello boot id did not match".into());
    }
    if build != env!("CARGO_PKG_VERSION") {
        return Err("status Hello build did not match this package".into());
    }
    if source != option_env!("ADAPTER_SOURCE_SHA").unwrap_or("unknown") {
        return Err("status Hello source pin did not match the build environment".into());
    }

    match option_env!("ADAPTER_SOURCE_SHA") {
        Some(expected_source) if valid_source_sha(expected_source) => {
            let verified = hello
                .verified_boot_id(expected_source, env!("CARGO_PKG_VERSION"))
                .map_err(|_| "pinned Hello verification failed".to_owned())?;
            if verified != expected_boot {
                return Err("verified status Hello boot id did not match".into());
            }
        }
        _ => {
            // A missing or malformed compile-time pin must fail closed. The
            // already checked Hello fields still let this test exercise the
            // read-only wire protocol, without claiming source verification.
            if hello.verified_boot_id(FALLBACK_SOURCE_SHA, env!("CARGO_PKG_VERSION"))
                != Err("backend_version_mismatch")
            {
                return Err("unpinned Hello unexpectedly passed source verification".into());
            }
        }
    }
    Ok(())
}

fn status_exchange(
    identity: &Identity,
    expected_boot: &str,
    request_id: &str,
    command: AppCommand,
) -> Result<StatusReply, String> {
    let status_identity = identity.status_channel();
    let mut pipe = Pipe::connect(&status_identity, Duration::from_secs(3))
        .map_err(|_| "status pipe connection failed".to_owned())?;
    let hello: AppReply = read_frame(&mut pipe)
        .map_err(|_| "status Hello frame was invalid or unavailable".to_owned())?;
    verify_hello(&hello, expected_boot)?;

    let request = AppRequest {
        major: APP_API_MAJOR,
        boot_id: expected_boot.into(),
        request_id: request_id.into(),
        command,
    };
    write_frame(&mut pipe, &request).map_err(|_| "status request write failed".to_owned())?;
    let reply: StatusReply = read_frame(&mut pipe)
        .map_err(|_| "status reply frame was invalid or unavailable".to_owned())?;
    write_frame(
        &mut pipe,
        &ResponseAck {
            request_id: request.request_id,
        },
    )
    .map_err(|_| "status response acknowledgement failed".to_owned())?;
    Ok(reply)
}

fn expect_snapshot(
    reply: StatusReply,
    boot: &str,
    source: &str,
    build: &str,
    sequence: u64,
) -> Result<(), String> {
    let dashboard = reply
        .into_dashboard(boot, source, build, Duration::ZERO)
        .map_err(|code| format!("snapshot conversion failed: {code}"))?;
    if dashboard.sequence != sequence {
        return Err("snapshot sequence did not match publication".into());
    }
    if dashboard.status != format!("fixture-public-{sequence}") {
        return Err("snapshot status did not match its public fixture".into());
    }
    let observation = dashboard
        .status_observation
        .ok_or_else(|| "snapshot age observation was missing".to_owned())?;
    if observation.capture_ms > observation.age_ms {
        return Err("snapshot capture age exceeded its reported age".into());
    }
    Ok(())
}

struct HeldControlPipe {
    release: SyncSender<()>,
    client: Option<Pipe>,
    server: Option<JoinHandle<io::Result<()>>>,
}

impl HeldControlPipe {
    fn start(identity: &Identity) -> Result<Self, String> {
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let server_identity = identity.clone();
        let server = std::thread::spawn(move || -> io::Result<()> {
            let mut pipe = Pipe::accept(&server_identity, Duration::from_secs(3))?;
            let mut request = [0; 4];
            pipe.read_exact(&mut request)?;
            if &request != b"hold" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "control_hold_request_invalid",
                ));
            }
            ready_tx
                .send(())
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "control_hold_ready"))?;
            release_rx
                .recv_timeout(Duration::from_secs(8))
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "control_hold_release"))?;
            pipe.write_all(b"done")?;
            let mut ack = [0];
            pipe.read_exact(&mut ack)?;
            if ack != [1] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "control_hold_ack_invalid",
                ));
            }
            Ok(())
        });
        let mut held = Self {
            release: release_tx,
            client: None,
            server: Some(server),
        };
        let mut client = Pipe::connect(identity, Duration::from_secs(3))
            .map_err(|_| "control hold connection failed".to_owned())?;
        client
            .write_all(b"hold")
            .map_err(|_| "control hold request failed".to_owned())?;
        ready_rx
            .recv_timeout(Duration::from_secs(3))
            .map_err(|_| "control hold server did not become ready".to_owned())?;
        held.client = Some(client);
        Ok(held)
    }

    fn finish(mut self) -> Result<(), String> {
        self.release
            .send(())
            .map_err(|_| "control hold server did not accept release".to_owned())?;
        let mut client = self
            .client
            .take()
            .ok_or_else(|| "control hold client was missing".to_owned())?;
        let mut reply = [0; 4];
        client
            .read_exact(&mut reply)
            .map_err(|_| "control hold reply failed".to_owned())?;
        if &reply != b"done" {
            return Err("control hold reply did not match".into());
        }
        client
            .write_all(&[1])
            .map_err(|_| "control hold acknowledgement failed".to_owned())?;
        drop(client);
        let result = self
            .server
            .take()
            .ok_or_else(|| "control hold server was missing".to_owned())?
            .join()
            .map_err(|_| "control hold server thread panicked".to_owned())?;
        result.map_err(|_| "control hold server exchange failed".to_owned())
    }
}

impl Drop for HeldControlPipe {
    fn drop(&mut self) {
        let _ = self.release.send(());
        self.client.take();
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
    }
}

struct StatusServerGuard(Option<StatusServer>);

impl StatusServerGuard {
    fn stop(&mut self) {
        if let Some(server) = self.0.take() {
            server.stop_for_test();
        }
    }
}

impl Drop for StatusServerGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

#[test]
fn production_status_pipe_is_independent_read_only_and_refreshes_stale_cache() -> Result<(), String>
{
    let boot = boot_id().expect("test boot id");
    let scope = format!("StatusPipeTest-{boot}");
    let identity = Identity::current()
        .expect("current user identity")
        .with_scope(&scope)
        .expect("unique test identity");
    let build = env!("CARGO_PKG_VERSION");
    let source = option_env!("ADAPTER_SOURCE_SHA").unwrap_or("unknown");
    let publication = StatusPublication::default();
    publication
        .publish(
            &fixture_dashboard(&boot, source, build, 101),
            Instant::now(),
        )
        .expect("publish initial public fixture");
    let server = StatusServer::start(&identity, boot.clone(), publication.clone())
        .expect("start independent status server");
    let mut server = StatusServerGuard(Some(server));

    // Keep a real control-scope connection open while the production status
    // endpoint completes a separate authenticated request.
    let held_control = HeldControlPipe::start(&identity).expect("hold control pipe open");
    let initial_result = status_exchange(&identity, &boot, "status-initial", AppCommand::Dashboard);
    let control_result = held_control.finish();
    let initial = initial_result.expect("status exchange during control connection");
    control_result.expect("control connection remains usable after status exchange");
    expect_snapshot(initial, &boot, source, build, 101).expect("initial public snapshot");

    // A deliberately old publication is rejected by the production pipe;
    // replacing it with a fresh sequence restores reads without a restart.
    publication
        .publish(
            &fixture_dashboard(&boot, source, build, 102),
            Instant::now() - Duration::from_secs(4),
        )
        .expect("publish deliberately stale public fixture");
    match status_exchange(&identity, &boot, "status-stale", AppCommand::Dashboard)
        .expect("read stale snapshot result")
    {
        StatusReply::Error { code } if code == "status_snapshot_stale" => {}
        StatusReply::Error { .. } => return Err("stale snapshot returned the wrong error".into()),
        StatusReply::Snapshot { .. } => return Err("stale snapshot was served".into()),
    }

    publication
        .publish(
            &fixture_dashboard(&boot, source, build, 103),
            Instant::now(),
        )
        .expect("publish fresh public fixture");
    let fresh = status_exchange(&identity, &boot, "status-refreshed", AppCommand::Dashboard)
        .expect("read refreshed snapshot");
    expect_snapshot(fresh, &boot, source, build, 103).expect("refreshed public snapshot");

    for (request_id, command) in [
        ("status-reveal-key", AppCommand::RevealKey { confirm: true }),
        ("status-connect", AppCommand::Connect),
    ] {
        match status_exchange(&identity, &boot, request_id, command)
            .expect("read-only command result")
        {
            StatusReply::Error { code } if code == "status_read_only" => {}
            StatusReply::Error { .. } => {
                return Err("read-only command returned the wrong error".into())
            }
            StatusReply::Snapshot { .. } => {
                return Err("read-only command unexpectedly returned a snapshot".into())
            }
        }
    }

    server.stop();
    Ok(())
}
