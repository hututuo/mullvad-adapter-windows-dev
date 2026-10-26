use super::*;
use crate::{read_frame, MAX_FRAME};
use std::io::{Cursor, Write};

const BOOT: &str = "boot-fixture-1";
const SOURCE: &str = "0123456789abcdef0123456789abcdef01234567";
const BUILD: &str = "0.1.0-fixture";

#[test]
fn chain_preparation_is_superseded_by_explicit_intent_and_legacy_config_remains_valid() {
    for command in [
        AppCommand::Disconnect,
        AppCommand::CancelOperation,
        AppCommand::ConnectRelay {
            hostname: "xx-relay-1".into(),
        },
        AppCommand::RestoreVerifiedChain {
            expected_revision: None,
        },
    ] {
        assert!(command.supersedes_chain_preparation());
    }
    let legacy: AppCommand =
        serde_json::from_str(r#"{"kind":"configure_chain","proxy":"fixture"}"#).unwrap();
    assert!(legacy.supersedes_chain_preparation());
    assert!(!AppCommand::ConfigureChain {
        proxy: SecretText::new("fixture".into()),
        preparation: Some("ticket".into()),
        expected_revision: None
    }
    .supersedes_chain_preparation());
    assert!(!AppCommand::Dashboard.supersedes_chain_preparation());
}

fn dashboard(sequence: u64, status: &str) -> Dashboard {
    Dashboard {
        status_observation: None,
        sequence,
        boot_id: BOOT.into(),
        build: BUILD.into(),
        source_sha: SOURCE.into(),
        status: status.into(),
        physical_attachment: "available".into(),
        settings: Settings::default(),
        front_ready: true,
        front_selected: "fixture-front".into(),
        identity_configured: false,
        device_draft: None,
        device_name: None,
        public_key: None,
        active_relay: None,
        connection: None,
        readiness: Some("ready".into()),
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
        logs_path: "fixture-public-log-path".into(),
        last_report_path: None,
        logging_degraded: false,
        logging_dropped: 0,
        quick_test: None,
        city_candidates: vec![],
    }
}

fn request(command: AppCommand) -> AppRequest {
    AppRequest {
        major: APP_API_MAJOR,
        boot_id: BOOT.into(),
        request_id: "request-fixture-1".into(),
        command,
    }
}

fn response(
    publication: &StatusPublication,
    request: &AppRequest,
    now: Instant,
) -> (StatusReply, Vec<u8>) {
    let mut bytes = Vec::new();
    publication.respond(request, BOOT, now, &mut bytes).unwrap();
    let reply = read_frame(&mut Cursor::new(&bytes)).unwrap();
    (reply, bytes)
}

fn error_code(reply: StatusReply) -> String {
    match reply {
        StatusReply::Error { code } => code,
        StatusReply::Snapshot { .. } => panic!("expected a status error"),
    }
}

fn error_for(publication: &StatusPublication, request: &AppRequest, now: Instant) -> String {
    error_code(response(publication, request, now).0)
}

#[test]
fn missing_snapshot_is_unavailable_and_fresh_publication_can_be_refreshed() {
    let publication = StatusPublication::default();
    let request = request(AppCommand::Dashboard);
    let captured = Instant::now();
    assert_eq!(
        error_for(&publication, &request, captured),
        "status_snapshot_unavailable"
    );

    publication
        .publish(&dashboard(1, "first"), captured)
        .unwrap();
    let (reply, bytes) = response(&publication, &request, captured + Duration::from_secs(2));
    assert!(u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize <= MAX_FRAME);
    match reply {
        StatusReply::Snapshot {
            age_ms,
            dashboard: value,
            ..
        } => {
            assert_eq!(age_ms, 2_000);
            assert_eq!(value.sequence, 1);
            assert_eq!(value.status, "first");
        }
        StatusReply::Error { code } => panic!("unexpected error: {code}"),
    }

    let refreshed = Instant::now();
    publication
        .publish(&dashboard(2, "refreshed"), refreshed)
        .unwrap();
    let (reply, _) = response(
        &publication,
        &request,
        refreshed + Duration::from_millis(500),
    );
    match reply {
        StatusReply::Snapshot {
            age_ms,
            dashboard: value,
            ..
        } => {
            assert_eq!(age_ms, 500);
            assert_eq!(value.sequence, 2);
            assert_eq!(value.status, "refreshed");
        }
        StatusReply::Error { code } => panic!("unexpected error: {code}"),
    }
}

#[test]
fn snapshots_are_accepted_at_three_seconds_and_rejected_afterward() {
    let publication = StatusPublication::default();
    let captured = Instant::now();
    publication
        .publish(&dashboard(1, "fresh"), captured)
        .unwrap();
    let request = request(AppCommand::Dashboard);

    let (reply, _) = response(&publication, &request, captured + Duration::from_secs(3));
    assert!(matches!(reply, StatusReply::Snapshot { age_ms: 3_000, .. }));
    assert_eq!(
        error_for(
            &publication,
            &request,
            captured + Duration::from_millis(3_001)
        ),
        "status_snapshot_stale"
    );
}

#[test]
fn busy_cache_lock_returns_prompt_error() {
    let publication = StatusPublication::default();
    let request = request(AppCommand::Dashboard);
    let guard = publication.0.write().unwrap();
    let started = Instant::now();
    let code = error_for(&publication, &request, started);
    let elapsed = started.elapsed();
    drop(guard);

    assert_eq!(code, "status_read_busy");
    assert!(elapsed < Duration::from_millis(100));
}

struct CacheCheckingWriter<'a> {
    publication: &'a StatusPublication,
    bytes: Vec<u8>,
    cache_unlocked_on_write: Option<bool>,
}

impl Write for CacheCheckingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.cache_unlocked_on_write.is_none() {
            self.cache_unlocked_on_write = Some(self.publication.0.try_write().is_ok());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn response_writer_runs_after_cache_read_lock_is_released() {
    let publication = StatusPublication::default();
    let captured = Instant::now();
    publication
        .publish(&dashboard(1, "fresh"), captured)
        .unwrap();
    let mut writer = CacheCheckingWriter {
        publication: &publication,
        bytes: Vec::new(),
        cache_unlocked_on_write: None,
    };

    publication
        .respond(
            &request(AppCommand::Dashboard),
            BOOT,
            captured + Duration::from_millis(10),
            &mut writer,
        )
        .unwrap();

    assert_eq!(writer.cache_unlocked_on_write, Some(true));
    assert!(matches!(
        read_frame::<StatusReply>(&mut Cursor::new(writer.bytes)).unwrap(),
        StatusReply::Snapshot { .. }
    ));
}

#[test]
fn failed_publication_does_not_refresh_the_cached_age() {
    let publication = StatusPublication::default();
    let captured = Instant::now();
    publication.publish(&dashboard(1, "old"), captured).unwrap();
    let guard = publication.0.write().unwrap();
    assert_eq!(
        publication.publish(&dashboard(2, "rejected"), captured + Duration::from_secs(2)),
        Err("status_read_busy")
    );
    drop(guard);

    let reply = response(
        &publication,
        &request(AppCommand::Dashboard),
        captured + Duration::from_millis(3_001),
    )
    .0;
    assert_eq!(error_code(reply), "status_snapshot_stale");
}

#[test]
fn publication_rejects_oversize_frames_without_replacing_the_cache() {
    let publication = StatusPublication::default();
    let captured = Instant::now();
    publication
        .publish(&dashboard(1, "retained"), captured)
        .unwrap();
    let mut oversized = dashboard(2, "oversized");
    oversized.logs_path = "x".repeat(MAX_FRAME);

    assert_eq!(
        publication.publish(&oversized, captured + Duration::from_millis(1)),
        Err("status_response_invalid")
    );
    match response(
        &publication,
        &request(AppCommand::Dashboard),
        captured + Duration::from_millis(10),
    )
    .0
    {
        StatusReply::Snapshot {
            dashboard: value, ..
        } => {
            assert_eq!(value.sequence, 1);
            assert_eq!(value.status, "retained");
        }
        StatusReply::Error { code } => panic!("unexpected error: {code}"),
    }
}

#[test]
fn status_reader_rejects_every_non_dashboard_command_including_private_key_access() {
    let publication = StatusPublication::default();
    let captured = Instant::now();
    publication
        .publish(&dashboard(1, "fixture"), captured)
        .unwrap();
    let commands = [
        AppCommand::SaveSettings {
            settings: Settings::default(),
        },
        AppCommand::RefreshCatalogue,
        AppCommand::BeginChainPreparation,
        AppCommand::ConfigureChain {
            proxy: SecretText::new("fixture-secret".into()),
            preparation: None,
            expected_revision: None,
        },
        AppCommand::RestoreVerifiedChain {
            expected_revision: None,
        },
        AppCommand::Relays {
            city: None,
            page: 0,
        },
        AppCommand::SelectCity {
            city: "us-sjc".into(),
        },
        AppCommand::Connect,
        AppCommand::ConnectRelay {
            hostname: "us-sjc-wg-001".into(),
        },
        AppCommand::RecoveryAction {
            action: RecoveryAction::RetryCurrent,
        },
        AppCommand::Disconnect,
        AppCommand::CancelOperation,
        AppCommand::QuickTest {
            city: "us-sjc".into(),
        },
        AppCommand::FullTest {
            city: "us-sjc".into(),
        },
        AppCommand::AccountLogin {
            account: SecretText::new("fixture-secret".into()),
        },
        AppCommand::AccountRefresh,
        AppCommand::AccountLogout,
        AppCommand::RemoveDevice {
            device_id: "fixture-device".into(),
        },
        AppCommand::CreateDevice { confirm: true },
        AppCommand::UseCreatedDevice { confirm: true },
        AppCommand::RevealKey { confirm: true },
        AppCommand::RedeemVoucher {
            voucher: SecretText::new("fixture-secret".into()),
        },
        AppCommand::ExportReport,
        AppCommand::Shutdown,
    ];

    for command in commands {
        assert_eq!(
            error_for(&publication, &request(command), captured),
            "status_read_only"
        );
    }
}

#[test]
fn request_fences_reject_wrong_boot_major_and_request_id() {
    let publication = StatusPublication::default();
    let captured = Instant::now();
    publication
        .publish(&dashboard(1, "fixture"), captured)
        .unwrap();

    let mut bad_boot = request(AppCommand::Dashboard);
    bad_boot.boot_id = "other-boot".into();
    assert_eq!(
        error_for(&publication, &bad_boot, captured),
        "boot_changed_reconcile"
    );

    let mut bad_major = request(AppCommand::Dashboard);
    bad_major.major = APP_API_MAJOR + 1;
    assert_eq!(
        error_for(&publication, &bad_major, captured),
        "incompatible_protocol"
    );

    let mut bad_request_id = request(AppCommand::Dashboard);
    bad_request_id.request_id = "private\nvalue".into();
    assert_eq!(
        error_for(&publication, &bad_request_id, captured),
        "invalid_request_id"
    );
}

fn snapshot(dashboard: Dashboard, age_ms: u64, capture_ms: u64) -> StatusReply {
    StatusReply::Snapshot {
        age_ms,
        capture_ms,
        dashboard: Box::new(dashboard),
    }
}

#[test]
fn client_rejects_identity_mismatch_stale_delivery_and_invalid_capture_age() {
    let valid = snapshot(dashboard(1, "fixture"), 1_000, 500);
    let received = valid
        .into_dashboard(BOOT, SOURCE, BUILD, Duration::from_millis(500))
        .unwrap();
    let observation = received.status_observation.unwrap();
    assert_eq!(observation.age_ms, 1_500);
    assert_eq!(observation.capture_ms, 500);

    assert_eq!(
        snapshot(dashboard(1, "fixture"), 1_000, 500)
            .into_dashboard("other-boot", SOURCE, BUILD, Duration::ZERO)
            .unwrap_err(),
        "status_identity_mismatch"
    );
    assert_eq!(
        snapshot(dashboard(1, "fixture"), 1_000, 500)
            .into_dashboard(
                BOOT,
                "ffffffffffffffffffffffffffffffffffffffff",
                BUILD,
                Duration::ZERO,
            )
            .unwrap_err(),
        "status_identity_mismatch"
    );
    assert_eq!(
        snapshot(dashboard(1, "fixture"), 1_000, 500)
            .into_dashboard(BOOT, SOURCE, "other-build", Duration::ZERO)
            .unwrap_err(),
        "status_identity_mismatch"
    );
    assert_eq!(
        snapshot(dashboard(1, "fixture"), 2_900, 500)
            .into_dashboard(BOOT, SOURCE, BUILD, Duration::from_millis(101))
            .unwrap_err(),
        "status_snapshot_stale"
    );
    assert_eq!(
        snapshot(dashboard(1, "fixture"), 1_000, 1_001)
            .into_dashboard(BOOT, SOURCE, BUILD, Duration::ZERO)
            .unwrap_err(),
        "status_snapshot_stale"
    );
}

#[test]
fn unknown_error_codes_are_collapsed_without_echoing_private_text() {
    let private = "private-key=fixture-never-echo";
    let result = StatusReply::Error {
        code: private.into(),
    }
    .into_dashboard(BOOT, SOURCE, BUILD, Duration::ZERO);

    let error = result.unwrap_err();
    assert_eq!(error, "status_response_invalid");
    assert!(!error.contains(private));
}
