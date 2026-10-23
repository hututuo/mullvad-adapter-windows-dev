//! Bounded allowlisted diagnostics. No keys, accounts, raw engine output or renderer paths.
use adapter_protocol::app::Dashboard;
use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    thread,
};
fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LogEvent {
    time: u64,
    layer: String,
    stage: String,
    code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    connection: Option<adapter_protocol::app::ConnectionInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    quick_test: Option<adapter_protocol::app::QuickTestState>,
}
fn safe_event(value: &LogEvent) -> bool {
    value.connection.as_ref().is_none_or(|c| c.valid())
        && value
            .quick_test
            .as_ref()
            .is_none_or(|q| q.valid() && value.stage == "quick")
        && value.time <= 9_007_199_254_740_991
        && value.layer == "agent"
        && matches!(
            value.stage.as_str(),
            "start" | "front" | "physical" | "api" | "api_access" | "stop" | "quick" | "connection"
        )
        && matches!(
            value.code.as_str(),
            "agent_started"
                | "started"
                | "cancelled"
                | "ready_reject"
                | "stopped"
                | "stopped_uncertain"
                | "available"
                | "unavailable"
                | "unknown"
                | "complete"
                | "agent_stopped"
                | "cleanup_uncertain"
                | "invalid_metadata"
                | "policy_write_failed"
                | "report_write_failed"
                | "metadata_cache_write_failed"
                | "metadata_cache_access_denied"
                | "metadata_cache_read_failed"
                | "metadata_missing"
                | "metadata_refresh_started"
                | "metadata_refresh_complete"
                | "metadata_refresh_unavailable"
                | "account_required"
                | "identity_missing"
                | "current_device_protected"
                | "device_not_found"
                | "outcome_unknown"
                | "invalid_api_command"
                | "invalid_bootstrap_proxy"
                | "invalid_account_number"
                | "invalid_voucher_code"
                | "invalid_device_id"
                | "invalid_public_key"
                | "api_unreachable"
                | "api_proxy_tunnel_failed"
                | "api_tls_failed"
                | "api_deadline_exceeded"
                | "api_response_too_large"
                | "invalid_api_response"
                | "mutation_outcome_unknown"
                | "invalid_account"
                | "invalid_access_token"
                | "invalid_voucher"
                | "voucher_used"
                | "api_rejected"
                | "connected"
                | "disconnected"
                | "probing"
                | "degraded_preserved"
                | "candidate_not_ready"
                | "same_relay_inlet_retry"
                | "same_relay_chain_retry"
                | "chain_not_configured"
                | "chain_configuration_invalid"
                | "chain_write_failed"
                | "chain_verified_missing"
                | "chain_configured"
                | "recovery_retry_scheduled"
                | "recovery_retry_started"
                | "shadowsocks_inlets_exhausted"
                | "candidate_cancelled"
                | "candidate_start_failed"
                | "worker_start_cancelled"
                | "worker_route_unavailable"
                | "worker_chain_resolution_failed"
                | "worker_configuration_rejected"
                | "peer_reservation_unavailable"
                | "worker_start_failed"
                | "worker_controller_unavailable"
                | "worker_start_deadline"
                | "candidate_probe_failed"
                | "candidate_stale"
                | "candidate_evidence_stale"
                | "active_evidence_stale"
                | "candidate_commit_failed"
                | "candidate_commit_stale"
                | "candidate_selection_failed"
                | "connection_cancelled"
                | "tunnel_command_busy"
                | "tunnel_transaction_failed"
                | "active_probe_failed"
                | "active_probe_local_failure"
                | "active_probe_cancelled"
                | "active_binding_changed"
                | "active_local_rebuild"
                | "active_data_failed"
                | "active_failure_confirmation"
                | "active_front_repair_failed"
                | "original_inlet_short_retry"
                | "direct_routes_exhausted_chain_last"
                | "route_trial_failed"
                | "route_trial_failed_restore_previous"
                | "restore_previous_failed_use_verified_backup"
                | "network_binding_changed"
                | "waiting_network_settle"
                | "direct_verified"
                | "independent_proxy_verified"
                | "healthy_tunnel_verified"
                | "cache_write_failed"
                | "active_worker_missing"
                | "binding_changed"
                | "relay_not_active"
                | "original_inlet_withdrawn"
                | "same_city_recovery_exhausted"
                | "recovery_budget_exhausted"
                | "device_creation_outcome_unknown"
                | "device_creation_not_confirmed"
                | "device_draft_invalid"
                | "device_draft_unavailable"
                | "device_draft_write_failed"
                | "device_draft_readback_failed"
                | "device_draft_missing"
                | "device_draft_other_account"
                | "device_not_registered"
                | "public_key_in_use"
                | "identity_backup_occupied"
                | "identity_activation_uncertain"
                | "identity_store_write_failed"
                | "identity_store_read_failed"
                | "identity_store_readback_mismatch"
                | "random_unavailable"
                | "maintenance_started"
                | "maintenance_preempted"
                | "maintenance_complete"
                | "maintenance_cancelled"
        )
}

/// Renderer-safe event projection. It deliberately excludes the raw connection
/// object, which contains the public inlet address and local interface details.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventView {
    pub time: u64,
    pub stage: String,
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<adapter_protocol::app::ProbeOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<adapter_protocol::app::ProbeOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https: Option<adapter_protocol::app::ProbeOutcome>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventPage {
    pub events: Vec<EventView>,
    /// Number of malformed, rejected, or incomplete event rows in the read tail.
    pub skipped: usize,
    /// True when the byte tail or requested event limit omitted older rows.
    pub truncated: bool,
}

const EVENT_TAIL_BYTES: u64 = 512 * 1024;
const EVENT_PAGE_MAX: usize = 500;

fn event_log_error(kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, "event_log_unavailable")
}

fn accept_event_line(
    line: &[u8],
    events: &mut VecDeque<EventView>,
    limit: usize,
    skipped: &mut usize,
    truncated: &mut bool,
) {
    let value = match serde_json::from_slice::<LogEvent>(line) {
        Ok(value) if safe_event(&value) => value,
        _ => {
            *skipped = skipped.saturating_add(1);
            return;
        }
    };
    let connection = value.connection;
    let outcome = |explicit: Option<adapter_protocol::app::ProbeOutcome>,
                   fallback: Option<bool>| {
        explicit.or_else(|| {
            fallback.map(|passed| {
                if passed {
                    adapter_protocol::app::ProbeOutcome::Passed
                } else {
                    adapter_protocol::app::ProbeOutcome::Rejected
                }
            })
        })
    };
    let projected = EventView {
        time: value.time,
        stage: value.stage,
        code: value.code,
        relay: connection.as_ref().map(|c| c.relay.clone()),
        city: connection.as_ref().map(|c| c.city.clone()),
        phase: connection.as_ref().map(|c| c.phase.clone()),
        ip: connection
            .as_ref()
            .and_then(|c| outcome(c.probes.as_ref().map(|p| p.ip), c.ip)),
        dns: connection
            .as_ref()
            .and_then(|c| outcome(c.probes.as_ref().map(|p| p.dns), c.dns)),
        https: connection
            .as_ref()
            .and_then(|c| outcome(c.probes.as_ref().map(|p| p.https), c.https)),
    };
    if events.len() == limit {
        events.pop_front();
        *truncated = true;
    }
    events.push_back(projected);
}

fn collect_event_tail(
    bytes: &[u8],
    starts_mid_line: bool,
    events: &mut VecDeque<EventView>,
    limit: usize,
    skipped: &mut usize,
    truncated: &mut bool,
) {
    let mut cursor = 0;
    if starts_mid_line {
        // The byte cap cut through an older row. Count it and discard through
        // the first newline so only complete rows reach the parser.
        *skipped = skipped.saturating_add(1);
        let Some(newline) = bytes.iter().position(|byte| *byte == b'\n') else {
            return;
        };
        cursor = newline + 1;
    }

    while cursor < bytes.len() {
        let Some(relative_newline) = bytes[cursor..].iter().position(|byte| *byte == b'\n') else {
            // The writer terminates every row. An unterminated tail may be a
            // partial write, so never display it even if its JSON happens to parse.
            *skipped = skipped.saturating_add(1);
            break;
        };
        let end = cursor + relative_newline;
        accept_event_line(&bytes[cursor..end], events, limit, skipped, truncated);
        cursor = end + 1;
    }
}

/// Read a bounded tail of the two fixed event files without creating or
/// changing anything in `root`.
pub fn recent_events(root: &Path, limit: usize) -> io::Result<EventPage> {
    if !(1..=EVENT_PAGE_MAX).contains(&limit) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid_event_limit",
        ));
    }

    let mut events = VecDeque::with_capacity(limit);
    let mut skipped = 0usize;
    let mut truncated = false;
    for name in ["events.previous.jsonl", "events.jsonl"] {
        let path = root.join(name);
        let mut options = OpenOptions::new();
        options.read(true);
        let mut file = match open_log_file(&path, options) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(event_log_error(error.kind())),
        };
        let length = file
            .metadata()
            .map_err(|error| event_log_error(error.kind()))?
            .len();
        let offset = length.saturating_sub(EVENT_TAIL_BYTES);
        let read_length = length - offset;
        if offset > 0 {
            truncated = true;
        }
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| event_log_error(error.kind()))?;
        let mut bytes = Vec::with_capacity(read_length as usize);
        file.take(read_length)
            .read_to_end(&mut bytes)
            .map_err(|error| event_log_error(error.kind()))?;
        collect_event_tail(
            &bytes,
            offset > 0,
            &mut events,
            limit,
            &mut skipped,
            &mut truncated,
        );
    }

    Ok(EventPage {
        events: events.into_iter().collect(),
        skipped,
        truncated,
    })
}

pub(crate) fn open_log_file(path: &std::path::Path, options: OpenOptions) -> io::Result<File> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(io::Error::other("log_file_rejected"));
        }
    }
    #[cfg(windows)]
    let options = {
        use std::os::windows::fs::OpenOptionsExt;
        let mut options = options;
        options.custom_flags(0x0020_0000);
        options
    };
    let file = options.open(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::*;
        let mut info = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0
            || info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
                != 0
            || info.nNumberOfLinks != 1
        {
            return Err(io::Error::other("log_file_rejected"));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if file.metadata()?.nlink() != 1 {
            return Err(io::Error::other("log_file_rejected"));
        }
    }
    Ok(file)
}
pub(crate) fn open_writer_file(
    path: &std::path::Path,
    append: bool,
    exclusive: bool,
) -> io::Result<File> {
    #[cfg(windows)]
    {
        adapter_platform::windows_user_file::open_writer(path, append, exclusive)
    }
    #[cfg(not(windows))]
    {
        let mut options = OpenOptions::new();
        options
            .write(true)
            .append(append)
            .create(!exclusive)
            .create_new(exclusive);
        open_log_file(path, options)
    }
}

// Keep the report export independent from the public Dashboard DTO. That DTO is
// consumed by the renderer and intentionally contains account, device and
// local-path details that must never be copied wholesale into a report.
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum ReportStatusValue {
    StartingFront,
    Disconnected,
    Blocked,
    WaitingNetwork,
    UnknownNetwork,
    NetworkRecovering,
    ConfirmingPath,
    Connecting,
    Disconnecting,
    Connected,
    RetryWait,
}
impl ReportStatusValue {
    fn from_dashboard(value: &str) -> Option<Self> {
        Some(match value {
            "starting_front" => Self::StartingFront,
            "disconnected" => Self::Disconnected,
            "blocked" => Self::Blocked,
            "waiting_network" => Self::WaitingNetwork,
            "unknown_network" => Self::UnknownNetwork,
            "network_recovering" => Self::NetworkRecovering,
            "confirming_path" => Self::ConfirmingPath,
            "connecting" => Self::Connecting,
            "disconnecting" => Self::Disconnecting,
            "connected" => Self::Connected,
            "retry_wait" => Self::RetryWait,
            _ => return None,
        })
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum ReportAttachment {
    Available,
    Unavailable,
    Unknown,
}
impl ReportAttachment {
    fn from_dashboard(value: &str) -> Option<Self> {
        Some(match value {
            "available" => Self::Available,
            "unavailable" => Self::Unavailable,
            "unknown" => Self::Unknown,
            _ => return None,
        })
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum ReportFrontSelection {
    Reject,
    SlotA,
    SlotB,
    Unavailable,
}
impl ReportFrontSelection {
    fn from_dashboard(value: &str) -> Option<Self> {
        Some(match value {
            "reject" => Self::Reject,
            "slot_a" => Self::SlotA,
            "slot_b" => Self::SlotB,
            "unavailable" => Self::Unavailable,
            _ => return None,
        })
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum ReportMetadataSource {
    Missing,
    LocalCache,
    OfficialApi,
}
impl ReportMetadataSource {
    fn from_dashboard(value: &str) -> Option<Self> {
        Some(match value {
            "missing" => Self::Missing,
            "local_cache" => Self::LocalCache,
            "official_api" => Self::OfficialApi,
            _ => return None,
        })
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum ReportReadiness {
    Ready,
    Degraded,
}
impl ReportReadiness {
    fn from_dashboard(value: &str) -> Option<Self> {
        Some(match value {
            "ready" => Self::Ready,
            "degraded" => Self::Degraded,
            _ => return None,
        })
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum ReportConnectionPhase {
    Starting,
    Prepared,
    Connected,
    Health,
    Failed,
    Stopped,
}
impl ReportConnectionPhase {
    fn from_dashboard(value: &str) -> Option<Self> {
        Some(match value {
            "starting" => Self::Starting,
            "prepared" => Self::Prepared,
            "connected" => Self::Connected,
            "health" => Self::Health,
            "failed" => Self::Failed,
            "stopped" => Self::Stopped,
            _ => return None,
        })
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum ReportRecoveryStage {
    WaitingNetwork,
    RestoringPrevious,
    ReturningDirect,
    TestingBackup,
    LocalFront,
    Confirming,
    Exhausted,
    ChainConnected,
    Connected,
    VerifyingOriginal,
    Idle,
    ChainFallback,
    SameCity,
    OriginalInlet,
    SameRelayInlets,
}
impl ReportRecoveryStage {
    fn from_dashboard(value: &str) -> Option<Self> {
        Some(match value {
            "waiting_network" => Self::WaitingNetwork,
            "restoring_previous" => Self::RestoringPrevious,
            "returning_direct" => Self::ReturningDirect,
            "testing_backup" => Self::TestingBackup,
            "local_front" => Self::LocalFront,
            "confirming" => Self::Confirming,
            "exhausted" => Self::Exhausted,
            "chain_connected" => Self::ChainConnected,
            "connected" => Self::Connected,
            "verifying_original" => Self::VerifyingOriginal,
            "idle" => Self::Idle,
            "chain_fallback" => Self::ChainFallback,
            "same_city" => Self::SameCity,
            "original_inlet" => Self::OriginalInlet,
            "same_relay_inlets" => Self::SameRelayInlets,
            _ => return None,
        })
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum ReportBackupTestStatus {
    Passed,
    Failed,
}
impl ReportBackupTestStatus {
    fn from_dashboard(value: &str) -> Option<Self> {
        Some(match value {
            "passed" => Self::Passed,
            "failed" => Self::Failed,
            _ => return None,
        })
    }
}

#[derive(serde::Serialize)]
struct ReportSettings {
    automatic_recovery: bool,
    connect_on_start: bool,
    tunnel_route: adapter_protocol::app::TunnelRoute,
    required_multihop: bool,
    required_pq: bool,
}

#[derive(serde::Serialize)]
struct ReportConnection {
    phase: Option<ReportConnectionPhase>,
    ping: Option<adapter_protocol::app::PingMeasurement>,
    chained: bool,
    ip: Option<bool>,
    dns: Option<bool>,
    https: Option<bool>,
    probes: Option<adapter_protocol::app::ProbeMeasurements>,
}
impl From<&adapter_protocol::app::ConnectionInfo> for ReportConnection {
    fn from(value: &adapter_protocol::app::ConnectionInfo) -> Self {
        Self {
            phase: ReportConnectionPhase::from_dashboard(&value.phase),
            ping: value.ping,
            chained: value.chained,
            ip: value.ip,
            dns: value.dns,
            https: value.https,
            probes: value
                .probes
                .as_ref()
                .map(|probes| adapter_protocol::app::ProbeMeasurements {
                    ip: probes.ip,
                    dns: probes.dns,
                    https: probes.https,
                }),
        }
    }
}

#[derive(serde::Serialize)]
struct ReportRecovery {
    stage: Option<ReportRecoveryStage>,
    attempt: u32,
    elapsed_seconds: u64,
    budget_seconds: u64,
    wait_seconds: u64,
    direct_return_in_seconds: Option<u64>,
}

#[derive(serde::Serialize)]
struct ReportQuickTest {
    total: usize,
    completed: usize,
    replies: usize,
    no_reply: usize,
    local_errors: usize,
    discarded: usize,
    unmeasured: usize,
    active: bool,
    cancelled: bool,
    finished_at: Option<u64>,
}
impl From<&adapter_protocol::app::QuickTestState> for ReportQuickTest {
    fn from(value: &adapter_protocol::app::QuickTestState) -> Self {
        Self {
            total: value.total,
            completed: value.completed,
            replies: value.replies,
            no_reply: value.no_reply,
            local_errors: value.local_errors,
            discarded: value.discarded,
            unmeasured: value.unmeasured,
            active: value.active,
            cancelled: value.cancelled,
            finished_at: value.finished_at,
        }
    }
}

#[derive(serde::Serialize)]
struct ReportStatus {
    status_observation: Option<adapter_protocol::app::StatusObservation>,
    sequence: u64,
    status: Option<ReportStatusValue>,
    physical_attachment: Option<ReportAttachment>,
    settings: ReportSettings,
    front_ready: bool,
    front_selected: Option<ReportFrontSelection>,
    identity_configured: bool,
    connection: Option<ReportConnection>,
    readiness: Option<ReportReadiness>,
    metadata_refreshing: bool,
    metadata_source: Option<ReportMetadataSource>,
    metadata_updated_at: Option<u64>,
    metadata_error: Option<String>,
    retry_in_seconds: Option<u64>,
    recovery: Option<ReportRecovery>,
    backup_verified: bool,
    backup_test_status: Option<ReportBackupTestStatus>,
    backup_test_restored: bool,
    last_error: Option<String>,
    logging_degraded: bool,
    logging_dropped: u64,
    quick_test: Option<ReportQuickTest>,
    city_count: usize,
    city_candidate_count: usize,
}
impl From<&Dashboard> for ReportStatus {
    fn from(value: &Dashboard) -> Self {
        Self {
            status_observation: value.status_observation.as_ref().map(|observation| {
                adapter_protocol::app::StatusObservation {
                    age_ms: observation.age_ms,
                    capture_ms: observation.capture_ms,
                    native_elapsed_ms: observation.native_elapsed_ms,
                }
            }),
            sequence: value.sequence,
            status: ReportStatusValue::from_dashboard(&value.status),
            physical_attachment: ReportAttachment::from_dashboard(&value.physical_attachment),
            settings: ReportSettings {
                automatic_recovery: value.settings.automatic_recovery,
                connect_on_start: value.settings.connect_on_start,
                tunnel_route: value.settings.tunnel_route,
                required_multihop: value.settings.required_multihop,
                required_pq: value.settings.required_pq,
            },
            front_ready: value.front_ready,
            front_selected: ReportFrontSelection::from_dashboard(&value.front_selected),
            identity_configured: value.identity_configured,
            connection: value
                .connection
                .as_ref()
                .filter(|connection| connection.valid())
                .map(ReportConnection::from),
            readiness: value
                .readiness
                .as_deref()
                .and_then(ReportReadiness::from_dashboard),
            metadata_refreshing: value.metadata_refreshing,
            metadata_source: ReportMetadataSource::from_dashboard(&value.metadata_source),
            metadata_updated_at: value.metadata_updated_at,
            metadata_error: safe_report_code(value.metadata_error.as_deref()),
            retry_in_seconds: value.retry_in_seconds,
            recovery: value.recovery.as_ref().map(|progress| ReportRecovery {
                stage: ReportRecoveryStage::from_dashboard(&progress.stage),
                attempt: progress.attempt,
                elapsed_seconds: progress.elapsed_seconds,
                budget_seconds: progress.budget_seconds,
                wait_seconds: progress.wait_seconds,
                direct_return_in_seconds: progress.direct_return_in_seconds,
            }),
            backup_verified: value.backup_verified_at.is_some(),
            backup_test_status: value
                .backup_test_status
                .as_deref()
                .and_then(ReportBackupTestStatus::from_dashboard),
            backup_test_restored: value.backup_test_restored,
            last_error: safe_report_code(value.last_error.as_deref()),
            logging_degraded: value.logging_degraded,
            logging_dropped: value.logging_dropped,
            quick_test: value
                .quick_test
                .as_ref()
                .filter(|test| test.valid())
                .map(ReportQuickTest::from),
            city_count: value.cities.len(),
            city_candidate_count: value.city_candidates.len(),
        }
    }
}

fn safe_report_code(value: Option<&str>) -> Option<String> {
    value
        .filter(|code| {
            safe_event(&LogEvent {
                time: 0,
                layer: "agent".into(),
                stage: "api".into(),
                code: (*code).into(),
                connection: None,
                quick_test: None,
            })
        })
        .map(str::to_owned)
}

pub struct Logs {
    pub root: PathBuf,
}
impl Logs {
    pub fn event(&self, stage: &str, code: &str) -> io::Result<()> {
        self.detailed_event(stage, code, None, None)
    }
    fn detailed_event(
        &self,
        stage: &str,
        code: &str,
        connection: Option<adapter_protocol::app::ConnectionInfo>,
        quick_test: Option<adapter_protocol::app::QuickTestState>,
    ) -> io::Result<()> {
        // Only compile-time stage names and safe error codes reach this method.
        let row = LogEvent {
            time: now_seconds(),
            layer: "agent".into(),
            stage: stage.into(),
            code: code.into(),
            connection,
            quick_test,
        };
        if !safe_event(&row) {
            return Err(io::Error::other("log_event_rejected"));
        }
        let path = self.root.join("events.jsonl");
        if std::fs::metadata(&path)
            .map(|m| m.len() >= 10 * 1024 * 1024)
            .unwrap_or(false)
        {
            let previous = self.root.join("events.previous.jsonl");
            if previous.exists() {
                std::fs::remove_file(&previous)?;
            }
            std::fs::rename(&path, previous)?;
        }
        let mut file = open_writer_file(&path, true, false)?;
        serde_json::to_writer(&mut file, &row)?;
        file.write_all(b"\n")?;
        Ok(())
    }
    pub fn report(&self, snapshot: &Dashboard, report_id: &str) -> io::Result<PathBuf> {
        if report_id.len() != 36
            || !report_id.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
        {
            return Err(io::Error::other("invalid_report_id"));
        }
        let path = self.root.join(format!("report-{report_id}.json"));
        // Include a strict, identity-free status projection and a bounded tail
        // of allowlisted events, never engine stderr/config.
        let mut history = VecDeque::new();
        for name in ["events.previous.jsonl", "events.jsonl"] {
            let mut options = OpenOptions::new();
            options.read(true);
            match open_log_file(&self.root.join(name), options) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => return Err(io::Error::other("log_file_rejected")),
                Ok(mut file) => {
                    let mut body = String::new();
                    Read::by_ref(&mut file)
                        .take(10 * 1024 * 1024 + 4096)
                        .read_to_string(&mut body)?;
                    for line in body.lines() {
                        if let Ok(value) = serde_json::from_str::<LogEvent>(line) {
                            if !safe_event(&value) {
                                continue;
                            }
                            if history.len() >= 200 {
                                history.pop_front();
                            }
                            history.push_back(value);
                        }
                    }
                }
            }
        }
        let mut file = open_writer_file(&path, false, true)?;
        let source_sha = option_env!("ADAPTER_SOURCE_SHA")
            .filter(|value| value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit()));
        serde_json::to_writer_pretty(
            &mut file,
            &serde_json::json!({"schema":2,"agent_version":env!("CARGO_PKG_VERSION"),"source_sha":source_sha,"generated_at":now_seconds(),"status":ReportStatus::from(snapshot),"events":history,"scope":"adapter_only_no_system_kill_switch"}),
        )?;
        file.sync_all()?;
        Ok(path)
    }
}
#[derive(Clone)]
pub struct LogClient {
    sender: mpsc::SyncSender<(
        String,
        String,
        Option<adapter_protocol::app::ConnectionInfo>,
        Option<adapter_protocol::app::QuickTestState>,
    )>,
    pub fault: Arc<AtomicBool>,
    pub dropped: Arc<AtomicU64>,
}
impl LogClient {
    pub fn start(root: PathBuf) -> io::Result<Self> {
        let (sender, receive) = mpsc::sync_channel::<(
            String,
            String,
            Option<adapter_protocol::app::ConnectionInfo>,
            Option<adapter_protocol::app::QuickTestState>,
        )>(256);
        let fault = Arc::new(AtomicBool::new(false));
        let observed = fault.clone();
        thread::Builder::new()
            .name("bounded-event-log".into())
            .spawn(move || {
                let logs = Logs { root };
                while let Ok((stage, code, connection, quick_test)) = receive.recv() {
                    if logs
                        .detailed_event(&stage, &code, connection, quick_test)
                        .is_err()
                    {
                        observed.store(true, Ordering::Release);
                    }
                }
            })?;
        Ok(Self {
            sender,
            fault,
            dropped: Arc::new(AtomicU64::new(0)),
        })
    }
    pub fn event(&self, stage: &str, code: &str) -> io::Result<()> {
        self.send(stage, code, None, None)
    }
    pub fn connection(
        &self,
        code: &str,
        info: Option<&adapter_protocol::app::ConnectionInfo>,
    ) -> io::Result<()> {
        self.send("connection", code, info.cloned(), None)
    }
    pub fn quick(
        &self,
        code: &str,
        progress: &adapter_protocol::app::QuickTestState,
    ) -> io::Result<()> {
        self.send("quick", code, None, Some(progress.clone()))
    }
    fn send(
        &self,
        stage: &str,
        code: &str,
        connection: Option<adapter_protocol::app::ConnectionInfo>,
        quick_test: Option<adapter_protocol::app::QuickTestState>,
    ) -> io::Result<()> {
        if self
            .sender
            .try_send((stage.into(), code.into(), connection, quick_test))
            .is_err()
        {
            self.dropped.fetch_add(1, Ordering::AcqRel);
            self.fault.store(true, Ordering::Release);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    fn temporary() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "adapter-diagnostics-test-{}-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    fn event_line(time: u64, code: &str, connection: Option<serde_json::Value>) -> Vec<u8> {
        let mut event = serde_json::json!({
            "time": time,
            "layer": "agent",
            "stage": "connection",
            "code": code,
        });
        if let Some(connection) = connection {
            event["connection"] = connection;
        }
        let mut line = serde_json::to_vec(&event).unwrap();
        line.push(b'\n');
        line
    }

    fn connection_facts(probes: bool) -> serde_json::Value {
        let mut connection = serde_json::json!({
            "chained": false,
            "relay": "xx-aaa-wg-001",
            "city": "xx-aaa",
            "inlet": "192.0.2.1:20484",
            "interface_index": 5,
            "instance": 17,
            "phase": "failed",
            "ip": true,
            "dns": false,
            "https": false,
        });
        if probes {
            connection["probes"] = serde_json::json!({
                "ip": "passed",
                "dns": "timeout",
                "https": "not_run_dns_failed",
            });
        }
        connection
    }

    fn append_bytes(path: &std::path::Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn recent_events_projects_safe_fields_in_rotation_order_and_keeps_only_latest_limit() {
        let root = temporary();
        let previous = root.join("events.previous.jsonl");
        let active = root.join("events.jsonl");
        append_bytes(
            &previous,
            &[
                event_line(1, "connected", None),
                event_line(2, "candidate_not_ready", Some(connection_facts(true))),
            ]
            .concat(),
        );
        append_bytes(
            &active,
            &[
                event_line(3, "active_data_failed", None),
                event_line(4, "connected", None),
            ]
            .concat(),
        );
        let before = (
            std::fs::read(&previous).unwrap(),
            std::fs::read(&active).unwrap(),
            {
                let mut names: Vec<_> = std::fs::read_dir(&root)
                    .unwrap()
                    .map(|item| item.unwrap().file_name())
                    .collect();
                names.sort();
                names
            },
        );

        let page = recent_events(&root, 3).unwrap();

        assert_eq!(page.events.len(), 3);
        let serialized: Vec<serde_json::Value> = page
            .events
            .iter()
            .map(|event| serde_json::to_value(event).unwrap())
            .collect();
        assert_eq!(serialized[0]["time"], 2);
        assert_eq!(serialized[0]["code"], "candidate_not_ready");
        assert_eq!(serialized[0]["relay"], "xx-aaa-wg-001");
        assert_eq!(serialized[0]["city"], "xx-aaa");
        assert_eq!(serialized[0]["phase"], "failed");
        assert_eq!(serialized[0]["ip"], "passed");
        assert_eq!(serialized[0]["dns"], "timeout");
        assert_eq!(serialized[0]["https"], "not_run_dns_failed");
        for forbidden in [
            "connection",
            "inlet",
            "interface_index",
            "instance",
            "ping",
            "probes",
        ] {
            assert!(
                serialized[0].get(forbidden).is_none(),
                "projection leaked {forbidden}"
            );
        }
        assert!(!serialized[0].to_string().contains("192.0.2.1"));
        assert_eq!(serialized[1]["time"], 3);
        assert_eq!(serialized[2]["time"], 4);
        assert!(page.truncated);
        assert_eq!(page.skipped, 0);

        let after = (
            std::fs::read(&previous).unwrap(),
            std::fs::read(&active).unwrap(),
            {
                let mut names: Vec<_> = std::fs::read_dir(&root)
                    .unwrap()
                    .map(|item| item.unwrap().file_name())
                    .collect();
                names.sort();
                names
            },
        );
        assert_eq!(
            before, after,
            "event reader must leave the directory untouched"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recent_events_maps_legacy_booleans_to_closed_probe_outcomes() {
        let root = temporary();
        append_bytes(
            &root.join("events.jsonl"),
            &event_line(5, "candidate_not_ready", Some(connection_facts(false))),
        );
        let page = recent_events(&root, 10).unwrap();
        let view = serde_json::to_value(&page.events[0]).unwrap();
        assert_eq!(view["ip"], "passed");
        assert_eq!(view["dns"], "rejected");
        assert_eq!(view["https"], "rejected");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recent_events_reads_only_bounded_tail_and_discards_cut_row() {
        let root = temporary();
        let path = root.join("events.jsonl");
        let mut oversized_row = b"{\"time\":1,\"layer\":\"agent\",\"stage\":\"api\",\"code\":\"complete\",\"unknown\":\"".to_vec();
        oversized_row.resize(EVENT_TAIL_BYTES as usize + 1024, b'x');
        oversized_row.extend_from_slice(b"\"}\n");
        oversized_row.extend_from_slice(&event_line(9, "connected", None));
        append_bytes(&path, &oversized_row);

        let page = recent_events(&root, 10).unwrap();

        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].time, 9);
        assert_eq!(page.skipped, 1, "the leading partial row is counted");
        assert!(page.truncated);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recent_events_counts_invalid_rows_and_never_returns_raw_json_fields() {
        let root = temporary();
        let path = root.join("events.jsonl");
        let mut bytes = event_line(1, "connected", None);
        bytes.extend_from_slice(b"not-json\n");
        bytes.extend_from_slice(&event_line(2, "unrecognized-code", None));
        let mut unknown = serde_json::json!({
            "time": 3,
            "layer": "agent",
            "stage": "connection",
            "code": "connected",
            "private_key": "synthetic-sensitive-sentinel",
        });
        bytes.extend_from_slice(&serde_json::to_vec(&unknown).unwrap());
        bytes.push(b'\n');
        unknown["code"] = serde_json::json!("active_data_failed");
        bytes.extend_from_slice(&serde_json::to_vec(&unknown).unwrap());
        bytes.push(b'\n');
        // Even a complete JSON object is not a committed event until newline.
        bytes.extend_from_slice(
            b"{\"time\":4,\"layer\":\"agent\",\"stage\":\"connection\",\"code\":\"connected\"}",
        );
        append_bytes(&path, &bytes);

        let page = recent_events(&root, 10).unwrap();

        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].time, 1);
        assert_eq!(page.skipped, 5);
        let output = serde_json::to_string(&page).unwrap();
        assert!(!output.contains("synthetic-sensitive-sentinel"));
        assert!(!output.contains("private_key"));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recent_events_missing_logs_and_invalid_limits_are_bounded_and_read_only() {
        let root = temporary();
        assert!(recent_events(&root, 0)
            .unwrap_err()
            .to_string()
            .contains("invalid_event_limit"));
        assert!(recent_events(&root, EVENT_PAGE_MAX + 1)
            .unwrap_err()
            .to_string()
            .contains("invalid_event_limit"));
        let page = recent_events(&root, EVENT_PAGE_MAX).unwrap();
        assert!(page.events.is_empty());
        assert_eq!(page.skipped, 0);
        assert!(!page.truncated);
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recent_events_rejects_hard_link_without_disclosing_path_or_mutating_it() {
        let root = temporary();
        let source = root.join("source");
        let log = root.join("events.jsonl");
        let contents = event_line(1, "connected", None);
        std::fs::write(&source, &contents).unwrap();
        std::fs::hard_link(&source, &log).unwrap();

        let error = recent_events(&root, 10).unwrap_err();

        assert_eq!(error.to_string(), "event_log_unavailable");
        assert!(!error.to_string().contains(root.to_string_lossy().as_ref()));
        assert_eq!(std::fs::read(&source).unwrap(), contents);
        assert!(std::fs::metadata(&log).unwrap().is_file());
        std::fs::remove_file(&log).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn recent_events_rejects_symlink_without_disclosing_path_or_mutating_target() {
        use std::os::unix::fs::symlink;

        let root = temporary();
        let source = root.join("source");
        let log = root.join("events.jsonl");
        let contents = event_line(1, "connected", None);
        std::fs::write(&source, &contents).unwrap();
        symlink(&source, &log).unwrap();

        let error = recent_events(&root, 10).unwrap_err();

        assert_eq!(error.to_string(), "event_log_unavailable");
        assert!(!error.to_string().contains(root.to_string_lossy().as_ref()));
        assert_eq!(std::fs::read(&source).unwrap(), contents);
        assert!(std::fs::symlink_metadata(&log)
            .unwrap()
            .file_type()
            .is_symlink());
        std::fs::remove_file(&log).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn api_routes_and_network_recovery_events_remain_loggable_without_raw_data() {
        for (stage, code) in [
            ("api_access", "direct_verified"),
            ("api_access", "independent_proxy_verified"),
            ("api_access", "healthy_tunnel_verified"),
            ("api_access", "cache_write_failed"),
            ("connection", "network_binding_changed"),
            ("connection", "waiting_network_settle"),
            ("connection", "active_probe_local_failure"),
            ("connection", "active_probe_cancelled"),
            ("connection", "active_binding_changed"),
            ("connection", "active_local_rebuild"),
            ("connection", "active_data_failed"),
            ("connection", "maintenance_preempted"),
            ("connection", "same_relay_inlet_retry"),
            ("connection", "shadowsocks_inlets_exhausted"),
        ] {
            let event = LogEvent {
                time: 1,
                layer: "agent".into(),
                stage: stage.into(),
                code: code.into(),
                connection: None,
                quick_test: None,
            };
            assert!(
                safe_event(&event),
                "{stage}/{code} must not disable event logging"
            );
        }
    }
    fn snapshot() -> Dashboard {
        use adapter_protocol::app::{Account, Settings};
        Dashboard {
            status_observation: None,
            sequence: 0,
            boot_id: "synthetic".into(),
            build: "test".into(),
            source_sha: String::new(),
            status: "disconnected".into(),
            physical_attachment: "unknown".into(),
            settings: Settings::default(),
            front_ready: false,
            front_selected: "reject".into(),
            device_draft: None,
            identity_configured: false,
            device_name: None,
            public_key: None,
            active_relay: None,
            connection: None,
            readiness: None,
            cities: vec![],
            metadata_source: "missing".into(),
            metadata_updated_at: None,
            metadata_refreshing: false,
            metadata_error: None,
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
            logs_path: "synthetic".into(),
            last_report_path: None,
            logging_degraded: false,
            logging_dropped: 0,
            quick_test: None,
            city_candidates: vec![],
        }
    }

    #[test]
    fn report_status_is_a_strict_allowlist_without_identity_or_paths() {
        use adapter_protocol::app::{
            Account, City, CityCandidate, ConnectionInfo, Device, DeviceDraft, PingMeasurement,
            ProbeMeasurements, ProbeOutcome, QuickTestState, RecoveryProgress, StatusObservation,
            TunnelRoute,
        };

        let root = temporary();
        let logs = Logs { root: root.clone() };
        let mut dashboard = snapshot();
        dashboard.status_observation = Some(StatusObservation {
            age_ms: 11,
            capture_ms: 7,
            native_elapsed_ms: 3,
        });
        dashboard.sequence = 17;
        dashboard.status = "connected".into();
        dashboard.physical_attachment = "available".into();
        dashboard.settings.favorite_cities = vec!["xx-aaa".into()];
        dashboard.settings.selected_city = Some("xx-aaa".into());
        dashboard.settings.chain_selection = Some("settings-chain-path-sentinel".into());
        dashboard.settings.tunnel_route = TunnelRoute::Chain;
        dashboard.settings.automatic_recovery = true;
        dashboard.settings.required_multihop = true;
        dashboard.front_ready = true;
        dashboard.front_selected = "slot_a".into();
        dashboard.identity_configured = true;
        dashboard.device_draft = Some(DeviceDraft {
            state: "draft-state-sentinel".into(),
            public_key: "draft-public-key-sentinel".into(),
            device_id: Some("draft-device-id-sentinel".into()),
            device_name: Some("draft-device-name-sentinel".into()),
        });
        dashboard.device_name = Some("dashboard-device-name-sentinel".into());
        dashboard.public_key = Some("dashboard-public-key-sentinel".into());
        dashboard.active_relay = Some("active-relay-path-sentinel".into());
        dashboard.connection = Some(ConnectionInfo {
            ping: Some(PingMeasurement {
                rtt_ms: 42,
                measured_at: 99,
            }),
            chained: true,
            relay: "connection-relay-path-sentinel".into(),
            city: "xx-aaa".into(),
            inlet: "192.0.2.1:20484".into(),
            interface_index: 5,
            instance: 17,
            phase: "connected".into(),
            ip: Some(true),
            dns: Some(false),
            https: Some(false),
            probes: Some(ProbeMeasurements {
                ip: ProbeOutcome::Passed,
                dns: ProbeOutcome::Timeout,
                https: ProbeOutcome::NotRunDnsFailed,
            }),
        });
        dashboard.readiness = Some("ready".into());
        dashboard.metadata_source = "official_api".into();
        dashboard.metadata_updated_at = Some(123);
        dashboard.metadata_refreshing = true;
        dashboard.metadata_error = Some("metadata_refresh_unavailable".into());
        dashboard.chain_node = Some("chain-node-path-sentinel".into());
        dashboard.chain_fingerprint = Some("chain-fingerprint-sentinel".into());
        dashboard.retry_in_seconds = Some(8);
        dashboard.recovery = Some(RecoveryProgress {
            stage: "waiting_network".into(),
            relay: Some("recovery-relay-path-sentinel".into()),
            inlet: Some("recovery-inlet-path-sentinel".into()),
            attempt: 3,
            elapsed_seconds: 12,
            budget_seconds: 300,
            wait_seconds: 8,
            next: "recovery-next-path-sentinel".into(),
            direct_return_in_seconds: Some(5),
        });
        dashboard.backup_verified_at = Some(100);
        dashboard.backup_test_id = 101;
        dashboard.backup_test_status = Some("passed".into());
        dashboard.backup_test_restored = true;
        dashboard.account = Account {
            authenticated: true,
            expiry: Some("account-expiry-sentinel".into()),
            devices: vec![Device {
                id: "account-device-id-sentinel".into(),
                name: "account-device-name-sentinel".into(),
                public_key: "account-public-key-sentinel".into(),
                created: "account-created-sentinel".into(),
                current: true,
            }],
            error_code: Some("account-error-sentinel".into()),
        };
        dashboard.operation = Some("operation-sentinel".into());
        dashboard.last_error = Some("active_front_repair_failed".into());
        dashboard.logs_path = "/synthetic/logs-path-sentinel/events.jsonl".into();
        dashboard.last_report_path =
            Some("/synthetic/last-report-path-sentinel/report.json".into());
        dashboard.logging_degraded = true;
        dashboard.logging_dropped = 2;
        dashboard.quick_test = Some(QuickTestState {
            city: "yy-bbb".into(),
            total: 5,
            completed: 2,
            replies: 1,
            no_reply: 1,
            local_errors: 0,
            discarded: 0,
            unmeasured: 3,
            active: false,
            cancelled: false,
            finished_at: Some(200),
        });
        dashboard.cities = vec![City {
            id: "city-id-sentinel".into(),
            name: "city-name-sentinel".into(),
            country: "country-sentinel".into(),
            relay_count: 2,
        }];
        dashboard.city_candidates = vec![CityCandidate {
            city: "zz-ccc".into(),
            hostname: "candidate-path-sentinel".into(),
            ping_ms: 13,
            measured_at: 201,
        }];

        let report_path = logs
            .report(&dashboard, "44444444-4444-4444-4444-444444444444")
            .unwrap();
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(report_path).unwrap()).unwrap();
        let status = &report["status"];
        let text = report.to_string();

        assert_eq!(report["schema"], 2);
        assert_eq!(status["sequence"], 17);
        assert_eq!(status["status"], "connected");
        assert_eq!(status["physical_attachment"], "available");
        assert_eq!(status["front_ready"], true);
        assert_eq!(status["front_selected"], "slot_a");
        assert_eq!(status["identity_configured"], true);
        assert_eq!(status["settings"]["tunnel_route"], "chain");
        assert_eq!(status["connection"]["phase"], "connected");
        assert_eq!(status["connection"]["ping"]["rtt_ms"], 42);
        assert_eq!(status["connection"]["probes"]["dns"], "timeout");
        assert_eq!(status["readiness"], "ready");
        assert_eq!(status["metadata_error"], "metadata_refresh_unavailable");
        assert_eq!(status["recovery"]["stage"], "waiting_network");
        assert_eq!(status["recovery"]["attempt"], 3);
        assert_eq!(status["backup_test_status"], "passed");
        assert_eq!(status["last_error"], "active_front_repair_failed");
        assert_eq!(status["quick_test"]["total"], 5);
        assert_eq!(status["city_count"], 1);
        assert_eq!(status["city_candidate_count"], 1);

        for field in [
            "boot_id",
            "device_draft",
            "device_name",
            "public_key",
            "active_relay",
            "account",
            "operation",
            "logs_path",
            "last_report_path",
            "chain_node",
            "chain_fingerprint",
            "cities",
            "city_candidates",
        ] {
            assert!(
                status.get(field).is_none(),
                "unexpected status field {field}"
            );
        }
        for (object, fields) in [
            (
                &status["settings"],
                &["favorite_cities", "selected_city", "chain_selection"][..],
            ),
            (
                &status["connection"],
                &["relay", "city", "inlet", "interface_index", "instance"][..],
            ),
            (&status["recovery"], &["relay", "inlet", "next"][..]),
        ] {
            for field in fields {
                assert!(object.get(field).is_none(), "unexpected {field} identifier");
            }
        }
        for sentinel in [
            "draft-state-sentinel",
            "draft-public-key-sentinel",
            "draft-device-id-sentinel",
            "draft-device-name-sentinel",
            "dashboard-device-name-sentinel",
            "dashboard-public-key-sentinel",
            "active-relay-path-sentinel",
            "connection-relay-path-sentinel",
            "chain-node-path-sentinel",
            "chain-fingerprint-sentinel",
            "recovery-relay-path-sentinel",
            "recovery-inlet-path-sentinel",
            "recovery-next-path-sentinel",
            "account-expiry-sentinel",
            "account-device-id-sentinel",
            "account-device-name-sentinel",
            "account-public-key-sentinel",
            "account-created-sentinel",
            "account-error-sentinel",
            "operation-sentinel",
            "logs-path-sentinel",
            "last-report-path-sentinel",
            "settings-chain-path-sentinel",
            "city-id-sentinel",
            "city-name-sentinel",
            "country-sentinel",
            "candidate-path-sentinel",
            "xx-aaa",
            "yy-bbb",
            "zz-ccc",
        ] {
            assert!(!text.contains(sentinel), "report exposed {sentinel}");
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_transitions_survive_diagnostic_export_without_accepting_free_text() {
        let root = temporary();
        let logs = Logs { root: root.clone() };
        let transitions = [
            "active_failure_confirmation",
            "active_front_repair_failed",
            "original_inlet_short_retry",
            "direct_routes_exhausted_chain_last",
            "route_trial_failed",
            "route_trial_failed_restore_previous",
            "restore_previous_failed_use_verified_backup",
            "maintenance_preempted",
        ];
        for code in transitions {
            logs.event("connection", code).unwrap();
            assert!(logs
                .event("connection", &format!("{code} private-key=untrusted"))
                .is_err());
        }
        let report = logs
            .report(&snapshot(), "33333333-3333-3333-3333-333333333333")
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
        let exported: Vec<_> = body["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["code"].as_str().unwrap())
            .collect();
        assert_eq!(exported, transitions);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn withdrawn_original_inlet_is_reported_without_disabling_logging() {
        let root = temporary();
        let logs = Logs { root: root.clone() };
        logs.event("connection", "relay_not_active").unwrap();
        logs.event("connection", "original_inlet_withdrawn")
            .unwrap();
        assert!(logs
            .event("connection", "untrusted-arbitrary-text")
            .is_err());
        let report = logs
            .report(&snapshot(), "33333333-3333-3333-3333-333333333333")
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
        assert_eq!(body["events"][0]["code"], "relay_not_active");
        assert_eq!(body["events"][1]["code"], "original_inlet_withdrawn");
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn uncertain_identity_activation_is_a_retained_closed_diagnostic() {
        let root = temporary();
        let logs = Logs { root: root.clone() };
        // This diagnostics module is also compiled in the desktop crate.
        // Exercise the wire code without importing the agent's device manager.
        logs.event("api", "identity_activation_uncertain").unwrap();
        let report = logs
            .report(&snapshot(), "33333333-3333-3333-3333-333333333333")
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
        assert_eq!(body["events"][0]["code"], "identity_activation_uncertain");
        assert!(logs
            .event("api", "identity_activation_uncertain private-key")
            .is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn quick_batches_keep_counts_and_reject_credentials_and_counter_overflow() {
        let root = temporary();
        let logs = Logs { root: root.clone() };
        let mut progress = adapter_protocol::app::QuickTestState {
            city: "xx-aaa".into(),
            total: 13,
            completed: 13,
            replies: 2,
            no_reply: 9,
            local_errors: 1,
            discarded: 1,
            unmeasured: 0,
            active: false,
            cancelled: false,
            finished_at: Some(1),
        };
        logs.detailed_event("quick", "complete", None, Some(progress.clone()))
            .unwrap();
        progress.replies = usize::MAX;
        assert!(logs
            .detailed_event("quick", "complete", None, Some(progress))
            .is_err());
        let mut injected: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(root.join("events.jsonl")).unwrap())
                .unwrap();
        injected["quick_test"]["private_key"] = serde_json::json!("never-export-this");
        assert!(serde_json::from_value::<LogEvent>(injected).is_err());
        let report = logs
            .report(&snapshot(), "33333333-3333-3333-3333-333333333333")
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
        assert_eq!(body["events"][0]["quick_test"]["total"], 13);
        assert_eq!(body["events"][0]["quick_test"]["no_reply"], 9);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn public_connection_facts_survive_report_without_accepting_path_or_secret_fields() {
        let root = temporary();
        let logs = Logs { root: root.clone() };
        let mut info = adapter_protocol::app::ConnectionInfo {
            ping: None,
            chained: false,
            relay: "xx-aaa-wg-001".into(),
            city: "xx-aaa".into(),
            inlet: "192.0.2.1:20484".into(),
            interface_index: 5,
            instance: 1,
            phase: "failed".into(),
            ip: Some(true),
            dns: Some(false),
            https: Some(false),
            probes: Some(adapter_protocol::app::ProbeMeasurements {
                ip: adapter_protocol::app::ProbeOutcome::Passed,
                dns: adapter_protocol::app::ProbeOutcome::Timeout,
                https: adapter_protocol::app::ProbeOutcome::NotRunDnsFailed,
            }),
        };
        logs.detailed_event(
            "connection",
            "candidate_not_ready",
            Some(info.clone()),
            None,
        )
        .unwrap();
        let mut contradictory = info.clone();
        contradictory.dns = Some(true);
        assert!(logs
            .detailed_event("connection", "complete", Some(contradictory), None)
            .is_err());
        let mut injected = serde_json::to_value(&info).unwrap();
        injected["probes"]["private_key"] = "synthetic-sensitive-sentinel".into();
        assert!(serde_json::from_value::<adapter_protocol::app::ConnectionInfo>(injected).is_err());
        info.inlet = "private-key://never-log-this".into();
        assert!(logs
            .detailed_event("connection", "candidate_not_ready", Some(info), None)
            .is_err());
        let path = logs
            .report(&snapshot(), "11111111-1111-1111-1111-111111111111")
            .unwrap();
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let text = report.to_string();
        assert!(text.contains("xx-aaa-wg-001"));
        assert!(text.contains("192.0.2.1:20484"));
        assert_eq!(
            report["events"][0]["connection"]["probes"]["dns"],
            "timeout"
        );
        assert_eq!(
            report["events"][0]["connection"]["probes"]["https"],
            "not_run_dns_failed"
        );
        assert!(!text.contains("never-log-this"));
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn reports_drop_extra_credentials_and_unrecognized_codes() {
        let root = temporary();
        let logs = Logs { root: root.clone() };
        logs.event("start", "agent_started").unwrap();
        let mut file = OpenOptions::new()
            .append(true)
            .open(root.join("events.jsonl"))
            .unwrap();
        file.write_all(b"{\"time\":1,\"layer\":\"agent\",\"stage\":\"api\",\"code\":\"complete\",\"private_key\":\"synthetic-sensitive-sentinel\"}\n{\"time\":2,\"layer\":\"agent\",\"stage\":\"api\",\"code\":\"synthetic-sensitive-sentinel\"}\n").unwrap();
        drop(file);
        let report = logs
            .report(&snapshot(), "00000000-0000-0000-0000-000000000001")
            .unwrap();
        let body = std::fs::read_to_string(report).unwrap();
        assert!(!body.contains("synthetic-sensitive-sentinel"));
        assert!(!body.contains("private_key"));
        let result: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(result["events"].as_array().unwrap().len(), 1);
        assert!(logs.report(&snapshot(), "../outside").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn report_preserves_only_the_bounded_tail_and_refuses_clobber() {
        let root = temporary();
        let logs = Logs { root: root.clone() };
        for _ in 0..210 {
            logs.event("api", "complete").unwrap();
        }
        let id = "00000000-0000-0000-0000-000000000002";
        let report = logs.report(&snapshot(), id).unwrap();
        let result: serde_json::Value =
            serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
        assert_eq!(result["events"].as_array().unwrap().len(), 200);
        assert!(logs.report(&snapshot(), id).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn linked_log_is_never_exported_or_modified() {
        let root = temporary();
        let outside = root.join("unrelated-private-file");
        std::fs::write(&outside, b"synthetic-sensitive-sentinel").unwrap();
        std::fs::hard_link(&outside, root.join("events.jsonl")).unwrap();
        let logs = Logs { root: root.clone() };
        assert!(logs
            .report(&snapshot(), "00000000-0000-0000-0000-000000000003")
            .is_err());
        assert!(logs.event("api", "complete").is_err());
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            b"synthetic-sensitive-sentinel"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn symbolic_log_is_never_followed() {
        let root = temporary();
        let outside = root.join("unrelated-private-file");
        std::fs::write(&outside, b"synthetic-sensitive-sentinel").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("events.jsonl")).unwrap();
        assert!(Logs { root: root.clone() }
            .report(&snapshot(), "00000000-0000-0000-0000-000000000004")
            .is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
