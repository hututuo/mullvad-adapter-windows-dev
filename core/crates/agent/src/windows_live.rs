//! Live per-user host. One owner polls hardware and services bounded IPC.
//! No mock data, automatic identity registration or global network mutation.
use crate::live_diagnostics::{open_log_file, open_writer_file, LogClient, Logs};
use crate::live_identity::{load_identity, persist_identity, TunnelIdentity, MAX_IDENTITY_JSON};
use crate::live_quick::{Message as QuickMessage, Run as QuickRun, Target};
use adapter_control::{
    observer::ObservedOwner,
    owned_lifecycle::{Event, OperationTicket, ResourceOwner},
};
use adapter_domain::{Attachment, State};
use adapter_engine_mihomo::connection_lifecycle::{
    self, ConnectionResource, FrontConfig, FrontStatus,
};
use adapter_mullvad_api::{
    AccountNumber, AccountSession, AccountSnapshot, BootstrapProxy, DeviceId, MullvadClient,
    VoucherCode,
};
use adapter_platform::windows_icmp::PingResult;
use adapter_platform::{
    storage_record::RecordKind,
    windows::{boot_id, Identity, Pipe, SingleInstance},
    windows_paths::AppRoot,
    windows_runtime::PrivateRuntime,
    windows_store::PrivateStore,
};
use adapter_protocol::{app::*, read_frame, write_frame, ResponseAck};
use std::time::Instant;
use std::{
    collections::{BTreeMap, VecDeque},
    fs::OpenOptions,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
    sync::{atomic::Ordering, mpsc},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
struct PingObservation {
    city: String,
    result: Result<PingResult, &'static str>,
    measured: Instant,
    at: u64,
}
struct PendingQuick {
    ticket: OperationTicket,
    run: QuickRun,
    observed: BTreeMap<String, PingObservation>,
    automatic: bool,
    progress: QuickTestState,
}
struct QueuedConnect {
    relay: Option<String>,
}
const PING_DISPLAY_TTL: Duration = Duration::from_secs(180);
fn update_candidates(dashboard: &mut Dashboard, pings: &BTreeMap<String, PingObservation>) {
    dashboard.city_candidates.clear();
    for city in &dashboard.settings.favorite_cities {
        let mut candidates: Vec<_> = pings
            .iter()
            .filter_map(|(hostname, observation)| {
                if &observation.city != city
                    || observation.measured.elapsed() >= PING_DISPLAY_TTL
                    || dashboard.active_relay.as_ref() == Some(hostname)
                {
                    return None;
                }
                match observation.result {
                    Ok(PingResult::Reply { rtt_ms }) => Some(CityCandidate {
                        city: city.clone(),
                        hostname: hostname.clone(),
                        ping_ms: u64::from(rtt_ms),
                        measured_at: observation.at,
                    }),
                    _ => None,
                }
            })
            .collect();
        candidates.sort_by(|a, b| {
            a.ping_ms
                .cmp(&b.ping_ms)
                .then_with(|| a.hostname.cmp(&b.hostname))
        });
        dashboard
            .city_candidates
            .extend(candidates.into_iter().take(2));
    }
}

fn failure(code: &str) -> AppReply {
    AppReply::Error {
        code: code.to_owned(),
    }
}
fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
fn load_settings(store: &PrivateStore) -> io::Result<Settings> {
    match store.load(RecordKind::Policy) {
        Ok(value) => {
            let settings: Settings = serde_json::from_slice(value.expose())
                .map_err(|_| io::Error::other("policy_invalid"))?;
            settings.validate().map_err(io::Error::other)?;
            Ok(settings)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Settings::default()),
        Err(_) => Err(io::Error::other("policy_unavailable")),
    }
}
fn save_settings(store: &PrivateStore, value: &Settings) -> io::Result<()> {
    value.validate().map_err(io::Error::other)?;
    let data = serde_json::to_vec(value).map_err(|_| io::Error::other("policy_invalid"))?;
    store.prepare(RecordKind::Policy, &data)?.commit()?;
    let verified: Settings = serde_json::from_slice(store.load(RecordKind::Policy)?.expose())
        .map_err(|_| io::Error::other("policy_readback_failed"))?;
    if verified != *value {
        return Err(io::Error::other("policy_readback_failed"));
    }
    Ok(())
}
enum WorkCommand {
    Api(AppCommand),
    Save(Settings),
    Report(Box<Dashboard>),
}
struct ApiJob {
    id: String,
    proxy: u16,
    public_key: Option<String>,
    command: WorkCommand,
}
struct ApiDone {
    id: String,
    result: Result<ApiValue, &'static str>,
    draft: Option<crate::live_device::PublicDraft>,
}
enum ApiValue {
    Catalogue(adapter_catalogue::Catalogue, Vec<City>, u64),
    Account(AccountSnapshot),
    Draft(crate::live_device::PublicDraft),
    DeviceIdentity(TunnelIdentity),
    Login,
    Logout,
    Settings(Settings),
    Report(PathBuf),
}
fn api_worker(
    store: PrivateStore,
    report_root: PathBuf,
) -> io::Result<(mpsc::SyncSender<ApiJob>, mpsc::Receiver<ApiDone>)> {
    let (send, receive) = mpsc::sync_channel::<ApiJob>(1);
    let (done, results) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("account-metadata-io".into())
        .spawn(move || {
            let mut session: Option<AccountSession> = None;
            let mut uncertain_mutation = false;
            while let Ok(job) = receive.recv() {
                let result = (|| -> Result<ApiValue, &'static str> {
                    let command = match job.command {
                        WorkCommand::Save(settings) => {
                            save_settings(&store, &settings).map_err(|_| "policy_write_failed")?;
                            return Ok(ApiValue::Settings(settings));
                        }
                        WorkCommand::Report(snapshot) => {
                            return Logs {
                                root: report_root.clone(),
                            }
                            .report(&snapshot, &job.id)
                            .map(ApiValue::Report)
                            .map_err(|_| "report_write_failed")
                        }
                        WorkCommand::Api(command) => command,
                    };
                    if matches!(command, AppCommand::AccountLogout) {
                        session = None;
                        uncertain_mutation = false;
                        return Ok(ApiValue::Logout);
                    }
                    let client = if job.proxy == 0 {
                        MullvadClient::direct()
                    } else {
                        BootstrapProxy::new(
                            SocketAddrV4::new(Ipv4Addr::LOCALHOST, job.proxy).into(),
                        )
                        .and_then(MullvadClient::new)
                    }
                    .map_err(|e| e.code())?;
                    match command {
                        AppCommand::RefreshCatalogue => {
                            let bytes = client.fetch_relays().map_err(|e| e.code())?;
                            let (catalogue, cities) = read_catalogue(&bytes)?;
                            let pending = report_root.join("relays.pending");
                            let path = report_root.join("relays.json");
                            let mut file = open_writer_file(&pending, false, false)
                                .map_err(|_| "metadata_cache_write_failed")?;
                            file.set_len(0).map_err(|_| "metadata_cache_write_failed")?;
                            file.write_all(&bytes)
                                .and_then(|_| file.sync_all())
                                .map_err(|_| "metadata_cache_write_failed")?;
                            drop(file);
                            std::fs::rename(&pending, path)
                                .map_err(|_| "metadata_cache_write_failed")?;
                            Ok(ApiValue::Catalogue(catalogue, cities, now_seconds()))
                        }
                        AppCommand::AccountLogin { account } => {
                            let mut input = account.into_value();
                            let number =
                                AccountNumber::from_user_entry(std::mem::take(&mut *input))
                                    .map_err(|e| e.code())?;
                            let mut proposed = client.authenticate(number).map_err(|e| e.code())?;
                            let snapshot = match job.public_key.as_deref() {
                                Some(key) => client.read_account(&mut proposed, key),
                                None => client.read_account_devices(&mut proposed),
                            }
                            .map_err(|e| e.code())?;
                            if session.as_ref().is_none_or(|old| {
                                old.binding_fingerprint() != proposed.binding_fingerprint()
                            }) {
                                uncertain_mutation = false;
                            }
                            session = Some(proposed);
                            Ok(ApiValue::Account(snapshot))
                        }
                        AppCommand::AccountRefresh => {
                            let account = session.as_mut().ok_or("account_required")?;
                            let key = job.public_key.as_deref();
                            // A refreshed expiry alone cannot prove an uncertain
                            // voucher outcome. No blind mutation retry is enabled.
                            match key {
                                Some(key) => client.read_account(account, key),
                                None => client.read_account_devices(account),
                            }
                            .map(ApiValue::Account)
                            .map_err(|e| e.code())
                        }
                        AppCommand::CreateDevice { confirm: true } => {
                            if uncertain_mutation {
                                return Err("outcome_unknown");
                            }
                            let account = session.as_ref().ok_or("account_required")?;
                            crate::live_device::create(&store, &client, account)
                                .map(ApiValue::Draft)
                        }
                        AppCommand::UseCreatedDevice { confirm: true } => {
                            let account = session.as_mut().ok_or("account_required")?;
                            crate::live_device::activate(&store, &client, account)
                                .map(ApiValue::DeviceIdentity)
                        }
                        AppCommand::RemoveDevice { device_id } => {
                            if uncertain_mutation {
                                return Err("outcome_unknown");
                            }
                            let account = session.as_mut().ok_or("account_required")?;
                            let key = job.public_key.as_deref();
                            let snapshot = match key {
                                Some(key) => client.read_account(account, key),
                                None => client.read_account_devices(account),
                            }
                            .map_err(|e| e.code())?;
                            let id = DeviceId::new(device_id).map_err(|e| e.code())?;
                            let device = snapshot
                                .devices
                                .iter()
                                .find(|d| d.id == id)
                                .ok_or("device_not_found")?;
                            if device.current {
                                return Err("current_device_protected");
                            }
                            if let Err(e) = client.remove_device(account, &id) {
                                uncertain_mutation |= e.requires_reconciliation();
                                return Err(e.code());
                            }
                            match key {
                                Some(key) => client.read_account(account, key),
                                None => client.read_account_devices(account),
                            }
                            .map(ApiValue::Account)
                            .map_err(|e| e.code())
                        }
                        AppCommand::RedeemVoucher { voucher } => {
                            if uncertain_mutation {
                                return Err("outcome_unknown");
                            }
                            let account = session.as_mut().ok_or("account_required")?;
                            let mut value = voucher.into_value();
                            let voucher = VoucherCode::new(std::mem::take(&mut *value))
                                .map_err(|e| e.code())?;
                            let key = job.public_key.as_deref().ok_or("identity_missing")?;
                            if let Err(e) = client.redeem_voucher(account, voucher) {
                                uncertain_mutation |= e.requires_reconciliation();
                                return Err(e.code());
                            }
                            client
                                .read_account(account, key)
                                .map(ApiValue::Account)
                                .map_err(|e| e.code())
                        }
                        _ => Err("invalid_api_command"),
                    }
                })();
                let draft = session
                    .as_ref()
                    .and_then(|s| crate::live_device::snapshot(&store, s).ok().flatten());
                if done
                    .send(ApiDone {
                        id: job.id,
                        result,
                        draft,
                    })
                    .is_err()
                {
                    break;
                }
            }
        })?;
    Ok((send, results))
}
struct Pending {
    request: AppRequest,
    reply: mpsc::SyncSender<AppReply>,
}
fn ipc_worker(identity: Identity, boot: String) -> io::Result<mpsc::Receiver<Pending>> {
    let (send, incoming) = mpsc::sync_channel(4);
    thread::Builder::new()
        .name("authorized-app-pipe".into())
        .spawn(move || loop {
            let mut pipe = match Pipe::accept(&identity, Duration::from_secs(1)) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let hello = AppReply::Hello {
                major: APP_API_MAJOR,
                boot_id: boot.clone(),
                build: env!("CARGO_PKG_VERSION").into(),
                source_sha: option_env!("ADAPTER_SOURCE_SHA")
                    .unwrap_or("unknown")
                    .into(),
            };
            if write_frame(&mut pipe, &hello).is_err() {
                continue;
            }
            let request: AppRequest = match read_frame(&mut pipe) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let id = request.request_id.clone();
            let (reply, answer) = mpsc::sync_channel(1);
            if send.try_send(Pending { request, reply }).is_err() {
                let _ = write_frame(&mut pipe, &failure("operation_busy"));
                continue;
            }
            let value = answer
                .recv_timeout(Duration::from_secs(2))
                .unwrap_or_else(|_| failure("owner_unavailable"));
            if write_frame(&mut pipe, &value).is_ok() {
                let ack: io::Result<ResponseAck> = read_frame(&mut pipe);
                if !matches!(ack,Ok(ref ack) if ack.request_id==id) {
                    continue;
                }
            }
        })?;
    Ok(incoming)
}
fn read_catalogue(bytes: &[u8]) -> Result<(adapter_catalogue::Catalogue, Vec<City>), &'static str> {
    let catalogue = adapter_catalogue::Catalogue::parse(bytes).map_err(|_| "invalid_metadata")?;
    let root: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| "invalid_metadata")?;
    let mut counts = BTreeMap::<&str, usize>::new();
    for relay in catalogue.relays() {
        *counts.entry(relay.location()).or_default() += usize::from(relay.active());
    }
    let cities = counts
        .into_iter()
        .map(|(id, relay_count)| {
            let location = &root["locations"][id];
            let text = |key: &str| {
                location[key]
                    .as_str()
                    .filter(|s| s.len() <= 128 && !s.chars().any(char::is_control))
                    .map(str::to_owned)
            };
            City {
                id: id.into(),
                name: text("city").unwrap_or_else(|| id.into()),
                country: text("country")
                    .unwrap_or_else(|| id.split('-').next().unwrap_or("").to_uppercase()),
                relay_count,
            }
        })
        .collect();
    Ok((catalogue, cities))
}

/// Explicit streaming import. Never reads a guessed path, registers, or prints keys.
pub fn import_stdin(scope: &str) -> io::Result<()> {
    let root = AppRoot::open(scope)?;
    let store = PrivateStore::open(&root.path().join("store"))?;
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take((MAX_IDENTITY_JSON + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_IDENTITY_JSON {
        return Err(io::Error::other("identity_payload_too_large"));
    }
    let text = Zeroizing::new(
        String::from_utf8(std::mem::take(&mut *bytes))
            .map_err(|_| io::Error::other("identity_invalid_json"))?,
    );
    let mut text = text;
    let proposed = TunnelIdentity::from_backup_json(std::mem::take(&mut *text))
        .map_err(|e| io::Error::other(e.code()))?;
    if let Some(current) = load_identity(&store).map_err(|e| io::Error::other(e.code()))? {
        if current.metadata() != proposed.metadata() {
            return Err(io::Error::other("identity_already_configured"));
        }
        println!("identity_already_imported");
        return Ok(());
    }
    let _verified = persist_identity(&store, &proposed).map_err(|e| io::Error::other(e.code()))?;
    println!("identity_imported");
    Ok(())
}

pub fn serve(scope: &str) -> io::Result<()> {
    let pipe_identity = Identity::current()?.with_scope(scope)?;
    let _instance = SingleInstance::acquire(&pipe_identity)?;
    let boot = boot_id()?;
    let root = AppRoot::open(scope)?;
    let store = PrivateStore::open(&root.path().join("store"))?;
    let mut identity = load_identity(&store).map_err(|e| io::Error::other(e.code()))?;
    let settings = load_settings(&store)?;
    let runtime =
        crate::live_runtime::resolve_process().map_err(|_| io::Error::other("runtime_invalid"))?;
    let observer = ObservedOwner::windows(State::new(boot.clone()))?;
    let mut owner = ResourceOwner::new(observer);
    let commands = ipc_worker(pipe_identity, boot.clone())?;
    let (api, api_results) = api_worker(store.clone(), root.path().to_owned())?;
    let logs = LogClient::start(root.path().to_owned())?;
    logs.event("start", "agent_started")?;
    let mut dashboard = Dashboard {
        sequence: 0,
        boot_id: boot,
        build: env!("CARGO_PKG_VERSION").into(),
        source_sha: option_env!("ADAPTER_SOURCE_SHA").unwrap_or("").into(),
        status: "disconnected".into(),
        physical_attachment: "unknown".into(),
        settings,
        front_ready: false,
        front_selected: "unavailable".into(),
        identity_configured: identity.is_some(),
        device_draft: None,
        device_name: identity.as_ref().map(|i| i.metadata().device_name.clone()),
        public_key: identity.as_ref().map(|i| i.metadata().public_key.clone()),
        active_relay: None,
        connection: None,
        readiness: None,
        cities: vec![],
        metadata_source: "missing".into(),
        metadata_updated_at: None,
        account: Account::default(),
        operation: None,
        last_error: None,
        logs_path: root
            .path()
            .join("events.jsonl")
            .to_string_lossy()
            .into_owned(),
        last_report_path: None,
        logging_degraded: false,
        logging_dropped: 0,
        quick_test: None,
        city_candidates: vec![],
    };
    let mut catalogue = None;
    let mut cache_options = OpenOptions::new();
    cache_options.read(true);
    let mut cache_data = Vec::new();
    let cached = match open_log_file(&root.path().join("relays.json"), cache_options) {
        Ok(file) => file
            .take((adapter_mullvad_api::RELAY_BODY_CAP + 1) as u64)
            .read_to_end(&mut cache_data)
            .map(|_| ())
            .map_err(|_| "metadata_cache_read_failed"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            Err("metadata_cache_access_denied")
        }
        Err(_) => Err("metadata_cache_read_failed"),
    }
    .and_then(|_| {
        if cache_data.is_empty() {
            return Ok(());
        }
        read_catalogue(&cache_data).map(|(parsed, cities)| {
            catalogue = Some(parsed);
            dashboard.cities = cities;
            dashboard.metadata_source = "local_cache".into();
        })
    });
    if let Err(code) = cached {
        dashboard.last_error = Some(code.into());
        logs.event("start", code)?;
    }
    let (_front, front_events, mailbox) = connection_lifecycle::mailbox();
    let (mut connections, tunnel_mailbox) =
        crate::live_connection::Connections::new(root.path().to_owned(), logs.clone());
    let tunnel_store = store.clone();
    let front_runtime = PrivateRuntime::open(&root.path().join("front"))?;
    let executable = runtime.mihomo.clone();
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(|_| io::Error::other("random_unavailable"))?;
    let secret = Zeroizing::new(
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
    random.fill(0);
    let port = dashboard.settings.front_port;
    owner.start_persistent(move |cancel| {
        let tunnel_executable = executable.clone();
        let result = ConnectionResource::build(
            FrontConfig {
                executable,
                runtime: front_runtime,
                mixed_port: port,
                controller_port: port
                    .checked_add(2)
                    .ok_or(adapter_control::owned_lifecycle::Failure::Start)?,
                slot_a: 17920,
                slot_b: 17930,
                controller_secret: secret,
            },
            mailbox,
            cancel,
        )?;
        match result {
            adapter_control::owned_lifecycle::BuildOutcome::Ready(mut resource) => {
                resource.attach_tunnels(tunnel_executable, tunnel_store, tunnel_mailbox);
                Ok(adapter_control::owned_lifecycle::BuildOutcome::Ready(
                    resource,
                ))
            }
            adapter_control::owned_lifecycle::BuildOutcome::CancelledClean => {
                Ok(adapter_control::owned_lifecycle::BuildOutcome::CancelledClean)
            }
        }
    })?;
    dashboard.status = "starting_front".into();
    let mut pending_work: Option<String> = None;
    let mut quick: Option<PendingQuick> = None;
    let mut queued_connect: Option<QueuedConnect> = None;
    let mut pings = BTreeMap::<String, PingObservation>::new();
    let mut ping_stamp = owner.observation().stamp();
    let mut maintenance = BTreeMap::<String, (u64, usize)>::new();
    let mut shutdown = false;
    let mut receipts = VecDeque::<(String, AppReply)>::new();
    let mut last_attachment = "unknown".to_string();
    loop {
        let (effect, event) = owner.poll();
        if let Some(event) = event {
            if shutdown && matches!(event, Event::Finished(_, Err(_))) {
                logs.event("stop", "cleanup_uncertain")?;
                return Err(io::Error::other("cleanup_uncertain"));
            }
            match event {
                Event::Ready(_) => {
                    dashboard.front_ready = true;
                    dashboard.front_selected = "reject".into();
                    dashboard.status = "disconnected".into();
                    logs.event("front", "ready_reject")?;
                }
                Event::Finished(_, result) => {
                    connections.freeze();
                    dashboard.front_ready = false;
                    dashboard.front_selected = "unavailable".into();
                    dashboard.status = "blocked".into();
                    if result.is_err() {
                        dashboard.last_error = Some("front_stopped_uncertain".into());
                    }
                    logs.event(
                        "front",
                        if result.is_ok() {
                            "stopped"
                        } else {
                            "stopped_uncertain"
                        },
                    )?;
                }
            }
        }
        dashboard.physical_attachment = match owner.state().attachment {
            Attachment::Available => "available",
            Attachment::Unavailable => "unavailable",
            Attachment::Unknown => "unknown",
        }
        .into();
        if last_attachment != dashboard.physical_attachment {
            logs.event("physical", &dashboard.physical_attachment)?;
            last_attachment = dashboard.physical_attachment.clone();
        }
        let stamp = owner.observation().stamp();
        let binding_changed = ping_stamp != stamp;
        if stamp.is_none() || binding_changed {
            pings.clear();
        }
        if binding_changed && stamp.is_some() {
            logs.event("physical", "binding_changed")?;
            connections.recheck_soon();
        }
        ping_stamp = stamp;
        if let Some(status) = crate::live_status::attachment_status(
            owner.state().attachment,
            owner.state().paused,
            &dashboard.status,
            owner.state().path.is_some(),
            binding_changed,
        ) {
            dashboard.status = status.into();
            dashboard.readiness = None;
        }
        let mut quick_finished = None;
        if let Some(pending) = &mut quick {
            for _ in 0..16 {
                match pending.run.receive.try_recv() {
                    Ok(QuickMessage::Observed {
                        hostname,
                        result,
                        measured,
                    }) => {
                        {
                            let progress = &mut pending.progress;
                            progress.completed += 1;
                            let current = owner.is_operation_current(&pending.ticket)
                                && measured.elapsed() < Duration::from_secs(2)
                                && result != Err("icmp_cancelled");
                            if current {
                                match result {
                                    Ok(PingResult::Reply { .. }) => progress.replies += 1,
                                    Ok(PingResult::NoReply { .. }) => progress.no_reply += 1,
                                    Err(_) => progress.local_errors += 1,
                                }
                            } else {
                                progress.discarded += 1;
                            }
                            progress.unmeasured = progress.total.saturating_sub(progress.completed);
                            if current {
                                pending.observed.insert(
                                    hostname,
                                    PingObservation {
                                        city: progress.city.clone(),
                                        result,
                                        measured,
                                        at: now_seconds(),
                                    },
                                );
                            }
                        }
                        if !pending.automatic {
                            dashboard.quick_test = Some(pending.progress.clone());
                        }
                    }
                    Ok(QuickMessage::Finished { unmeasured }) => {
                        quick_finished = Some(unmeasured);
                        break;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        quick_finished = Some(usize::MAX);
                        break;
                    }
                }
            }
        }
        if let Some(unmeasured) = quick_finished {
            let mut pending = quick.take().unwrap();
            let valid = unmeasured != usize::MAX && owner.is_operation_current(&pending.ticket);
            // Receipt means all four lanes have actually returned; cancellation
            // alone must never release this registry for a replacement batch.
            owner.finish_operation(&pending.ticket);
            if valid {
                pings.extend(pending.observed);
            }
            {
                let progress = &mut pending.progress;
                if !valid {
                    progress.discarded +=
                        progress.replies + progress.no_reply + progress.local_errors;
                    progress.replies = 0;
                    progress.no_reply = 0;
                    progress.local_errors = 0;
                }
                progress.active = false;
                progress.cancelled = !valid;
                progress.finished_at = Some(now_seconds());
                progress.unmeasured = progress.total.saturating_sub(progress.completed);
            }
            if !pending.automatic && pending_work.is_none() {
                dashboard.operation = None;
            }
            logs.quick(
                match (pending.automatic, valid) {
                    (true, true) => "maintenance_complete",
                    (true, false) => "maintenance_cancelled",
                    (false, true) => "complete",
                    (false, false) => "cancelled",
                },
                &pending.progress,
            )?;
            if !pending.automatic {
                dashboard.quick_test = Some(pending.progress);
            }
        }
        // User intent preempts automatic ICMP maintenance, but cancellation is
        // not completion: keep the owner occupied until every native call has
        // returned and the Finished receipt above releases its ticket.
        if quick.is_none() {
            if let Some(intent) = queued_connect.take() {
                dashboard.operation = None;
                let result = match (identity.as_ref(), catalogue.as_ref()) {
                    (Some(identity), Some(catalogue)) => connections.connect(
                        &mut owner,
                        &mut dashboard,
                        identity,
                        catalogue,
                        intent.relay.as_deref(),
                        false,
                    ),
                    (None, _) => Err("identity_missing"),
                    (_, None) => Err("metadata_missing"),
                };
                if let Err(code) = result {
                    dashboard.last_error = Some(code.into());
                    logs.event("connection", code)?;
                }
            }
        }
        update_candidates(&mut dashboard, &pings);
        while let Some(reply) = front_events.poll() {
            dashboard.front_selected = match reply.status {
                FrontStatus::Reject => "reject",
                FrontStatus::SlotA => "slot_a",
                FrontStatus::SlotB => "slot_b",
                FrontStatus::Unavailable => "unavailable",
            }
            .into();
        }
        connections.poll(
            &mut owner,
            &mut dashboard,
            identity.as_ref(),
            catalogue.as_ref(),
            matches!(effect, Some(adapter_domain::Effect::Verify(_, _))),
        );
        if let Ok(done) = api_results.try_recv() {
            if pending_work.as_deref() == Some(done.id.as_str()) {
                dashboard.operation = quick
                    .as_ref()
                    .filter(|q| !q.automatic)
                    .map(|_| "quick_test".into());
                pending_work = None;
                dashboard.device_draft = done.draft.map(|draft| DeviceDraft {
                    state: draft.state,
                    public_key: draft.public_key,
                    device_id: draft.device_id,
                    device_name: draft.device_name,
                });
                match done.result {
                    Ok(ApiValue::Catalogue(parsed, cities, updated_at)) => {
                        owner.cancel_current_operation();
                        pings.clear();
                        maintenance.clear();
                        catalogue = Some(parsed);
                        dashboard.cities = cities;
                        dashboard.metadata_source = "official_api".into();
                        dashboard.metadata_updated_at = Some(updated_at);
                        dashboard.last_error = None;
                    }
                    Ok(ApiValue::Account(account)) => {
                        dashboard.account = Account {
                            authenticated: true,
                            expiry: Some(account.expiry),
                            devices: account
                                .devices
                                .into_iter()
                                .map(|d| Device {
                                    id: d.id.as_str().into(),
                                    name: d.name,
                                    public_key: d.pubkey,
                                    created: d.created,
                                    current: d.current,
                                })
                                .collect(),
                            error_code: None,
                        };
                        dashboard.last_error = None;
                    }
                    Ok(ApiValue::Draft(draft)) => {
                        dashboard.device_draft = Some(DeviceDraft {
                            state: draft.state,
                            public_key: draft.public_key,
                            device_id: draft.device_id,
                            device_name: draft.device_name,
                        });
                        dashboard.last_error = None;
                    }
                    Ok(ApiValue::DeviceIdentity(value)) => {
                        connections.identity_changed(&mut owner);
                        dashboard.identity_configured = true;
                        dashboard.device_name = Some(value.metadata().device_name.clone());
                        dashboard.public_key = Some(value.metadata().public_key.clone());
                        identity = Some(value);
                        dashboard.account.devices.clear();
                        dashboard.last_error = None;
                    }
                    Ok(ApiValue::Login) => {
                        dashboard.account.authenticated = true;
                        dashboard.account.error_code = None;
                    }
                    Ok(ApiValue::Logout) => {
                        dashboard.account = Account::default();
                        dashboard.last_error = None;
                    }
                    Ok(ApiValue::Settings(settings)) => {
                        owner.state_mut().manual_preempt();
                        dashboard.settings = settings;
                        dashboard.last_error = None;
                    }
                    Ok(ApiValue::Report(path)) => {
                        dashboard.last_report_path = Some(path.to_string_lossy().into_owned());
                        dashboard.last_error = None;
                    }
                    Err(code) => {
                        if crate::live_device::fence_uncertain_activation(code, &mut identity) {
                            connections.identity_changed(&mut owner);
                            dashboard.identity_configured = false;
                            dashboard.device_name = None;
                            dashboard.public_key = None;
                            dashboard.account.devices.clear();
                            dashboard.connection = None;
                            dashboard.readiness = None;
                            dashboard.status = "blocked".into();
                        }
                        dashboard.last_error = Some(code.into());
                        dashboard.account.error_code = Some(code.into());
                    }
                }
                logs.event("api", dashboard.last_error.as_deref().unwrap_or("complete"))?;
            }
        }
        dashboard.logging_degraded = logs.fault.load(Ordering::Acquire);
        dashboard.logging_dropped = logs.dropped.load(Ordering::Acquire);
        dashboard.sequence = dashboard.sequence.saturating_add(1);
        if let Ok(pending) = commands.try_recv() {
            let request = pending.request;
            let read_only = matches!(
                request.command,
                AppCommand::Dashboard | AppCommand::Relays { .. } | AppCommand::RevealKey { .. }
            );
            let id = request.request_id;
            let reply = if request.major != APP_API_MAJOR || request.boot_id != dashboard.boot_id {
                failure("boot_changed_reconcile")
            } else if let Some((_, reply)) = receipts.iter().find(|(key, _)| key == &id) {
                reply.clone()
            } else {
                // Validate before destructuring a secret command; error strings
                // never include request bodies or upstream responses.
                let checked = AppRequest {
                    major: request.major,
                    boot_id: request.boot_id,
                    request_id: id.clone(),
                    command: request.command,
                };
                if let Err(code) = checked.validate(&dashboard.boot_id) {
                    failure(code)
                } else {
                    match checked.command {
                        AppCommand::Dashboard => AppReply::Dashboard {
                            dashboard: Box::new(dashboard.clone()),
                        },
                        AppCommand::ExportReport => {
                            if pending_work.is_some()
                                || queued_connect.is_some()
                                || dashboard.operation.is_some()
                                || connections.busy()
                            {
                                failure("operation_busy")
                            } else {
                                let operation_id = boot_id()?;
                                let job = ApiJob {
                                    id: operation_id.clone(),
                                    proxy: 0,
                                    public_key: None,
                                    command: WorkCommand::Report(Box::new(dashboard.clone())),
                                };
                                if api.try_send(job).is_err() {
                                    failure("operation_busy")
                                } else {
                                    pending_work = Some(operation_id.clone());
                                    dashboard.operation = Some("report_export".into());
                                    AppReply::Accepted { operation_id }
                                }
                            }
                        }
                        AppCommand::Relays { city, page } => {
                            let all: Vec<_> = catalogue
                                .as_ref()
                                .map(|c| {
                                    c.relays()
                                        .iter()
                                        .filter(|r| {
                                            city.as_ref().map_or(true, |city| r.location() == city)
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();
                            let total = all.len();
                            let relays = all
                                .into_iter()
                                .skip(usize::from(page) * 64)
                                .take(64)
                                .map(|r| Relay {
                                    hostname: r.hostname().into(),
                                    city: r.location().into(),
                                    active: r.active(),
                                    ipv4: r.ipv4().is_some(),
                                    ipv6: r.ipv6().is_some(),
                                    shadowsocks: catalogue
                                        .as_ref()
                                        .unwrap()
                                        .transports(r)
                                        .contains(&adapter_catalogue::Transport::Shadowsocks),
                                    last_ping_ms: pings
                                        .get(r.hostname())
                                        .filter(|p| p.measured.elapsed() < PING_DISPLAY_TTL)
                                        .and_then(|p| match p.result {
                                            Ok(PingResult::Reply { rtt_ms }) => {
                                                Some(u64::from(rtt_ms))
                                            }
                                            _ => None,
                                        }),
                                    readiness: None,
                                })
                                .collect();
                            AppReply::Relays {
                                relays,
                                page,
                                total,
                            }
                        }
                        AppCommand::SaveSettings { settings } => {
                            if dashboard.operation.is_some() {
                                failure("operation_busy")
                            } else if settings.required_multihop || settings.required_pq {
                                failure("protection_unsupported")
                            } else if settings.front_port != dashboard.settings.front_port {
                                failure("front_port_restart_required")
                            } else if settings
                                .favorite_cities
                                .iter()
                                .any(|id| !dashboard.cities.iter().any(|c| &c.id == id))
                            {
                                failure("invalid_city")
                            } else {
                                let operation_id = boot_id()?;
                                let job = ApiJob {
                                    id: operation_id.clone(),
                                    proxy: 0,
                                    public_key: None,
                                    command: WorkCommand::Save(settings),
                                };
                                if api.try_send(job).is_err() {
                                    failure("operation_busy")
                                } else {
                                    pending_work = Some(operation_id.clone());
                                    dashboard.operation = Some("settings_save".into());
                                    AppReply::Accepted { operation_id }
                                }
                            }
                        }
                        AppCommand::SelectCity { city } => {
                            if dashboard.operation.is_some() {
                                failure("operation_busy")
                            } else if !dashboard.settings.favorite_cities.contains(&city) {
                                failure("invalid_city")
                            } else {
                                let mut settings = dashboard.settings.clone();
                                settings.selected_city = Some(city);
                                let operation_id = boot_id()?;
                                let job = ApiJob {
                                    id: operation_id.clone(),
                                    proxy: 0,
                                    public_key: None,
                                    command: WorkCommand::Save(settings),
                                };
                                if api.try_send(job).is_err() {
                                    failure("operation_busy")
                                } else {
                                    pending_work = Some(operation_id.clone());
                                    dashboard.operation = Some("settings_save".into());
                                    AppReply::Accepted { operation_id }
                                }
                            }
                        }
                        AppCommand::RevealKey { confirm: true } => {
                            if let Some(identity) = &identity {
                                AppReply::PrivateKey {
                                    private_key: SecretText::from_protected(
                                        identity.reveal_for_local_view(),
                                    ),
                                }
                            } else {
                                failure("identity_missing")
                            }
                        }
                        AppCommand::UseCreatedDevice { .. }
                            if connections.busy()
                                || dashboard.active_relay.is_some()
                                || dashboard.status != "disconnected"
                                || dashboard.front_selected != "reject" =>
                        {
                            failure("disconnect_before_identity_change")
                        }
                        command @ (AppCommand::Connect | AppCommand::ConnectRelay { .. }) => {
                            let relay = match &command {
                                AppCommand::ConnectRelay { hostname } => Some(hostname.as_str()),
                                _ => None,
                            };
                            if queued_connect.is_some()
                                || pending_work.is_some()
                                || connections.busy()
                            {
                                failure("operation_busy")
                            } else if quick.as_ref().is_some_and(|q| q.automatic) {
                                let operation_id = boot_id()?;
                                owner.cancel_current_operation();
                                connections.begin_user_selection();
                                queued_connect = Some(QueuedConnect {
                                    relay: relay.map(str::to_owned),
                                });
                                dashboard.operation = Some("connect".into());
                                dashboard.last_error = None;
                                logs.event("connection", "maintenance_preempted")?;
                                AppReply::Accepted { operation_id }
                            } else if quick.is_some() {
                                failure("operation_busy")
                            } else if let (Some(identity), Some(catalogue)) =
                                (identity.as_ref(), catalogue.as_ref())
                            {
                                connections.begin_user_selection();
                                match connections.connect(
                                    &mut owner,
                                    &mut dashboard,
                                    identity,
                                    catalogue,
                                    relay,
                                    false,
                                ) {
                                    Ok(operation_id) => AppReply::Accepted { operation_id },
                                    Err(code) => {
                                        dashboard.last_error = Some(code.into());
                                        failure(code)
                                    }
                                }
                            } else {
                                failure(if identity.is_none() {
                                    "identity_missing"
                                } else {
                                    "metadata_missing"
                                })
                            }
                        }
                        AppCommand::FullTest { .. } => failure("use_connection_validation"),
                        AppCommand::QuickTest { city } => {
                            if dashboard.operation.is_some()
                                || quick.is_some()
                                || connections.busy()
                            {
                                failure("operation_busy")
                            } else if owner.state().paused {
                                failure("waiting_network")
                            } else if !dashboard.front_ready {
                                failure("front_unavailable")
                            } else if owner.state().attachment != Attachment::Available {
                                failure("physical_binding_unavailable")
                            } else if let Some(catalogue) = &catalogue {
                                let targets: Vec<_> = catalogue
                                    .active_in_city(&city)
                                    .filter_map(|r| {
                                        r.ipv4().map(|address| Target {
                                            hostname: r.hostname().into(),
                                            address,
                                        })
                                    })
                                    .collect();
                                if targets.is_empty() {
                                    failure("quick_targets_missing")
                                } else if targets.len() > crate::live_quick::MAX_CITY_RELAYS {
                                    failure("quick_city_too_large")
                                } else if let Some(binding) = owner
                                    .observation()
                                    .bindings()
                                    .iter()
                                    .find(|b| b.ipv4)
                                    .copied()
                                {
                                    let total = targets.len();
                                    match owner.begin_operation(
                                        binding,
                                        dashboard.sequence.max(1),
                                        None,
                                    ) {
                                        Err(_) => failure("physical_binding_unavailable"),
                                        Ok((ticket, network)) => {
                                            match QuickRun::start(targets, network) {
                                                Err(_) => {
                                                    owner.finish_operation(&ticket);
                                                    failure("quick_start_failed")
                                                }
                                                Ok(run) => {
                                                    let operation_id =
                                                        format!("quick-{}", ticket.id());
                                                    quick = Some(PendingQuick {
                                                        ticket,
                                                        run,
                                                        observed: BTreeMap::new(),
                                                        automatic: false,
                                                        progress: QuickTestState {
                                                            city: city.clone(),
                                                            total,
                                                            completed: 0,
                                                            replies: 0,
                                                            no_reply: 0,
                                                            local_errors: 0,
                                                            discarded: 0,
                                                            unmeasured: total,
                                                            active: true,
                                                            cancelled: false,
                                                            finished_at: None,
                                                        },
                                                    });
                                                    dashboard.quick_test = Some(QuickTestState {
                                                        city,
                                                        total,
                                                        completed: 0,
                                                        replies: 0,
                                                        no_reply: 0,
                                                        local_errors: 0,
                                                        discarded: 0,
                                                        unmeasured: total,
                                                        active: true,
                                                        cancelled: false,
                                                        finished_at: None,
                                                    });
                                                    dashboard.operation = Some("quick_test".into());
                                                    dashboard.last_error = None;
                                                    logs.quick(
                                                        "started",
                                                        dashboard.quick_test.as_ref().unwrap(),
                                                    )?;
                                                    AppReply::Accepted { operation_id }
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    failure("physical_binding_unavailable")
                                }
                            } else {
                                failure("metadata_missing")
                            }
                        }
                        AppCommand::CancelOperation => {
                            if queued_connect.take().is_some() {
                                owner.cancel_current_operation();
                                dashboard.operation = None;
                                AppReply::Accepted {
                                    operation_id: "queued-connection-cancel".into(),
                                }
                            } else if connections.busy() {
                                match connections.disconnect(&mut owner, &mut dashboard) {
                                    Ok(()) => AppReply::Accepted {
                                        operation_id: "connection-cancel".into(),
                                    },
                                    Err(code) => failure(code),
                                }
                            } else if quick.is_some() {
                                owner.cancel_current_operation();
                                AppReply::Accepted {
                                    operation_id: "quick-cancel".into(),
                                }
                            } else if pending_work.is_some() {
                                failure("operation_cannot_cancel")
                            } else {
                                failure("operation_missing")
                            }
                        }
                        AppCommand::Disconnect => {
                            if queued_connect.take().is_some() {
                                dashboard.operation = None;
                            }
                            match connections.disconnect(&mut owner, &mut dashboard) {
                                Ok(()) => AppReply::Accepted {
                                    operation_id: "disconnect".into(),
                                },
                                Err(code) => failure(code),
                            }
                        }
                        AppCommand::Shutdown => {
                            queued_connect = None;
                            shutdown = true;
                            owner.cancel();
                            AppReply::Accepted {
                                operation_id: "shutdown".into(),
                            }
                        }
                        command => {
                            if dashboard.operation.is_some() {
                                failure("operation_busy")
                            } else {
                                let operation_id = boot_id()?;
                                let label = match &command {
                                    AppCommand::RefreshCatalogue => "metadata_refresh",
                                    AppCommand::AccountLogin { .. } => "account_login",
                                    AppCommand::AccountRefresh => "account_refresh",
                                    AppCommand::AccountLogout => "account_logout",
                                    AppCommand::RemoveDevice { .. } => "device_remove",
                                    AppCommand::CreateDevice { .. } => "device_create",
                                    AppCommand::UseCreatedDevice { .. } => "device_activate",
                                    AppCommand::RedeemVoucher { .. } => "voucher_redeem",
                                    _ => "operation",
                                };
                                let job = ApiJob {
                                    id: operation_id.clone(),
                                    proxy: dashboard.settings.bootstrap_port.unwrap_or(0),
                                    public_key: dashboard.public_key.clone(),
                                    command: WorkCommand::Api(command),
                                };
                                if api.try_send(job).is_err() {
                                    failure("operation_busy")
                                } else {
                                    pending_work = Some(operation_id.clone());
                                    dashboard.operation = Some(label.into());
                                    dashboard.last_error = None;
                                    AppReply::Accepted { operation_id }
                                }
                            }
                        }
                    }
                }
            };
            if !read_only {
                if receipts.len() >= 128 {
                    receipts.pop_front();
                }
                receipts.push_back((id, reply.clone()));
            }
            let _ = pending.reply.try_send(reply);
        }
        // Maintenance is deliberately tiny: two ICMP targets in ONE city at
        // a time. It never acquires a tunnel identity or blocks account/disk I/O.
        // User operations have priority because this runs after IPC dispatch.
        if !shutdown
            && quick.is_none()
            && pending_work.is_none()
            && dashboard.operation.is_none()
            && dashboard.settings.automatic_recovery
            && dashboard.front_ready
            && owner.state().attachment == Attachment::Available
            && !owner.state().paused
        {
            let now = owner.now();
            let mut cities = dashboard.settings.favorite_cities.clone();
            cities.sort_by_key(|c| {
                if Some(c) == dashboard.settings.selected_city.as_ref() {
                    0
                } else {
                    1
                }
            });
            let due = cities
                .into_iter()
                .find(|city| maintenance.get(city).map_or(true, |(at, _)| now >= *at));
            if let (Some(city), Some(catalogue), Some(binding)) = (
                due,
                &catalogue,
                owner
                    .observation()
                    .bindings()
                    .iter()
                    .find(|b| b.ipv4)
                    .copied(),
            ) {
                let relays: Vec<_> = catalogue
                    .active_in_city(&city)
                    .filter_map(|r| r.ipv4().map(|address| (r.hostname(), address)))
                    .collect();
                let cursor = maintenance.get(&city).map_or(0, |(_, cursor)| *cursor);
                let targets: Vec<_> = relays
                    .iter()
                    .cycle()
                    .skip(if relays.is_empty() {
                        0
                    } else {
                        cursor % relays.len()
                    })
                    .take(relays.len().min(2))
                    .map(|(hostname, address)| Target {
                        hostname: (*hostname).into(),
                        address: *address,
                    })
                    .collect();
                let period = if Some(&city) == dashboard.settings.selected_city.as_ref() {
                    30_000
                } else {
                    180_000
                };
                maintenance.insert(
                    city.clone(),
                    (now.saturating_add(period), cursor.saturating_add(2)),
                );
                if !targets.is_empty() {
                    let total = targets.len();
                    if let Ok((ticket, network)) =
                        owner.begin_operation(binding, dashboard.sequence.max(1), None)
                    {
                        match QuickRun::start(targets, network) {
                            Ok(run) => {
                                quick = Some(PendingQuick {
                                    ticket,
                                    run,
                                    observed: BTreeMap::new(),
                                    automatic: true,
                                    progress: QuickTestState {
                                        city,
                                        total,
                                        completed: 0,
                                        replies: 0,
                                        no_reply: 0,
                                        local_errors: 0,
                                        discarded: 0,
                                        unmeasured: total,
                                        active: true,
                                        cancelled: false,
                                        finished_at: None,
                                    },
                                });
                                logs.quick(
                                    "maintenance_started",
                                    &quick.as_ref().unwrap().progress,
                                )?;
                            }
                            Err(_) => {
                                owner.finish_operation(&ticket);
                            }
                        }
                    }
                }
            }
        }
        if shutdown && !owner.has_active_resource() && quick.is_none() {
            if owner.replacement_blocked() {
                logs.event("stop", "cleanup_uncertain")?;
                return Err(io::Error::other("cleanup_uncertain"));
            }
            logs.event("stop", "agent_stopped")?;
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
}
