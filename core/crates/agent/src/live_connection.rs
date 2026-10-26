//! Product connection owner. Network/process I/O stays in the persistent resource.
use crate::live_identity::TunnelIdentity;
use crate::live_route::{self, Route};
use adapter_control::owned_lifecycle::{OperationTicket, ResourceOwner};
use adapter_domain::{Attachment, CandidateAttempt, Path};
use adapter_engine_mihomo::{
    connection_tunnel::{self, Command, Reply, TunnelSpec},
    controller::Selected,
};
use adapter_platform::windows_runtime::PrivateRuntime;
use adapter_protocol::app::{ConnectionInfo, Dashboard};
use std::{
    collections::{BTreeSet, VecDeque},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
const HEALTHY_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq)]
enum TrialKind {
    TestBackup,
    ReturnDirect,
    ChainFallback,
}
struct RouteTrial {
    kind: TrialKind,
    previous: Option<Path>,
    restoring: bool,
    tested: bool,
    verified_backup: Option<Path>,
    rescue: bool,
    alternate_used: bool,
}
struct Pending {
    ticket: OperationTicket,
    attempt: Option<CandidateAttempt>,
    promoting: bool,
    aborting: bool,
    automatic: bool,
    rejected: Option<(u64, adapter_domain::Canary)>,
    retry_stale: bool,
    retry_network: bool,
    failed_reply: Option<crate::recovery_retry::AttemptFailureDisposition>,
}
pub(crate) struct Connections {
    pub(crate) client: connection_tunnel::Client,
    events: connection_tunnel::Events,
    root: PathBuf,
    pending: Option<Pending>,
    held_reply: Option<Reply>,
    parameter_wait_since: Option<Instant>,
    next_instance: u64,
    next_health: Instant,
    local_probe_failures: u8,
    recovering: Option<(Instant, VecDeque<String>)>,
    manual_candidates: Option<(Instant, String, VecDeque<String>, bool)>,
    deferred: Option<String>,
    last_relay: Option<String>,
    startup_route: Option<(String, Route)>,
    disconnecting: bool,
    next_attempt: Instant,
    logs: crate::live_diagnostics::LogClient,
    frozen: bool,
    inlet_trials: crate::inlet_trials::InletTrials,
    chain: Option<Arc<adapter_engine_mihomo::chain::UpstreamSs>>,
    chain_relays: BTreeSet<String>,
    chain_mode: adapter_protocol::app::TunnelRoute,
    retry_round: crate::recovery_retry::RecoveryRetry,
    local_retry: crate::recovery_retry::LocalFailureRetry,
    plan: crate::recovery_plan::RoundPlan,
    active_failures: crate::recovery_plan::ActiveFailures,
    direct_return: crate::recovery_plan::DirectReturn,
    route_trial: Option<RouteTrial>,
    forced_route: Option<bool>,
    restore_target: Option<Path>,
    history_save: Option<(
        std::sync::mpsc::SyncSender<()>,
        Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    )>,
    chain_store: Option<adapter_platform::windows_store::PrivateStore>,
    verified_chain: Option<crate::verified_chain::VerifiedChain>,
}
impl Connections {
    pub(crate) fn new(
        root: PathBuf,
        logs: crate::live_diagnostics::LogClient,
    ) -> (Self, connection_tunnel::Mailbox) {
        let (client, events, mailbox) = connection_tunnel::mailbox();
        (
            Self {
                client,
                events,
                root,
                pending: None,
                held_reply: None,
                parameter_wait_since: None,
                next_instance: 0,
                next_health: Instant::now(),
                local_probe_failures: 0,
                recovering: None,
                manual_candidates: None,
                deferred: None,
                last_relay: None,
                startup_route: None,
                disconnecting: false,
                next_attempt: Instant::now(),
                logs,
                frozen: false,
                inlet_trials: Default::default(),
                chain: None,
                chain_relays: Default::default(),
                chain_mode: adapter_protocol::app::TunnelRoute::Auto,
                retry_round: Default::default(),
                local_retry: Default::default(),
                plan: Default::default(),
                active_failures: Default::default(),
                direct_return: Default::default(),
                route_trial: None,
                forced_route: None,
                restore_target: None,
                history_save: None,
                chain_store: None,
                verified_chain: None,
            },
            mailbox,
        )
    }
    pub(crate) fn set_chain(
        &mut self,
        chain: Option<Arc<adapter_engine_mihomo::chain::UpstreamSs>>,
    ) {
        self.chain = chain;
    }
    fn clear_plan(&mut self) {
        self.plan.clear();
        self.active_failures.clear();
        self.direct_return.clear();
        self.route_trial = None;
        self.forced_route = None;
        self.restore_target = None;
        self.startup_route = None;
    }
    fn begin_route_trial(&mut self) {
        // Route trials have a temporary target and rollback path. Keep the
        // persistent city/relay intent used by ordinary recovery.
        self.plan.clear();
        self.startup_route = None;
        self.active_failures.clear();
        self.route_trial = None;
        self.forced_route = None;
        self.restore_target = None;
        self.inlet_trials.clear();
        self.chain_relays.clear();
        self.manual_candidates = None;
        self.recovering = None;
        self.deferred = None;
        self.local_retry.clear();
        self.next_attempt = Instant::now();
    }
    fn begin_recovery_action(
        &mut self,
        action: adapter_protocol::app::RecoveryAction,
        city: Option<&str>,
        relay: Option<&str>,
    ) {
        if let Some(persistent_relay) =
            crate::recovery_retry::persistent_relay_for_action(action, relay)
        {
            self.begin_user_selection(city, persistent_relay);
        } else {
            self.begin_route_trial();
        }
    }
    pub(crate) fn restore_history(&mut self, store: adapter_platform::windows_store::PrivateStore) {
        use adapter_platform::storage_record::RecordKind;
        self.verified_chain = store
            .load(RecordKind::VerifiedChain)
            .ok()
            .and_then(|bytes| crate::verified_chain::VerifiedChain::decode(bytes.expose()).ok());
        self.chain_store = Some(store.clone());
        if let Ok(bytes) = store.load(RecordKind::RecoveryHistory) {
            self.inlet_trials.restore_history(bytes.expose());
        }
        let (send, receive) = std::sync::mpsc::sync_channel::<()>(1);
        let latest = Arc::new(std::sync::Mutex::new(None::<Vec<u8>>));
        let pending = latest.clone();
        let logs = self.logs.clone();
        if std::thread::Builder::new()
            .name("inlet-history-save".into())
            .spawn(move || {
                while receive.recv().is_ok() {
                    let bytes = pending.lock().ok().and_then(|mut p| p.take());
                    let Some(bytes) = bytes else {
                        continue;
                    };
                    if store
                        .prepare(RecordKind::RecoveryHistory, &bytes)
                        .and_then(|p| p.commit())
                        .is_err()
                    {
                        let _ = logs.event("connection", "recovery_history_save_failed");
                    }
                }
            })
            .is_ok()
        {
            self.history_save = Some((send, latest));
        }
    }
    fn save_history(&self) {
        let Some((send, pending)) = &self.history_save else {
            return;
        };
        let Some(bytes) = self.inlet_trials.history_bytes() else {
            let _ = self
                .logs
                .event("connection", "recovery_history_save_failed");
            return;
        };
        // Coalesce to the newest full snapshot while disk I/O is in flight;
        // a full notification queue must not discard the newest attempts.
        if let Ok(mut latest) = pending.lock() {
            *latest = Some(bytes);
        }
        let _ = send.try_send(());
    }
    pub(crate) fn verified_at(&self, fingerprint: Option<&str>) -> Option<u64> {
        self.verified_chain
            .as_ref()
            .filter(|v| v.matches(fingerprint))
            .map(|v| v.at)
    }
    pub(crate) fn saved_verified_chain(
        &self,
    ) -> Option<Arc<adapter_engine_mihomo::chain::UpstreamSs>> {
        self.verified_chain.as_ref().map(|v| v.proxy.clone())
    }
    pub(crate) fn chain_change_busy(&self) -> bool {
        self.pending.is_some()
            || self.route_trial.is_some()
            || self.recovering.is_some()
            || self.manual_candidates.is_some()
            || self.deferred.is_some()
    }
    fn record_verified_chain(&mut self, dashboard: &mut Dashboard) {
        let Some(proxy) = self.chain.clone() else {
            return;
        };
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let verified = crate::verified_chain::VerifiedChain { proxy, at };
        // A tiny atomic encrypted write after promotion, never a network wait
        // or WG start. Keep the old snapshot if preparing/committing fails.
        let saved = self.chain_store.as_ref().is_some_and(|store| {
            verified
                .encode()
                .and_then(|bytes| {
                    store.prepare(
                        adapter_platform::storage_record::RecordKind::VerifiedChain,
                        &bytes,
                    )
                })
                .and_then(|write| write.commit())
                .is_ok()
        });
        if saved {
            self.verified_chain = Some(verified);
        } else {
            dashboard.last_error = Some("chain_write_failed".into());
            let _ = self.logs.event("api", "chain_write_failed");
        }
        dashboard.backup_verified_at = self.verified_at(dashboard.chain_fingerprint.as_deref());
    }
    fn active_negative(
        &mut self,
        owner: &mut ResourceOwner,
        dashboard: &mut Dashboard,
        catalogue: Option<&adapter_catalogue::Catalogue>,
    ) {
        let Some(instance) = owner.state().path.as_ref().map(|p| p.instance) else {
            return;
        };
        if !self.active_failures.failed(instance) {
            self.next_health = Instant::now() + Duration::from_secs(2);
            dashboard.status = "confirming_path".into();
            let _ = self.logs.event("connection", "active_failure_confirmation");
        } else {
            self.next_health = Instant::now() + Duration::from_secs(15);
            if let Some(catalogue) = catalogue {
                self.recovery(owner, dashboard, catalogue);
            }
        }
    }
    /// Both Unready and Prepared->Abort->Stopped reach here only AFTER cleanup.
    fn measured_failure(
        &mut self,
        owner: &mut ResourceOwner,
        dashboard: &mut Dashboard,
        pending: &Pending,
        at: u64,
        canary: adapter_domain::Canary,
        catalogue: Option<&adapter_catalogue::Catalogue>,
    ) -> Option<bool> {
        let Some(attempt) = &pending.attempt else {
            return None;
        };
        let now = owner.now();
        if owner.state().paused
            || !owner
                .state()
                .candidate_evidence_is_current(attempt, at, now)
        {
            return None;
        }
        self.local_retry.clear();
        if self.route_trial.is_some() {
            if !canary.alive()
                && self.advance_trial_inlet(&attempt.path, catalogue, pending.automatic)
            {
                return Some(true);
            }
            return Some(self.trial_failed(owner, dashboard, true));
        }
        let delay = if !canary.alive() {
            self.plan.short_retry(
                &attempt.path.relay,
                &attempt.path.inlet,
                &attempt.path.transport,
            )
        } else {
            None
        };
        if owner.state().stage == adapter_domain::Stage::RebuildOriginal {
            let _ = owner.state_mut().original_rebuilt_retry(
                attempt,
                adapter_domain::RebuildResult::Canary {
                    path: attempt.path.clone(),
                    canary,
                },
                at,
                now,
                delay.map(|d| d.as_millis() as u64),
            );
        }
        if let Some(delay) = delay {
            if pending.automatic {
                self.deferred = Some(attempt.path.relay.clone());
            } else {
                self.retry_manual_candidate(attempt.path.relay.clone(), true);
            }
            self.next_attempt = Instant::now() + delay;
            let _ = self.logs.event("connection", "original_inlet_short_retry");
            return Some(true);
        }
        if canary.alive() {
            if pending.automatic {
                self.defer_stale_candidate(attempt.path.relay.clone());
            } else {
                self.retry_manual_candidate(attempt.path.relay.clone(), true);
            }
            self.next_attempt = Instant::now() + Duration::from_secs(2);
            return Some(true);
        }
        let advanced = self.advance_inlet(
            &attempt.path,
            catalogue,
            pending.automatic,
            owner.state().stage == adapter_domain::Stage::Fallback,
        );
        self.save_history();
        Some(advanced)
    }
    fn enter_next_phase(&mut self, owner: &mut ResourceOwner, dashboard: &Dashboard) -> bool {
        if self.route_trial.is_none()
            && dashboard.settings.tunnel_route != adapter_protocol::app::TunnelRoute::Chain
            && self.plan.enter_native()
        {
            self.refill_phase(owner);
            let code = if self.plan.native_phase == Some(live_route::Family::V6) {
                "native_ipv6_fallback_started"
            } else {
                "native_ipv4_fallback_started"
            };
            let _ = self.logs.event("connection", code);
            return true;
        }
        self.enter_chain(owner, dashboard)
    }
    fn refill_phase(&mut self, owner: &mut ResourceOwner) {
        if let Some((_, queue)) = &mut self.recovering {
            *queue = self.plan.relays.iter().cloned().collect();
        }
        if let Some((_, _, queue, _)) = &mut self.manual_candidates {
            *queue = self.plan.relays.iter().cloned().collect();
        }
        self.deferred = None;
        let now = owner.now();
        let _ = owner.state_mut().finish_original_phase(now);
        self.next_attempt = Instant::now();
    }
    fn enter_chain(&mut self, owner: &mut ResourceOwner, dashboard: &Dashboard) -> bool {
        if self.route_trial.is_some()
            || self.chain.is_none()
            || dashboard.settings.tunnel_route != adapter_protocol::app::TunnelRoute::Auto
            || !self.plan.enter_chain()
        {
            return false;
        }
        self.refill_phase(owner);
        let _ = self
            .logs
            .event("connection", "direct_routes_exhausted_chain_last");
        true
    }
    pub(crate) fn recovery_action(
        &mut self,
        owner: &mut ResourceOwner,
        dashboard: &mut Dashboard,
        identity: &TunnelIdentity,
        catalogue: &adapter_catalogue::Catalogue,
        action: adapter_protocol::app::RecoveryAction,
    ) -> Result<String, &'static str> {
        use adapter_protocol::app::RecoveryAction as A;
        if self.busy() {
            return Err("operation_busy");
        }
        if owner.state().paused || !owner.observation().binding_settled() {
            return Err("waiting_network");
        }
        if matches!(action, A::TestBackup | A::ChainFallback) && self.chain.is_none() {
            return Err("chain_not_configured");
        }
        // Keep the last committed path as the rollback target even when the
        // front is currently rejecting traffic after a failed rebuild.
        let previous = owner.state().path.clone();
        let relay = if action == A::RetryCity {
            None
        } else {
            previous
                .as_ref()
                .map(|p| p.relay.clone())
                .or_else(|| self.last_relay.clone())
        };
        self.begin_recovery_action(
            action,
            dashboard.settings.selected_city.as_deref(),
            relay.as_deref(),
        );
        if action == A::RetryCurrent {
            if let Some(path) = &previous {
                if let Some(relay) = catalogue
                    .active_in_city(&path.city)
                    .find(|r| r.hostname() == path.relay)
                {
                    if let Some(route) =
                        Route::authorize(catalogue, relay, &path.transport, &path.inlet)
                            .filter(|r| !r.is_ss())
                    {
                        self.startup_route = Some((path.relay.clone(), route));
                    }
                }
            }
        }
        if matches!(action, A::TestBackup | A::ChainFallback | A::ReturnDirect) {
            self.forced_route = Some(action != A::ReturnDirect);
            self.route_trial = Some(RouteTrial {
                kind: match action {
                    A::TestBackup => TrialKind::TestBackup,
                    A::ReturnDirect => TrialKind::ReturnDirect,
                    _ => TrialKind::ChainFallback,
                },
                previous,
                restoring: false,
                tested: false,
                verified_backup: None,
                rescue: false,
                alternate_used: false,
            });
            if action == A::TestBackup {
                dashboard.backup_test_id = dashboard.backup_test_id.saturating_add(1);
                dashboard.backup_test_status = Some("testing".into());
                dashboard.backup_test_restored = false;
            }
        }
        match self.connect(
            owner,
            dashboard,
            identity,
            catalogue,
            relay.as_deref(),
            false,
        ) {
            Ok(id) => Ok(id),
            Err(code) => {
                self.route_trial = None;
                self.forced_route = None;
                self.restore_target = None;
                if action == A::TestBackup {
                    dashboard.backup_test_status = Some("failed".into());
                }
                Err(code)
            }
        }
    }
    fn queue_restore(&mut self, owner: &mut ResourceOwner, target: Path) {
        owner.state_mut().manual_preempt();
        self.inlet_trials.clear();
        self.forced_route = Some(target.transport == "wireguard-over-shadowsocks-chain");
        self.restore_target = Some(target.clone());
        self.manual_candidates = Some((
            Instant::now() + Duration::from_secs(90),
            target.city.clone(),
            VecDeque::from([target.relay]),
            true,
        ));
        self.recovering = None;
        self.deferred = None;
        self.next_attempt = Instant::now();
    }
    /// Only a fresh measured data failure, after owned cleanup, may spend this
    /// one extra SS entry. Local/start/cancellation errors must not rotate it.
    fn advance_trial_inlet(
        &mut self,
        path: &Path,
        catalogue: Option<&adapter_catalogue::Catalogue>,
        automatic: bool,
    ) -> bool {
        if !self
            .route_trial
            .as_ref()
            .is_some_and(|t| !t.restoring && !t.rescue && !t.alternate_used)
        {
            return false;
        }
        let advanced = self.advance_inlet(path, catalogue, automatic, true);
        self.save_history();
        if advanced {
            self.route_trial.as_mut().unwrap().alternate_used = true;
        }
        advanced
    }
    fn trial_failed(
        &mut self,
        owner: &mut ResourceOwner,
        dashboard: &mut Dashboard,
        schedule_retry: bool,
    ) -> bool {
        let Some(trial) = self.route_trial.as_mut() else {
            return false;
        };
        if !trial.restoring {
            trial.restoring = true;
            if trial.kind == TrialKind::ReturnDirect {
                self.direct_return.failed(Instant::now());
            }
            if let Some(previous) = trial.previous.clone() {
                let _ = self
                    .logs
                    .event("connection", "route_trial_failed_restore_previous");
                self.queue_restore(owner, previous);
                return true;
            }
        } else if trial.kind == TrialKind::TestBackup && trial.tested && !trial.rescue {
            // If the old direct route has stopped working during the test,
            // retain the just-verified chain as a second serial rollback target.
            trial.rescue = true;
            if let Some(backup) = trial.verified_backup.clone() {
                let _ = self
                    .logs
                    .event("connection", "restore_previous_failed_use_verified_backup");
                self.queue_restore(owner, backup);
                return true;
            }
        }
        let is_test = trial.kind == TrialKind::TestBackup;
        self.route_trial = None;
        self.forced_route = None;
        self.restore_target = None;
        self.manual_candidates = None;
        if is_test {
            dashboard.backup_test_status = Some("failed".into());
            dashboard.backup_test_restored = false;
        }
        dashboard.last_error = Some("route_trial_failed".into());
        if schedule_retry {
            self.schedule_retry(dashboard);
        }
        false
    }
    fn trial_connected(
        &mut self,
        owner: &mut ResourceOwner,
        dashboard: &mut Dashboard,
        path: &Path,
    ) {
        if path.transport == "wireguard-over-shadowsocks-chain" {
            self.record_verified_chain(dashboard);
        }
        if let Some(trial) = self.route_trial.as_mut() {
            if !trial.restoring && trial.kind == TrialKind::TestBackup {
                trial.tested = true;
                trial.verified_backup = Some(path.clone());
                trial.restoring = true;
                if let Some(previous) = trial.previous.clone() {
                    self.queue_restore(owner, previous);
                    return;
                }
            }
            if trial.kind == TrialKind::TestBackup {
                dashboard.backup_test_status =
                    Some(if trial.tested { "passed" } else { "failed" }.into());
                dashboard.backup_test_restored = trial.previous.as_ref().is_some_and(|previous| {
                    previous.relay == path.relay
                        && previous.inlet == path.inlet
                        && previous.transport == path.transport
                });
            }
            self.route_trial = None;
            self.forced_route = None;
            self.restore_target = None;
        }
        if path.transport == "wireguard-over-shadowsocks-chain"
            && dashboard.settings.tunnel_route == adapter_protocol::app::TunnelRoute::Auto
        {
            self.direct_return.connected(Instant::now());
        } else {
            self.direct_return.clear();
        }
    }
    pub(crate) fn update_progress(&self, dashboard: &mut Dashboard) {
        let now = Instant::now();
        let target = self
            .pending
            .as_ref()
            .and_then(|p| p.attempt.as_ref())
            .map(|a| &a.path);
        let (stage, next) = if dashboard.physical_attachment != "available" {
            ("waiting_network", "verify_original")
        } else if self.route_trial.as_ref().is_some_and(|t| t.restoring) {
            ("restoring_previous", "verify_previous")
        } else if let Some(trial) = &self.route_trial {
            if trial.kind == TrialKind::ReturnDirect {
                ("returning_direct", "restore_chain_if_failed")
            } else {
                ("testing_backup", "restore_previous_after_test")
            }
        } else if dashboard.last_error.as_deref() == Some("active_front_repair_failed") {
            ("local_front", "verify_previous")
        } else if self.active_failures.confirming() {
            ("confirming", "original_retry")
        } else if dashboard.retry_in_seconds.is_some() {
            ("exhausted", "new_round")
        } else if dashboard.status == "connected" {
            if dashboard.connection.as_ref().is_some_and(|c| c.chained) {
                ("chain_connected", "return_direct")
            } else {
                ("connected", "monitor")
            }
        } else if dashboard.status == "network_recovering"
            && dashboard.active_relay.is_some()
            && self.plan.started.is_none()
        {
            ("verifying_original", "original_retry")
        } else if self.plan.started.is_none()
            && dashboard.active_relay.is_none()
            && dashboard.operation.is_none()
        {
            ("idle", "monitor")
        } else if self.plan.native_phase == Some(live_route::Family::V6) {
            ("native_ipv6", "native_ipv4")
        } else if self.plan.native_phase == Some(live_route::Family::V4) {
            ("native_ipv4", "chain_fallback")
        } else if self.plan.chain_phase {
            ("chain_fallback", "new_round")
        } else if target.is_some_and(|p| Some(p.relay.as_str()) != self.plan.original_relay()) {
            ("same_city", "native_ipv6")
        } else if self.plan.short_attempt() < 3 || self.plan.attempts <= 3 {
            ("original_inlet", "same_relay_inlets")
        } else {
            ("same_relay_inlets", "same_city")
        };
        dashboard.recovery = Some(adapter_protocol::app::RecoveryProgress {
            transport: target.map(|p| p.transport.clone()).or_else(|| {
                dashboard
                    .connection
                    .as_ref()
                    .and_then(|c| c.transport.clone())
            }),
            stage: stage.into(),
            relay: target
                .map(|p| p.relay.clone())
                .or_else(|| dashboard.connection.as_ref().map(|c| c.relay.clone())),
            inlet: target
                .map(|p| p.inlet.clone())
                .or_else(|| dashboard.connection.as_ref().map(|c| c.inlet.clone())),
            attempt: self.plan.attempts,
            elapsed_seconds: self
                .plan
                .started
                .map_or(0, |at| now.saturating_duration_since(at).as_secs()),
            budget_seconds: adapter_domain::RECOVERY_BUDGET_MS / 1000,
            wait_seconds: dashboard
                .retry_in_seconds
                .unwrap_or_else(|| self.next_attempt.saturating_duration_since(now).as_secs()),
            next: next.into(),
            direct_return_in_seconds: self.direct_return.remaining(now),
        });
    }
    pub(crate) fn remember_startup_path(
        &mut self,
        bytes: &[u8],
        catalogue: &adapter_catalogue::Catalogue,
        dashboard: &Dashboard,
    ) {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return;
        };
        let Some(city) = value["city"]
            .as_str()
            .filter(|city| Some(*city) == dashboard.settings.selected_city.as_deref())
        else {
            return;
        };
        let Some(relay) = value["relay"].as_str().and_then(|name| {
            catalogue
                .active_in_city(city)
                .find(|r| r.hostname() == name)
        }) else {
            return;
        };
        let Some(kind) = value["transport"].as_str() else {
            return;
        };
        let Some(route) = value["inlet"]
            .as_str()
            .and_then(|inlet| Route::authorize(catalogue, relay, kind, inlet))
        else {
            return;
        };
        self.last_relay = Some(relay.hostname().into());
        self.startup_route = None;
        if !route.is_ss() {
            if dashboard.settings.tunnel_route != adapter_protocol::app::TunnelRoute::Chain {
                self.startup_route = Some((relay.hostname().into(), route));
            }
            return;
        }
        let endpoint = route.endpoint();
        let inlet = match endpoint.ip() {
            std::net::IpAddr::V4(ip) => {
                catalogue.authorize_shadowsocks_inlet(relay, ip, endpoint.port())
            }
            _ => None,
        };
        let Some(inlet) = inlet else {
            return;
        };
        let chained = route.chained
            && dashboard.settings.tunnel_route == adapter_protocol::app::TunnelRoute::Chain
            && self.chain.is_some();
        self.inlet_trials.reconcile(
            relay.hostname(),
            relay.public_key(),
            &catalogue.shadowsocks_inlets(relay),
        );
        self.inlet_trials.prefer(relay.hostname(), inlet, chained);
        if chained {
            self.chain_relays.insert(relay.hostname().into());
        }
    }
    pub(crate) fn freeze(&mut self) {
        self.retry_round.cancel();
        self.clear_plan();
        self.frozen = true;
        self.inlet_trials.clear();
        self.chain_relays.clear();
        self.recovering = None;
        self.manual_candidates = None;
        self.deferred = None;
        self.local_retry.clear();
    }
    pub(crate) fn identity_changed(&mut self, owner: &mut ResourceOwner) {
        self.retry_round.cancel();
        self.clear_plan();
        self.inlet_trials.clear();
        self.chain_relays.clear();
        self.recovering = None;
        self.manual_candidates = None;
        self.deferred = None;
        owner.state_mut().manual_preempt();
        owner.state_mut().path = None;
        owner.state_mut().readiness = None;
    }
    pub(crate) fn busy(&self) -> bool {
        self.pending.is_some()
    }
    pub(crate) fn recheck_soon(&mut self) {
        self.active_failures.clear();
        self.next_health = Instant::now();
    }
    fn finish_recovery(
        &mut self,
        owner: &mut ResourceOwner,
        dashboard: &mut Dashboard,
        code: &'static str,
    ) {
        debug_assert!(self.pending.is_none());
        if self.route_trial.is_some() && self.trial_failed(owner, dashboard, true) {
            return;
        }
        self.inlet_trials.clear();
        self.chain_relays.clear();
        self.recovering = None;
        self.manual_candidates = None;
        self.deferred = None;
        let retained_worker = dashboard.active_relay.as_deref().is_some_and(|relay| {
            owner
                .state()
                .path
                .as_ref()
                .is_some_and(|path| path.relay == relay)
        });
        owner.state_mut().finish_recovery(retained_worker);
        if retained_worker {
            self.next_health = Instant::now();
        }
        dashboard.status = if owner.state().paused {
            "waiting_network"
        } else if retained_worker {
            "blocked"
        } else {
            "disconnected"
        }
        .into();
        dashboard.readiness = None;
        dashboard.last_error = Some(code.into());
        let _ = self.logs.event("connection", code);
        self.schedule_retry(dashboard);
    }
    fn schedule_retry(&mut self, dashboard: &mut Dashboard) {
        if !dashboard.settings.automatic_recovery {
            return;
        }
        if let Some(city) = self
            .retry_round
            .city()
            .filter(|city| Some(*city) == dashboard.settings.selected_city.as_deref())
            .map(str::to_owned)
        {
            if self.retry_round.exhausted(Instant::now(), &city) {
                dashboard.retry_in_seconds = self.retry_round.remaining(Instant::now());
                if dashboard.physical_attachment == "available" {
                    dashboard.status = "retry_wait".into();
                }
                let _ = self.logs.event("connection", "recovery_retry_scheduled");
            }
        }
    }
    pub(crate) fn defer_start_failure(&mut self, dashboard: &mut Dashboard, code: &str) {
        // Local failures stay local: do not quarantine/consume an SS inlet. An
        // uncertain stop or invalid identity/configuration must not auto-loop.
        if crate::recovery_retry::is_retryable_local_failure(code) {
            self.schedule_retry(dashboard);
        }
    }
    /// Called only for an accepted user intent, never for scheduler retries.
    pub(crate) fn begin_user_selection(&mut self, city: Option<&str>, relay: Option<&str>) {
        self.clear_plan();
        self.retry_round.user_connect(city, relay);
        self.local_retry.clear();
        self.inlet_trials.clear();
        self.chain_relays.clear();
        self.manual_candidates = None;
        self.recovering = None;
        self.deferred = None;
        self.next_attempt = Instant::now();
    }
    fn pick_route(
        &mut self,
        catalogue: &adapter_catalogue::Catalogue,
        relay: &adapter_catalogue::Relay,
        exact: Option<&Path>,
        chained: bool,
    ) -> Result<Route, &'static str> {
        if let Some(path) = exact {
            return Route::authorize(catalogue, relay, &path.transport, &path.inlet)
                .ok_or("original_inlet_withdrawn");
        }
        if let Some(family) = self.plan.native_phase {
            return Route::native(catalogue, relay, family).ok_or("native_path_unavailable");
        }
        if self.forced_route.is_none() && !chained {
            if let Some((name, route)) = self.startup_route.as_ref() {
                if name == relay.hostname() {
                    if let Some(route) = Route::authorize(
                        catalogue,
                        relay,
                        route.kind(),
                        &route.endpoint().to_string(),
                    ) {
                        return Ok(route);
                    }
                    self.startup_route = None;
                }
            }
        }
        let mut allowed = catalogue.shadowsocks_inlets(relay);
        if let Some(selected) = self
            .inlet_trials
            .selected_route(relay.hostname(), chained)
            .and_then(|i| catalogue.authorize_shadowsocks_inlet(relay, i.address, i.port))
        {
            if !allowed.contains(&selected) {
                allowed.push(selected);
            }
        }
        self.inlet_trials
            .reconcile(relay.hostname(), relay.public_key(), &allowed);
        let inlet = self
            .inlet_trials
            .choose_route(relay.hostname(), &allowed, chained)
            .ok_or("shadowsocks_inlets_exhausted")?;
        Ok(Route::ss(inlet, chained))
    }
    pub(crate) fn connect(
        &mut self,
        owner: &mut ResourceOwner,
        dashboard: &mut Dashboard,
        identity: &TunnelIdentity,
        catalogue: &adapter_catalogue::Catalogue,
        relay: Option<&str>,
        automatic: bool,
    ) -> Result<String, &'static str> {
        if self.frozen {
            return Err("cleanup_uncertain");
        }
        if self.pending.is_some() {
            return Err("operation_busy");
        }
        if owner.state().paused
            || owner.state().attachment != Attachment::Available
            || !owner.observation().binding_settled()
        {
            return Err("waiting_network");
        }
        if dashboard.settings.required_multihop || dashboard.settings.required_pq {
            return Err("protection_unsupported");
        }
        if automatic && owner.state().stage == adapter_domain::Stage::Deferred {
            return Err("recovery_deferred");
        }
        let city = if automatic {
            owner.state().city.as_ref()
        } else {
            dashboard.settings.selected_city.as_ref()
        }
        .cloned()
        .ok_or("selected_city_missing")?;
        let picked = relay
            .and_then(|r| catalogue.active_in_city(&city).find(|n| n.hostname() == r))
            .or_else(|| {
                dashboard
                    .active_relay
                    .as_deref()
                    .and_then(|r| catalogue.active_in_city(&city).find(|n| n.hostname() == r))
            })
            .or_else(|| {
                self.last_relay.as_deref().and_then(|name| {
                    catalogue
                        .active_in_city(&city)
                        .find(|r| r.hostname() == name)
                })
            })
            .or_else(|| {
                dashboard
                    .city_candidates
                    .iter()
                    .filter(|n| n.city == city)
                    .find_map(|n| {
                        catalogue
                            .active_in_city(&city)
                            .find(|r| r.hostname() == n.hostname)
                    })
            })
            .or_else(|| catalogue.active_in_city(&city).next())
            .ok_or("city_relays_missing")?;
        // Explicit recovery targets cannot silently turn into another relay.
        if relay.is_some_and(|r| r != picked.hostname()) {
            return Err("relay_not_active");
        }
        let original = automatic
            && owner.state().stage == adapter_domain::Stage::RebuildOriginal
            && owner
                .state()
                .path
                .as_ref()
                .is_some_and(|p| p.relay == picked.hostname());
        self.chain_mode = dashboard.settings.tunnel_route;
        if self.plan.started.is_none() {
            let mut relays = vec![picked.hostname().to_owned()];
            if relay.is_none() {
                for candidate in dashboard.city_candidates.iter().filter(|c| c.city == city) {
                    if relays.len() < crate::recovery_plan::MAX_CITY_RELAYS
                        && !relays.contains(&candidate.hostname)
                    {
                        relays.push(candidate.hostname.clone());
                    }
                }
                for candidate in catalogue.active_in_city(&city) {
                    if relays.len() < crate::recovery_plan::MAX_CITY_RELAYS
                        && !relays.iter().any(|r| r == candidate.hostname())
                    {
                        relays.push(candidate.hostname().into());
                    }
                }
            }
            self.plan.start(
                relays,
                self.forced_route
                    .unwrap_or(self.chain_mode == adapter_protocol::app::TunnelRoute::Chain),
            );
            self.inlet_trials.primary(picked.hostname());
        }
        let chained = if let Some(forced) = self.forced_route {
            forced
        } else if original {
            owner
                .state()
                .path
                .as_ref()
                .is_some_and(|p| p.transport == "wireguard-over-shadowsocks-chain")
        } else {
            self.chain_mode == adapter_protocol::app::TunnelRoute::Chain
                || (self.chain_mode == adapter_protocol::app::TunnelRoute::Auto
                    && self.plan.chain_phase)
        };
        let exact = self
            .restore_target
            .as_ref()
            .filter(|p| p.relay == picked.hostname())
            .or_else(|| original.then(|| owner.state().path.as_ref().unwrap()))
            .cloned();
        let mut route = match self.pick_route(catalogue, picked, exact.as_ref(), chained) {
            Ok(route) => route,
            Err(code @ ("shadowsocks_inlets_exhausted" | "native_path_unavailable")) => {
                if !automatic && self.manual_candidates.is_none() {
                    let alternatives = self.plan.relays.iter().skip(1).cloned().collect();
                    self.seed_manual_candidates(city.clone(), alternatives, relay.is_some());
                    dashboard.status = "connecting".into();
                    return Ok("recovery_selection_queued".into());
                }
                return Err(code);
            }
            Err(code) => return Err(code),
        };
        let mut binding = route.binding(owner.observation().bindings());
        // A saved native hint cannot strand startup after changing networks.
        // Exact active rebuild/rollback remains exact; it never silently swaps.
        if binding.is_none()
            && exact.is_none()
            && self.plan.native_phase.is_none()
            && !route.is_ss()
            && self.startup_route.is_some()
        {
            self.startup_route = None;
            route = self.pick_route(catalogue, picked, None, chained)?;
            binding = route.binding(owner.observation().bindings());
        }
        let binding = binding.ok_or(if self.plan.native_phase.is_some() && exact.is_none() {
            "native_path_unavailable"
        } else if !route.is_ss()
            && exact.is_some()
            && owner
                .observation()
                .bindings()
                .iter()
                .any(|b| b.ipv4 || b.ipv6)
        {
            "original_native_family_unavailable"
        } else {
            "physical_binding_unavailable"
        })?;
        let chained = route.chained;
        if chained && self.chain.is_none() {
            return Err("chain_not_configured");
        }
        if chained {
            self.chain_relays.insert(picked.hostname().into());
        }
        self.next_instance = self
            .next_instance
            .checked_add(1)
            .ok_or("instance_exhausted")?;
        let slot = if original {
            owner.state().path.as_ref().unwrap().slot.as_str()
        } else if owner.state().path.as_ref().is_some_and(|p| p.slot == "a") {
            "b"
        } else {
            "a"
        };
        let path = Path {
            relay: picked.hostname().into(),
            city: city.clone(),
            transport: route.kind().into(),
            inlet: route.endpoint().to_string(),
            entry_relay: None,
            slot: slot.into(),
            instance: self.next_instance,
            front: 1,
        };
        let worker_runtime =
            PrivateRuntime::open(&self.root.join(format!("worker-{}", self.next_instance)))
                .map_err(|_| "worker_runtime_unavailable")?;
        let mut random = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *random).map_err(|_| "random_unavailable")?;
        let secret = Zeroizing::new(random.iter().map(|b| format!("{b:02x}")).collect());
        let port = if slot == "a" { 17920 } else { 17930 };
        let policy = serde_json::to_vec(&serde_json::json!({"schema":1,"relay":path.relay,"city":path.city,"transport":path.transport,"inlet":path.inlet,"instance":path.instance,"slot":path.slot,"front":path.front})).map_err(|_|"policy_invalid")?;
        let spec = identity.with_engine_identity(|key| TunnelSpec {
            instance: path.instance,
            runtime: worker_runtime,
            private_key: Zeroizing::new(key.private_key.to_owned()),
            ipv4: key.ipv4,
            ipv6: key.ipv6,
            relay_public_key: picked.public_key().into(),
            transport: route.transport,
            chain: if chained { self.chain.clone() } else { None },
            slot: if slot == "a" {
                Selected::SlotA
            } else {
                Selected::SlotB
            },
            mixed_port: port,
            controller_port: port + 1,
            controller_secret: secret,
            policy,
        });
        let now = owner.now();
        let attempt = if original {
            owner.state_mut().begin_original_rebuild(path, now)?
        } else if automatic {
            owner.state_mut().begin_fallback(path, now)?
        } else {
            owner.state_mut().begin_manual_selection(path, now)?
        };
        let (ticket, network) = owner
            .begin_operation(binding, self.next_instance, Some(&attempt))
            .map_err(|_| "operation_busy")?;
        let id = ticket.id();
        if self
            .client
            .submit(Command::Prepare {
                id,
                spec: Box::new(spec),
                network,
            })
            .is_err()
        {
            owner.finish_operation(&ticket);
            return Err("tunnel_command_busy");
        }
        if !automatic {
            let alternatives = if relay.is_none() {
                self.plan.relays.iter().skip(1).cloned().collect()
            } else {
                VecDeque::new()
            };
            self.seed_manual_candidates(attempt.path.city.clone(), alternatives, relay.is_some());
        }
        dashboard.connection = Some(ConnectionInfo {
            transport: Some(route.kind().into()),
            ping: None,
            relay: attempt.path.relay.clone(),
            city: attempt.path.city.clone(),
            inlet: attempt.path.inlet.clone(),
            instance: attempt.path.instance,
            interface_index: binding.index,
            phase: "starting".into(),
            chained,
            ip: None,
            dns: None,
            https: None,
            probes: None,
        });
        self.local_probe_failures = 0;
        self.plan.attempted(
            &attempt.path.relay,
            &attempt.path.inlet,
            &attempt.path.transport,
        );
        self.pending = Some(Pending {
            ticket,
            attempt: Some(attempt),
            promoting: false,
            aborting: false,
            automatic,
            rejected: None,
            retry_stale: false,
            retry_network: false,
            failed_reply: None,
        });
        dashboard.active_relay = None;
        dashboard.operation = Some(
            if automatic {
                "automatic_recovery"
            } else {
                "connecting"
            }
            .into(),
        );
        dashboard.status = "connecting".into();
        dashboard.readiness = None;
        dashboard.last_error = None;
        self.record(dashboard, "started", "starting", None);
        Ok(format!("connect-{id}"))
    }
    fn record(
        &self,
        dashboard: &mut Dashboard,
        code: &str,
        phase: &str,
        canary: Option<adapter_domain::Canary>,
    ) {
        self.record_with_probes(dashboard, code, phase, canary, None);
    }
    fn record_with_probes(
        &self,
        dashboard: &mut Dashboard,
        code: &str,
        phase: &str,
        canary: Option<adapter_domain::Canary>,
        probes: Option<adapter_protocol::app::ProbeMeasurements>,
    ) {
        if let Some(info) = &mut dashboard.connection {
            info.phase = phase.into();
            if let Some(canary) = canary {
                info.ip = Some(canary.ip);
                info.dns = Some(canary.dns);
                info.https = Some(canary.https);
                // A bare canary is a new observation, not the previous batch.
                info.probes = probes;
            } else if phase == "starting" || phase == "failed" {
                info.ip = None;
                info.dns = None;
                info.https = None;
                info.probes = None;
            }
        }
        let _ = self.logs.connection(code, dashboard.connection.as_ref());
    }
    fn record_measured(
        &self,
        dashboard: &mut Dashboard,
        code: &str,
        proof: &adapter_engine_mihomo::worker_lifecycle::BoundReport,
    ) {
        use adapter_control::candidate_evidence::ReadinessEvidence;
        use adapter_engine_mihomo::canary_batch::ProbeOutcome as Engine;
        use adapter_protocol::app::{ProbeMeasurements, ProbeOutcome as Wire};
        fn outcome(value: Engine) -> Wire {
            match value {
                Engine::Passed => Wire::Passed,
                Engine::Rejected => Wire::Rejected,
                Engine::Cancelled => Wire::Cancelled,
                Engine::Deadline => Wire::Deadline,
                Engine::Timeout => Wire::Timeout,
                Engine::Unavailable => Wire::Unavailable,
                Engine::NotRunDnsFailed => Wire::NotRunDnsFailed,
            }
        }
        let measured = proof.report().outcomes();
        self.record_with_probes(
            dashboard,
            code,
            "connected",
            proof.fresh_canary(),
            Some(ProbeMeasurements {
                ip: outcome(measured.ip),
                dns: outcome(measured.dns),
                https: outcome(measured.hostname),
            }),
        );
    }
    fn abort(&mut self, owner: &ResourceOwner, code: &'static str, dashboard: &mut Dashboard) {
        self.abort_with_canary(owner, code, dashboard, None);
    }
    fn abort_with_canary(
        &mut self,
        owner: &ResourceOwner,
        code: &'static str,
        dashboard: &mut Dashboard,
        canary: Option<adapter_domain::Canary>,
    ) {
        owner.cancel_current_operation();
        if let Some(pending) = &mut self.pending {
            pending.retry_stale |= code == "candidate_evidence_stale";
            pending.retry_network |= code == "network_binding_changed";
            if self
                .client
                .submit(Command::Abort {
                    id: pending.ticket.id(),
                })
                .is_ok()
            {
                pending.aborting = true;
            }
        }
        self.record(dashboard, code, "failed", canary);
        dashboard.last_error = Some(code.into());
        dashboard.readiness = None;
    }
    pub(crate) fn disconnect(
        &mut self,
        owner: &mut ResourceOwner,
        dashboard: &mut Dashboard,
    ) -> Result<(), &'static str> {
        self.retry_round.cancel();
        if dashboard.backup_test_status.as_deref() == Some("testing") {
            dashboard.backup_test_status = Some("cancelled".into());
        }
        self.clear_plan();
        dashboard.retry_in_seconds = None;
        if self.frozen {
            return Err("cleanup_uncertain");
        }
        self.recovering = None;
        self.manual_candidates = None;
        self.deferred = None;
        self.inlet_trials.clear();
        self.chain_relays.clear();
        self.disconnecting = true;
        self.last_relay = None;
        owner.cancel_current_operation();
        if let Some(p) = &mut self.pending {
            self.client.submit(Command::Abort { id: p.ticket.id() })?;
            p.aborting = true;
        } else {
            self.client.submit(Command::Abort { id: 0 })?;
        }
        owner.state_mut().manual_preempt();
        owner.state_mut().path = None;
        owner.state_mut().readiness = None;
        dashboard.status = "disconnecting".into();
        dashboard.readiness = None;
        Ok(())
    }
    fn seed_manual_candidates(
        &mut self,
        city: String,
        alternatives: VecDeque<String>,
        exact: bool,
    ) {
        // An exact relay has no alternatives, but still owns a bounded retry
        // intent. Scheduler retries must not refill its queue or renew its budget.
        self.manual_candidates.get_or_insert_with(|| {
            (
                Instant::now() + Duration::from_millis(adapter_domain::RECOVERY_BUDGET_MS),
                city,
                alternatives,
                exact,
            )
        });
    }
    fn retry_manual_candidate(&mut self, relay: String, retry_exact: bool) {
        if let Some((_, _, queue, exact)) = &mut self.manual_candidates {
            if *exact && !retry_exact {
                // Explicit selection retries network/stale interruption only;
                // a real measurement/start failure must not spin the same node.
                self.manual_candidates = None;
                return;
            }
            queue.push_front(relay);
            self.next_attempt =
                Instant::now() + Duration::from_millis(adapter_domain::LOCAL_RETRY_MS);
        }
    }
    fn advance_inlet(
        &mut self,
        path: &Path,
        catalogue: Option<&adapter_catalogue::Catalogue>,
        automatic: bool,
        fallback_allowed: bool,
    ) -> bool {
        if automatic && !fallback_allowed {
            return false;
        }
        if !automatic && self.manual_candidates.is_none() {
            return false;
        }
        if matches!(path.transport.as_str(), live_route::V6 | live_route::V4) {
            self.startup_route = None;
            if self.plan.native_phase.is_none() && self.route_trial.is_none() {
                if automatic {
                    self.deferred = Some(path.relay.clone());
                } else {
                    self.retry_manual_candidate(path.relay.clone(), true);
                }
                self.next_attempt = Instant::now() + Duration::from_millis(250);
                return true;
            }
            return false;
        }
        let Some(catalogue) = catalogue else {
            return false;
        };
        let Some(relay) = catalogue
            .active_in_city(&path.city)
            .find(|r| r.hostname() == path.relay)
        else {
            return false;
        };
        let was_chain = path.transport == "wireguard-over-shadowsocks-chain";
        if !self
            .inlet_trials
            .reject_route(&path.relay, &path.inlet, was_chain)
        {
            return false;
        }
        self.local_retry.clear();
        let next_chain = was_chain;
        let mut allowed = catalogue.shadowsocks_inlets(relay);
        if let Some(selected) = self
            .inlet_trials
            .selected_route(&path.relay, next_chain)
            .and_then(|i| catalogue.authorize_shadowsocks_inlet(relay, i.address, i.port))
        {
            if !allowed.contains(&selected) {
                allowed.push(selected);
            }
        }
        if self
            .inlet_trials
            .choose_route(&path.relay, &allowed, next_chain)
            .is_none()
        {
            return false;
        }
        if next_chain {
            self.chain_relays.insert(path.relay.clone());
        } else {
            self.chain_relays.remove(&path.relay);
        }
        if automatic {
            self.deferred = Some(path.relay.clone());
        } else {
            self.retry_manual_candidate(path.relay.clone(), true);
        }
        // Owned Unready already joined its worker/carrier. Only a short dispatch
        // pause is needed; the unchanged network-settle guard remains mandatory.
        self.next_attempt = Instant::now() + Duration::from_millis(250);
        let _ = self.logs.event(
            "connection",
            if next_chain && !was_chain {
                "same_relay_chain_retry"
            } else {
                "same_relay_inlet_retry"
            },
        );
        true
    }
    fn defer_stale_candidate(&mut self, relay: String) {
        // Do not pop the next city candidate or renew its recovery budget.
        self.deferred = Some(relay);
        self.next_attempt = Instant::now() + Duration::from_millis(adapter_domain::LOCAL_RETRY_MS);
    }
    fn defer_local_target(&mut self, relay: String) {
        // A start/canary transaction failure contains no remote negative
        // evidence. Retry this exact target with increasing bounded waits;
        // the current round deadline still limits its total lifetime.
        self.next_attempt = Instant::now() + self.local_retry.next_delay(&relay);
        self.deferred = Some(relay);
    }
    fn retry_window_open(&self, automatic: bool) -> bool {
        let now = Instant::now();
        if automatic {
            self.recovering
                .as_ref()
                .is_some_and(|(deadline, _)| now < *deadline)
        } else {
            self.manual_candidates
                .as_ref()
                .is_some_and(|(deadline, _, _, _)| now < *deadline)
        }
    }
    fn retry_failed_attempt_locally(
        &mut self,
        owner: &mut ResourceOwner,
        attempt: &CandidateAttempt,
        automatic: bool,
    ) -> bool {
        if !owner.state().current(&attempt.owner) || !self.retry_window_open(automatic) {
            return false;
        }
        let expected_stage = if automatic {
            matches!(
                owner.state().stage,
                adapter_domain::Stage::RebuildOriginal | adapter_domain::Stage::Fallback
            )
        } else {
            owner.state().stage == adapter_domain::Stage::ManualSelection
        };
        if !expected_stage {
            return false;
        }
        let relay = attempt.path.relay.clone();
        if automatic {
            // This operation is known to have drained, but carries no fresh
            // negative evidence. Clear its token without requiring the old
            // attempt freshness deadline, then preserve its domain phase.
            let now = owner.now();
            let effect = owner.state_mut().retry_after_local_cleanup(attempt, now);
            if effect == adapter_domain::Effect::Disconnected {
                return false;
            }
            self.defer_local_target(relay);
        } else {
            // The Reply::Failed path has no measurement to justify moving an
            // explicit selection to another relay or inlet.
            self.retry_manual_candidate(relay.clone(), true);
            self.next_attempt = Instant::now() + self.local_retry.next_delay(&relay);
        }
        true
    }
    fn abandon_failed_attempt(
        &mut self,
        owner: &mut ResourceOwner,
        dashboard: &mut Dashboard,
        attempt: &CandidateAttempt,
    ) {
        if !owner.state().current(&attempt.owner) {
            return;
        }
        let now = owner.now();
        let _ = owner.state_mut().retry_after_local_cleanup(attempt, now);
        self.local_retry.clear();
        self.retry_round.cancel_scheduled_retry();
        if self.route_trial.is_some() {
            if !self.trial_failed(owner, dashboard, false) {
                owner.state_mut().finish_recovery(false);
            }
        } else {
            self.recovering = None;
            self.manual_candidates = None;
            self.deferred = None;
            owner.state_mut().finish_recovery(false);
        }
    }
    fn apply_attempt_failure_disposition(
        &mut self,
        owner: &mut ResourceOwner,
        dashboard: &mut Dashboard,
        attempt: &CandidateAttempt,
        disposition: crate::recovery_retry::AttemptFailureDisposition,
        automatic: bool,
    ) -> crate::recovery_retry::AttemptFailureDisposition {
        use crate::recovery_retry::AttemptFailureDisposition as D;
        if !owner.state().current(&attempt.owner) {
            return D::StopCleanly;
        }
        match disposition {
            D::SkipUnavailablePath => {
                let now = owner.now();
                let _ = owner.state_mut().retry_after_local_cleanup(attempt, now);
                if owner.state().stage == adapter_domain::Stage::RebuildOriginal {
                    let _ = owner.state_mut().finish_original_phase(now);
                    self.startup_route = None;
                    self.deferred = Some(attempt.path.relay.clone());
                } else {
                    self.deferred = None;
                }
                self.local_retry.clear();
                let _ = self.logs.event("connection", "native_path_unavailable");
                D::SkipUnavailablePath
            }
            D::RetrySameTarget if self.retry_failed_attempt_locally(owner, attempt, automatic) => {
                D::RetrySameTarget
            }
            D::RetrySameTarget => {
                if owner.state().current(&attempt.owner)
                    && (!self.retry_window_open(automatic)
                        || owner.state().stage == adapter_domain::Stage::Disconnected)
                {
                    self.finish_recovery(owner, dashboard, "recovery_budget_exhausted");
                    D::RoundExpired
                } else {
                    self.abandon_failed_attempt(owner, dashboard, attempt);
                    D::StopCleanly
                }
            }
            D::StopCleanly => {
                self.abandon_failed_attempt(owner, dashboard, attempt);
                D::StopCleanly
            }
            D::RoundExpired => {
                self.finish_recovery(owner, dashboard, "recovery_budget_exhausted");
                D::RoundExpired
            }
            D::Freeze => {
                self.frozen = true;
                self.retry_round.cancel_scheduled_retry();
                self.recovering = None;
                self.manual_candidates = None;
                self.deferred = None;
                D::Freeze
            }
        }
    }
    fn handle_attempt_failure(
        &mut self,
        owner: &mut ResourceOwner,
        dashboard: &mut Dashboard,
        attempt: &CandidateAttempt,
        code: &str,
        automatic: bool,
    ) -> crate::recovery_retry::AttemptFailureDisposition {
        let disposition = if code == "worker_route_unavailable"
            && (self.plan.native_phase.is_some()
                || owner.state().stage == adapter_domain::Stage::RebuildOriginal)
            && self.route_trial.is_none()
            && matches!(
                attempt.path.transport.as_str(),
                live_route::V6 | live_route::V4
            )
            && !owner.state().paused
            && owner.observation().binding_settled()
            && self.retry_window_open(automatic)
        {
            crate::recovery_retry::AttemptFailureDisposition::SkipUnavailablePath
        } else {
            crate::recovery_retry::attempt_failure_disposition(code)
        };
        self.apply_attempt_failure_disposition(owner, dashboard, attempt, disposition, automatic)
    }
    fn recovery(
        &mut self,
        owner: &mut ResourceOwner,
        dashboard: &Dashboard,
        catalogue: &adapter_catalogue::Catalogue,
    ) {
        if self.recovering.is_some() || !dashboard.settings.automatic_recovery {
            return;
        }
        let Some(city) = owner.state().city.clone() else {
            return;
        };
        let mut relays = VecDeque::new();
        if let Some(active) = &self.last_relay {
            relays.push_back(active.clone());
        }
        for candidate in dashboard.city_candidates.iter().filter(|c| c.city == city) {
            if !relays.contains(&candidate.hostname) {
                relays.push_back(candidate.hostname.clone());
            }
        }
        for relay in catalogue.active_in_city(&city) {
            if relays.len() >= crate::recovery_plan::MAX_CITY_RELAYS {
                break;
            }
            if !relays.iter().any(|r| r == relay.hostname()) {
                relays.push_back(relay.hostname().into());
            }
        }
        relays.truncate(crate::recovery_plan::MAX_CITY_RELAYS);
        let now = owner.now();
        if owner.state_mut().request_original_rebuild(now).is_err() {
            return;
        }
        self.retry_round.round_started();
        self.local_retry.clear();
        self.inlet_trials.clear();
        self.chain_relays.clear();
        self.plan.start(
            relays.iter().cloned().collect(),
            dashboard.settings.tunnel_route == adapter_protocol::app::TunnelRoute::Chain,
        );
        if let Some(primary) = self.plan.original_relay() {
            self.inlet_trials.primary(primary);
        }
        if dashboard.settings.tunnel_route == adapter_protocol::app::TunnelRoute::Auto
            && owner
                .state()
                .path
                .as_ref()
                .is_some_and(|p| p.transport == "wireguard-over-shadowsocks-chain")
        {
            let now = owner.now();
            let _ = owner.state_mut().finish_original_phase(now);
        }
        self.active_failures.clear();
        self.next_attempt = Instant::now();
        self.recovering = Some((
            Instant::now() + Duration::from_millis(adapter_domain::RECOVERY_BUDGET_MS),
            relays,
        ));
    }
    pub(crate) fn poll(
        &mut self,
        owner: &mut ResourceOwner,
        dashboard: &mut Dashboard,
        identity: Option<&TunnelIdentity>,
        catalogue: Option<&adapter_catalogue::Catalogue>,
        restored: bool,
    ) {
        dashboard.retry_in_seconds = self.retry_round.remaining(Instant::now());
        if dashboard.retry_in_seconds.is_none() && dashboard.status == "retry_wait" {
            dashboard.status = "disconnected".into();
        }
        if self.frozen {
            return;
        }
        if restored {
            self.active_failures.clear();
            self.inlet_trials.clear();
            self.chain_relays.clear();
            if let Some((deadline, _, _, _)) = &mut self.manual_candidates {
                *deadline =
                    Instant::now() + Duration::from_millis(adapter_domain::RECOVERY_BUDGET_MS);
            }
            if dashboard.active_relay.is_some() {
                // A retained worker gets a fresh Verify before any old queued
                // rebuild. The previous network window cannot force Fallback
                // while Domain is waiting to verify the original path.
                if self.route_trial.is_none() {
                    self.recovering = None;
                    self.manual_candidates = None;
                    self.deferred = None;
                    self.plan.clear();
                }
                self.next_health = Instant::now();
            } else if self.recovering.is_some() {
                let now = owner.now();
                let _ = owner.state_mut().request_original_rebuild(now);
                let relays = self.plan.relays.clone();
                self.plan.start(
                    relays.clone(),
                    dashboard.settings.tunnel_route == adapter_protocol::app::TunnelRoute::Chain,
                );
                if let Some(primary) = self.plan.original_relay() {
                    self.inlet_trials.primary(primary);
                }
                self.deferred = None;
                self.next_attempt = Instant::now();
                self.recovering = Some((
                    Instant::now() + Duration::from_millis(adapter_domain::RECOVERY_BUDGET_MS),
                    relays.into(),
                ));
            } else if self.manual_candidates.is_none() {
                // Only a confirmed offline->stable-online Effect::Verify gets
                // here, never a binding hint. A prior exhausted round must not
                // prevent this new physical-network recovery of the old path.
                if let Some(catalogue) = catalogue {
                    self.recovery(owner, dashboard, catalogue);
                }
            }
        }
        if let Some(pending) = &self.pending {
            if !pending.aborting && !owner.is_operation_current(&pending.ticket) {
                if pending.attempt.is_some() {
                    let code = if owner.operation_binding_changed(&pending.ticket) {
                        "network_binding_changed"
                    } else {
                        "connection_cancelled"
                    };
                    self.abort(owner, code, dashboard);
                }
                // A health probe uses its own cancellable operation. The selected
                // worker survives cancellation; wait for the probe reply to drain.
            }
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|p| !p.aborting && owner.is_operation_current(&p.ticket))
            && owner.observation().parameter_check_pending()
        {
            let since = self.parameter_wait_since.get_or_insert_with(Instant::now);
            if since.elapsed() < Duration::from_secs(2) {
                // Hold replies, not the owner or data plane, while local fields
                // are classified. Never renew a measurement's freshness budget.
                return;
            }
            owner.cancel_current_operation();
            if self.pending.as_ref().is_some_and(|p| p.attempt.is_some()) {
                self.abort(owner, "candidate_evidence_stale", dashboard);
            }
        } else {
            self.parameter_wait_since = None;
        }
        while let Some(reply) = self.held_reply.take().or_else(|| self.events.poll()) {
            if let Reply::Lost { instance } = reply {
                if owner
                    .state()
                    .path
                    .as_ref()
                    .is_some_and(|p| p.instance == instance)
                    && dashboard.active_relay.is_some()
                {
                    let _ = self.logs.event("connection", "active_worker_missing");
                    dashboard.readiness = None;
                    dashboard.last_error = Some("active_worker_missing".into());
                    self.next_health = Instant::now();
                    if self.pending.is_none() {
                        if let Some(c) = catalogue {
                            self.recovery(owner, dashboard, c);
                        }
                    }
                }
                continue;
            }
            let id = match &reply {
                Reply::Prepared { id, .. }
                | Reply::Promoted { id, .. }
                | Reply::Verified { id, .. }
                | Reply::Stopped { id }
                | Reply::Failed { id, .. }
                | Reply::Unready { id, .. }
                | Reply::ActiveUnready { id, .. } => *id,
                Reply::Lost { .. } => unreachable!(),
            };
            if id == 0 && matches!(reply, Reply::Stopped { .. }) {
                self.record(dashboard, "stopped", "stopped", None);
                dashboard.active_relay = None;
                dashboard.status = "disconnected".into();
                dashboard.front_selected = "reject".into();
                self.disconnecting = false;
                continue;
            }
            let Some(p) = self.pending.as_ref().filter(|p| p.ticket.id() == id) else {
                continue;
            };
            let automatic = p.automatic;
            if p.aborting && !matches!(reply, Reply::Stopped { .. }) {
                continue;
            }
            if !p.aborting
                && owner.is_operation_current(&p.ticket)
                && owner.observation().parameter_check_pending()
                && matches!(
                    reply,
                    Reply::Prepared { .. }
                        | Reply::Promoted { .. }
                        | Reply::Verified { .. }
                        | Reply::Unready { .. }
                        | Reply::ActiveUnready { .. }
                )
            {
                let since = self.parameter_wait_since.get_or_insert_with(Instant::now);
                if since.elapsed() < Duration::from_secs(2) {
                    self.held_reply = Some(reply);
                    return;
                }
                owner.cancel_current_operation();
            }
            match reply {
                Reply::Prepared { proof, .. } => {
                    let aborting = p.aborting;
                    let checked = if owner.state().stage == adapter_domain::Stage::RebuildOriginal {
                        owner.validate_original_preservation(&p.ticket, &*proof)
                    } else {
                        owner.validate_operation_measurement(&p.ticket, &*proof)
                    };
                    if matches!(checked, Err(adapter_control::candidate_evidence::SelectionCheckError::PendingNetwork)) {
                        self.held_reply = Some(Reply::Prepared { id, proof });
                        self.parameter_wait_since.get_or_insert_with(Instant::now);
                        return;
                    }
                    if p.aborting || checked.is_err() {
                        if matches!(
                            checked,
                            Err(
                                adapter_control::candidate_evidence::SelectionCheckError::NotReady(
                                    _
                                )
                            )
                        ) && owner.is_operation_current(&p.ticket)
                        {
                            use adapter_control::candidate_evidence::{
                                MeasuredEvidence, ReadinessEvidence,
                            };
                            let now = owner.now();
                            if let (Some(canary), Some(at)) = (
                                proof.fresh_canary(),
                                now.checked_sub(
                                    proof.oldest_observation().elapsed().as_millis() as u64
                                ),
                            ) {
                                self.pending.as_mut().unwrap().rejected = Some((at, canary));
                            }
                        }
                        let code = if !aborting
                            && matches!(
                                checked,
                                Err(
                                    adapter_control::candidate_evidence::SelectionCheckError::Stale
                                )
                            ) {
                            "candidate_evidence_stale"
                        } else {
                            "candidate_not_ready"
                        };
                        // These failed checks were actually measured. Preserve
                        // fresh negative facts in the failed-phase log instead
                        // of erasing them during cleanup. They never authorize
                        // promotion or survive an invalid operation fence.
                        let canary = if !aborting
                            && matches!(checked, Err(adapter_control::candidate_evidence::SelectionCheckError::NotReady(_)))
                            && self.pending.as_ref().is_some_and(|p| owner.is_operation_current(&p.ticket))
                        {
                            use adapter_control::candidate_evidence::ReadinessEvidence;
                            proof.fresh_canary()
                        } else { None };
                        self.abort_with_canary(owner, code, dashboard, canary);
                    } else if self.client.submit(Command::Promote { id, proof }).is_ok() {
                        self.pending.as_mut().unwrap().promoting = true;
                    } else {
                        self.abort(owner, "tunnel_command_busy", dashboard);
                    }
                }
                Reply::Promoted { proof, .. } => {
                    let p = self.pending.as_ref().unwrap();
                    let checked = if owner.state().stage == adapter_domain::Stage::RebuildOriginal {
                        owner.validate_original_preservation(&p.ticket, &*proof)
                    } else {
                        owner.validate_operation_measurement(&p.ticket, &*proof)
                    };
                    if matches!(checked, Err(adapter_control::candidate_evidence::SelectionCheckError::PendingNetwork)) {
                        self.held_reply = Some(Reply::Promoted { id, proof });
                        self.parameter_wait_since.get_or_insert_with(Instant::now);
                        return;
                    }
                    let evidence_stale = matches!(
                        checked,
                        Err(adapter_control::candidate_evidence::SelectionCheckError::Stale)
                    );
                    let accepted = checked.ok().and_then(|(at, canary)| {
                        let now = owner.now();
                        let attempt = p.attempt.as_ref()?;
                        match owner.state().stage {
                            adapter_domain::Stage::ManualSelection => owner
                                .state_mut()
                                .commit_manual_selection(attempt, canary, at, now)
                                .ok(),
                            adapter_domain::Stage::Fallback => owner
                                .state_mut()
                                .commit_fallback(attempt, canary, at, now)
                                .ok(),
                            adapter_domain::Stage::RebuildOriginal => {
                                match owner.state_mut().original_rebuilt(
                                    attempt,
                                    adapter_domain::RebuildResult::Canary {
                                        path: attempt.path.clone(),
                                        canary,
                                    },
                                    at,
                                    now,
                                ) {
                                    adapter_domain::Effect::Preserved(_) => Some(()),
                                    _ => None,
                                }
                            }
                            _ => None,
                        }
                    });
                    if accepted.is_none() {
                        self.abort(
                            owner,
                            if evidence_stale {
                                "candidate_evidence_stale"
                            } else {
                                "candidate_commit_stale"
                            },
                            dashboard,
                        );
                        continue;
                    }
                    let p = self.pending.take().unwrap();
                    owner.finish_operation(&p.ticket);
                    let path = p.attempt.unwrap().path;
                    dashboard.front_selected =
                        if path.slot == "a" { "slot_a" } else { "slot_b" }.into();
                    if self
                        .retry_round
                        .connection_succeeded(&path.city, &path.relay)
                    {
                        dashboard.retry_in_seconds = None;
                    }
                    dashboard.active_relay = Some(path.relay.clone());
                    self.last_relay = dashboard.active_relay.clone();
                    if matches!(path.transport.as_str(), live_route::SS | live_route::CHAIN) {
                        self.inlet_trials.succeeded(
                            &path.relay,
                            &path.inlet,
                            path.transport == live_route::CHAIN,
                        );
                        self.save_history();
                    }
                    self.startup_route = None;
                    self.inlet_trials.clear();
                    self.chain_relays.clear();
                    self.active_failures.clear();
                    self.local_retry.clear();
                    dashboard.status = "connected".into();
                    dashboard.readiness = owner.state().readiness.map(|r| {
                        if r == adapter_domain::Readiness::Ready {
                            "ready"
                        } else {
                            "degraded"
                        }
                        .into()
                    });
                    dashboard.operation = None;
                    dashboard.last_error = None;
                    self.record_measured(dashboard, "connected", &proof);
                    self.recovering = None;
                    self.manual_candidates = None;
                    self.deferred = None;
                    self.plan.clear();
                    self.trial_connected(owner, dashboard, &path);
                    self.next_health = Instant::now() + HEALTHY_INTERVAL;
                }
                Reply::Verified { proof, .. } => {
                    if !owner.is_operation_current(&p.ticket) {
                        let p = self.pending.take().unwrap();
                        owner.finish_operation(&p.ticket);
                        dashboard.operation = None;
                        dashboard.readiness = None;
                        self.next_health = Instant::now();
                        continue;
                    }
                    use adapter_control::candidate_evidence::ReadinessEvidence;
                    if proof.fresh_canary().is_none() {
                        let p = self.pending.take().unwrap();
                        owner.finish_operation(&p.ticket);
                        dashboard.operation = None;
                        dashboard.readiness = None;
                        dashboard.last_error = Some("active_evidence_stale".into());
                        self.record(dashboard, "active_evidence_stale", "failed", None);
                        self.next_health = Instant::now() + Duration::from_secs(3);
                        continue;
                    }
                    self.local_probe_failures = 0;
                    let ready = owner.is_operation_current(&p.ticket)
                        && proof.fresh_canary().is_some_and(|c| c.alive());
                    let p = self.pending.take().unwrap();
                    if ready && owner.state().stage == adapter_domain::Stage::VerifyOriginal {
                        use adapter_control::candidate_evidence::MeasuredEvidence;
                        let now = owner.now();
                        if let (Some(canary), Ok(at)) = (
                            proof.fresh_canary(),
                            now.checked_sub(
                                u64::try_from(proof.oldest_observation().elapsed().as_millis())
                                    .unwrap_or(u64::MAX),
                            )
                            .ok_or(()),
                        ) {
                            let _ = owner.state_mut().original_verified(
                                p.ticket.token(),
                                canary,
                                at,
                                now,
                                true,
                            );
                        }
                    }
                    owner.finish_operation(&p.ticket);
                    dashboard.operation = None;
                    if ready {
                        self.active_failures.clear();
                        self.local_retry.clear();
                        if owner.state().path.as_ref().is_some_and(|path| {
                            self.retry_round
                                .connection_succeeded(&path.city, &path.relay)
                        }) {
                            dashboard.retry_in_seconds = None;
                        }
                        self.record_measured(
                            dashboard,
                            if proof
                                .fresh_canary()
                                .is_some_and(|c| c.ip && c.dns && c.https)
                            {
                                "complete"
                            } else {
                                "degraded_preserved"
                            },
                            &proof,
                        );
                        dashboard.last_error = None;
                        if let Some(canary) = proof.fresh_canary() {
                            owner.state_mut().readiness = Some(canary.readiness());
                        }
                        dashboard.status = "connected".into();
                        dashboard.readiness = proof.fresh_canary().map(|c| {
                            if c.ip && c.dns && c.https {
                                "ready"
                            } else {
                                "degraded"
                            }
                            .into()
                        });
                        self.next_health = Instant::now() + HEALTHY_INTERVAL;
                    } else {
                        // Recovery may be disabled or unavailable (e.g. no
                        // catalogue). Never keep an expired timer and enqueue
                        // another full Verify on every host tick in that case.
                        self.next_health = Instant::now() + Duration::from_secs(15);
                        dashboard.readiness = None;
                        dashboard.last_error = Some("active_probe_failed".into());
                        self.active_negative(owner, dashboard, catalogue);
                    }
                }
                Reply::ActiveUnready { proof, .. } => {
                    let current = owner.is_operation_current(&p.ticket);
                    let canary = proof.failed_canary();
                    let p = self.pending.take().unwrap();
                    owner.finish_operation(&p.ticket);
                    dashboard.operation = None;
                    dashboard.readiness = None;
                    if current && canary.is_some() {
                        self.record(dashboard, "active_data_failed", "failed", canary);
                        dashboard.last_error = Some("active_data_failed".into());
                        self.active_negative(owner, dashboard, catalogue);
                    } else {
                        self.active_failures.clear();
                        dashboard.last_error = Some("active_evidence_stale".into());
                        self.next_health = Instant::now() + Duration::from_secs(3);
                    }
                }
                Reply::Unready { proof, .. } => {
                    // A hint can arrive after poll's first ticket check but before
                    // this completion. Cleanup is confirmed by Unready; retain
                    // the exact selected inlet and original budget, not negative
                    // evidence from an interrupted physical-network window.
                    let negative = proof.failed_canary();
                    // Capture one completion-time fence; repeated current checks
                    // must not create an unclassified late-hint branch.
                    let current = owner.is_operation_current(&p.ticket);
                    if !current && owner.operation_binding_changed(&p.ticket) {
                        let p = self.pending.take().unwrap();
                        owner.finish_operation(&p.ticket);
                        if let Some(attempt) = p.attempt.as_ref() {
                            if automatic {
                                self.defer_stale_candidate(attempt.path.relay.clone());
                            } else {
                                self.retry_manual_candidate(attempt.path.relay.clone(), true);
                            }
                        }
                        dashboard.operation = None;
                        dashboard.front_selected = "reject".into();
                        dashboard.readiness = None;
                        dashboard.status = if owner.state().paused {
                            "waiting_network"
                        } else {
                            "disconnected"
                        }
                        .into();
                        dashboard.last_error = Some("network_binding_changed".into());
                        self.record(dashboard, "network_binding_changed", "failed", None);
                        continue;
                    }
                    if !current {
                        let p = self.pending.take().unwrap();
                        owner.finish_operation(&p.ticket);
                        if let Some(attempt) = &p.attempt {
                            if owner.state().current(&attempt.owner) {
                                let now = owner.now();
                                owner.state_mut().retry_after_local_cleanup(attempt, now);
                                if automatic {
                                    self.defer_stale_candidate(attempt.path.relay.clone());
                                } else {
                                    self.retry_manual_candidate(attempt.path.relay.clone(), true);
                                }
                            }
                        }
                        dashboard.operation = None;
                        dashboard.front_selected = "reject".into();
                        dashboard.readiness = None;
                        dashboard.status = if owner.state().paused {
                            "waiting_network"
                        } else {
                            "disconnected"
                        }
                        .into();
                        dashboard.last_error = Some("candidate_evidence_stale".into());
                        self.record(dashboard, "candidate_evidence_stale", "failed", None);
                        continue;
                    }
                    if negative.is_none() {
                        let p = self.pending.take().unwrap();
                        owner.finish_operation(&p.ticket);
                        if current {
                            if let Some(attempt) = &p.attempt {
                                if automatic {
                                    self.defer_stale_candidate(attempt.path.relay.clone());
                                } else {
                                    self.retry_manual_candidate(attempt.path.relay.clone(), true);
                                }
                            }
                        }
                        dashboard.operation = None;
                        dashboard.front_selected = "reject".into();
                        dashboard.readiness = None;
                        dashboard.status = if owner.state().paused {
                            "waiting_network"
                        } else {
                            "disconnected"
                        }
                        .into();
                        dashboard.last_error = Some("candidate_evidence_stale".into());
                        self.record(dashboard, "candidate_evidence_stale", "failed", None);
                        continue;
                    }
                    self.record(dashboard, "candidate_not_ready", "failed", negative);
                    use adapter_control::candidate_evidence::MeasuredEvidence;
                    let now = owner.now();
                    let measured =
                        now.checked_sub(proof.oldest_observation().elapsed().as_millis() as u64);
                    let p = self.pending.take().unwrap();
                    let classification = if current {
                        measured.zip(negative).and_then(|(at, canary)| {
                            self.measured_failure(owner, dashboard, &p, at, canary, catalogue)
                        })
                    } else {
                        None
                    };
                    if classification.is_none() && current {
                        if let Some(attempt) = &p.attempt {
                            let now = owner.now();
                            owner.state_mut().retry_after_local_cleanup(attempt, now);
                            if automatic {
                                self.defer_stale_candidate(attempt.path.relay.clone());
                            } else {
                                self.retry_manual_candidate(attempt.path.relay.clone(), true);
                            }
                        }
                    }
                    let retry_same = classification != Some(false);
                    owner.finish_operation(&p.ticket);
                    dashboard.operation = None;
                    dashboard.readiness = None;
                    dashboard.front_selected = "reject".into();
                    dashboard.status = "disconnected".into();
                    dashboard.last_error = Some("candidate_not_ready".into());
                    if !automatic {
                        self.recovering = None;
                        if !retry_same
                            && self
                                .manual_candidates
                                .as_ref()
                                .is_some_and(|(_, _, _, exact)| *exact)
                            && !self.enter_next_phase(owner, dashboard)
                        {
                            self.manual_candidates = None;
                            self.schedule_retry(dashboard);
                        }
                        owner.state_mut().manual_preempt();
                    }
                }
                Reply::Failed { code, .. } => {
                    // Covers failed active Verify as well as prepare errors;
                    // recovery/rebind can still explicitly recheck immediately.
                    self.next_health = Instant::now() + Duration::from_secs(15);
                    self.record(dashboard, code, "failed", None);
                    if matches!(
                        code,
                        "active_evidence_stale"
                            | "active_probe_local_failure"
                            | "active_probe_cancelled"
                            | "active_front_repair_failed"
                    ) && p.attempt.is_none()
                        && owner.is_operation_current(&p.ticket)
                    {
                        let p = self.pending.take().unwrap();
                        owner.finish_operation(&p.ticket);
                        dashboard.operation = None;
                        dashboard.readiness = None;
                        dashboard.last_error = Some(code.into());
                        // Local evidence expiry proves no relay failure. Keep
                        // the selected worker and retry its measurement only.
                        self.active_failures.clear();
                        self.next_health = Instant::now() + Duration::from_secs(3);
                        if code == "active_probe_local_failure" {
                            self.local_probe_failures = self.local_probe_failures.saturating_add(1);
                            if self.local_probe_failures >= 2 {
                                // DHCP/source/gateway changes can invalidate the
                                // carrier without changing LUID/index. Rebuild
                                // the same path, never fabricate relay failure.
                                self.local_probe_failures = 0;
                                let _ = self.logs.event("connection", "active_local_rebuild");
                                if let Some(c) = catalogue {
                                    self.recovery(owner, dashboard, c);
                                }
                            }
                        }
                        continue;
                    }
                    if p.attempt.is_none() && !owner.is_operation_current(&p.ticket) {
                        let p = self.pending.take().unwrap();
                        owner.finish_operation(&p.ticket);
                        dashboard.operation = None;
                        dashboard.readiness = None;
                        self.next_health = Instant::now();
                        continue;
                    }
                    // Prepare failure has positively stopped the candidate. A
                    // promotion rejection still needs explicit reconciliation.
                    if p.promoting {
                        if let Some(pending) = &mut self.pending {
                            pending.failed_reply =
                                Some(crate::recovery_retry::attempt_failure_disposition(code));
                        }
                        self.abort(owner, code, dashboard);
                        continue;
                    }
                    let p = self.pending.take().unwrap();
                    owner.finish_operation(&p.ticket);
                    if let Some(attempt) = &p.attempt {
                        let disposition =
                            self.handle_attempt_failure(owner, dashboard, attempt, code, automatic);
                        use crate::recovery_retry::AttemptFailureDisposition as D;
                        if disposition != D::Freeze {
                            // These classified outcomes confirm the candidate
                            // transaction stopped before returning its failure.
                            dashboard.front_selected = "reject".into();
                            dashboard.active_relay = None;
                        }
                        match disposition {
                            D::RetrySameTarget | D::StopCleanly | D::SkipUnavailablePath => {}
                            D::RoundExpired => {
                                dashboard.operation = None;
                                dashboard.readiness = None;
                                continue;
                            }
                            D::Freeze => {
                                // Unknown ownership/identity results cannot be
                                // converted into a new start or a relay failure.
                                dashboard.operation = None;
                                dashboard.readiness = None;
                                dashboard.status = "blocked".into();
                                dashboard.last_error = Some(code.into());
                                continue;
                            }
                        }
                    }
                    dashboard.operation = None;
                    dashboard.readiness = None;
                    dashboard.last_error = Some(code.into());
                    dashboard.status = if owner.state().paused {
                        "waiting_network"
                    } else {
                        "disconnected"
                    }
                    .into();
                    if !automatic && self.manual_candidates.is_none() && p.attempt.is_some() {
                        self.defer_start_failure(dashboard, code);
                    }
                }
                Reply::Lost { .. } => unreachable!(),
                Reply::Stopped { .. } => {
                    let _ = self.logs.event("connection", "stopped");
                    let p = self.pending.take().unwrap();
                    let now = owner.now();
                    let binding_changed = owner.operation_binding_changed(&p.ticket);
                    let attempt_current = p
                        .attempt
                        .as_ref()
                        .is_some_and(|a| owner.state().current(&a.owner));
                    if !automatic && binding_changed {
                        if let Some(attempt) = &p.attempt {
                            self.retry_manual_candidate(attempt.path.relay.clone(), true);
                        }
                    }
                    if !automatic
                        && p.rejected.is_none()
                        && p.failed_reply.is_none()
                        && self.route_trial.is_none()
                        && !binding_changed
                    {
                        if let Some(attempt) = &p.attempt {
                            self.retry_manual_candidate(
                                attempt.path.relay.clone(),
                                p.retry_network || p.retry_stale,
                            );
                        }
                    }
                    let mut classification = if !binding_changed {
                        p.rejected.and_then(|(at, canary)| {
                            self.measured_failure(owner, dashboard, &p, at, canary, catalogue)
                        })
                    } else {
                        None
                    };
                    if classification.is_none()
                        && p.failed_reply.is_some()
                        && attempt_current
                        && !binding_changed
                    {
                        if let Some(attempt) = &p.attempt {
                            self.apply_attempt_failure_disposition(
                                owner,
                                dashboard,
                                attempt,
                                p.failed_reply.unwrap(),
                                automatic,
                            );
                            classification = Some(true);
                        }
                    }
                    if classification.is_none()
                        && !binding_changed
                        && attempt_current
                        && self.route_trial.is_some()
                        && !p.retry_network
                        && !p.retry_stale
                        && p.failed_reply.is_none()
                        && !self.disconnecting
                    {
                        classification = Some(self.trial_failed(owner, dashboard, true));
                    }
                    if classification.is_none() {
                        if let Some(attempt) = &p.attempt {
                            if p.failed_reply.is_some() {
                                // The failed reply's code was classified before
                                // Abort. Stopped now confirms cleanup, so an
                                // unsafe/unknown code may end the round but may
                                // not silently turn into a target retry.
                                self.abandon_failed_attempt(owner, dashboard, attempt);
                            } else {
                                let stage = owner.state().stage;
                                let _ = owner.state_mut().retry_after_local_cleanup(attempt, now);
                                if automatic
                                    && attempt_current
                                    && !owner.state().paused
                                    && !self.disconnecting
                                    && matches!(
                                        stage,
                                        adapter_domain::Stage::RebuildOriginal
                                            | adapter_domain::Stage::Fallback
                                    )
                                {
                                    self.defer_local_target(attempt.path.relay.clone());
                                } else if !automatic
                                    && p.rejected.is_some()
                                    && attempt_current
                                    && !binding_changed
                                    && !self.disconnecting
                                {
                                    self.retry_manual_candidate(attempt.path.relay.clone(), true);
                                }
                            }
                        }
                    }
                    if classification == Some(false)
                        && !automatic
                        && self
                            .manual_candidates
                            .as_ref()
                            .is_some_and(|(_, _, _, exact)| *exact)
                        && !self.enter_next_phase(owner, dashboard)
                    {
                        self.manual_candidates = None;
                        self.schedule_retry(dashboard);
                    }
                    if automatic && owner.state().paused {
                        self.deferred = self.last_relay.clone();
                    }
                    owner.finish_operation(&p.ticket);
                    let retry_wait = dashboard.status == "retry_wait";
                    dashboard.front_selected = "reject".into();
                    dashboard.operation = None;
                    dashboard.readiness = None;
                    dashboard.status = if self.frozen {
                        "blocked"
                    } else if owner.state().paused {
                        "waiting_network"
                    } else if retry_wait {
                        "retry_wait"
                    } else {
                        "disconnected"
                    }
                    .into();
                    if self.disconnecting {
                        dashboard.active_relay = None;
                        self.disconnecting = false;
                    }
                    if !automatic {
                        self.recovering = None;
                    }
                }
            }
        }
        if self.pending.is_some()
            || owner.state().paused
            || owner.state().attachment != Attachment::Available
            || !owner.observation().binding_settled()
            || dashboard.operation.is_some()
        {
            return;
        }
        if Instant::now() < self.next_attempt {
            return;
        }
        if self.manual_candidates.is_none()
            && self.recovering.is_none()
            && self.retry_round.take_due(
                Instant::now(),
                dashboard.settings.selected_city.as_deref(),
                dashboard.settings.automatic_recovery,
            )
        {
            // This is a NEW bounded round after a monotonic backoff, never a
            // continuation/refill of the exhausted round. Retain the old inlet
            // preference and city, and run the same full prepare/commit gate.
            self.inlet_trials.clear();
            self.chain_relays.clear();
            self.plan.clear();
            if let (Some(identity), Some(catalogue)) = (identity, catalogue) {
                let exact = self.retry_round.exact_relay().map(str::to_owned);
                if exact.is_none() {
                    if let Some(path) = owner.state().path.as_ref() {
                        let saved = serde_json::json!({"city":path.city,"relay":path.relay,
                            "inlet":path.inlet,"transport":path.transport});
                        if let Ok(bytes) = serde_json::to_vec(&saved) {
                            self.remember_startup_path(&bytes, catalogue, dashboard);
                        }
                    }
                }
                let _ = self.logs.event("connection", "recovery_retry_started");
                dashboard.retry_in_seconds = None;
                if let Err(code) = self.connect(
                    owner,
                    dashboard,
                    identity,
                    catalogue,
                    exact.as_deref(),
                    false,
                ) {
                    dashboard.last_error = Some(code.into());
                    self.defer_start_failure(dashboard, code);
                }
            } else {
                self.schedule_retry(dashboard);
            }
            return;
        }
        if let Some((deadline, city, queue, _)) = &mut self.manual_candidates {
            if Instant::now() >= *deadline
                || dashboard.settings.selected_city.as_ref() != Some(city)
            {
                self.finish_recovery(owner, dashboard, "same_city_recovery_exhausted");
                return;
            }
            if let (Some(identity), Some(catalogue)) = (identity, catalogue) {
                if let Some(relay) = queue.pop_front() {
                    if let Err(code) =
                        self.connect(owner, dashboard, identity, catalogue, Some(&relay), false)
                    {
                        if self.route_trial.is_some()
                            && matches!(
                                code,
                                "original_native_family_unavailable" | "original_inlet_withdrawn"
                            )
                        {
                            self.trial_failed(owner, dashboard, true);
                            dashboard.last_error = Some(code.into());
                            return;
                        }
                        if !matches!(
                            code,
                            "relay_not_active"
                                | "shadowsocks_inlets_exhausted"
                                | "native_path_unavailable"
                        ) {
                            if let Some((_, _, queue, _)) = &mut self.manual_candidates {
                                queue.push_front(relay.clone());
                            }
                            self.next_attempt =
                                Instant::now() + self.local_retry.next_delay(&relay);
                        } else {
                            self.local_retry.clear();
                        }
                        dashboard.last_error = Some(code.into());
                    }
                } else if !self.enter_next_phase(owner, dashboard) {
                    self.finish_recovery(owner, dashboard, "same_city_recovery_exhausted");
                }
            }
            return;
        }
        if self.recovering.as_ref().is_some_and(|(_, q)| q.is_empty()) && self.deferred.is_none() {
            self.enter_next_phase(owner, dashboard);
        }
        if let Some((deadline, relays)) = &mut self.recovering {
            if Instant::now() >= *deadline {
                self.finish_recovery(owner, dashboard, "recovery_budget_exhausted");
                return;
            }
            if self.deferred.is_none() {
                self.deferred = relays.pop_front();
            }
            if self.deferred.is_none() {
                self.finish_recovery(owner, dashboard, "same_city_recovery_exhausted");
                return;
            }
        }
        if let (Some(relay), Some(identity), Some(catalogue)) =
            (self.deferred.clone(), identity, catalogue)
        {
            match self.connect(owner, dashboard, identity, catalogue, Some(&relay), true) {
                Ok(_) => self.deferred = None,
                Err("operation_busy" | "recovery_deferred") => {
                    self.defer_local_target(relay.clone());
                }
                Err(code) => {
                    if code == "original_native_family_unavailable"
                        && owner.state().stage == adapter_domain::Stage::RebuildOriginal
                    {
                        let now = owner.now();
                        let _ = owner.state_mut().finish_original_phase(now);
                        self.startup_route = None;
                        self.deferred = Some(relay.clone());
                        self.local_retry.clear();
                        self.next_attempt = Instant::now();
                        let _ = self.logs.event("connection", code);
                    } else if matches!(code, "relay_not_active" | "original_inlet_withdrawn")
                        && owner.state().stage == adapter_domain::Stage::RebuildOriginal
                    {
                        self.deferred = None;
                        self.local_retry.clear();
                        let now = owner.now();
                        let token = owner.state().token();
                        let _ = owner.state_mut().original_withdrawn(&token, now);
                        let _ = self.logs.event("connection", code);
                    } else if matches!(
                        code,
                        "relay_not_active"
                            | "recovery_budget_exhausted"
                            | "shadowsocks_inlets_exhausted"
                            | "native_path_unavailable"
                    ) {
                        self.deferred = None;
                        self.local_retry.clear();
                    } else {
                        // No candidate was measured. Local preparation/queue
                        // errors do not prove this relay is dead and must not
                        // consume the original target or the fallback queue.
                        self.defer_local_target(relay.clone());
                    }
                    dashboard.last_error = Some(code.into());
                }
            }
            return;
        }
        if dashboard.settings.tunnel_route == adapter_protocol::app::TunnelRoute::Auto
            && dashboard.connection.as_ref().is_some_and(|c| c.chained)
            && dashboard.status == "connected"
            && self.route_trial.is_none()
            && self.direct_return.due(Instant::now())
        {
            if let (Some(identity), Some(catalogue)) = (identity, catalogue) {
                let remaining = std::mem::take(&mut self.direct_return);
                let result = self.recovery_action(
                    owner,
                    dashboard,
                    identity,
                    catalogue,
                    adapter_protocol::app::RecoveryAction::ReturnDirect,
                );
                self.direct_return = remaining;
                if result.is_err() {
                    self.direct_return.failed(Instant::now());
                }
                return;
            }
        }
        if dashboard.active_relay.is_some() && Instant::now() >= self.next_health {
            let Some(path) = owner.state().path.as_ref() else {
                return;
            };
            let instance = path.instance;
            let Some(binding) = owner
                .observation()
                .bindings()
                .iter()
                .find(|b| b.ipv4)
                .copied()
            else {
                return;
            };
            if let Ok((ticket, network)) = owner.begin_operation(binding, instance, None) {
                let id = ticket.id();
                if self
                    .client
                    .submit(Command::Verify {
                        id,
                        instance,
                        network,
                    })
                    .is_ok()
                {
                    self.pending = Some(Pending {
                        ticket,
                        attempt: None,
                        promoting: false,
                        aborting: false,
                        automatic: true,
                        rejected: None,
                        retry_stale: false,
                        retry_network: false,
                        failed_reply: None,
                    });
                    let _ = self.logs.event("connection", "probing");
                } else {
                    owner.finish_operation(&ticket);
                }
            }
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    #[test]
    fn exact_manual_intent_has_no_fallback_and_retries_do_not_renew_it() {
        let root =
            std::env::temp_dir().join(format!("mullvad-exact-intent-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let logs = crate::live_diagnostics::LogClient::start(root.clone()).unwrap();
        let (mut c, _mailbox) = Connections::new(root, logs);
        c.seed_manual_candidates("city".into(), VecDeque::new(), true);
        let (deadline, city, queue, _) = c.manual_candidates.as_mut().unwrap();
        assert_eq!(city, "city");
        assert!(
            queue.is_empty(),
            "explicit selection must not choose another relay"
        );
        *deadline = Instant::now() - Duration::from_millis(1);
        let expired = *deadline;
        queue.push_front("exact-relay".into());
        c.seed_manual_candidates(
            "other-city".into(),
            VecDeque::from(["other-relay".into()]),
            false,
        );
        let (deadline, city, queue, _) = c.manual_candidates.as_ref().unwrap();
        assert_eq!(*deadline, expired);
        assert_eq!(city, "city");
        assert_eq!(queue, &VecDeque::from(["exact-relay".to_string()]));
        c.retry_manual_candidate("exact-relay".into(), false);
        assert!(
            c.manual_candidates.is_none(),
            "measured/start failure stops exact retry"
        );
        c.seed_manual_candidates("city".into(), VecDeque::new(), true);
        let budget = c.manual_candidates.as_ref().unwrap().0;
        c.retry_manual_candidate("exact-relay".into(), true);
        assert_eq!(c.manual_candidates.as_ref().unwrap().0, budget);
        assert_eq!(
            c.manual_candidates.as_ref().unwrap().2,
            VecDeque::from(["exact-relay".to_string()])
        );
        c.begin_user_selection(Some("city"), None);
        assert!(c.manual_candidates.is_none());
    }

    #[test]
    fn exact_relay_can_advance_inlet_without_other_relay_or_budget_renewal() {
        let root =
            std::env::temp_dir().join(format!("mullvad-inlet-intent-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let logs = crate::live_diagnostics::LogClient::start(root.clone()).unwrap();
        let (mut c, _) = Connections::new(root, logs);
        let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../catalogue/fixtures/relay-contract.json"
        ))
        .unwrap();
        let cat = adapter_catalogue::Catalogue::parse(
            &serde_json::to_vec(&fixture[0]["payload"]).unwrap(),
        )
        .unwrap();
        let relay = cat
            .relays()
            .iter()
            .find(|r| r.active() && cat.shadowsocks_inlets(r).len() > 1)
            .unwrap();
        let city = relay.location().to_string();
        c.seed_manual_candidates(city.clone(), VecDeque::new(), true);
        let deadline = c.manual_candidates.as_ref().unwrap().0;
        let first = cat.shadowsocks_inlets(relay)[0];
        let mut path = Path {
            relay: relay.hostname().into(),
            city,
            inlet: format!("{}:{}", first.address, first.port),
            transport: "wireguard-over-shadowsocks".into(),
            entry_relay: None,
            slot: "a".into(),
            instance: 1,
            front: 1,
        };
        assert!(c.advance_inlet(&path, Some(&cat), false, false));
        let (after, _, q, exact) = c.manual_candidates.as_mut().unwrap();
        assert_eq!(*after, deadline);
        assert!(*exact);
        assert_eq!(q.pop_front().as_deref(), Some(path.relay.as_str()));
        let next = c
            .inlet_trials
            .choose(&path.relay, &cat.shadowsocks_inlets(relay))
            .unwrap();
        assert_ne!(next, first);
        path.inlet = format!("{}:{}", next.address, next.port);
        assert!(
            !c.advance_inlet(&path, Some(&cat), true, false),
            "cannot change original inlet before domain fallback"
        );
        assert!(c.deferred.is_none());
        c.begin_user_selection(Some("city"), None);
        let retry = c
            .inlet_trials
            .choose(&path.relay, &cat.shadowsocks_inlets(relay));
        assert!(
            retry.is_some(),
            "a fresh round still admits an authorized alternative"
        );
        assert_ne!(
            retry,
            Some(first),
            "a user retry resets the round budget, not persistent SS attempts"
        );
    }

    #[test]
    fn stale_candidate_keeps_next_city_candidates_and_original_budget_until_user_preempts() {
        let root = std::env::temp_dir().join(format!(
            "mullvad-stale-recovery-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let logs = crate::live_diagnostics::LogClient::start(root.clone()).unwrap();
        let (mut connections, _mailbox) = Connections::new(root, logs);
        let deadline = Instant::now() - Duration::from_millis(1);
        connections.recovering = Some((deadline, VecDeque::from(["same-city-backup".into()])));
        connections.defer_stale_candidate("original".into());
        assert_eq!(connections.deferred.as_deref(), Some("original"));
        let (after, queue) = connections.recovering.as_ref().unwrap();
        assert_eq!(
            *after, deadline,
            "local expiry cannot renew an exhausted budget"
        );
        assert_eq!(queue, &VecDeque::from([String::from("same-city-backup")]));
        assert!(connections.next_attempt > Instant::now());
        connections.begin_user_selection(Some("city"), None);
        assert!(connections.deferred.is_none() && connections.recovering.is_none());
    }
}

#[cfg(test)]
#[path = "live_trial_tests.rs"]
mod trial_tests;

#[cfg(test)]
#[path = "live_native_tests.rs"]
mod native_tests;
