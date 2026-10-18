//! Product connection owner. Network/process I/O stays in the persistent resource.
use crate::live_identity::TunnelIdentity;
use adapter_control::owned_lifecycle::{OperationTicket, ResourceOwner};
use adapter_domain::{Attachment, CandidateAttempt, Path};
use adapter_engine_mihomo::{
    connection_tunnel::{self, Command, Reply, TunnelSpec},
    controller::Selected,
    Transport,
};
use adapter_platform::windows_runtime::PrivateRuntime;
use adapter_protocol::app::{ConnectionInfo, Dashboard};
use std::{
    collections::VecDeque,
    path::PathBuf,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

struct Pending {
    ticket: OperationTicket,
    attempt: Option<CandidateAttempt>,
    promoting: bool,
    aborting: bool,
    automatic: bool,
    rejected: Option<(u64, adapter_domain::Canary)>,
    retry_stale: bool,
}
pub(crate) struct Connections {
    pub(crate) client: connection_tunnel::Client,
    events: connection_tunnel::Events,
    root: PathBuf,
    pending: Option<Pending>,
    next_instance: u64,
    next_health: Instant,
    recovering: Option<(Instant, VecDeque<String>)>,
    manual_candidates: Option<(Instant, String, VecDeque<String>)>,
    deferred: Option<String>,
    last_relay: Option<String>,
    disconnecting: bool,
    next_attempt: Instant,
    logs: crate::live_diagnostics::LogClient,
    frozen: bool,
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
                next_instance: 0,
                next_health: Instant::now(),
                recovering: None,
                manual_candidates: None,
                deferred: None,
                last_relay: None,
                disconnecting: false,
                next_attempt: Instant::now(),
                logs,
                frozen: false,
            },
            mailbox,
        )
    }
    pub(crate) fn freeze(&mut self) {
        self.frozen = true;
        self.recovering = None;
        self.manual_candidates = None;
        self.deferred = None;
    }
    pub(crate) fn identity_changed(&mut self, owner: &mut ResourceOwner) {
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
        self.next_health = Instant::now();
    }
    /// Called only for an accepted user intent, never for scheduler retries.
    pub(crate) fn begin_user_selection(&mut self) {
        self.manual_candidates = None;
        self.recovering = None;
        self.deferred = None;
        self.next_attempt = Instant::now();
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
        if owner.state().paused || owner.state().attachment != Attachment::Available {
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
            && owner
                .state()
                .path
                .as_ref()
                .is_some_and(|p| p.relay == picked.hostname());
        let inlet = if original {
            let saved = owner
                .state()
                .path
                .as_ref()
                .unwrap()
                .inlet
                .parse::<std::net::SocketAddrV4>()
                .map_err(|_| "original_inlet_withdrawn")?;
            catalogue
                .authorize_shadowsocks_inlet(picked, *saved.ip(), saved.port())
                .ok_or("original_inlet_withdrawn")?
        } else {
            catalogue
                .shadowsocks_inlet(picked, None)
                .ok_or("shadowsocks_inlet_missing")?
        };
        let binding = owner
            .observation()
            .bindings()
            .iter()
            .find(|b| b.ipv4)
            .copied()
            .ok_or("physical_binding_unavailable")?;
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
            transport: "wireguard-over-shadowsocks".into(),
            inlet: format!("{}:{}", inlet.address, inlet.port),
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
            transport: Transport::Shadowsocks {
                endpoint: inlet.address,
                port: inlet.port,
            },
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
        if !automatic && relay.is_none() {
            let alternatives = catalogue
                .active_in_city(&attempt.path.city)
                .filter(|r| {
                    r.hostname() != picked.hostname()
                        && catalogue.shadowsocks_inlet(r, None).is_some()
                })
                .take(2)
                .map(|r| r.hostname().to_owned())
                .collect();
            self.manual_candidates = Some((
                Instant::now() + Duration::from_millis(adapter_domain::RECOVERY_BUDGET_MS),
                attempt.path.city.clone(),
                alternatives,
            ));
        }
        dashboard.connection = Some(ConnectionInfo {
            relay: attempt.path.relay.clone(),
            city: attempt.path.city.clone(),
            inlet: attempt.path.inlet.clone(),
            instance: attempt.path.instance,
            interface_index: binding.index,
            phase: "starting".into(),
            ip: None,
            dns: None,
            https: None,
            probes: None,
        });
        self.pending = Some(Pending {
            ticket,
            attempt: Some(attempt),
            promoting: false,
            aborting: false,
            automatic,
            rejected: None,
            retry_stale: false,
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
        if let Some(info) = &mut dashboard.connection {
            info.phase = phase.into();
            if let Some(canary) = canary {
                info.ip = Some(canary.ip);
                info.dns = Some(canary.dns);
                info.https = Some(canary.https);
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
        if let Some(info) = &mut dashboard.connection {
            info.probes = Some(ProbeMeasurements {
                ip: outcome(measured.ip),
                dns: outcome(measured.dns),
                https: outcome(measured.hostname),
            });
        }
        self.record(dashboard, code, "connected", proof.fresh_canary());
    }
    fn abort(&mut self, owner: &ResourceOwner, code: &'static str, dashboard: &mut Dashboard) {
        owner.cancel_current_operation();
        if let Some(pending) = &mut self.pending {
            pending.retry_stale |= code == "candidate_evidence_stale";
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
        self.record(dashboard, code, "failed", None);
        dashboard.last_error = Some(code.into());
        dashboard.readiness = None;
    }
    pub(crate) fn disconnect(
        &mut self,
        owner: &mut ResourceOwner,
        dashboard: &mut Dashboard,
    ) -> Result<(), &'static str> {
        if self.frozen {
            return Err("cleanup_uncertain");
        }
        self.recovering = None;
        self.manual_candidates = None;
        self.deferred = None;
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
    fn defer_stale_candidate(&mut self, relay: String) {
        // Do not pop the next city candidate or renew its recovery budget.
        self.deferred = Some(relay);
        self.next_attempt = Instant::now() + Duration::from_millis(adapter_domain::LOCAL_RETRY_MS);
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
            if relays.len() >= 3 {
                break;
            }
            if !relays.iter().any(|r| r == relay.hostname()) {
                relays.push_back(relay.hostname().into());
            }
        }
        relays.truncate(3);
        let now = owner.now();
        if owner.state_mut().request_original_rebuild(now).is_err() {
            return;
        }
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
        if self.frozen {
            return;
        }
        if restored {
            if let Some((deadline, _, _)) = &mut self.manual_candidates {
                *deadline =
                    Instant::now() + Duration::from_millis(adapter_domain::RECOVERY_BUDGET_MS);
            }
            if dashboard.active_relay.is_some() {
                self.next_health = Instant::now();
            } else if self.recovering.is_some() {
                let now = owner.now();
                let _ = owner.state_mut().request_original_rebuild(now);
                self.deferred = self.last_relay.clone();
                self.next_attempt = Instant::now();
                if let Some((deadline, _)) = &mut self.recovering {
                    *deadline =
                        Instant::now() + Duration::from_millis(adapter_domain::RECOVERY_BUDGET_MS);
                }
            }
        }
        if let Some(pending) = &self.pending {
            if !pending.aborting && !owner.is_operation_current(&pending.ticket) {
                if pending.attempt.is_some() {
                    self.abort(owner, "connection_cancelled", dashboard);
                }
                // A health probe uses its own cancellable operation. The selected
                // worker survives cancellation; wait for the probe reply to drain.
            }
        }
        while let Some(reply) = self.events.poll() {
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
                | Reply::Unready { id, .. } => *id,
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
            match reply {
                Reply::Prepared { proof, .. } => {
                    let aborting = p.aborting;
                    let checked = if owner.state().stage == adapter_domain::Stage::RebuildOriginal {
                        owner.validate_original_preservation(&p.ticket, &*proof)
                    } else {
                        owner.validate_operation_measurement(&p.ticket, &*proof)
                    };
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
                        self.abort(owner, code, dashboard);
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
                    dashboard.active_relay = Some(path.relay);
                    self.last_relay = dashboard.active_relay.clone();
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
                    self.next_health = Instant::now() + Duration::from_secs(15);
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
                        self.next_health = Instant::now() + Duration::from_secs(15);
                    } else {
                        // Recovery may be disabled or unavailable (e.g. no
                        // catalogue). Never keep an expired timer and enqueue
                        // another full Verify on every host tick in that case.
                        self.next_health = Instant::now() + Duration::from_secs(15);
                        dashboard.readiness = None;
                        dashboard.last_error = Some("active_probe_failed".into());
                        if let Some(c) = catalogue {
                            self.recovery(owner, dashboard, c);
                        }
                    }
                }
                Reply::Unready { proof, .. } => {
                    self.record(
                        dashboard,
                        "candidate_not_ready",
                        "failed",
                        proof.failed_canary(),
                    );
                    use adapter_control::candidate_evidence::MeasuredEvidence;
                    let now = owner.now();
                    let measured =
                        now.checked_sub(proof.oldest_observation().elapsed().as_millis() as u64);
                    let current = owner.is_operation_current(&p.ticket);
                    let p = self.pending.take().unwrap();
                    if current {
                        if let (Some(attempt), Some(at), Some(canary)) =
                            (&p.attempt, measured, proof.failed_canary())
                        {
                            if owner.state().stage == adapter_domain::Stage::RebuildOriginal {
                                let _ = owner.state_mut().original_rebuilt(
                                    attempt,
                                    adapter_domain::RebuildResult::Canary {
                                        path: attempt.path.clone(),
                                        canary,
                                    },
                                    at,
                                    now,
                                );
                            }
                        }
                    }
                    owner.finish_operation(&p.ticket);
                    dashboard.operation = None;
                    dashboard.readiness = None;
                    dashboard.front_selected = "reject".into();
                    dashboard.status = "disconnected".into();
                    dashboard.last_error = Some("candidate_not_ready".into());
                    if !automatic {
                        self.recovering = None;
                        owner.state_mut().manual_preempt();
                    }
                }
                Reply::Failed { code, .. } => {
                    // Covers failed active Verify as well as prepare errors;
                    // recovery/rebind can still explicitly recheck immediately.
                    self.next_health = Instant::now() + Duration::from_secs(15);
                    self.record(dashboard, code, "failed", None);
                    if code == "active_evidence_stale"
                        && p.attempt.is_none()
                        && owner.is_operation_current(&p.ticket)
                    {
                        let p = self.pending.take().unwrap();
                        owner.finish_operation(&p.ticket);
                        dashboard.operation = None;
                        dashboard.readiness = None;
                        dashboard.last_error = Some(code.into());
                        // Local evidence expiry proves no relay failure. Keep
                        // the selected worker and retry its measurement only.
                        self.next_health = Instant::now() + Duration::from_secs(3);
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
                        self.abort(owner, code, dashboard);
                        continue;
                    }
                    let p = self.pending.take().unwrap();
                    owner.finish_operation(&p.ticket);
                    if p.attempt.is_some() {
                        // Failed Prepare has stopped the old worker and read
                        // back Reject. Retain owner.path/last_relay for recovery,
                        // but do not display the previous slot as live.
                        dashboard.front_selected = "reject".into();
                        dashboard.active_relay = None;
                    }
                    if !automatic {
                        if let (Some((_, _, queue)), Some(attempt)) =
                            (&mut self.manual_candidates, &p.attempt)
                        {
                            queue.push_front(attempt.path.relay.clone());
                            self.next_attempt = Instant::now()
                                + Duration::from_millis(adapter_domain::LOCAL_RETRY_MS);
                        }
                    }
                    if automatic && owner.state().stage == adapter_domain::Stage::RebuildOriginal {
                        if let Some(attempt) = &p.attempt {
                            let now = owner.now();
                            let _ = owner.state_mut().original_rebuilt(
                                attempt,
                                adapter_domain::RebuildResult::LocalFailure,
                                now,
                                now,
                            );
                            self.deferred = Some(attempt.path.relay.clone());
                            self.next_attempt = Instant::now()
                                + Duration::from_millis(adapter_domain::LOCAL_RETRY_MS);
                        }
                    }
                    if automatic && code == "candidate_evidence_stale" {
                        if let Some(attempt) = &p.attempt {
                            self.defer_stale_candidate(attempt.path.relay.clone());
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
                    if automatic {
                        if let Some(c) = catalogue {
                            self.recovery(owner, dashboard, c);
                        }
                    }
                }
                Reply::Lost { .. } => unreachable!(),
                Reply::Stopped { .. } => {
                    let _ = self.logs.event("connection", "stopped");
                    let p = self.pending.take().unwrap();
                    let now = owner.now();
                    if automatic
                        && p.retry_stale
                        && p.attempt
                            .as_ref()
                            .is_some_and(|attempt| owner.state().candidate_is_current(attempt, now))
                    {
                        self.defer_stale_candidate(p.attempt.as_ref().unwrap().path.relay.clone());
                    }
                    if !automatic && p.rejected.is_none() {
                        if let (Some((_, _, queue)), Some(attempt)) =
                            (&mut self.manual_candidates, &p.attempt)
                        {
                            queue.push_front(attempt.path.relay.clone());
                            self.next_attempt = Instant::now()
                                + Duration::from_millis(adapter_domain::LOCAL_RETRY_MS);
                        }
                    }
                    if automatic && owner.state().stage == adapter_domain::Stage::RebuildOriginal {
                        if let Some(attempt) = &p.attempt {
                            let result = p
                                .rejected
                                .filter(|(_, canary)| !canary.alive())
                                .map(|(_, canary)| adapter_domain::RebuildResult::Canary {
                                    path: attempt.path.clone(),
                                    canary,
                                })
                                .unwrap_or(adapter_domain::RebuildResult::LocalFailure);
                            let at = p.rejected.map_or(now, |(at, _)| at);
                            let effect =
                                owner.state_mut().original_rebuilt(attempt, result, at, now);
                            if matches!(effect, adapter_domain::Effect::Deferred(_)) {
                                self.deferred = Some(attempt.path.relay.clone());
                                self.next_attempt = Instant::now()
                                    + Duration::from_millis(adapter_domain::LOCAL_RETRY_MS);
                            }
                        }
                    }
                    if automatic && owner.state().paused {
                        self.deferred = self.last_relay.clone();
                    }
                    owner.finish_operation(&p.ticket);
                    dashboard.front_selected = "reject".into();
                    dashboard.operation = None;
                    dashboard.readiness = None;
                    dashboard.status = if owner.state().paused {
                        "waiting_network"
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
            || dashboard.operation.is_some()
        {
            return;
        }
        if Instant::now() < self.next_attempt {
            return;
        }
        if let Some((deadline, city, queue)) = &mut self.manual_candidates {
            if Instant::now() >= *deadline
                || dashboard.settings.selected_city.as_ref() != Some(city)
            {
                self.manual_candidates = None;
                dashboard.last_error = Some("same_city_recovery_exhausted".into());
                return;
            }
            if let (Some(identity), Some(catalogue)) = (identity, catalogue) {
                if let Some(relay) = queue.pop_front() {
                    if let Err(code) =
                        self.connect(owner, dashboard, identity, catalogue, Some(&relay), false)
                    {
                        if code != "relay_not_active" {
                            if let Some((_, _, queue)) = &mut self.manual_candidates {
                                queue.push_front(relay);
                            }
                            self.next_attempt = Instant::now()
                                + Duration::from_millis(adapter_domain::LOCAL_RETRY_MS);
                        }
                        dashboard.last_error = Some(code.into());
                    }
                } else {
                    self.manual_candidates = None;
                    dashboard.last_error = Some("same_city_recovery_exhausted".into());
                }
            }
            return;
        }
        if let Some((deadline, relays)) = &mut self.recovering {
            if Instant::now() >= *deadline {
                self.recovering = None;
                dashboard.last_error = Some("recovery_budget_exhausted".into());
                return;
            }
            if self.deferred.is_none() {
                self.deferred = relays.pop_front();
            }
            if self.deferred.is_none() {
                self.recovering = None;
                dashboard.last_error = Some("same_city_recovery_exhausted".into());
                return;
            }
        }
        if let (Some(relay), Some(identity), Some(catalogue)) =
            (self.deferred.clone(), identity, catalogue)
        {
            match self.connect(owner, dashboard, identity, catalogue, Some(&relay), true) {
                Ok(_) => self.deferred = None,
                Err("operation_busy" | "recovery_deferred") => {}
                Err(code) => {
                    if matches!(code, "relay_not_active" | "original_inlet_withdrawn")
                        && owner.state().stage == adapter_domain::Stage::RebuildOriginal
                    {
                        self.deferred = None;
                        let now = owner.now();
                        let token = owner.state().token();
                        let _ = owner.state_mut().original_withdrawn(&token, now);
                        let _ = self.logs.event("connection", code);
                    } else if matches!(code, "relay_not_active" | "recovery_budget_exhausted") {
                        self.deferred = None;
                    } else {
                        // No candidate was measured. Local preparation/queue
                        // errors do not prove this relay is dead and must not
                        // consume the original target or the fallback queue.
                        self.next_attempt =
                            Instant::now() + Duration::from_millis(adapter_domain::LOCAL_RETRY_MS);
                    }
                    dashboard.last_error = Some(code.into());
                }
            }
            return;
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
        connections.begin_user_selection();
        assert!(connections.deferred.is_none() && connections.recovering.is_none());
    }
}
