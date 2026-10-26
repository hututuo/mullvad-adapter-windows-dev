//! Synthetic trial-inlet scheduling tests. No engine, sockets, identity, or GUI.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

struct TestRoot(PathBuf);
impl Drop for TestRoot {
    fn drop(&mut self) {
        // LogClient has a detached writer; deletion is best effort on Windows
        // while its final allowlisted event is being drained.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temporary() -> TestRoot {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "mullvad-trial-inlets-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    ));
    std::fs::create_dir(&root).unwrap();
    TestRoot(root)
}

fn catalogue() -> adapter_catalogue::Catalogue {
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../catalogue/fixtures/relay-contract.json"
    ))
    .unwrap();
    let mut payload = fixture[0]["payload"].clone();
    // The shared metadata-validation corpus intentionally has one relay per
    // city. These orchestration tests require a distinct authorized same-city
    // peer; construct it explicitly rather than assume a validation fixture.
    let mut other = payload["wireguard"]["relays"][0].clone();
    other["hostname"] = "same-city-backup".into();
    other["public_key"] = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=".into();
    other["ipv4_addr_in"] = "192.0.2.12".into();
    other["shadowsocks_extra_addr_in"] = serde_json::json!(["192.0.2.23"]);
    payload["wireguard"]["relays"]
        .as_array_mut()
        .unwrap()
        .push(other);
    adapter_catalogue::Catalogue::parse(&serde_json::to_vec(&payload).unwrap()).unwrap()
}

fn dashboard() -> Dashboard {
    serde_json::from_value(serde_json::json!({
        "sequence": 0,
        "boot_id": "synthetic-trial",
        "build": "test",
        "source_sha": "synthetic",
        "status": "connecting",
        "physical_attachment": "available",
        "settings": adapter_protocol::app::Settings::default(),
        "front_ready": false,
        "front_selected": "reject",
        "identity_configured": false,
        "cities": [],
        "metadata_source": "fixture",
        "backup_test_id": 73,
        "backup_test_status": "testing",
        "backup_test_restored": false,
        "account": adapter_protocol::app::Account::default(),
        "logs_path": "synthetic",
        "logging_degraded": false,
        "logging_dropped": 0,
        "city_candidates": []
    }))
    .unwrap()
}

struct Fixture {
    connections: Connections,
    catalogue: adapter_catalogue::Catalogue,
    path: Path,
    previous: Path,
    dashboard: Dashboard,
    // Drop the Connections sender before trying to remove its log directory.
    _root: TestRoot,
}

fn fixture(kind: TrialKind) -> Fixture {
    let root = temporary();
    let logs = crate::live_diagnostics::LogClient::start(root.0.clone()).unwrap();
    let (mut connections, _mailbox) = Connections::new(root.0.clone(), logs);
    let catalogue = catalogue();
    let relay = catalogue
        .relays()
        .iter()
        .find(|r| r.active() && catalogue.shadowsocks_inlets(r).len() > 1)
        .expect("fixture needs two authorized SS inlets on one relay");
    let inlet = catalogue.shadowsocks_inlets(relay)[0];
    let chained = kind != TrialKind::ReturnDirect;
    let path = Path {
        relay: relay.hostname().into(),
        city: relay.location().to_string(),
        inlet: format!("{}:{}", inlet.address, inlet.port),
        transport: if chained {
            "wireguard-over-shadowsocks-chain"
        } else {
            "wireguard-over-shadowsocks"
        }
        .into(),
        entry_relay: None,
        slot: "b".into(),
        instance: 91,
        front: 1,
    };
    let mut previous = path.clone();
    previous.transport = if chained {
        "wireguard-over-shadowsocks"
    } else {
        "wireguard-over-shadowsocks-chain"
    }
    .into();
    previous.slot = "a".into();
    previous.instance = 90;
    connections.seed_manual_candidates(path.city.clone(), VecDeque::new(), true);
    // An unusual remaining budget makes accidental deadline renewal visible.
    connections.manual_candidates.as_mut().unwrap().0 = Instant::now() + Duration::from_secs(37);
    connections.plan.start(vec![path.relay.clone()], chained);
    connections
        .plan
        .attempted(&path.relay, &path.inlet, chained);
    connections.inlet_trials.primary(&path.relay);
    connections.inlet_trials.prefer(&path.relay, inlet, chained);
    connections.forced_route = Some(chained);
    connections.route_trial = Some(RouteTrial {
        kind,
        previous: Some(previous.clone()),
        restoring: false,
        tested: false,
        verified_backup: None,
        rescue: false,
        alternate_used: false,
    });
    Fixture {
        connections,
        catalogue,
        path,
        previous,
        dashboard: dashboard(),
        _root: root,
    }
}

fn domain_fallback_owner(original: &Path, target: &Path) -> (ResourceOwner, CandidateAttempt) {
    use adapter_control::observer::ObservedOwner;
    use adapter_domain::{Canary, Effect, RebuildResult, State};
    use adapter_platform::physical_attachment::{Attachment as Physical, Observation};

    let mut state = State::new("synthetic-fallback".into());
    state.path = Some(original.clone());
    state.city = Some(original.city.clone());
    state.observe(adapter_domain::Attachment::Available, 0);
    state.request_original_rebuild(0).unwrap();

    let mut rebuilt_path = original.clone();
    rebuilt_path.instance += 1;
    let original_attempt = state.begin_original_rebuild(rebuilt_path, 1).unwrap();
    assert!(matches!(
        state.original_rebuilt(
            &original_attempt,
            RebuildResult::Canary {
                path: original_attempt.path.clone(),
                canary: Canary {
                    ip: false,
                    dns: false,
                    https: false,
                },
            },
            1,
            1,
        ),
        Effect::SameCity(_, _)
    ));

    let attempt = state.begin_fallback(target.clone(), 2).unwrap();
    let observation = ObservedOwner::new(state, || Observation {
        attachment: Physical::Unknown,
        bindings: vec![],
    })
    .unwrap();
    (ResourceOwner::new(observation), attempt)
}

fn kinds() -> [(TrialKind, &'static str); 3] {
    [
        (TrialKind::TestBackup, "TestBackup"),
        (TrialKind::ChainFallback, "ChainFallback"),
        (TrialKind::ReturnDirect, "ReturnDirect"),
    ]
}

#[test]
fn native_route_trial_entry_preserves_the_persistent_city_or_pin() {
    use adapter_protocol::app::RecoveryAction as A;
    for action in [A::ReturnDirect, A::TestBackup, A::ChainFallback] {
        for pin in [None, Some("user-selected-relay")] {
            let mut f = fixture(TrialKind::ReturnDirect);
            f.connections.begin_user_selection(Some("xx-aaa"), pin);
            f.connections
                .begin_recovery_action(action, Some("xx-aaa"), Some("temporary-relay"));
            assert_eq!(f.connections.retry_round.city(), Some("xx-aaa"));
            assert_eq!(f.connections.retry_round.exact_relay(), pin);
        }
    }
}

fn fallback_fixture() -> (Fixture, ResourceOwner, CandidateAttempt) {
    let mut f = fixture(TrialKind::ChainFallback);
    let original = f.previous.clone();
    let next_relay = f
        .catalogue
        .active_in_city(&original.city)
        .find(|relay| relay.hostname() != original.relay)
        .expect("fixture needs a second relay in the same city");
    let inlet = f.catalogue.shadowsocks_inlets(next_relay)[0];
    let target = Path {
        relay: next_relay.hostname().into(),
        city: original.city.clone(),
        inlet: format!("{}:{}", inlet.address, inlet.port),
        transport: "wireguard-over-shadowsocks".into(),
        entry_relay: None,
        slot: "b".into(),
        instance: original.instance + 2,
        front: original.front,
    };
    let (owner, attempt) = domain_fallback_owner(&original, &target);

    f.connections.route_trial = None;
    f.connections.manual_candidates = None;
    f.connections.deferred = None;
    let remaining = VecDeque::from(["later-city-candidate".into()]);
    f.connections.recovering = Some((Instant::now() + Duration::from_secs(30), remaining.clone()));
    f.connections
        .retry_round
        .user_connect(Some(&original.city), None);
    f.dashboard.settings.selected_city = Some(original.city);
    f.dashboard.settings.automatic_recovery = true;
    f.dashboard.physical_attachment = "available".into();
    (f, owner, attempt)
}

#[test]
fn local_reply_failure_keeps_the_actual_domain_fallback_target_and_round_queue() {
    use crate::recovery_retry::AttemptFailureDisposition as D;
    let (mut f, mut owner, attempt) = fallback_fixture();
    let remaining = f.connections.recovering.as_ref().unwrap().1.clone();
    let before = Instant::now();
    assert_eq!(
        f.connections.handle_attempt_failure(
            &mut owner,
            &mut f.dashboard,
            &attempt,
            "worker_route_unavailable",
            true,
        ),
        D::RetrySameTarget
    );
    assert_eq!(owner.state().stage, adapter_domain::Stage::Fallback);
    assert_eq!(
        f.connections.deferred.as_deref(),
        Some(attempt.path.relay.as_str())
    );
    assert_eq!(f.connections.recovering.as_ref().unwrap().1, remaining);
    assert!(f.connections.next_attempt >= before + Duration::from_secs(1));
    assert!(!owner.state().candidate_is_current(&attempt, owner.now()));
    assert_eq!(
        f.connections.retry_round.city(),
        Some(attempt.path.city.as_str())
    );
}

#[test]
fn expired_local_retry_round_schedules_cooldown_without_losing_city_intent() {
    use crate::recovery_retry::AttemptFailureDisposition as D;
    let (mut f, mut owner, attempt) = fallback_fixture();
    f.connections.recovering.as_mut().unwrap().0 = Instant::now() - Duration::from_secs(1);
    assert_eq!(
        f.connections.handle_attempt_failure(
            &mut owner,
            &mut f.dashboard,
            &attempt,
            "candidate_probe_failed",
            true
        ),
        D::RoundExpired
    );
    assert_eq!(owner.state().stage, adapter_domain::Stage::Disconnected);
    assert_eq!(
        f.connections.retry_round.city(),
        Some(attempt.path.city.as_str())
    );
    assert_eq!(f.connections.retry_round.exact_relay(), None);
    assert!(f
        .connections
        .retry_round
        .remaining(Instant::now())
        .is_some());
    assert!(f.connections.recovering.is_none() && f.connections.deferred.is_none());
    assert_eq!(f.dashboard.status, "retry_wait");
}

#[test]
fn unsafe_attempt_failure_never_schedules_another_worker_or_remote_sample() {
    use crate::recovery_retry::AttemptFailureDisposition as D;
    for (code, expected) in [
        ("worker_configuration_rejected", D::StopCleanly),
        ("cleanup_uncertain", D::Freeze),
        ("tunnel_transaction_failed", D::Freeze),
    ] {
        let (mut f, mut owner, attempt) = fallback_fixture();
        assert_eq!(
            f.connections.handle_attempt_failure(
                &mut owner,
                &mut f.dashboard,
                &attempt,
                code,
                true
            ),
            expected
        );
        assert!(f.connections.deferred.is_none());
        assert!(f.connections.recovering.is_none());
        assert!(f.connections.manual_candidates.is_none());
        assert!(f
            .connections
            .retry_round
            .remaining(Instant::now())
            .is_none());
        if expected == D::Freeze {
            assert!(f.connections.frozen);
            // Uncertain ownership remains reserved, rather than being released.
            assert!(owner.state().candidate_is_current(&attempt, 2));
        } else {
            assert_eq!(owner.state().stage, adapter_domain::Stage::Disconnected);
        }
    }
}

#[test]
fn fresh_negative_after_success_remains_loggable_without_old_probe_outcomes() {
    use adapter_domain::Canary;
    use adapter_protocol::app::{ProbeMeasurements, ProbeOutcome};
    let mut f = fixture(TrialKind::TestBackup);
    f.dashboard.connection = Some(ConnectionInfo {
        ping: None,
        chained: false,
        relay: f.path.relay.clone(),
        city: f.path.city.clone(),
        inlet: f.path.inlet.clone(),
        interface_index: 5,
        instance: f.path.instance,
        phase: "connected".into(),
        ip: Some(true),
        dns: Some(true),
        https: Some(true),
        probes: Some(ProbeMeasurements {
            ip: ProbeOutcome::Passed,
            dns: ProbeOutcome::Passed,
            https: ProbeOutcome::Passed,
        }),
    });
    f.connections.record(
        &mut f.dashboard,
        "active_data_failed",
        "failed",
        Some(Canary {
            ip: false,
            dns: false,
            https: false,
        }),
    );
    let negative = f.dashboard.connection.as_ref().unwrap();
    assert!(
        negative.valid(),
        "fresh negative must survive log validation"
    );
    assert_eq!(negative.ip, Some(false));
    assert!(
        negative.probes.is_none(),
        "old passed batch is not current evidence"
    );

    f.connections.record_with_probes(
        &mut f.dashboard,
        "degraded_preserved",
        "connected",
        Some(Canary {
            ip: true,
            dns: false,
            https: false,
        }),
        Some(ProbeMeasurements {
            ip: ProbeOutcome::Passed,
            dns: ProbeOutcome::Timeout,
            https: ProbeOutcome::NotRunDnsFailed,
        }),
    );
    let measured = f.dashboard.connection.as_ref().unwrap();
    assert!(measured.valid());
    assert!(matches!(
        measured.probes.as_ref().unwrap().dns,
        ProbeOutcome::Timeout
    ));

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let text = std::fs::read_to_string(f._root.0.join("events.jsonl")).unwrap_or_default();
        let rows: Vec<serde_json::Value> = text
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();
        if rows.len() == 2 {
            assert_eq!(rows[0]["code"], "active_data_failed");
            assert!(rows[0]["connection"].get("probes").is_none());
            assert_eq!(rows[1]["connection"]["probes"]["dns"], "timeout");
            assert!(!f.connections.logs.fault.load(Ordering::Acquire));
            assert_eq!(f.connections.logs.dropped.load(Ordering::Acquire), 0);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "fresh failure and next measured batch must reach disk"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn each_trial_schedules_only_one_other_authorized_ss_without_replacing_its_intent() {
    for (kind, label) in kinds() {
        let mut f = fixture(kind);
        let c = &mut f.connections;
        let chained = kind != TrialKind::ReturnDirect;
        let deadline = c.manual_candidates.as_ref().unwrap().0;
        let started = c.plan.started;
        let attempts = c.plan.attempts;
        let test_id = f.dashboard.backup_test_id;

        assert!(
            c.advance_trial_inlet(&f.path, Some(&f.catalogue), false),
            "{label} must allow the first measured failure to try another SS"
        );
        let next = c
            .inlet_trials
            .selected_route(&f.path.relay, chained)
            .unwrap();
        let next_endpoint = format!("{}:{}", next.address, next.port);
        assert_ne!(next_endpoint, f.path.inlet, "{label}");
        let relay = f
            .catalogue
            .active_in_city(&f.path.city)
            .find(|r| r.hostname() == f.path.relay)
            .unwrap();
        assert_eq!(
            f.catalogue
                .authorize_shadowsocks_inlet(relay, next.address, next.port),
            Some(next),
            "{label} must use an inlet authorized for the same city and relay"
        );
        assert!(c
            .inlet_trials
            .selected_route(&f.path.relay, !chained)
            .is_none());
        assert_eq!(c.forced_route, Some(chained), "{label}");
        let (after, city, queue, exact) = c.manual_candidates.as_ref().unwrap();
        assert_eq!(
            *after, deadline,
            "{label} must not renew the round deadline"
        );
        assert_eq!(city, &f.path.city);
        assert!(*exact);
        assert_eq!(queue, &VecDeque::from([f.path.relay.clone()]));
        assert_eq!(c.plan.started, started);
        assert_eq!(c.plan.attempts, attempts, "scheduling is not a new start");

        let mut second = f.path.clone();
        second.inlet = next_endpoint;
        second.instance += 1;
        let history_after_first = c.inlet_trials.history_bytes();
        let dispatch_after_first = c.next_attempt;
        assert!(
            !c.advance_trial_inlet(&second, Some(&f.catalogue), false),
            "{label} must not schedule a third SS candidate"
        );
        assert_eq!(
            c.inlet_trials.selected_route(&second.relay, chained),
            Some(next)
        );
        assert_eq!(c.inlet_trials.history_bytes(), history_after_first);
        assert_eq!(c.next_attempt, dispatch_after_first);
        assert_eq!(c.manual_candidates.as_ref().unwrap().0, deadline);
        assert_eq!(
            c.manual_candidates.as_ref().unwrap().2,
            VecDeque::from([f.path.relay.clone()])
        );
        let trial = c.route_trial.as_ref().expect("trial must remain owned");
        assert!(trial.kind == kind, "{label}");
        assert_eq!(trial.previous.as_ref(), Some(&f.previous), "{label}");
        assert!(!trial.restoring && !trial.tested && !trial.rescue);
        assert!(trial.verified_backup.is_none());
        assert!(trial.alternate_used);
        assert!(c.restore_target.is_none());
        c.update_progress(&mut f.dashboard);
        assert_eq!(f.dashboard.backup_test_id, test_id, "{label}");
        assert_eq!(f.dashboard.backup_test_status.as_deref(), Some("testing"));
        assert!(!f.dashboard.backup_test_restored);
        assert_eq!(
            f.dashboard.recovery.as_ref().unwrap().stage,
            if kind == TrialKind::ReturnDirect {
                "returning_direct"
            } else {
                "testing_backup"
            }
        );
    }
}

#[test]
fn restoration_and_rescue_never_spend_a_trial_alternate() {
    for (kind, label) in kinds() {
        for (restoring, rescue) in [(true, false), (false, true), (true, true)] {
            let mut f = fixture(kind);
            let c = &mut f.connections;
            let trial = c.route_trial.as_mut().unwrap();
            trial.restoring = restoring;
            trial.rescue = rescue;
            let deadline = c.manual_candidates.as_ref().unwrap().0;
            let history = c.inlet_trials.history_bytes();
            let chained = kind != TrialKind::ReturnDirect;
            let selected = c.inlet_trials.selected_route(&f.path.relay, chained);
            let dispatch = c.next_attempt;
            assert!(
                !c.advance_trial_inlet(&f.path, Some(&f.catalogue), false),
                "{label}: restoring={restoring}, rescue={rescue} must keep exact rollback"
            );
            let trial = c.route_trial.as_ref().unwrap();
            assert!(!trial.alternate_used);
            assert_eq!(trial.restoring, restoring);
            assert_eq!(trial.rescue, rescue);
            assert_eq!(trial.previous.as_ref(), Some(&f.previous));
            assert_eq!(
                c.inlet_trials.selected_route(&f.path.relay, chained),
                selected
            );
            assert_eq!(c.inlet_trials.history_bytes(), history);
            assert_eq!(c.manual_candidates.as_ref().unwrap().0, deadline);
            assert!(c.manual_candidates.as_ref().unwrap().2.is_empty());
            assert_eq!(c.next_attempt, dispatch);
        }
    }
}

#[test]
fn unavailable_catalogue_does_not_consume_the_one_trial_alternate() {
    for (kind, label) in kinds() {
        let mut f = fixture(kind);
        let c = &mut f.connections;
        let deadline = c.manual_candidates.as_ref().unwrap().0;
        let history = c.inlet_trials.history_bytes();
        let chained = kind != TrialKind::ReturnDirect;
        let selected = c.inlet_trials.selected_route(&f.path.relay, chained);
        let dispatch = c.next_attempt;
        assert!(!c.advance_trial_inlet(&f.path, None, false), "{label}");
        let trial = c.route_trial.as_ref().unwrap();
        assert!(!trial.alternate_used && !trial.restoring && !trial.rescue);
        assert_eq!(trial.previous.as_ref(), Some(&f.previous));
        assert_eq!(
            c.inlet_trials.selected_route(&f.path.relay, chained),
            selected
        );
        assert_eq!(c.inlet_trials.history_bytes(), history);
        assert_eq!(c.manual_candidates.as_ref().unwrap().0, deadline);
        assert!(c.manual_candidates.as_ref().unwrap().2.is_empty());
        assert_eq!(c.next_attempt, dispatch);
        assert!(
            c.advance_trial_inlet(&f.path, Some(&f.catalogue), false),
            "{label} must retain its allowance when catalogue becomes available"
        );
        assert!(c.route_trial.as_ref().unwrap().alternate_used);
        assert_eq!(c.manual_candidates.as_ref().unwrap().0, deadline);
    }
}

#[test]
fn retained_worker_revalidation_is_not_a_rebuild_and_trial_gaps_reject_chain_changes() {
    let mut f = fixture(TrialKind::TestBackup);
    assert!(f.connections.pending.is_none());
    assert!(
        f.connections.chain_change_busy(),
        "a serial trial gap still owns its chain intent"
    );
    f.connections.route_trial = None;
    f.connections.manual_candidates = None;
    f.connections.plan.clear();
    f.dashboard.status = "network_recovering".into();
    f.dashboard.active_relay = Some(f.path.relay.clone());
    f.dashboard.operation = None;
    f.connections.update_progress(&mut f.dashboard);
    let progress = f.dashboard.recovery.as_ref().unwrap();
    assert_eq!(progress.stage, "verifying_original");
    assert_eq!(progress.attempt, 0);
    assert_eq!(progress.next, "original_retry");
    assert!(!f.connections.chain_change_busy());
    f.connections.plan.start(vec![f.path.relay.clone()], false);
    f.connections.update_progress(&mut f.dashboard);
    assert_eq!(
        f.dashboard.recovery.as_ref().unwrap().stage,
        "original_inlet"
    );
}

#[test]
fn failed_snapshot_write_cannot_mark_new_credentials_as_saved() {
    use sha2::{Digest, Sha256};
    let mut f = fixture(TrialKind::TestBackup);
    let old = Arc::new(adapter_engine_mihomo::chain::UpstreamSs::decode(br#"{"name":"previous","server":"ss.example.com","port":443,"cipher":"aes-128-gcm","password":"old-fixture"}"#).unwrap());
    let next = Arc::new(adapter_engine_mihomo::chain::UpstreamSs::decode(br#"{"name":"candidate","server":"ss.example.com","port":443,"cipher":"aes-128-gcm","password":"new-fixture"}"#).unwrap());
    let old_fp = format!("{:x}", Sha256::digest(&*old.encode().unwrap()));
    let next_fp = format!("{:x}", Sha256::digest(&*next.encode().unwrap()));
    f.connections.verified_chain =
        Some(crate::verified_chain::VerifiedChain { proxy: old, at: 42 });
    f.connections.set_chain(Some(next));
    f.dashboard.chain_fingerprint = Some(next_fp);
    f.dashboard.backup_verified_at = Some(99);
    assert!(
        f.connections.chain_store.is_none(),
        "synthetic write has no store"
    );
    f.connections.record_verified_chain(&mut f.dashboard);
    assert_eq!(f.dashboard.backup_verified_at, None);
    assert_eq!(f.connections.verified_at(Some(&old_fp)), Some(42));
    assert_eq!(
        f.dashboard.last_error.as_deref(),
        Some("chain_write_failed")
    );
}
