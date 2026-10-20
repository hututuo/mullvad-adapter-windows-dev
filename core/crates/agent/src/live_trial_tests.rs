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
    adapter_catalogue::Catalogue::parse(&serde_json::to_vec(&fixture[0]["payload"]).unwrap())
        .unwrap()
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

fn kinds() -> [(TrialKind, &'static str); 3] {
    [
        (TrialKind::TestBackup, "TestBackup"),
        (TrialKind::ChainFallback, "ChainFallback"),
        (TrialKind::ReturnDirect, "ReturnDirect"),
    ]
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
