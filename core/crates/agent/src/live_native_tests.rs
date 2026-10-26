//! Pure native-route recovery scheduling tests. No worker, identity, network, or GUI.
use super::*;
use adapter_catalogue::{Catalogue, Relay};
use serde_json::json;
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

const PUBLIC_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
const IPV4: &str = "192.0.2.10";
const IPV6: &str = "2001:db8::10";

struct TestRoot(PathBuf);
impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Harness {
    connections: Connections,
    // Drop Connections and its log sender before removing the temporary root.
    _root: TestRoot,
}

fn harness() -> Harness {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "mullvad-native-routes-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    ));
    std::fs::create_dir(&root).unwrap();
    let logs = crate::live_diagnostics::LogClient::start(root.clone()).unwrap();
    let (connections, _mailbox) = Connections::new(root.clone(), logs);
    Harness {
        connections,
        _root: TestRoot(root),
    }
}

fn make_catalogue(ipv4: Option<&str>, ipv6: Option<&str>) -> Catalogue {
    let payload = json!({
        "wireguard": {
            "port_ranges": [[33431, 33431], [51820, 51820]],
            "shadowsocks_port_ranges": [[51900, 51901]],
            "relays": [{
                "hostname": "us-test-wg-1",
                "location": "us-test",
                "active": true,
                "public_key": PUBLIC_KEY,
                "ipv4_addr_in": ipv4,
                "ipv6_addr_in": ipv6,
                "shadowsocks_extra_addr_in": ["192.0.2.20"]
            }]
        }
    });
    Catalogue::parse(payload.to_string().as_bytes()).expect("synthetic catalogue is valid")
}

fn only_relay(catalogue: &Catalogue) -> &Relay {
    &catalogue.relays()[0]
}

fn dashboard(city: Option<&str>) -> Dashboard {
    let mut dashboard: Dashboard = serde_json::from_value(json!({
        "sequence": 0,
        "boot_id": "synthetic-native-test",
        "build": "test",
        "source_sha": "synthetic",
        "status": "disconnected",
        "physical_attachment": "available",
        "settings": adapter_protocol::app::Settings::default(),
        "front_ready": false,
        "front_selected": "reject",
        "identity_configured": false,
        "cities": [],
        "metadata_source": "fixture",
        "account": adapter_protocol::app::Account::default(),
        "logs_path": "synthetic",
        "logging_degraded": false,
        "logging_dropped": 0,
        "city_candidates": []
    }))
    .unwrap();
    dashboard.settings.selected_city = city.map(str::to_owned);
    dashboard
}

fn native_path(relay: &Relay, kind: &str, inlet: &str, instance: u64) -> Path {
    Path {
        relay: relay.hostname().into(),
        city: relay.location().into(),
        transport: kind.into(),
        inlet: inlet.into(),
        entry_relay: None,
        slot: "a".into(),
        instance,
        front: 1,
    }
}

fn saved_path(path: &Path) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "city": path.city,
        "relay": path.relay,
        "transport": path.transport,
        "inlet": path.inlet,
    }))
    .unwrap()
}

fn synthetic_owner(original: &Path) -> ResourceOwner {
    use adapter_control::observer::ObservedOwner;
    use adapter_domain::State;
    use adapter_platform::physical_attachment::{Attachment as Physical, Observation};

    let mut state = State::new("synthetic-native-phase".into());
    state.path = Some(original.clone());
    state.city = Some(original.city.clone());
    state.observe(adapter_domain::Attachment::Available, 0);
    state.request_original_rebuild(0).unwrap();
    let observation = ObservedOwner::new(state, || Observation {
        attachment: Physical::Unknown,
        bindings: vec![],
    })
    .unwrap();
    ResourceOwner::new(observation)
}

fn synthetic_native_fallback_attempt(
    original: &Path,
    target: &Path,
) -> (ResourceOwner, CandidateAttempt) {
    use adapter_control::observer::ObservedOwner;
    use adapter_domain::{Canary, Effect, RebuildResult, State};
    use adapter_platform::physical_attachment::{Attachment as Physical, Observation};

    let mut state = State::new("synthetic-native-fallback".into());
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

#[test]
fn pick_route_defaults_to_an_authorized_unchained_ss_inlet() {
    let mut harness = harness();
    let catalogue = make_catalogue(Some(IPV4), Some(IPV6));
    let relay = only_relay(&catalogue);

    let route = harness
        .connections
        .pick_route(&catalogue, relay, None, false)
        .expect("default route remains SS");

    assert_eq!(route.kind(), live_route::SS);
    assert!(route.is_ss());
    assert!(!route.chained);
}

#[test]
fn native_phase_selects_v6_then_v4_for_the_fixed_relay() {
    let mut harness = harness();
    let catalogue = make_catalogue(Some(IPV4), Some(IPV6));
    let relay = only_relay(&catalogue);
    harness
        .connections
        .plan
        .start(vec![relay.hostname().into()], false);

    assert!(harness.connections.plan.enter_native());
    let v6 = harness
        .connections
        .pick_route(&catalogue, relay, None, false)
        .unwrap();
    assert_eq!(v6.kind(), live_route::V6);
    assert!(v6.ipv6());

    assert!(harness.connections.plan.enter_native());
    let v4 = harness
        .connections
        .pick_route(&catalogue, relay, None, false)
        .unwrap();
    assert_eq!(v4.kind(), live_route::V4);
    assert!(!v4.ipv6());
}

#[test]
fn exact_native_restore_overrides_a_different_forced_and_planned_route() {
    let mut harness = harness();
    let catalogue = make_catalogue(Some(IPV4), Some(IPV6));
    let relay = only_relay(&catalogue);
    let exact = native_path(relay, live_route::V6, "[2001:db8::10]:33431", 17);
    harness.connections.forced_route = Some(true);
    harness
        .connections
        .plan
        .start(vec![relay.hostname().into()], false);
    assert!(harness.connections.plan.enter_native());
    assert!(harness.connections.plan.enter_native());
    assert_eq!(
        harness.connections.plan.native_phase,
        Some(live_route::Family::V4)
    );

    let restored = harness
        .connections
        .pick_route(&catalogue, relay, Some(&exact), true)
        .expect("exact restore keeps its authorized native V6 path");
    assert_eq!(restored.kind(), live_route::V6);
    assert!(!restored.chained);
}

#[test]
fn exact_restore_rejects_unknown_kind_and_withdrawn_native_endpoint() {
    let mut harness = harness();
    let catalogue = make_catalogue(Some(IPV4), Some(IPV6));
    let relay = only_relay(&catalogue);
    let unknown = native_path(relay, "wireguard-unknown", "192.0.2.10:51820", 18);
    let withdrawn = native_path(relay, live_route::V6, "[2001:db8::11]:33431", 19);

    assert!(matches!(
        harness
            .connections
            .pick_route(&catalogue, relay, Some(&unknown), false),
        Err("original_inlet_withdrawn")
    ));
    assert!(matches!(
        harness
            .connections
            .pick_route(&catalogue, relay, Some(&withdrawn), false),
        Err("original_inlet_withdrawn")
    ));
}

#[test]
fn remembered_native_startup_route_requires_selected_city_and_current_catalogue() {
    let mut accepted = harness();
    let catalogue = make_catalogue(Some(IPV4), Some(IPV6));
    let relay = only_relay(&catalogue);
    let saved = native_path(relay, live_route::V4, "192.0.2.10:51820", 20);
    accepted.connections.remember_startup_path(
        &saved_path(&saved),
        &catalogue,
        &dashboard(Some("us-test")),
    );
    let picked = accepted
        .connections
        .pick_route(&catalogue, relay, None, false)
        .unwrap();
    assert_eq!(picked.kind(), live_route::V4);

    let mut wrong_city = harness();
    wrong_city.connections.remember_startup_path(
        &saved_path(&saved),
        &catalogue,
        &dashboard(Some("ca-other")),
    );
    assert!(wrong_city.connections.startup_route.is_none());
    let defaulted = wrong_city
        .connections
        .pick_route(&catalogue, relay, None, false)
        .unwrap();
    assert_eq!(defaulted.kind(), live_route::SS);

    let mut withdrawn = harness();
    withdrawn.connections.remember_startup_path(
        &saved_path(&saved),
        &catalogue,
        &dashboard(Some("us-test")),
    );
    let refreshed = make_catalogue(Some("198.51.100.10"), Some(IPV6));
    let refreshed_relay = only_relay(&refreshed);
    let current = withdrawn
        .connections
        .pick_route(&refreshed, refreshed_relay, None, false)
        .unwrap();
    assert_eq!(current.kind(), live_route::SS);
    assert!(withdrawn.connections.startup_route.is_none());
}

#[test]
fn native_phase_failure_does_not_consume_ss_history_or_advance_as_an_ss_inlet() {
    let mut harness = harness();
    let catalogue = make_catalogue(Some(IPV4), Some(IPV6));
    let relay = only_relay(&catalogue);
    let ss = catalogue
        .shadowsocks_inlet(relay, None)
        .expect("fixture has an authorized SS inlet");
    harness.connections.inlet_trials.succeeded(
        relay.hostname(),
        &format!("{}:{}", ss.address, ss.port),
        false,
    );
    let before = harness.connections.inlet_trials.history_bytes().unwrap();
    harness
        .connections
        .plan
        .start(vec![relay.hostname().into()], false);
    assert!(harness.connections.plan.enter_native());
    let path = native_path(relay, live_route::V6, "[2001:db8::10]:33431", 21);

    assert!(!harness
        .connections
        .advance_inlet(&path, Some(&catalogue), true, true));
    assert_eq!(
        harness.connections.inlet_trials.history_bytes().unwrap(),
        before
    );
    assert!(harness.connections.deferred.is_none());
}

#[test]
fn native_phase_refill_preserves_manual_deadline_city_and_fixed_relay_set() {
    let mut harness = harness();
    let catalogue = make_catalogue(Some(IPV4), Some(IPV6));
    let relay = only_relay(&catalogue);
    let original = native_path(relay, live_route::SS, "192.0.2.20:20484", 22);
    let mut owner = synthetic_owner(&original);
    let dashboard = dashboard(Some("us-test"));
    let fixed_relays = vec!["us-test-wg-1".to_string(), "us-test-wg-backup".to_string()];
    harness.connections.plan.start(fixed_relays.clone(), false);
    let deadline = Instant::now() + Duration::from_secs(90);
    harness.connections.manual_candidates = Some((
        deadline,
        "us-test".into(),
        VecDeque::from(["stale-queue-entry".into()]),
        false,
    ));

    assert!(harness.connections.enter_next_phase(&mut owner, &dashboard));
    for expected in [live_route::Family::V6, live_route::Family::V4] {
        let (saved_deadline, city, relays, exact) =
            harness.connections.manual_candidates.as_ref().unwrap();
        assert_eq!(*saved_deadline, deadline);
        assert_eq!(city, "us-test");
        assert_eq!(relays, &VecDeque::from(fixed_relays.clone()));
        assert!(!exact);
        assert_eq!(harness.connections.plan.native_phase, Some(expected));
        if expected == live_route::Family::V6 {
            assert!(harness.connections.enter_next_phase(&mut owner, &dashboard));
        }
    }
}

#[test]
fn unavailable_native_fallback_preserves_retry_queues_deadlines_and_ss_history() {
    use crate::recovery_retry::AttemptFailureDisposition as D;

    let mut harness = harness();
    let catalogue = make_catalogue(Some(IPV4), Some(IPV6));
    let relay = only_relay(&catalogue);
    let original = native_path(relay, live_route::SS, "192.0.2.20:51900", 30);
    let target = native_path(relay, live_route::V6, "[2001:db8::10]:33431", 32);
    let (mut owner, attempt) = synthetic_native_fallback_attempt(&original, &target);

    harness
        .connections
        .plan
        .start(vec![relay.hostname().into()], false);
    assert!(harness.connections.plan.enter_native());
    let inlet = catalogue.shadowsocks_inlets(relay)[0];
    harness.connections.inlet_trials.succeeded(
        relay.hostname(),
        &format!("{}:{}", inlet.address, inlet.port),
        false,
    );
    let history_before = harness.connections.inlet_trials.history_bytes().unwrap();

    let manual_deadline = Instant::now() + Duration::from_secs(90);
    let recovery_deadline = Instant::now() + Duration::from_secs(120);
    let manual_queue = VecDeque::from(["manual-backup".into()]);
    let recovery_queue = VecDeque::from(["same-city-backup".into()]);
    harness.connections.manual_candidates = Some((
        manual_deadline,
        "us-test".into(),
        manual_queue.clone(),
        false,
    ));
    harness.connections.recovering = Some((recovery_deadline, recovery_queue.clone()));
    harness.connections.deferred = Some("deferred-native-relay".into());

    let mut dashboard = dashboard(Some("us-test"));
    let disposition = harness.connections.apply_attempt_failure_disposition(
        &mut owner,
        &mut dashboard,
        &attempt,
        D::SkipUnavailablePath,
        true,
    );

    assert_eq!(disposition, D::SkipUnavailablePath);
    assert_eq!(
        harness.connections.manual_candidates,
        Some((manual_deadline, "us-test".into(), manual_queue, false))
    );
    assert_eq!(
        harness.connections.recovering,
        Some((recovery_deadline, recovery_queue))
    );
    assert!(harness.connections.deferred.is_none());
    assert_eq!(
        harness.connections.inlet_trials.history_bytes().unwrap(),
        history_before
    );
}

#[test]
fn native_negative_outside_native_phase_returns_to_same_relay_ss_without_recording_ss_failure() {
    let mut harness = harness();
    let catalogue = make_catalogue(Some(IPV4), Some(IPV6));
    let relay = only_relay(&catalogue);
    let inlets = catalogue.shadowsocks_inlets(relay);
    harness
        .connections
        .inlet_trials
        .reconcile(relay.hostname(), relay.public_key(), &inlets);
    let prior_success = inlets[0];
    harness.connections.inlet_trials.succeeded(
        relay.hostname(),
        &format!("{}:{}", prior_success.address, prior_success.port),
        false,
    );
    let history_before = harness.connections.inlet_trials.history_bytes().unwrap();

    let native = native_path(relay, live_route::V6, "[2001:db8::10]:33431", 40);
    let deadline = Instant::now() + Duration::from_secs(90);
    let remaining = VecDeque::from(["manual-backup".into()]);
    harness.connections.manual_candidates =
        Some((deadline, relay.location().into(), remaining.clone(), false));

    assert!(harness
        .connections
        .advance_inlet(&native, Some(&catalogue), false, false));
    assert_eq!(
        harness.connections.inlet_trials.history_bytes().unwrap(),
        history_before,
        "a native-path failure is not negative SS evidence"
    );
    let (saved_deadline, city, queue, exact) =
        harness.connections.manual_candidates.as_ref().unwrap();
    assert_eq!(*saved_deadline, deadline);
    assert_eq!(city, relay.location());
    assert_eq!(
        queue,
        &VecDeque::from([relay.hostname().to_string(), "manual-backup".into()])
    );
    assert!(!exact);

    let ss = harness
        .connections
        .pick_route(&catalogue, relay, None, false)
        .expect("outside the native phase, the same relay has an SS route");
    assert_eq!(ss.kind(), live_route::SS);
    assert_eq!(ss.endpoint().port(), inlets[1].port);
    assert_eq!(ss.endpoint().ip(), std::net::IpAddr::V4(inlets[1].address));
    assert_eq!(
        harness.connections.inlet_trials.history_bytes().unwrap(),
        history_before,
        "choosing the next SS endpoint alone does not record a failure"
    );

    let ss_attempt = native_path(relay, live_route::SS, &ss.endpoint().to_string(), 41);
    assert!(harness
        .connections
        .advance_inlet(&ss_attempt, Some(&catalogue), false, false));
    assert_ne!(
        harness.connections.inlet_trials.history_bytes().unwrap(),
        history_before,
        "only an actual SS inlet failure changes SS failure history"
    );
}
