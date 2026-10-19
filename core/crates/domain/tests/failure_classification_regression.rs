use adapter_domain::{
    Attachment, Canary, Effect, Path, Readiness, RebuildResult, Stage, State, Token,
    LOCAL_RETRY_MS, PROBE_TTL_MS, SETTLE_MS,
};

fn path(relay: &str, instance: u64, slot: &str) -> Path {
    Path {
        relay: relay.into(),
        city: "fixture-city".into(),
        transport: "wireguard-over-shadowsocks".into(),
        inlet: "192.0.2.2:20484".into(),
        entry_relay: None,
        slot: slot.into(),
        instance,
        front: 1,
    }
}

fn seeded() -> State {
    let mut state = State::new("classification-fixture".into());
    state.path = Some(path("original", 1, "a"));
    state.city = Some("fixture-city".into());
    state.observe(Attachment::Available, 0);
    state
}

fn resume_original(state: &mut State) -> (Token, u64) {
    state.observe(Attachment::Unavailable, 1);
    state.observe(Attachment::Available, 2);
    let now = 2 + SETTLE_MS;
    match state.tick(now) {
        Some(Effect::Verify(_, token)) => (token, now),
        other => panic!("expected an original-path verification, got {other:?}"),
    }
}

#[test]
fn partial_probe_failures_preserve_original_worker_without_a_new_operation() {
    for (canary, readiness) in [
        (
            Canary {
                ip: true,
                dns: false,
                https: false,
            },
            Readiness::DegradedDns,
        ),
        (
            Canary {
                ip: true,
                dns: true,
                https: false,
            },
            Readiness::DegradedService,
        ),
        (
            Canary {
                ip: false,
                dns: true,
                https: true,
            },
            Readiness::Ready,
        ),
        (
            Canary {
                ip: true,
                dns: false,
                https: true,
            },
            Readiness::DegradedDns,
        ),
    ] {
        let mut state = seeded();
        let (token, now) = resume_original(&mut state);
        let original = state.path.clone();
        assert_eq!(
            state.original_verified(&token, canary, now, now, true),
            Effect::Preserved(readiness),
        );
        assert_eq!(state.path, original);
        assert_eq!(
            state.token(),
            token,
            "a partial failure must not rotate ownership"
        );
        assert_eq!(state.stage, Stage::Idle);
        assert_eq!(state.readiness, Some(readiness));
    }
}

#[test]
fn full_data_failure_rebuilds_exact_path_and_local_failure_does_not_choose_a_relay() {
    let mut state = seeded();
    let (token, now) = resume_original(&mut state);
    let original = state.path.clone().unwrap();
    assert_eq!(
        state.original_verified(
            &token,
            Canary {
                ip: false,
                dns: true,
                https: false,
            },
            now,
            now,
            true,
        ),
        Effect::Rebuild(original.clone(), token.clone()),
    );
    assert_eq!(
        state.begin_original_rebuild(path("another-relay", 2, "a"), now),
        Err("invalid_original_path"),
    );
    let attempt = state
        .begin_original_rebuild(path("original", 2, "a"), now)
        .unwrap();
    assert_eq!(
        state.original_rebuilt(&attempt, RebuildResult::LocalFailure, now, now),
        Effect::Deferred(LOCAL_RETRY_MS),
    );
    assert_eq!(state.path, Some(original.clone()));
    assert!(state.tick(now + LOCAL_RETRY_MS - 1).is_none());
    assert_eq!(
        state.tick(now + LOCAL_RETRY_MS),
        Some(Effect::Rebuild(original, token)),
    );
}

#[test]
fn stale_future_or_superseded_negative_observations_cannot_start_recovery() {
    let failed = Canary {
        ip: false,
        dns: false,
        https: false,
    };
    for future in [false, true] {
        let mut state = seeded();
        let (token, now) = resume_original(&mut state);
        let original = state.path.clone();
        let (observed, received) = if future {
            (now + 1, now)
        } else {
            (now, now + PROBE_TTL_MS + 1)
        };
        assert_eq!(
            state.original_verified(&token, failed, observed, received, true),
            Effect::Stale,
        );
        assert_eq!(state.stage, Stage::VerifyOriginal);
        assert_eq!(state.path, original);
        assert_eq!(state.token(), token);
    }

    let mut state = seeded();
    let (old_token, now) = resume_original(&mut state);
    state.manual_preempt();
    let current = state.token();
    assert_eq!(
        state.original_verified(&old_token, failed, now, now, true),
        Effect::Stale,
    );
    assert_eq!(state.stage, Stage::Idle);
    assert_eq!(state.token(), current);
}

#[test]
fn physical_offline_waits_through_unknown_and_requires_a_new_positive_interval() {
    let mut state = seeded();
    let original = state.path.clone();
    state.observe(Attachment::Unavailable, 1);
    assert_eq!(state.stage, Stage::Waiting);
    assert_eq!(state.request_original_rebuild(2), Err("waiting_network"));
    state.observe(Attachment::Available, 3);
    state.observe(Attachment::Unknown, 3 + SETTLE_MS - 1);
    assert!(state.tick(3 + SETTLE_MS * 10).is_none());
    assert!(state.paused);
    assert_eq!(state.path, original);

    let resumed = 3 + SETTLE_MS * 10 + 1;
    state.observe(Attachment::Available, resumed);
    assert!(state.tick(resumed + SETTLE_MS - 1).is_none());
    assert!(matches!(
        state.tick(resumed + SETTLE_MS),
        Some(Effect::Verify(ref retained, _)) if Some(retained) == original.as_ref()
    ));
    assert!(!state.paused);
}

#[test]
fn degraded_preservation_does_not_authorize_a_new_fallback_worker() {
    let mut state = seeded();
    let (_, now) = resume_original(&mut state);
    let token = state.token();
    assert!(matches!(
        state.original_withdrawn(&token, now),
        Effect::SameCity(_, _)
    ));
    let attempt = state
        .begin_fallback(path("same-city-alternative", 2, "b"), now)
        .unwrap();
    for degraded in [
        Canary {
            ip: true,
            dns: false,
            https: false,
        },
        Canary {
            ip: true,
            dns: true,
            https: false,
        },
    ] {
        assert_eq!(
            state.commit_fallback(&attempt, degraded, now, now),
            Err("candidate_not_ready"),
        );
        assert_eq!(state.path.as_ref().unwrap().relay, "original");
        assert_eq!(state.generation, 0);
        assert!(state.candidate_is_current(&attempt, now));
    }
}
