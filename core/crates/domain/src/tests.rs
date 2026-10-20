use super::*;
#[test]
fn manual_city_selection_preserves_old_commit_until_fresh_ready() {
    let mut state = seeded();
    state.observe(Attachment::Available, 100);
    let old = state.path.clone();
    let attempt = state
        .begin_manual_selection(path("new", "jp-tyo", 2), 100)
        .unwrap();
    assert_eq!(state.path, old);
    assert_eq!(state.city.as_deref(), Some("us-sjc"));
    assert!(state.candidate_is_current(&attempt, 101));
    assert_eq!(
        state.commit_manual_selection(&attempt, canary(true, false, true), 101, 101),
        Err("candidate_not_ready")
    );
    assert_eq!(state.path, old);
    assert_eq!(
        state.commit_manual_selection(&attempt, canary(true, true, true), 101, 5102),
        Err("stale_candidate_evidence")
    );
    state
        .commit_manual_selection(&attempt, canary(true, true, true), 5102, 5102)
        .unwrap();
    assert_eq!(state.city.as_deref(), Some("jp-tyo"));
    assert_eq!(state.path.unwrap().instance, 2);
}
#[test]
fn manual_selection_rejects_offline_unknown_and_late_results() {
    let mut state = seeded();
    assert_eq!(
        state.begin_manual_selection(path("new", "jp-tyo", 2), 1),
        Err("waiting_network")
    );
    state.observe(Attachment::Available, 2);
    let attempt = state
        .begin_manual_selection(path("new", "jp-tyo", 2), 2)
        .unwrap();
    state.manual_preempt();
    assert_eq!(
        state.commit_manual_selection(&attempt, canary(true, true, true), 3, 3),
        Err("stale_attempt")
    );
    state.observe(Attachment::Unavailable, 4);
    assert_eq!(
        state.begin_manual_selection(path("new", "jp-tyo", 3), 5),
        Err("waiting_network")
    );
    assert_eq!(state.city.as_deref(), Some("us-sjc"));
}
fn path(relay: &str, city: &str, instance: u64) -> Path {
    Path {
        relay: relay.into(),
        city: city.into(),
        transport: "ss".into(),
        inlet: "192.0.2.2:20484".into(),
        entry_relay: None,
        slot: "a".into(),
        instance,
        front: 1,
    }
}
fn seeded() -> State {
    let mut state = State::new("test-boot".into());
    state.path = Some(path("one", "us-sjc", 1));
    state.city = Some("us-sjc".into());
    state
}
#[test]
fn terminal_recovery_preserves_intent_and_budget_until_a_real_new_outage() {
    let mut state = seeded();
    state.observe(Attachment::Available, 0);
    state.request_original_rebuild(100).unwrap();
    let attempt = state
        .begin_original_rebuild(path("one", "us-sjc", 2), 101)
        .unwrap();
    let committed = state.path.clone();
    let token = state.token();
    let budget = state.recovery_started;
    state.finish_recovery(false);
    assert_eq!(state.stage, Stage::Disconnected);
    assert_eq!(state.path, committed);
    assert_eq!(state.city.as_deref(), Some("us-sjc"));
    assert_eq!(state.token(), token);
    assert_eq!(state.recovery_started, budget);
    assert!(!state.candidate_is_current(&attempt, 102));
    assert!(state.deferred_until.is_none() && state.deferred_stage.is_none());
    let later = 100 + RECOVERY_BUDGET_MS;
    for attachment in [Attachment::Unknown, Attachment::Available] {
        state.observe(attachment, later);
        assert_eq!(state.tick(later + SETTLE_MS), None);
        assert_eq!(state.stage, Stage::Disconnected);
        assert_eq!(state.recovery_started, budget);
    }
    state.observe(Attachment::Unavailable, later + SETTLE_MS + 1);
    state.observe(Attachment::Available, later + SETTLE_MS + 2);
    let resumed = later + 2 * SETTLE_MS + 2;
    assert!(matches!(state.tick(resumed), Some(Effect::Verify(_, _))));
    assert_eq!(state.recovery_started, Some(resumed));
    assert_eq!(state.tick(resumed + SETTLE_MS), None);
    assert_eq!(state.path, committed);
}
#[test]
fn retained_worker_requires_fresh_health_before_an_independent_new_budget() {
    let mut state = seeded();
    state.observe(Attachment::Available, 0);
    state.request_original_rebuild(100).unwrap();
    let expired = 100 + RECOVERY_BUDGET_MS;
    state.finish_recovery(true);
    let token = state.token();
    assert_eq!(state.stage, Stage::VerifyOriginal);
    assert_eq!(state.readiness, None);
    assert_eq!(
        state.request_original_rebuild(expired),
        Err("recovery_budget_exhausted")
    );
    assert_eq!(state.token(), token);
    assert_eq!(state.recovery_started, Some(100));
    assert_eq!(
        state.original_verified(&token, canary(true, true, true), 100, expired, true),
        Effect::Stale
    );
    assert_eq!(state.stage, Stage::VerifyOriginal);
    assert_eq!(
        state.original_verified(&token, canary(true, true, true), expired, expired, true),
        Effect::Preserved(Readiness::Ready)
    );
    let later_failure = expired + RECOVERY_BUDGET_MS;
    state.request_original_rebuild(later_failure).unwrap();
    assert_eq!(state.recovery_started, Some(later_failure));
}
#[test]
fn later_active_path_failure_gets_a_fresh_recovery_budget() {
    let mut state = seeded();
    state.observe(Attachment::Available, 0);
    state.request_original_rebuild(1).unwrap();
    let attempt = state
        .begin_original_rebuild(path("one", "us-sjc", 2), 1)
        .unwrap();
    assert_eq!(
        state.original_rebuilt(
            &attempt,
            RebuildResult::Canary {
                path: attempt.path.clone(),
                canary: canary(true, true, true)
            },
            2,
            2
        ),
        Effect::Preserved(Readiness::Ready)
    );
    let later = RECOVERY_BUDGET_MS * 2;
    state.request_original_rebuild(later).unwrap();
    assert!(state
        .begin_original_rebuild(path("one", "us-sjc", 3), later)
        .is_ok());
}
fn canary(ip: bool, dns: bool, https: bool) -> Canary {
    Canary { ip, dns, https }
}
fn resume(state: &mut State) -> Token {
    state.observe(Attachment::Unavailable, 0);
    state.observe(Attachment::Available, 10);
    assert!(state.tick(2009).is_none());
    match state.tick(2010).unwrap() {
        Effect::Verify(_, token) => token,
        other => panic!("{other:?}"),
    }
}
#[test]
fn unknown_does_not_create_or_release_outage() {
    let mut s = seeded();
    s.observe(Attachment::Unknown, 0);
    assert!(!s.paused);
    s.observe(Attachment::Unavailable, 1);
    s.observe(Attachment::Available, 2);
    s.observe(Attachment::Unknown, 2001);
    assert!(s.tick(3000).is_none());
    assert!(s.paused);
    s.observe(Attachment::Available, 3001);
    assert!(s.tick(5000).is_none());
    assert!(s.tick(5001).is_some());
}
#[test]
fn dns_only_original_path_is_preserved_without_generation_change() {
    let mut s = seeded();
    let token = resume(&mut s);
    let original = s.path.clone();
    assert_eq!(
        s.original_verified(&token, canary(true, false, false), 2010, 2010, true),
        Effect::Preserved(Readiness::DegradedDns)
    );
    assert_eq!(s.path, original);
    assert_eq!(s.generation, 0);
}
#[test]
fn original_failure_rebuilds_exact_path_before_same_city_fallback() {
    let mut s = seeded();
    let token = resume(&mut s);
    assert_eq!(
        s.original_verified(&token, canary(false, false, false), 2010, 2011, true),
        Effect::Rebuild(s.path.clone().unwrap(), token.clone())
    );
    let attempt = s
        .begin_original_rebuild(path("one", "us-sjc", 2), 2011)
        .unwrap();
    assert_eq!(
        s.original_rebuilt(
            &attempt,
            RebuildResult::Canary {
                path: path("one", "us-sjc", 2),
                canary: canary(false, false, false)
            },
            2012,
            2012
        ),
        Effect::SameCity("us-sjc".into(), token)
    );
}
#[test]
fn local_busy_defers_without_fallback_or_poisoning_readiness() {
    let mut s = seeded();
    let token = resume(&mut s);
    s.original_verified(&token, canary(false, false, false), 2010, 2010, true);
    let attempt = s
        .begin_original_rebuild(path("one", "us-sjc", 2), 2011)
        .unwrap();
    assert_eq!(
        s.original_rebuilt(&attempt, RebuildResult::Busy, 2011, 2011),
        Effect::Deferred(250)
    );
    assert!(s.tick(2260).is_none());
    assert!(matches!(s.tick(2261), Some(Effect::Rebuild(_, _))));
}
#[test]
fn metadata_withdrawal_permits_same_city_only_and_fresh_full_readiness() {
    let mut s = seeded();
    let token = resume(&mut s);
    assert!(matches!(
        s.original_verified(&token, canary(false, false, false), 2010, 2010, false),
        Effect::SameCity(_, _)
    ));
    assert_eq!(
        s.begin_fallback(path("two", "jp-tyo", 2), 2011),
        Err("outside_selected_city")
    );
    let attempt = s.begin_fallback(path("two", "us-sjc", 2), 2011).unwrap();
    assert_eq!(
        s.commit_fallback(&attempt, canary(true, false, true), 2011, 2011),
        Err("candidate_not_ready")
    );
    assert!(s
        .commit_fallback(&attempt, canary(true, true, true), 2011, 2011)
        .is_ok());
    assert!(!s.current(&token));
}
#[test]
fn outage_manual_preemption_boot_and_instance_changes_invalidate_completions() {
    for which in 0..6 {
        let mut s = seeded();
        let token = resume(&mut s);
        match which {
            0 => s.observe(Attachment::Unavailable, 2011),
            1 => s.manual_preempt(),
            2 => s.boot = "restarted".into(),
            3 => s.path.as_mut().unwrap().instance += 1,
            4 => s.path.as_mut().unwrap().front += 1,
            _ => s.generation += 1,
        }
        assert_eq!(
            s.original_verified(&token, canary(false, false, false), 2010, 2012, true),
            Effect::Stale
        );
    }
}
#[test]
fn late_and_future_evidence_is_rejected() {
    let mut s = seeded();
    let token = resume(&mut s);
    assert_eq!(
        s.original_verified(&token, canary(true, true, true), 2010, 7011, true),
        Effect::Stale
    );
    assert_eq!(
        s.original_verified(&token, canary(true, true, true), 7012, 7011, true),
        Effect::Stale
    );
}
#[test]
fn budget_stops_starting_fallback() {
    let mut s = seeded();
    let token = resume(&mut s);
    assert_eq!(
        s.original_verified(
            &token,
            canary(false, false, false),
            2010 + RECOVERY_BUDGET_MS,
            2010 + RECOVERY_BUDGET_MS,
            false
        ),
        Effect::Disconnected
    );
}
#[test]
fn all_new_pq_paths_including_rollback_need_readiness() {
    for pq in [false, true] {
        for ip in [false, true] {
            for dns in [false, true] {
                for https in [false, true] {
                    let c = canary(ip, dns, https);
                    let p = Protection {
                        multihop: false,
                        post_quantum: pq,
                    };
                    assert_eq!(
                        c.accepts_new(p, false),
                        (ip || https) && (!pq || (dns && https))
                    );
                    assert_eq!(c.accepts_new(p, true), (ip || https) && dns && https);
                }
            }
        }
    }
}
#[test]
fn required_capabilities_never_silently_downgrade() {
    assert!(!Capabilities::default().supports(Protection {
        multihop: false,
        post_quantum: true
    }));
    assert!(!Capabilities {
        multihop: true,
        post_quantum: true
    }
    .supports(Protection {
        multihop: true,
        post_quantum: true
    }));
}
#[test]
fn peer_reservation_is_atomic_and_owner_scoped() {
    let mut peers = PeerReservations::default();
    assert!(peers.reserve(&["entry".into(), "exit".into()], 1).is_ok());
    assert!(peers.reserve(&["other".into(), "exit".into()], 2).is_err());
    assert!(peers.reserve(&["other".into()], 3).is_ok());
    peers.release(2);
    assert!(peers.reserve(&["entry".into()], 4).is_err());
    peers.release(1);
    assert!(peers.reserve(&["entry".into(), "exit".into()], 4).is_ok());
}

#[test]
fn completed_inflight_fallback_is_not_rejected_only_for_exceeding_start_budget() {
    let mut s = seeded();
    let token = resume(&mut s);
    s.original_verified(&token, canary(false, false, false), 2010, 2010, false);
    let start = 2010 + RECOVERY_BUDGET_MS;
    let attempt = s
        .begin_fallback(path("two", "us-sjc", 2), start - 100)
        .unwrap();
    assert!(s
        .commit_fallback(&attempt, canary(true, true, true), start + 100, start + 100)
        .is_ok());
}

#[test]
fn deferred_original_rebuild_does_not_start_after_budget_expires() {
    let mut s = seeded();
    let token = resume(&mut s);
    s.original_verified(&token, canary(false, false, false), 2010, 2010, true);
    let near_end = 2010 + RECOVERY_BUDGET_MS - 100;
    let attempt = s
        .begin_original_rebuild(path("one", "us-sjc", 2), near_end)
        .unwrap();
    s.original_rebuilt(&attempt, RebuildResult::Busy, near_end, near_end);
    assert_eq!(
        s.tick(near_end + LOCAL_RETRY_MS),
        Some(Effect::Disconnected)
    );
}

#[test]
fn accepted_rebuild_changes_instance_while_retaining_exact_original_path() {
    let mut s = seeded();
    let token = resume(&mut s);
    s.original_verified(&token, canary(false, false, false), 2010, 2010, true);
    let attempt = s
        .begin_original_rebuild(path("one", "us-sjc", 2), 2011)
        .unwrap();
    assert_eq!(
        s.original_rebuilt(
            &attempt,
            RebuildResult::Canary {
                path: path("one", "us-sjc", 2),
                canary: canary(true, true, true)
            },
            2011,
            2011
        ),
        Effect::Preserved(Readiness::Ready)
    );
    assert_eq!(s.path.as_ref().unwrap().instance, 2);
    assert!(!s.current(&token));
}

#[test]
fn rebuilt_worker_cannot_commit_an_unowned_slot() {
    let mut s = seeded();
    let token = resume(&mut s);
    s.original_verified(&token, canary(false, false, false), 2010, 2010, true);
    let attempt = s
        .begin_original_rebuild(path("one", "us-sjc", 2), 2011)
        .unwrap();
    let mut invalid = path("one", "us-sjc", 2);
    invalid.slot = "unowned-slot".into();
    assert_eq!(
        s.original_rebuilt(
            &attempt,
            RebuildResult::Canary {
                path: invalid,
                canary: canary(true, true, true)
            },
            2011,
            2011
        ),
        Effect::Stale
    );
}

#[test]
fn fallback_rejects_stale_swapped_and_superseded_candidate_evidence() {
    let mut s = seeded();
    let token = resume(&mut s);
    s.original_verified(&token, canary(false, false, false), 2010, 2010, false);
    assert_eq!(
        s.begin_fallback(path("two", "us-sjc", 1), 2011),
        Err("invalid_candidate_identity")
    );
    let first = s.begin_fallback(path("two", "us-sjc", 2), 2011).unwrap();
    assert_eq!(
        s.commit_fallback(&first, canary(true, true, true), 2011, 86_402_011),
        Err("stale_candidate_evidence")
    );
    assert_eq!(
        s.commit_fallback(&first, canary(true, true, true), 2010, 2011),
        Err("stale_candidate_evidence")
    );
    let mut swapped = first.clone();
    swapped.path.instance += 1;
    assert_eq!(
        s.commit_fallback(&swapped, canary(true, true, true), 2011, 2011),
        Err("stale_attempt")
    );
    let second = s.begin_fallback(path("three", "us-sjc", 3), 2012).unwrap();
    assert_eq!(
        s.commit_fallback(&first, canary(true, true, true), 2012, 2012),
        Err("stale_attempt")
    );
    s.manual_preempt();
    assert_eq!(
        s.commit_fallback(&second, canary(true, true, true), 2012, 2012),
        Err("stale_attempt")
    );
}

#[test]
fn rebuild_checks_evidence_time_identity_and_retry_registration() {
    let mut s = seeded();
    let token = resume(&mut s);
    s.original_verified(&token, canary(false, false, false), 2010, 2010, true);
    let first = s
        .begin_original_rebuild(path("one", "us-sjc", 2), 2011)
        .unwrap();
    for (observed, now) in [(2010, 2011), (2012, 2011), (2011, 7012)] {
        assert_eq!(
            s.original_rebuilt(&first, RebuildResult::Busy, observed, now),
            Effect::Stale
        );
    }
    let mut forged = first.clone();
    forged.path.instance += 1;
    assert_eq!(
        s.original_rebuilt(&forged, RebuildResult::Busy, 7011, 7011),
        Effect::Stale
    );
    assert_eq!(
        s.original_rebuilt(&first, RebuildResult::Busy, 2011, 7011),
        Effect::Deferred(250)
    );
    assert!(matches!(s.tick(7261), Some(Effect::Rebuild(_, _))));
    assert_eq!(
        s.original_rebuilt(&first, RebuildResult::Busy, 7261, 7261),
        Effect::Stale
    );
    let second = s
        .begin_original_rebuild(path("one", "us-sjc", 3), 7261)
        .unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!(
        s.original_rebuilt(&first, RebuildResult::Busy, 7261, 7261),
        Effect::Stale
    );
    assert_eq!(
        s.original_rebuilt(
            &second,
            RebuildResult::Canary {
                path: second.path.clone(),
                canary: canary(true, true, true)
            },
            7261,
            7261
        ),
        Effect::Preserved(Readiness::Ready)
    );
}

#[test]
fn hard_deadline_applies_to_every_rebuild_outcome_and_fallback() {
    for outcome in 0..4 {
        let mut s = seeded();
        let token = resume(&mut s);
        s.original_verified(&token, canary(false, false, false), 2010, 2010, true);
        let attempt = s
            .begin_original_rebuild(path("one", "us-sjc", 2), 2011)
            .unwrap();
        let result = match outcome {
            0 => RebuildResult::Busy,
            1 => RebuildResult::LocalFailure,
            _ => RebuildResult::Canary {
                path: attempt.path.clone(),
                canary: canary(outcome == 2, outcome == 2, outcome == 2),
            },
        };
        assert_eq!(
            s.original_rebuilt(&attempt, result, attempt.deadline, attempt.deadline),
            Effect::Stale
        );
        assert_eq!(s.path.as_ref().unwrap().instance, 1);
    }
    for offset in [0, 1] {
        let mut s = seeded();
        let token = resume(&mut s);
        s.original_verified(&token, canary(false, false, false), 2010, 2010, false);
        let attempt = s.begin_fallback(path("two", "us-sjc", 2), 2011).unwrap();
        let now = attempt.deadline - offset;
        assert_eq!(
            s.commit_fallback(&attempt, canary(true, true, true), now, now),
            if offset == 0 {
                Err("candidate_deadline")
            } else {
                Ok(())
            }
        );
    }
}

#[test]
fn serial_original_short_retries_keep_exact_path_and_never_refill_round() {
    let mut s = seeded();
    s.observe(Attachment::Available, 0);
    s.request_original_rebuild(100).unwrap();
    let committed = s.path.clone();
    let start = s.recovery_started;
    let mut now = 101;
    for (instance, delay) in [(2, Some(1000)), (3, Some(5000)), (4, None)] {
        let a = s
            .begin_original_rebuild(path("one", "us-sjc", instance), now)
            .unwrap();
        let result = s.original_rebuilt_retry(
            &a,
            RebuildResult::Canary {
                path: a.path.clone(),
                canary: canary(false, false, false),
            },
            now,
            now,
            delay,
        );
        assert_eq!(s.path, committed);
        assert_eq!(s.recovery_started, start);
        assert!(!s.candidate_is_current(&a, now));
        if let Some(delay) = delay {
            assert_eq!(result, Effect::Deferred(delay));
            now += delay;
            assert!(matches!(s.tick(now), Some(Effect::Rebuild(_, _))));
        } else {
            assert!(matches!(result, Effect::SameCity(_, _)));
            assert_eq!(s.stage, Stage::Fallback);
        }
    }
}
#[test]
fn retry_disposition_does_not_accept_stale_foreign_or_preempted_negatives() {
    for invalid in 0..4 {
        let mut s = seeded();
        s.observe(Attachment::Available, 0);
        s.request_original_rebuild(100).unwrap();
        let a = s
            .begin_original_rebuild(path("one", "us-sjc", 2), 101)
            .unwrap();
        let (at, now) = match invalid {
            0 => (100, 101),
            1 => (102, 101),
            2 => (101, 6000),
            _ => (102, 102),
        };
        if invalid == 3 {
            s.manual_preempt();
        }
        let token = s.token();
        let budget = s.recovery_started;
        assert_eq!(
            s.original_rebuilt_retry(
                &a,
                RebuildResult::Canary {
                    path: a.path.clone(),
                    canary: canary(false, false, false)
                },
                at,
                now,
                Some(1000)
            ),
            Effect::Stale
        );
        assert_eq!(s.token(), token);
        assert_eq!(s.recovery_started, budget);
    }
}
#[test]
fn drained_local_deadline_can_retry_original_without_inventing_negative_evidence() {
    let mut s = seeded();
    s.observe(Attachment::Available, 0);
    s.request_original_rebuild(100).unwrap();
    let a = s
        .begin_original_rebuild(path("one", "us-sjc", 2), 101)
        .unwrap();
    let late = a.deadline + 1;
    assert!(!s.candidate_is_current(&a, late));
    assert_eq!(
        s.retry_after_local_cleanup(&a, late),
        Effect::Deferred(LOCAL_RETRY_MS)
    );
    assert_eq!(s.recovery_started, Some(100));
    s.tick(late + LOCAL_RETRY_MS);
    assert!(s
        .begin_original_rebuild(path("one", "us-sjc", 3), late + LOCAL_RETRY_MS)
        .is_ok());
}
