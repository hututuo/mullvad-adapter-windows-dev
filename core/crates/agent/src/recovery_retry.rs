//! A new recovery round needs an explicit retained intent and an elapsed pause.
//! Hints and host ticks never refill a running round's attempts/time budget.
use std::time::{Duration, Instant};

/// Return a new persistent relay preference only for actual user selection
/// actions. Route trials keep their target in the trial/rollback state.
pub(crate) fn persistent_relay_for_action<'a>(
    action: adapter_protocol::app::RecoveryAction,
    relay: Option<&'a str>,
) -> Option<Option<&'a str>> {
    use adapter_protocol::app::RecoveryAction as A;
    match action {
        A::RetryCurrent => Some(relay),
        A::RetryCity => Some(None),
        A::TestBackup | A::ChainFallback | A::ReturnDirect => None,
    }
}

const LOCAL_FAILURE_BACKOFF: [u64; 5] = [1, 2, 5, 15, 30];

/// Codes shared with the worker startup/canary local-error taxonomy. A cleanup
/// uncertainty is intentionally excluded because ownership is not proven safe
/// for another start.
pub(crate) fn is_retryable_local_failure(code: &str) -> bool {
    matches!(
        code,
        "operation_busy"
            | "tunnel_command_busy"
            | "worker_runtime_unavailable"
            | "physical_binding_unavailable"
            | "worker_route_unavailable"
            | "worker_chain_resolution_failed"
            | "peer_reservation_unavailable"
            | "worker_start_failed"
            | "worker_controller_unavailable"
            | "worker_start_deadline"
            | "candidate_probe_failed"
            | "candidate_commit_failed"
            | "candidate_selection_failed"
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AttemptFailureDisposition {
    /// The operation was drained and the same target may be retried locally.
    RetrySameTarget,
    /// A native fallback has no route on this binding; skip without remote blame.
    SkipUnavailablePath,
    /// Local retries reached the existing recovery deadline; schedule only the
    /// ordinary city cooldown, without extending that round.
    RoundExpired,
    /// Cleanup is known complete, but the failure is deterministic or stale.
    StopCleanly,
    /// Cleanup or failure meaning is uncertain. Preserve ownership and do not restart.
    Freeze,
}

pub(crate) fn attempt_failure_disposition(code: &str) -> AttemptFailureDisposition {
    if is_retryable_local_failure(code) || code == "candidate_evidence_stale" {
        return AttemptFailureDisposition::RetrySameTarget;
    }
    match code {
        // The helper has already been positively stopped by Prepare. A QUIC
        // handshake/H3 timeout ends only this carrier candidate, without a WG
        // or SS failure sample and without a same-target local defer loop.
        "quic_helper_unavailable" | "quic_helper_start_failed" | "quic_connect_failed" => {
            AttemptFailureDisposition::SkipUnavailablePath
        }
        "worker_configuration_rejected"
        | "worker_start_cancelled"
        | "candidate_cancelled"
        | "candidate_stale" => AttemptFailureDisposition::StopCleanly,
        // Unknown transaction results are fail-closed. In particular, never
        // interpret cleanup or identity uncertainty as evidence to advance.
        _ => AttemptFailureDisposition::Freeze,
    }
}

/// Back off inconclusive local failures without changing the recovery target.
/// The active recovery round's fixed deadline still bounds how long this may
/// retry before normal city-level cooldown takes over.
#[derive(Default)]
pub(crate) struct LocalFailureRetry {
    target: Option<String>,
    failures: usize,
}

impl LocalFailureRetry {
    pub(crate) fn next_delay(&mut self, target: &str) -> Duration {
        if self.target.as_deref() != Some(target) {
            self.target = Some(target.into());
            self.failures = 0;
        }
        let delay = LOCAL_FAILURE_BACKOFF[self.failures.min(LOCAL_FAILURE_BACKOFF.len() - 1)];
        self.failures = self.failures.saturating_add(1);
        Duration::from_secs(delay)
    }

    pub(crate) fn clear(&mut self) {
        self.target = None;
        self.failures = 0;
    }
}

#[derive(Default)]
pub(crate) struct RecoveryRetry {
    wanted: Option<(String, Option<String>)>,
    failures: usize,
    pending: Option<(Instant, String)>,
}
impl RecoveryRetry {
    pub(crate) fn user_connect(&mut self, city: Option<&str>, relay: Option<&str>) {
        self.wanted = city.map(|city| (city.into(), relay.map(str::to_owned)));
        self.success();
    }
    pub(crate) fn cancel(&mut self) {
        self.wanted = None;
        self.success();
    }
    pub(crate) fn city(&self) -> Option<&str> {
        self.wanted.as_ref().map(|i| i.0.as_str())
    }
    pub(crate) fn exact_relay(&self) -> Option<&str> {
        self.wanted.as_ref().and_then(|i| i.1.as_deref())
    }
    pub(crate) fn success(&mut self) {
        self.failures = 0;
        self.pending = None;
    }
    pub(crate) fn connection_succeeded(&mut self, city: &str, relay: &str) -> bool {
        if self.city() != Some(city) || self.exact_relay().is_some_and(|name| name != relay) {
            return false;
        }
        self.success();
        true
    }
    pub(crate) fn round_started(&mut self) {
        self.pending = None;
    }
    pub(crate) fn cancel_scheduled_retry(&mut self) {
        self.pending = None;
    }
    pub(crate) fn exhausted(&mut self, now: Instant, city: &str) -> bool {
        if self.city() != Some(city) || self.pending.is_some() {
            return false;
        }
        let delay = [60, 180, 300][self.failures.min(2)];
        self.failures = self.failures.saturating_add(1);
        self.pending = Some((now + Duration::from_secs(delay), city.into()));
        true
    }
    pub(crate) fn remaining(&self, now: Instant) -> Option<u64> {
        self.pending
            .as_ref()
            .map(|(at, _)| at.saturating_duration_since(now).as_secs())
    }
    pub(crate) fn take_due(&mut self, now: Instant, city: Option<&str>, enabled: bool) -> bool {
        let Some((at, expected)) = &self.pending else {
            return false;
        };
        if !enabled || city != Some(expected.as_str()) {
            self.pending = None;
            return false;
        }
        if now < *at {
            return false;
        }
        self.pending = None;
        true
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_failures_back_off_for_the_same_target_and_reset_on_change() {
        let mut retry = LocalFailureRetry::default();
        for seconds in [1, 2, 5, 15, 30, 30] {
            assert_eq!(
                retry.next_delay("original-relay"),
                Duration::from_secs(seconds)
            );
        }
        assert_eq!(retry.next_delay("same-city-backup"), Duration::from_secs(1));
        retry.clear();
        assert_eq!(retry.next_delay("same-city-backup"), Duration::from_secs(1));
    }

    #[test]
    fn only_recoverable_local_codes_use_city_retry_after_a_start_error() {
        assert!(is_retryable_local_failure("worker_route_unavailable"));
        assert!(is_retryable_local_failure("peer_reservation_unavailable"));
        assert!(is_retryable_local_failure("candidate_probe_failed"));
        assert!(!is_retryable_local_failure("worker_configuration_rejected"));
        assert!(!is_retryable_local_failure("cleanup_uncertain"));
        assert!(!is_retryable_local_failure("relay_not_active"));
        // This is the transaction worker's generic wrapper for unclassified
        // failures, so it cannot safely opt into a local same-target retry.
        assert!(!is_retryable_local_failure("tunnel_transaction_failed"));
    }

    #[test]
    fn quic_start_timeout_and_local_unavailability_advance_without_retrying_same_target() {
        for code in [
            "quic_helper_start_failed",
            "quic_helper_unavailable",
            "quic_connect_failed",
        ] {
            assert!(!is_retryable_local_failure(code));
            assert_eq!(
                attempt_failure_disposition(code),
                AttemptFailureDisposition::SkipUnavailablePath
            );
        }
        assert_eq!(
            attempt_failure_disposition("cleanup_uncertain"),
            AttemptFailureDisposition::Freeze
        );
        assert_eq!(
            attempt_failure_disposition("worker_start_cancelled"),
            AttemptFailureDisposition::StopCleanly
        );
    }
    #[test]
    fn async_attempt_failures_retry_only_known_recoverable_local_codes() {
        use AttemptFailureDisposition as D;

        assert_eq!(
            attempt_failure_disposition("worker_route_unavailable"),
            D::RetrySameTarget
        );
        assert_eq!(
            attempt_failure_disposition("candidate_evidence_stale"),
            D::RetrySameTarget
        );
        assert_eq!(
            attempt_failure_disposition("worker_configuration_rejected"),
            D::StopCleanly
        );
        assert_eq!(
            attempt_failure_disposition("candidate_stale"),
            D::StopCleanly
        );
        assert_eq!(attempt_failure_disposition("cleanup_uncertain"), D::Freeze);
        assert_eq!(
            attempt_failure_disposition("identity_state_unknown"),
            D::Freeze
        );
        assert_eq!(attempt_failure_disposition("unclassified"), D::Freeze);
    }

    #[test]
    fn canceling_a_scheduled_retry_retains_the_selected_city_and_pin() {
        let now = Instant::now();
        let mut retry = RecoveryRetry::default();
        retry.user_connect(Some("xx-aaa"), Some("user-pin"));
        assert!(retry.exhausted(now, "xx-aaa"));
        retry.cancel_scheduled_retry();
        assert_eq!(retry.city(), Some("xx-aaa"));
        assert_eq!(retry.exact_relay(), Some("user-pin"));
        assert!(retry.remaining(now).is_none());
        assert!(!retry.take_due(now + Duration::from_secs(60), Some("xx-aaa"), true));
    }

    #[test]
    fn route_trials_preserve_city_and_pinned_relay_through_success_and_failure() {
        use adapter_protocol::app::RecoveryAction as A;

        let now = Instant::now();
        let mut city = RecoveryRetry::default();
        city.user_connect(Some("xx-aaa"), None);
        assert_eq!(
            persistent_relay_for_action(A::ReturnDirect, Some("trial-relay")),
            None
        );
        if let Some(relay) = persistent_relay_for_action(A::ReturnDirect, Some("trial-relay")) {
            city.user_connect(Some("xx-aaa"), relay);
        }
        assert_eq!(city.city(), Some("xx-aaa"));
        assert_eq!(city.exact_relay(), None);
        assert!(city.connection_succeeded("xx-aaa", "trial-relay"));
        assert_eq!(city.exact_relay(), None);

        let mut pinned = RecoveryRetry::default();
        pinned.user_connect(Some("xx-aaa"), Some("user-pin"));
        if let Some(relay) = persistent_relay_for_action(A::ReturnDirect, Some("trial-relay")) {
            pinned.user_connect(Some("xx-aaa"), relay);
        }
        assert!(!pinned.connection_succeeded("xx-aaa", "trial-relay"));
        assert_eq!(pinned.exact_relay(), Some("user-pin"));
        assert!(pinned.exhausted(now, "xx-aaa"));
        assert!(pinned.take_due(now + Duration::from_secs(60), Some("xx-aaa"), true));
        assert_eq!(pinned.exact_relay(), Some("user-pin"));
        assert!(pinned.connection_succeeded("xx-aaa", "user-pin"));
        assert_eq!(pinned.exact_relay(), Some("user-pin"));

        let mut withdrawn = RecoveryRetry::default();
        withdrawn.user_connect(Some("xx-aaa"), None);
        assert_eq!(
            persistent_relay_for_action(A::ReturnDirect, Some("withdrawn-relay")),
            None
        );
        assert!(withdrawn.exhausted(now, "xx-aaa"));
        assert!(withdrawn.take_due(now + Duration::from_secs(60), Some("xx-aaa"), true));
        assert_eq!(withdrawn.city(), Some("xx-aaa"));
        assert_eq!(withdrawn.exact_relay(), None);
    }

    #[test]
    fn only_retry_actions_replace_the_persistent_relay_preference() {
        use adapter_protocol::app::RecoveryAction as A;

        assert_eq!(
            persistent_relay_for_action(A::RetryCurrent, Some("user-pin")),
            Some(Some("user-pin"))
        );
        assert_eq!(
            persistent_relay_for_action(A::RetryCity, Some("temporary")),
            Some(None)
        );
        assert_eq!(
            persistent_relay_for_action(A::TestBackup, Some("temporary")),
            None
        );
        assert_eq!(
            persistent_relay_for_action(A::ChainFallback, Some("temporary")),
            None
        );
        assert_eq!(
            persistent_relay_for_action(A::ReturnDirect, Some("temporary")),
            None
        );
    }

    #[test]
    fn no_intent_and_explicit_disconnect_never_restart() {
        let now = Instant::now();
        let mut r = RecoveryRetry::default();
        assert!(!r.exhausted(now, "xx-aaa"));
        r.user_connect(Some("xx-aaa"), None);
        assert!(r.exhausted(now, "xx-aaa"));
        r.cancel();
        assert!(!r.take_due(now + Duration::from_secs(600), Some("xx-aaa"), true));
    }
    #[test]
    fn bounded_rounds_have_real_increasing_pauses() {
        let mut now = Instant::now();
        let mut r = RecoveryRetry::default();
        r.user_connect(Some("xx-aaa"), None);
        for seconds in [60, 180, 300, 300] {
            assert!(r.exhausted(now, "xx-aaa"));
            assert!(
                !r.exhausted(now, "xx-aaa"),
                "ticks cannot extend a deadline"
            );
            assert!(!r.take_due(now + Duration::from_secs(seconds - 1), Some("xx-aaa"), true));
            now += Duration::from_secs(seconds);
            assert!(r.take_due(now, Some("xx-aaa"), true));
            assert!(!r.take_due(now, Some("xx-aaa"), true));
        }
    }
    #[test]
    fn success_or_explicit_retry_resets_streak_but_hints_do_not() {
        let now = Instant::now();
        let mut r = RecoveryRetry::default();
        r.user_connect(Some("xx-aaa"), None);
        r.exhausted(now, "xx-aaa");
        r.round_started();
        r.exhausted(now, "xx-aaa");
        assert_eq!(r.remaining(now), Some(180));
        r.success();
        r.exhausted(now, "xx-aaa");
        assert_eq!(r.remaining(now), Some(60));
        r.user_connect(Some("xx-aaa"), None);
        assert_eq!(r.remaining(now), None);
    }
    #[test]
    fn disable_or_city_change_cancels_the_old_intent() {
        let now = Instant::now();
        let mut r = RecoveryRetry::default();
        r.user_connect(Some("xx-aaa"), None);
        for (city, enabled) in [
            (Some("xx-bbb"), true),
            (Some("xx-aaa"), false),
            (None, true),
        ] {
            r.exhausted(now, "xx-aaa");
            assert!(!r.take_due(now + Duration::from_secs(600), city, enabled));
            assert_eq!(r.remaining(now), None);
        }
    }
    #[test]
    fn exact_relay_intent_survives_cooldowns_and_success_until_user_replaces_it() {
        let now = Instant::now();
        let mut r = RecoveryRetry::default();
        r.user_connect(Some("xx-aaa"), Some("xx-aaa-wg-002"));
        assert!(!r.exhausted(now, "xx-bbb"));
        assert!(r.exhausted(now, "xx-aaa"));
        assert!(r.take_due(now + Duration::from_secs(60), Some("xx-aaa"), true));
        assert_eq!(r.exact_relay(), Some("xx-aaa-wg-002"));
        r.success();
        assert_eq!(r.city(), Some("xx-aaa"));
        assert_eq!(r.exact_relay(), Some("xx-aaa-wg-002"));
        r.user_connect(Some("xx-aaa"), None);
        assert_eq!(r.exact_relay(), None);
        r.cancel();
        assert_eq!(r.city(), None);
    }
    #[test]
    fn an_old_healthy_path_cannot_complete_a_new_exact_relay_intent() {
        let now = Instant::now();
        let mut r = RecoveryRetry::default();
        r.user_connect(Some("xx-aaa"), Some("xx-aaa-wg-002"));
        r.exhausted(now, "xx-aaa");
        assert!(!r.connection_succeeded("xx-aaa", "xx-aaa-wg-001"));
        assert!(!r.connection_succeeded("xx-bbb", "xx-aaa-wg-002"));
        assert_eq!(r.remaining(now), Some(60));
        assert!(r.connection_succeeded("xx-aaa", "xx-aaa-wg-002"));
        assert_eq!(r.remaining(now), None);
    }
}
