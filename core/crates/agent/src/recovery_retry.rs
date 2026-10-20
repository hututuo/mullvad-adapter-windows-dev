//! A new recovery round needs an explicit retained intent and an elapsed pause.
//! Hints and host ticks never refill a running round's attempts/time budget.
use std::time::{Duration, Instant};
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
