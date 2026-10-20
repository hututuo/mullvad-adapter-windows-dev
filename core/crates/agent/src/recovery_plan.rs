//! Bounded ordering and debounce, independent of process I/O and WG ownership.
use std::time::{Duration, Instant};
pub(crate) const MAX_CITY_RELAYS: usize = 5;

#[derive(Default)]
pub(crate) struct ActiveFailures {
    instance: Option<u64>,
    failures: u8,
}
impl ActiveFailures {
    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }
    /// Only current, fresh, real data negatives may call this method.
    pub(crate) fn failed(&mut self, instance: u64) -> bool {
        if self.instance != Some(instance) {
            self.failures = 0;
        }
        self.instance = Some(instance);
        self.failures = self.failures.saturating_add(1);
        self.failures >= 2
    }
    pub(crate) fn confirming(&self) -> bool {
        self.failures == 1
    }
}

#[derive(Default)]
pub(crate) struct RoundPlan {
    pub(crate) relays: Vec<String>,
    pub(crate) started: Option<Instant>,
    pub(crate) chain_phase: bool,
    pub(crate) chain_entered: bool,
    original: Option<(String, String, bool)>,
    original_failures: u8,
    pub(crate) attempts: u32,
}
impl RoundPlan {
    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }
    pub(crate) fn start(&mut self, relays: Vec<String>, chain_only: bool) {
        self.clear();
        self.relays = relays.into_iter().take(MAX_CITY_RELAYS).collect();
        self.started = Some(Instant::now());
        self.chain_phase = chain_only;
        self.chain_entered = chain_only;
    }
    pub(crate) fn attempted(&mut self, relay: &str, inlet: &str, chained: bool) {
        self.original
            .get_or_insert_with(|| (relay.into(), inlet.into(), chained));
        self.attempts = self.attempts.saturating_add(1);
    }
    pub(crate) fn original_relay(&self) -> Option<&str> {
        self.relays.first().map(String::as_str)
    }
    /// Three serial starts of the exact original inlet: immediate, then after
    /// 1s and 5s. A previous worker must be confirmed stopped by the caller.
    pub(crate) fn short_retry(
        &mut self,
        relay: &str,
        inlet: &str,
        chained: bool,
    ) -> Option<Duration> {
        if self
            .original
            .as_ref()
            .is_none_or(|p| p != &(relay.into(), inlet.into(), chained))
        {
            return None;
        }
        self.original_failures = self.original_failures.saturating_add(1);
        match self.original_failures {
            1 => Some(Duration::from_secs(1)),
            2 => Some(Duration::from_secs(5)),
            _ => None,
        }
    }
    pub(crate) fn short_attempt(&self) -> u32 {
        u32::from(self.original_failures.saturating_add(1).min(3))
    }
    pub(crate) fn enter_chain(&mut self) -> bool {
        if self.chain_entered || self.relays.is_empty() {
            return false;
        }
        self.chain_entered = true;
        self.chain_phase = true;
        true
    }
}

#[derive(Default)]
pub(crate) struct DirectReturn {
    due: Option<Instant>,
    failures: usize,
}
impl DirectReturn {
    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }
    pub(crate) fn connected(&mut self, now: Instant) {
        // A newly restored chain needs a stable window before another trial.
        // Preserve an outstanding future retry and the accumulated backoff.
        if self.due.is_none_or(|at| now >= at) {
            self.due = Some(now + Duration::from_secs([120, 300, 900, 1800][self.failures.min(3)]));
        }
    }
    pub(crate) fn failed(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        self.due = None;
        self.connected(now);
    }
    pub(crate) fn remaining(&self, now: Instant) -> Option<u64> {
        self.due
            .map(|at| at.saturating_duration_since(now).as_secs())
    }
    pub(crate) fn due(&self, now: Instant) -> bool {
        self.due.is_some_and(|at| now >= at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn short_retry_never_moves_endpoint_or_repeats_forever() {
        let mut p = RoundPlan::default();
        p.start(
            vec![
                "a".into(),
                "b".into(),
                "c".into(),
                "d".into(),
                "e".into(),
                "f".into(),
            ],
            false,
        );
        p.attempted("a", "192.0.2.1:443", false);
        assert_eq!(p.relays.len(), 5);
        assert_eq!(p.short_retry("b", "192.0.2.1:443", false), None);
        assert_eq!(p.short_retry("a", "192.0.2.1:443", true), None);
        assert_eq!(
            p.short_retry("a", "192.0.2.1:443", false),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            p.short_retry("a", "192.0.2.1:443", false),
            Some(Duration::from_secs(5))
        );
        for _ in 0..5 {
            assert_eq!(p.short_retry("a", "192.0.2.1:443", false), None);
        }
        assert!(p.enter_chain());
        assert!(!p.enter_chain());
        assert_eq!(p.short_retry("a", "192.0.2.1:443", true), None);
    }
    #[test]
    fn current_instance_needs_two_negatives_and_success_clears_them() {
        let mut gate = ActiveFailures::default();
        assert!(!gate.failed(1));
        assert!(gate.confirming());
        assert!(!gate.failed(2));
        assert!(gate.failed(2));
        gate.clear();
        assert!(!gate.failed(2));
    }
    #[test]
    fn return_to_direct_has_real_backoff_and_explicit_disconnect_cancels_it() {
        let now = Instant::now();
        let mut p = DirectReturn::default();
        p.connected(now);
        assert!(!p.due(now));
        p.connected(now + Duration::from_secs(30));
        assert_eq!(p.remaining(now), Some(120));
        assert!(p.due(now + Duration::from_secs(120)));
        p.failed(now);
        assert_eq!(p.remaining(now), Some(300));
        p.clear();
        assert!(!p.due(now + Duration::from_secs(3600)));
    }
    #[test]
    fn restored_chain_refreshes_expired_return_intent_without_resetting_backoff() {
        let now = Instant::now();
        let mut p = DirectReturn::default();
        p.connected(now);
        let restored = now + Duration::from_secs(140);
        assert!(p.due(restored));
        p.connected(restored);
        assert_eq!(p.remaining(restored), Some(120));
        assert!(!p.due(restored));

        p.failed(restored);
        p.connected(restored + Duration::from_secs(20));
        assert_eq!(p.remaining(restored), Some(300));
        let restored_late = restored + Duration::from_secs(350);
        p.connected(restored_late);
        assert_eq!(p.remaining(restored_late), Some(300));
        p.failed(restored_late);
        assert_eq!(p.remaining(restored_late), Some(900));
    }
}
