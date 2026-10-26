//! Pure scheduling policy for the official relay catalogue.
//!
//! The caller owns the cache and fetch task. Start a task only after reserving
//! this scheduler, and call `finish` exactly when that task has completed. A
//! failed refresh changes only the retry deadline; it never invalidates a cache.

use std::time::{Duration, Instant};

pub const REFRESH_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const RETRY_DELAYS: [Duration; 5] = [
    Duration::from_secs(30),
    Duration::from_secs(60),
    Duration::from_secs(120),
    Duration::from_secs(240),
    Duration::from_secs(300),
];

/// A missing/invalid timestamp cannot establish cache freshness. Keep using a
/// valid parsed cache while refreshing it; stale does not mean unusable.
pub fn cache_is_stale(fetched_at: Option<u64>, now_unix: u64) -> bool {
    let Some(fetched_at) = fetched_at.filter(|value| *value != 0) else {
        return true;
    };
    now_unix
        .checked_sub(fetched_at)
        .is_none_or(|age| age >= REFRESH_INTERVAL.as_secs())
}

#[derive(Debug)]
pub struct CatalogueRefresh {
    next_attempt: Instant,
    in_flight: bool,
    failures: usize,
    network_ready: bool,
    observed_offline: bool,
    recovery_wake_pending: bool,
    recovery_wake_used: bool,
}

impl CatalogueRefresh {
    /// Every process start schedules a background refresh, even with a fresh
    /// cache. Physical connectivity must be observed before it can start.
    pub fn new(now: Instant) -> Self {
        Self {
            next_attempt: now,
            in_flight: false,
            failures: 0,
            network_ready: false,
            observed_offline: false,
            recovery_wake_pending: false,
            recovery_wake_used: false,
        }
    }

    /// `stable` is supplied by the physical-network observer after its normal
    /// settling interval. Pass `physically_online = false` only for confirmed
    /// offline state; unknown attachment passes `(true, false)` to pause work
    /// without granting a physical-recovery wake.
    ///
    /// One stable offline-to-online recovery may advance a pending failed
    /// refresh. The allowance resets on success, not on another network flap or
    /// failure, so repeated attachment changes cannot bypass every retry delay.
    /// An already-running task retains its reservation until `finish`.
    pub fn observe_network(&mut self, physically_online: bool, stable: bool) {
        self.network_ready = physically_online && stable;
        if !physically_online {
            self.observed_offline = true;
            self.recovery_wake_pending = false;
        } else if stable && self.observed_offline {
            self.observed_offline = false;
            if self.failures != 0 && !self.recovery_wake_used {
                self.recovery_wake_pending = true;
            }
        }
    }

    pub fn try_start(&mut self, now: Instant) -> bool {
        if self.in_flight || !self.network_ready {
            return false;
        }
        let due = now >= self.next_attempt;
        if !due && !self.recovery_wake_pending {
            return false;
        }
        if !due {
            self.recovery_wake_used = true;
        }
        self.recovery_wake_pending = false;
        self.in_flight = true;
        true
    }

    /// A user refresh may bypass the deadline, while sharing the same network
    /// and one-in-flight guards as automatic refreshes.
    pub fn try_start_manual(&mut self) -> bool {
        if self.in_flight || !self.network_ready {
            return false;
        }
        self.recovery_wake_pending = false;
        self.in_flight = true;
        true
    }

    /// Called for automatic and manual refreshes alike. Success begins a new
    /// six-hour interval and resets failure backoff. Duplicate completions are
    /// ignored once the reservation has been released.
    pub fn finish(&mut self, now: Instant, succeeded: bool) {
        if !self.in_flight {
            return;
        }
        self.in_flight = false;
        self.recovery_wake_pending = false;
        if succeeded {
            self.failures = 0;
            self.recovery_wake_used = false;
            self.next_attempt = now + REFRESH_INTERVAL;
        } else {
            self.failures = self.failures.saturating_add(1);
            let index = self.failures.saturating_sub(1).min(RETRY_DELAYS.len() - 1);
            self.next_attempt = now + RETRY_DELAYS[index];
        }
    }

    pub fn in_flight(&self) -> bool {
        self.in_flight
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready(now: Instant) -> CatalogueRefresh {
        let mut refresh = CatalogueRefresh::new(now);
        refresh.observe_network(true, true);
        refresh
    }

    #[test]
    fn startup_refreshes_even_when_cache_is_fresh() {
        let now = Instant::now();
        assert!(!cache_is_stale(Some(1_000_000), 1_000_001));
        let mut refresh = ready(now);
        assert!(refresh.try_start(now));
        assert!(refresh.in_flight());
        assert!(!refresh.try_start(now + REFRESH_INTERVAL));
        assert!(!refresh.try_start_manual());
    }

    #[test]
    fn successful_refresh_waits_six_hours_from_completion() {
        let now = Instant::now();
        let completed = now + Duration::from_secs(7);
        let mut refresh = ready(now);
        assert!(refresh.try_start(now));
        refresh.finish(completed, true);
        assert!(!refresh.try_start(completed + REFRESH_INTERVAL - Duration::from_secs(1)));
        assert!(refresh.try_start(completed + REFRESH_INTERVAL));
    }

    #[test]
    fn failures_use_the_shared_thirty_to_three_hundred_second_backoff() {
        let mut now = Instant::now();
        let mut refresh = ready(now);
        for seconds in [30, 60, 120, 240, 300, 300] {
            assert!(refresh.try_start(now));
            refresh.finish(now, false);
            let deadline = now + Duration::from_secs(seconds);
            assert!(!refresh.try_start(deadline - Duration::from_secs(1)));
            now = deadline;
        }
        assert!(refresh.try_start(now));
    }

    #[test]
    fn offline_and_unsettled_network_pause_due_refreshes() {
        let now = Instant::now();
        let mut refresh = CatalogueRefresh::new(now);
        assert!(!refresh.try_start(now));
        refresh.observe_network(false, true);
        assert!(!refresh.try_start(now + REFRESH_INTERVAL));
        assert!(!refresh.try_start_manual());
        refresh.observe_network(true, false);
        assert!(!refresh.try_start(now + REFRESH_INTERVAL));
        refresh.observe_network(true, true);
        assert!(refresh.try_start(now + REFRESH_INTERVAL));
    }

    #[test]
    fn recovery_can_wake_only_one_retry_during_a_failure_streak() {
        let now = Instant::now();
        let mut refresh = ready(now);
        assert!(refresh.try_start(now));
        refresh.finish(now, false);
        refresh.observe_network(false, false);
        refresh.observe_network(true, false);
        assert!(!refresh.try_start(now + Duration::from_secs(1)));
        refresh.observe_network(true, true);
        let recovered = now + Duration::from_secs(2);
        assert!(refresh.try_start(recovered));
        refresh.finish(recovered, false);
        for seconds in [3, 4, 5] {
            refresh.observe_network(false, false);
            refresh.observe_network(true, true);
            assert!(!refresh.try_start(now + Duration::from_secs(seconds)));
        }
        assert!(!refresh.try_start(recovered + Duration::from_secs(59)));
        assert!(refresh.try_start(recovered + Duration::from_secs(60)));
    }

    #[test]
    fn recovery_does_not_bypass_a_healthy_catalogue_interval() {
        let now = Instant::now();
        let mut refresh = ready(now);
        assert!(refresh.try_start(now));
        refresh.finish(now, true);
        refresh.observe_network(false, false);
        refresh.observe_network(true, true);
        assert!(!refresh.try_start(now + Duration::from_secs(1)));
    }

    #[test]
    fn unknown_attachment_pauses_without_granting_a_recovery_wake() {
        let now = Instant::now();
        let mut refresh = ready(now);
        assert!(refresh.try_start(now));
        refresh.finish(now, false);
        refresh.observe_network(true, false);
        assert!(!refresh.try_start_manual());
        refresh.observe_network(true, true);
        assert!(!refresh.try_start(now + Duration::from_secs(1)));
        assert!(refresh.try_start(now + Duration::from_secs(30)));
    }

    #[test]
    fn offline_does_not_release_an_in_flight_reservation() {
        let now = Instant::now();
        let mut refresh = ready(now);
        assert!(refresh.try_start(now));
        refresh.observe_network(false, false);
        refresh.observe_network(true, true);
        assert!(!refresh.try_start(now + REFRESH_INTERVAL));
        assert!(!refresh.try_start_manual());
        refresh.finish(now, false);
        assert!(!refresh.try_start(now));
        assert!(refresh.try_start(now + Duration::from_secs(60)));
    }

    #[test]
    fn manual_success_resets_interval_backoff_and_recovery_allowance() {
        let now = Instant::now();
        let mut refresh = ready(now);
        assert!(refresh.try_start(now));
        refresh.finish(now, false);
        refresh.observe_network(false, false);
        refresh.observe_network(true, true);
        assert!(refresh.try_start(now));
        refresh.finish(now, false);
        assert!(refresh.try_start_manual());
        let completed = now + Duration::from_secs(1);
        refresh.finish(completed, true);
        assert!(!refresh.try_start(completed + Duration::from_secs(900)));
        assert!(refresh.try_start_manual());
        refresh.finish(completed, false);
        assert_eq!(refresh.failures, 1);
        assert_eq!(refresh.next_attempt, completed + Duration::from_secs(30));
        refresh.observe_network(false, false);
        refresh.observe_network(true, true);
        assert!(refresh.try_start(completed));
    }

    #[test]
    fn duplicate_completion_cannot_change_a_released_schedule() {
        let now = Instant::now();
        let mut refresh = ready(now);
        assert!(refresh.try_start(now));
        refresh.finish(now, true);
        refresh.finish(now + Duration::from_secs(1), false);
        assert_eq!(refresh.failures, 0);
        assert!(!refresh.try_start(now + REFRESH_INTERVAL - Duration::from_secs(1)));
        assert!(refresh.try_start(now + REFRESH_INTERVAL));
    }

    #[test]
    fn absent_zero_future_and_old_cache_times_are_stale() {
        let now = 1_000_000;
        for fetched_at in [
            None,
            Some(0),
            Some(now + 1),
            Some(u64::MAX),
            Some(now - REFRESH_INTERVAL.as_secs()),
            Some(1),
        ] {
            assert!(cache_is_stale(fetched_at, now));
        }
        assert!(!cache_is_stale(Some(now), now));
        assert!(!cache_is_stale(
            Some(now - REFRESH_INTERVAL.as_secs() + 1),
            now
        ));
    }
}
