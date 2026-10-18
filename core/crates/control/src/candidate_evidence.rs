//! One-shot evidence transport issued by the single resource/state owner.
use crate::owned_lifecycle::{BoundCancellation, Cancellation};
use adapter_domain::CandidateAttempt;
use std::{
    sync::{mpsc, Arc},
    time::Instant,
};

/// Immutable I/O results provide their oldest participating observation, not the
/// later time at which a collection or queue operation happened to complete.
pub trait MeasuredEvidence: Send + 'static {
    fn oldest_observation(&self) -> Instant;
}
/// Typed full-canary evidence, not ICMP or engine controller readiness.
/// Implementations must reject expired/future phase measurements themselves.
pub trait ReadinessEvidence: MeasuredEvidence {
    fn fresh_canary(&self) -> Option<adapter_domain::Canary>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionCheckError {
    Stale,
    NotReady(adapter_domain::Readiness),
    UnsupportedProtection,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceError {
    Cancelled,
    FutureObservation,
    BeforeOwnerClock,
    Closed,
    Stale,
}
pub(crate) struct Stamped<T> {
    pub operation: Cancellation,
    pub resource: u64,
    pub attempt: CandidateAttempt,
    pub observed_at: u64,
    pub value: T,
}
/// Not Clone; publication consumes the sole sender and cannot replace a message.
pub struct CandidateSender<T> {
    channel: mpsc::SyncSender<Stamped<T>>,
    resource: u64,
    attempt: CandidateAttempt,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    cancel: BoundCancellation,
}
impl<T: MeasuredEvidence> CandidateSender<T> {
    pub(crate) fn new(
        channel: mpsc::SyncSender<Stamped<T>>,
        resource: u64,
        attempt: CandidateAttempt,
        clock: Arc<dyn Fn() -> u64 + Send + Sync>,
        cancel: BoundCancellation,
    ) -> Self {
        Self {
            channel,
            resource,
            attempt,
            clock,
            cancel,
        }
    }
    pub fn accepts_network(&self, network: &crate::owned_lifecycle::BoundNetwork) -> bool {
        self.cancel.belongs_to(network)
    }
    pub fn attempt(&self) -> &CandidateAttempt {
        &self.attempt
    }
    pub fn submit(self, value: T) -> Result<(), EvidenceError> {
        if self.cancel.is_cancelled() {
            return Err(EvidenceError::Cancelled);
        }
        // Read owner time first. Any intervening delay is subtracted in age,
        // never added to the apparent freshness of the observation.
        let owner_now = (self.clock)();
        let real_now = Instant::now();
        let observed_at = stamp_observed_at(owner_now, real_now, value.oldest_observation())?;
        if self.cancel.is_cancelled() {
            return Err(EvidenceError::Cancelled);
        }
        self.channel
            .try_send(Stamped {
                operation: self.cancel.operation_identity(),
                resource: self.resource,
                attempt: self.attempt,
                observed_at,
                value,
            })
            .map_err(|_| EvidenceError::Closed)
    }
}
pub(crate) fn stamp_observed_at(
    owner_now: u64,
    real_now: Instant,
    observed: Instant,
) -> Result<u64, EvidenceError> {
    let age = real_now
        .checked_duration_since(observed)
        .ok_or(EvidenceError::FutureObservation)?;
    let millis = age
        .as_millis()
        .checked_add(u128::from(age.subsec_nanos() % 1_000_000 != 0))
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(EvidenceError::BeforeOwnerClock)?;
    owner_now
        .checked_sub(millis)
        .ok_or(EvidenceError::BeforeOwnerClock)
}
#[must_use]
pub struct CandidateReceiver<T> {
    pub(crate) operation: Cancellation,
    pub(crate) channel: Option<mpsc::Receiver<Stamped<T>>>,
    pub(crate) resource: u64,
    pub(crate) attempt: CandidateAttempt,
}
impl<T> CandidateReceiver<T> {
    pub fn resource(&self) -> u64 {
        self.resource
    }
    pub(crate) fn discard(&mut self) {
        self.channel = None;
    }
}
/// Valid at owner receipt. This is not permission to skip the final transaction
/// fence before selection/persistence or to commit from an I/O thread.
pub struct CandidateEvidence<T> {
    pub(crate) operation: Cancellation,
    pub(crate) resource: u64,
    pub(crate) attempt: CandidateAttempt,
    pub(crate) observed_at: u64,
    pub(crate) value: T,
}
impl<T> CandidateEvidence<T> {
    pub fn resource(&self) -> u64 {
        self.resource
    }
    pub fn attempt(&self) -> &CandidateAttempt {
        &self.attempt
    }
    pub fn observed_at(&self) -> u64 {
        self.observed_at
    }
    pub fn value(&self) -> &T {
        &self.value
    }
    pub fn into_parts(self) -> (CandidateAttempt, u64, T) {
        (self.attempt, self.observed_at, self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn timestamps_round_age_up_and_never_refresh_submillisecond_evidence() {
        let now = Instant::now() + Duration::from_secs(10);
        for (age, expected) in [
            (Duration::ZERO, 10000),
            (Duration::from_nanos(1), 9999),
            (Duration::from_millis(1), 9999),
            (Duration::from_secs(5), 5000),
            (Duration::from_secs(5) + Duration::from_nanos(1), 4999),
        ] {
            assert_eq!(stamp_observed_at(10000, now, now - age), Ok(expected));
        }
    }
    #[test]
    fn future_and_pre_origin_observations_cannot_be_clamped_into_freshness() {
        let now = Instant::now() + Duration::from_secs(10);
        // Windows Instant uses performance-counter ticks: adding one nanosecond
        // can leave the instant unchanged. Test an actually distinct future.
        let future = now + Duration::from_millis(1);
        assert!(future > now);
        assert_eq!(
            stamp_observed_at(10000, now, future),
            Err(EvidenceError::FutureObservation)
        );
        assert_eq!(
            stamp_observed_at(10, now, now - Duration::from_millis(11)),
            Err(EvidenceError::BeforeOwnerClock)
        );
    }
}
