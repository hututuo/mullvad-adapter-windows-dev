//! Single-flight physical sampling drives the domain only on its state-owner thread.
use adapter_domain::{Attachment, Effect, State};
use adapter_platform::physical_attachment::{self, Observation, PhysicalBinding};
use std::{
    io,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, TryRecvError},
        Arc,
    },
    thread,
    time::Instant,
};
const PERIOD_MS: u64 = 500;
const FRESH_MS: u64 = 2000;
type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;
fn unknown() -> Observation {
    Observation {
        attachment: physical_attachment::Attachment::Unknown,
        bindings: vec![],
    }
}
#[derive(Clone)]
pub struct ChangeHint(Arc<AtomicU64>);
impl ChangeHint {
    pub(crate) fn revision(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    /// Callback-safe coalescing hint only: never fabricates an outage or runs I/O.
    pub fn notify(&self) {
        let _ = self
            .0
            .fetch_update(Ordering::Release, Ordering::Relaxed, |value| {
                value.checked_add(1)
            });
    }
}
#[derive(Clone, Copy)]
struct Request {
    id: u64,
    started: u64,
    hint: u64,
}
struct Result {
    request: Request,
    finished: u64,
    observation: Observation,
}
struct Flight {
    request: Request,
    expired: bool,
}
struct Update {
    reset: bool,
    hint: u64,
    observation: Option<Observation>,
}
struct Worker {
    jobs: mpsc::SyncSender<Request>,
    results: mpsc::Receiver<Result>,
    _thread: thread::JoinHandle<()>,
    hint: ChangeHint,
    seen_hint: u64,
    next_id: u64,
    next_poll: u64,
    inflight: Option<Flight>,
    failed: bool,
    last_evidence: Option<u64>,
    completed: u64,
}
impl Worker {
    fn new(
        mut sample: impl FnMut() -> Observation + Send + 'static,
        clock: Clock,
        hint: ChangeHint,
    ) -> io::Result<Self> {
        let (jobs, requests) = mpsc::sync_channel::<Request>(1);
        let (send, results) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("physical-observer".into())
            .spawn(move || {
                while let Ok(request) = requests.recv() {
                    let observation = sample();
                    let finished = clock();
                    if send
                        .send(Result {
                            request,
                            finished,
                            observation,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            })?;
        Ok(Self {
            jobs,
            results,
            _thread: worker,
            hint,
            seen_hint: 0,
            next_id: 0,
            next_poll: 0,
            inflight: None,
            failed: false,
            last_evidence: None,
            completed: 0,
        })
    }
    fn poll(&mut self, now: u64) -> Update {
        let hint = self.hint.0.load(Ordering::Acquire);
        // Preserve an evidence gap even when a fresh result is queued on this
        // very poll. The owner must reset settling before applying that result.
        let mut reset = self
            .last_evidence
            .is_some_and(|at| now < at || now.saturating_sub(at) >= FRESH_MS);
        if reset {
            self.last_evidence = None;
        }
        let mut output = None;
        if hint != self.seen_hint || hint == u64::MAX {
            self.seen_hint = hint;
            self.last_evidence = None;
            reset = true;
            self.next_poll = now;
        }
        match self.results.try_recv() {
            Ok(result) => {
                self.completed = self.completed.saturating_add(1);
                let flight = self.inflight.take();
                let valid = flight
                    .as_ref()
                    .is_some_and(|f| f.request.id == result.request.id && !f.expired)
                    && result.request.hint == hint
                    && hint != u64::MAX
                    && result.request.started <= result.finished
                    && result.finished <= now
                    && now.saturating_sub(result.request.started) < FRESH_MS;
                if valid {
                    self.last_evidence = Some(result.finished);
                    output = Some(result.observation);
                } else {
                    self.last_evidence = None;
                    output = Some(unknown());
                }
            }
            Err(TryRecvError::Disconnected) => {
                if !self.failed {
                    self.failed = true;
                    self.inflight = None;
                    self.last_evidence = None;
                    output = Some(unknown());
                }
            }
            Err(TryRecvError::Empty) => {}
        }
        if let Some(flight) = &mut self.inflight {
            if !flight.expired && now.saturating_sub(flight.request.started) >= FRESH_MS {
                flight.expired = true;
                self.last_evidence = None;
                output = Some(unknown());
            }
        }
        // A timed-out OS call remains the one in-flight call. No replacement
        // thread or queued sample is created until its actual result returns.
        if !self.failed && self.inflight.is_none() && now >= self.next_poll && hint != u64::MAX {
            let Some(id) = self.next_id.checked_add(1) else {
                self.failed = true;
                return Update {
                    reset: true,
                    hint,
                    observation: None,
                };
            };
            let request = Request {
                id,
                started: now,
                hint,
            };
            if self.jobs.try_send(request).is_ok() {
                self.next_id = id;
                self.next_poll = now.saturating_add(PERIOD_MS);
                self.inflight = Some(Flight {
                    request,
                    expired: false,
                });
            } else {
                self.failed = true;
                self.last_evidence = None;
                output = Some(unknown());
            }
        }
        Update {
            reset,
            hint,
            observation: output,
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct BindingEvidence {
    continuity: u64,
    pub(crate) revision: u64,
    pub(crate) bindings: Vec<PhysicalBinding>,
}
/// Opaque identity for transient public measurements. It grants no permission
/// to start a worker or commit a selection. Changes/gaps invalidate old caches.
#[derive(Clone, PartialEq, Eq)]
pub struct ObservationStamp(BindingEvidence);
/// Keep on the same thread as all lifecycle decisions; no worker touches State.
/// Poll never waits for a sample. Dropping detaches a blocked single OS worker;
/// it exits after that call returns and observes the disconnected channels.
pub struct ObservedOwner {
    state: State,
    worker: Worker,
    clock: Clock,
    bindings: Vec<PhysicalBinding>,
    continuity: u64,
}
impl ObservedOwner {
    pub(crate) fn now(&self) -> u64 {
        (self.clock)()
    }
    pub(crate) fn evidence_clock(&self) -> Arc<dyn Fn() -> u64 + Send + Sync> {
        self.clock.clone()
    }
    pub fn new(
        state: State,
        sample: impl FnMut() -> Observation + Send + 'static,
    ) -> io::Result<Self> {
        let start = Instant::now();
        let clock: Clock =
            Arc::new(move || start.elapsed().as_millis().try_into().unwrap_or(u64::MAX));
        Self::with_clock(state, sample, clock)
    }
    #[cfg(test)]
    pub(crate) fn with_test_clock(
        state: State,
        sample: impl FnMut() -> Observation + Send + 'static,
        now: Arc<AtomicU64>,
    ) -> io::Result<Self> {
        Self::with_clock(state, sample, Arc::new(move || now.load(Ordering::SeqCst)))
    }
    fn with_clock(
        state: State,
        sample: impl FnMut() -> Observation + Send + 'static,
        clock: Clock,
    ) -> io::Result<Self> {
        Self::with_clock_and_hint(
            state,
            sample,
            clock,
            ChangeHint(Arc::new(AtomicU64::new(0))),
        )
    }
    fn with_clock_and_hint(
        state: State,
        sample: impl FnMut() -> Observation + Send + 'static,
        clock: Clock,
        hint: ChangeHint,
    ) -> io::Result<Self> {
        Ok(Self {
            state,
            worker: Worker::new(sample, clock.clone(), hint)?,
            clock,
            bindings: vec![],
            continuity: 0,
        })
    }
    #[cfg(any(windows, feature = "windows-api-check"))]
    pub fn windows(state: State) -> io::Result<Self> {
        let start = Instant::now();
        let clock: Clock =
            Arc::new(move || start.elapsed().as_millis().try_into().unwrap_or(u64::MAX));
        let hint = ChangeHint(Arc::new(AtomicU64::new(0)));
        let notifications =
            adapter_platform::windows_network_changes::NetworkChanges::register(hint.0.clone())?;
        Self::with_clock_and_hint(
            state,
            move || {
                // Capture the registration lease on the worker. Deregistration may
                // wait for callbacks, so owner Drop must not perform it or join.
                let _keep_registered = &notifications;
                physical_attachment::windows::observe().unwrap_or_else(|_| unknown())
            },
            clock,
            hint,
        )
    }
    pub fn change_hint(&self) -> ChangeHint {
        self.worker.hint.clone()
    }
    pub fn state(&self) -> &State {
        &self.state
    }
    pub fn state_mut(&mut self) -> &mut State {
        &mut self.state
    }
    pub fn bindings(&self) -> &[PhysicalBinding] {
        &self.bindings
    }
    pub fn stamp(&self) -> Option<ObservationStamp> {
        self.binding_evidence().map(ObservationStamp)
    }
    pub(crate) fn binding_evidence(&self) -> Option<BindingEvidence> {
        let revision = self.worker.hint.0.load(Ordering::Acquire);
        let now = (self.clock)();
        let observed = self.worker.last_evidence?;
        if self.continuity == u64::MAX
            || revision == u64::MAX
            || revision != self.worker.seen_hint
            || self.state.attachment != Attachment::Available
            || self.bindings.is_empty()
            || now < observed
            || now.saturating_sub(observed) >= FRESH_MS
        {
            return None;
        }
        let evidence = BindingEvidence {
            continuity: self.continuity,
            revision,
            bindings: self.bindings.clone(),
        };
        let finished = (self.clock)();
        if finished < observed
            || finished.saturating_sub(observed) >= FRESH_MS
            || self.worker.hint.0.load(Ordering::Acquire) != revision
        {
            return None;
        }
        Some(evidence)
    }
    pub fn poll(&mut self) -> Option<Effect> {
        let now = (self.clock)();
        let update = self.worker.poll(now);
        self.apply_update(now, update);
        self.state.tick(now)
    }
    fn apply_update(&mut self, now: u64, mut update: Update) {
        // This final acquire is the application linearization point. A hint
        // ordered before it invalidates the batch; a concurrent later hint is
        // consumed on the next poll. Callbacks never mutate owner state.
        if self.worker.hint.0.load(Ordering::Acquire) != update.hint {
            update.reset = true;
            update.observation = None;
            self.worker.last_evidence = None;
        }
        if update.reset {
            // A queued fresh sample cannot reauthorize a candidate across a
            // gap. Saturation permanently closes the bound-evidence gate.
            self.continuity = self.continuity.saturating_add(1);
            self.bindings.clear();
            self.state.observe(Attachment::Unknown, now);
        }
        if let Some(mut observation) = update.observation {
            // Provider inconsistencies never become confirmed outage evidence.
            let available = observation.attachment == physical_attachment::Attachment::Available;
            if observation.bindings.len() > 4096
                || (available && observation.bindings.is_empty())
                || (!available && !observation.bindings.is_empty())
            {
                observation = unknown();
            }
            let attachment = match observation.attachment {
                physical_attachment::Attachment::Available => Attachment::Available,
                physical_attachment::Attachment::Unavailable => Attachment::Unavailable,
                physical_attachment::Attachment::Unknown => Attachment::Unknown,
            };
            if attachment != Attachment::Available || self.bindings != observation.bindings {
                self.continuity = self.continuity.saturating_add(1);
            }
            self.bindings = observation.bindings;
            self.state.observe(attachment, now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn observation(value: u64) -> Observation {
        match value {
            0 => Observation {
                attachment: physical_attachment::Attachment::Unavailable,
                bindings: vec![],
            },
            1 => Observation {
                attachment: physical_attachment::Attachment::Available,
                bindings: vec![PhysicalBinding {
                    luid: 1,
                    index: 2,
                    ipv4: true,
                    ipv6: false,
                }],
            },
            _ => unknown(),
        }
    }
    fn clock() -> (Arc<AtomicU64>, Clock) {
        let now = Arc::new(AtomicU64::new(0));
        let read = now.clone();
        (now, Arc::new(move || read.load(Ordering::SeqCst)))
    }
    fn drain(owner: &mut ObservedOwner, count: u64) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while owner.worker.completed < count {
            owner.poll();
            assert!(Instant::now() < deadline, "sample completion deadline");
            thread::sleep(Duration::from_millis(1));
        }
    }
    fn sample_at(owner: &mut ObservedOwner, now: &AtomicU64, at: u64) {
        now.store(at, Ordering::SeqCst);
        let target = owner.worker.completed + 1;
        drain(owner, target);
    }
    #[test]
    fn confirmed_outage_invalidates_old_token_and_unknown_preserves_latch() {
        let (now, clock) = clock();
        let source = Arc::new(AtomicU64::new(0));
        let read = source.clone();
        let mut owner = ObservedOwner::with_clock(
            State::new("boot".into()),
            move || observation(read.load(Ordering::SeqCst)),
            clock,
        )
        .unwrap();
        let old = owner.state().token();
        drain(&mut owner, 1);
        assert!(owner.state().paused);
        assert_eq!(owner.state().epoch, 1);
        assert!(!owner.state().current(&old));
        source.store(1, Ordering::SeqCst);
        sample_at(&mut owner, &now, 500);
        assert!(owner.state().paused);
        source.store(2, Ordering::SeqCst);
        sample_at(&mut owner, &now, 1000);
        assert!(owner.state().paused);
        assert!(owner.bindings().is_empty());
        source.store(1, Ordering::SeqCst);
        sample_at(&mut owner, &now, 1500);
        for at in [2000, 2500, 3000] {
            sample_at(&mut owner, &now, at);
            assert!(owner.state().paused);
        }
        sample_at(&mut owner, &now, 3500);
        assert!(!owner.state().paused);
        assert!(!owner.state().current(&old));
    }
    #[test]
    fn owner_remains_responsive_and_never_replaces_a_timed_out_worker() {
        let (now, clock) = clock();
        let calls = Arc::new(AtomicU64::new(0));
        let count = calls.clone();
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let mut owner = ObservedOwner::with_clock(
            State::new("boot".into()),
            move || {
                if count.fetch_add(1, Ordering::SeqCst) == 0 {
                    entered_tx.send(()).unwrap();
                    release.recv().unwrap();
                }
                observation(1)
            },
            clock,
        )
        .unwrap();
        owner.poll();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        now.store(2000, Ordering::SeqCst);
        let (done_tx, done) = mpsc::channel();
        let handle = thread::spawn(move || {
            owner.state_mut().generation += 1;
            for _ in 0..1000 {
                owner.poll();
            }
            done_tx
                .send(owner)
                .unwrap_or_else(|_| panic!("owner result receiver gone"));
        });
        let returned = done.recv_timeout(Duration::from_secs(1));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        release_tx.send(()).unwrap();
        handle.join().unwrap();
        let mut owner = returned.expect("owner blocked on physical sampling");
        assert_eq!(owner.state().generation, 1);
        assert_eq!(owner.state().attachment, Attachment::Unknown);
        assert!(!owner.state().paused);
        drain(&mut owner, 1);
        assert_eq!(
            owner.state().attachment,
            Attachment::Unknown,
            "late available evidence accepted"
        );
        drain(&mut owner, 2);
        assert_eq!(owner.state().attachment, Attachment::Available);
    }
    #[test]
    fn hint_during_sampling_discards_old_outage_without_fabricating_pause() {
        let (_now, clock) = clock();
        let calls = Arc::new(AtomicU64::new(0));
        let count = calls.clone();
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let mut owner = ObservedOwner::with_clock(
            State::new("boot".into()),
            move || {
                if count.fetch_add(1, Ordering::SeqCst) == 0 {
                    entered_tx.send(()).unwrap();
                    release.recv().unwrap();
                    observation(0)
                } else {
                    observation(1)
                }
            },
            clock,
        )
        .unwrap();
        owner.poll();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        owner.change_hint().notify();
        owner.poll();
        release_tx.send(()).unwrap();
        drain(&mut owner, 1);
        assert!(!owner.state().paused);
        assert_eq!(owner.state().epoch, 0);
        assert_eq!(owner.state().attachment, Attachment::Unknown);
        drain(&mut owner, 2);
        assert_eq!(owner.state().attachment, Attachment::Available);
    }
    #[test]
    fn old_positive_evidence_expires_before_settle_even_with_younger_flight() {
        let (now, clock) = clock();
        let calls = Arc::new(AtomicU64::new(0));
        let count = calls.clone();
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let mut owner = ObservedOwner::with_clock(
            State::new("boot".into()),
            move || match count.fetch_add(1, Ordering::SeqCst) {
                0 => observation(0),
                1 => observation(1),
                2 => {
                    entered_tx.send(()).unwrap();
                    release.recv().unwrap();
                    observation(1)
                }
                _ => observation(1),
            },
            clock,
        )
        .unwrap();
        drain(&mut owner, 1);
        sample_at(&mut owner, &now, 500);
        now.store(1000, Ordering::SeqCst);
        owner.poll();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        now.store(2500, Ordering::SeqCst);
        owner.poll();
        assert!(owner.state().paused);
        assert_eq!(owner.state().attachment, Attachment::Unknown);
        assert!(owner.bindings().is_empty());
        release_tx.send(()).unwrap();
    }
    #[test]
    fn completion_age_boundary_is_strict() {
        for (at, expected) in [(1999, Attachment::Available), (2000, Attachment::Unknown)] {
            let (now, clock) = clock();
            let (entered_tx, entered) = mpsc::channel();
            let (release_tx, release) = mpsc::channel();
            let mut first = true;
            let mut owner = ObservedOwner::with_clock(
                State::new("boot".into()),
                move || {
                    if first {
                        first = false;
                        entered_tx.send(()).unwrap();
                        release.recv().unwrap();
                    }
                    observation(1)
                },
                clock,
            )
            .unwrap();
            owner.poll();
            entered.recv_timeout(Duration::from_secs(1)).unwrap();
            now.store(at, Ordering::SeqCst);
            release_tx.send(()).unwrap();
            drain(&mut owner, 1);
            assert_eq!(owner.state().attachment, expected);
        }
    }
    #[test]
    fn dropping_owner_does_not_join_blocked_sample() {
        let (_now, clock) = clock();
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let mut owner = ObservedOwner::with_clock(
            State::new("boot".into()),
            move || {
                entered_tx.send(()).unwrap();
                release.recv().unwrap();
                unknown()
            },
            clock,
        )
        .unwrap();
        owner.poll();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        let (done_tx, done) = mpsc::channel();
        let handle = thread::spawn(move || {
            drop(owner);
            done_tx.send(()).unwrap();
        });
        let result = done.recv_timeout(Duration::from_secs(1));
        release_tx.send(()).unwrap();
        handle.join().unwrap();
        assert!(result.is_ok(), "owner drop joined kernel worker");
    }
    #[test]
    fn inconsistent_provider_output_cannot_pause_or_expose_bindings() {
        let (_now, clock) = clock();
        let mut invalid = observation(1);
        invalid.attachment = physical_attachment::Attachment::Unavailable;
        let mut owner = ObservedOwner::with_clock(
            State::new("boot".into()),
            move || Observation {
                attachment: invalid.attachment,
                bindings: invalid.bindings.clone(),
            },
            clock,
        )
        .unwrap();
        drain(&mut owner, 1);
        assert_eq!(owner.state().attachment, Attachment::Unknown);
        assert!(!owner.state().paused);
        assert!(owner.bindings().is_empty());
    }
    #[test]
    fn failed_worker_becomes_unknown_without_creating_a_replacement() {
        let (now, clock) = clock();
        let calls = Arc::new(AtomicU64::new(0));
        let count = calls.clone();
        let mut state = State::new("boot".into());
        state.observe(Attachment::Unavailable, 0);
        let mut owner = ObservedOwner::with_clock(
            state,
            move || {
                count.fetch_add(1, Ordering::SeqCst);
                panic!("synthetic sampler panic");
            },
            clock,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !owner.worker.failed {
            owner.poll();
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        now.store(10000, Ordering::SeqCst);
        for _ in 0..100 {
            owner.change_hint().notify();
            owner.poll();
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(owner.state().paused);
        assert_eq!(owner.state().attachment, Attachment::Unknown);
    }
    #[cfg(any(windows, feature = "windows-api-check"))]
    #[test]
    fn actual_windows_read_only_sampler_delivers_through_worker() {
        let mut owner = ObservedOwner::windows(State::new("native-fixture".into())).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while owner.worker.completed == 0 {
            owner.poll();
            assert!(Instant::now() < deadline, "native sample did not return");
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(owner.worker.completed, 1);
    }
    #[test]
    fn review_owner_stall_must_not_hide_expired_positive_interval() {
        let (now, clock) = clock();
        let calls = Arc::new(AtomicU64::new(0));
        let count = calls.clone();
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let mut owner = ObservedOwner::with_clock(
            State::new("review".into()),
            move || match count.fetch_add(1, Ordering::SeqCst) {
                0 => observation(0),
                1 => observation(1),
                2 => {
                    entered_tx.send(()).unwrap();
                    release.recv().unwrap();
                    observation(1)
                }
                _ => observation(1),
            },
            clock,
        )
        .unwrap();
        drain(&mut owner, 1);
        sample_at(&mut owner, &now, 500);
        assert!(owner.state().paused);
        now.store(1000, Ordering::SeqCst);
        owner.poll();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        // Owner is not scheduled while last accepted positive expires at 2500.
        now.store(2900, Ordering::SeqCst);
        release_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        // Wait for a queued result without polling/refreshing owner state.
        let result = loop {
            if let Ok(result) = owner.worker.results.try_recv() {
                break result;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        };
        let (tx, rx) = mpsc::sync_channel(1);
        tx.send(result).unwrap();
        owner.worker.results = rx;
        owner.poll();
        assert!(
            owner.state().paused,
            "expired positive interval incorrectly released offline latch"
        );
    }
    #[test]
    fn hint_after_result_consumption_invalidates_before_owner_application() {
        let (_now, clock) = clock();
        let mut owner =
            ObservedOwner::with_clock(State::new("hint-apply".into()), || observation(0), clock)
                .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let update = loop {
            let update = owner.worker.poll(0);
            if update.observation.is_some() {
                break update;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        };
        // The result has left the mailbox, but the owner has not applied it.
        let hint = owner.change_hint();
        let (done_tx, done) = mpsc::channel();
        let notifier = thread::spawn(move || {
            hint.notify();
            done_tx.send(()).unwrap();
        });
        done.recv_timeout(Duration::from_secs(1)).unwrap();
        owner.apply_update(0, update);
        notifier.join().unwrap();
        assert_eq!(owner.state().attachment, Attachment::Unknown);
        assert!(!owner.state().paused);
        assert_eq!(owner.state().epoch, 0);
        assert!(owner.worker.last_evidence.is_none());
    }
    #[test]
    fn worker_releases_notification_lease_only_after_blocked_call_returns() {
        struct Lease(mpsc::Sender<()>);
        impl Drop for Lease {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }
        let (dropped_tx, dropped) = mpsc::channel();
        let lease = Lease(dropped_tx);
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let mut owner = ObservedOwner::new(State::new("lease".into()), move || {
            let _keep = &lease;
            entered_tx.send(()).unwrap();
            release.recv().unwrap();
            unknown()
        })
        .unwrap();
        owner.poll();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(owner);
        assert!(matches!(dropped.try_recv(), Err(TryRecvError::Empty)));
        release_tx.send(()).unwrap();
        dropped.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn binding_evidence_expires_even_before_the_next_owner_poll() {
        let (now, clock) = clock();
        let mut owner =
            ObservedOwner::with_clock(State::new("binding".into()), || observation(1), clock)
                .unwrap();
        drain(&mut owner, 1);
        assert!(owner.binding_evidence().is_some());
        now.store(2000, Ordering::SeqCst);
        assert!(owner.binding_evidence().is_none());
        assert!(!owner.state().paused);
    }
    #[test]
    fn binding_identity_change_changes_evidence_even_without_a_hint() {
        let (now, clock) = clock();
        let index = Arc::new(AtomicU64::new(2));
        let read = index.clone();
        let mut owner = ObservedOwner::with_clock(
            State::new("binding".into()),
            move || {
                let mut result = observation(1);
                result.bindings[0].index = read.load(Ordering::SeqCst) as u32;
                result
            },
            clock,
        )
        .unwrap();
        drain(&mut owner, 1);
        let first = owner.binding_evidence().unwrap();
        let first_stamp = owner.stamp().unwrap();
        index.store(3, Ordering::SeqCst);
        sample_at(&mut owner, &now, 500);
        assert!(owner.binding_evidence().unwrap() != first);
        assert!(owner.stamp().unwrap() != first_stamp);
        owner.change_hint().notify();
        assert!(
            owner.stamp().is_none(),
            "notification invalidates public measurement cache before next owner poll"
        );
        assert_eq!(owner.state().epoch, 0);
        assert!(!owner.state().paused);
    }
    #[test]
    fn exhausted_continuity_counter_never_reauthorizes_bound_evidence() {
        let (_now, clock) = clock();
        let mut owner =
            ObservedOwner::with_clock(State::new("exhausted".into()), || observation(1), clock)
                .unwrap();
        drain(&mut owner, 1);
        owner.continuity = u64::MAX - 1;
        owner.apply_update(
            0,
            Update {
                reset: true,
                hint: 0,
                observation: Some(observation(1)),
            },
        );
        assert_eq!(owner.continuity, u64::MAX);
        assert!(owner.binding_evidence().is_none());
        assert_eq!(owner.state().attachment, Attachment::Available);
        assert!(!owner.state().paused);
    }
}
