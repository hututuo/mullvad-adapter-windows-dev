//! Domain owner plus one independently owned, cooperatively cancelled I/O resource.
use crate::candidate_evidence::{
    CandidateEvidence, CandidateReceiver, CandidateSender, EvidenceError, MeasuredEvidence,
};
use crate::observer::{BindingEvidence, ChangeHint, ObservedOwner};
use adapter_domain::{CandidateAttempt, Effect, State, Token};
use adapter_platform::physical_attachment::PhysicalBinding;
use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, TryRecvError},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
#[derive(Clone)]
pub struct Cancellation(Arc<AtomicBool>);
impl Cancellation {
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
/// Issued only for a freshly observed selected binding. It fences worker-side
/// phases against notifications without waiting for the next owner poll.
/// No Clone/constructor: create route evidence within this operation, not before.
pub struct BoundNetwork {
    binding: PhysicalBinding,
    hint: ChangeHint,
    revision: u64,
    cancel: Cancellation,
}
/// Read-only cancellation view for libraries requiring owned callbacks.
/// Contains no binding or operation authorization and cannot start a resource.
#[derive(Clone)]
pub struct BoundCancellation {
    hint: ChangeHint,
    revision: u64,
    cancel: Cancellation,
}
impl BoundCancellation {
    pub(crate) fn operation_identity(&self) -> Cancellation {
        self.cancel.clone()
    }
    pub(crate) fn belongs_to(&self, network: &BoundNetwork) -> bool {
        self.revision == network.revision && Arc::ptr_eq(&self.cancel.0, &network.cancel.0)
    }
    pub fn is_cancelled(&self) -> bool {
        if self.hint.revision() != self.revision {
            self.cancel.0.store(true, Ordering::Release);
        }
        self.cancel.is_cancelled()
    }
}
impl BoundNetwork {
    pub fn cancellation_monitor(&self) -> BoundCancellation {
        BoundCancellation {
            hint: self.hint.clone(),
            revision: self.revision,
            cancel: self.cancel.clone(),
        }
    }
    pub fn binding(&self) -> PhysicalBinding {
        self.binding
    }
    pub fn is_cancelled(&self) -> bool {
        if self.hint.revision() != self.revision {
            self.cancel.0.store(true, Ordering::Release);
        }
        self.cancel.is_cancelled()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Start,
    Stop,
    Worker,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Ready(u64),
    Finished(u64, Result<(), Failure>),
}
/// A cancelled build may certify absence only after all partially constructed
/// resources have been synchronously cleaned up. Uncertain cleanup is Failure.
pub enum BuildOutcome<R> {
    Ready(R),
    CancelledClean,
}
/// Construct and destroy on the I/O thread. Resources need not be Send.
pub trait Resource: 'static {
    /// Bounded liveness check on the I/O worker, never on the domain owner.
    fn check(&mut self) -> Result<(), Failure> {
        Ok(())
    }
    fn stop(&mut self) -> Result<(), Failure>;
}
struct ResourcePresence(Arc<AtomicBool>);
impl ResourcePresence {
    fn new(flag: Arc<AtomicBool>) -> Self {
        let guard = Self(flag);
        guard.0.store(true, Ordering::Release);
        guard
    }
}
impl Drop for ResourcePresence {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
struct Active {
    id: u64,
    token: Token,
    binding: Option<BindingEvidence>,
    candidate: Option<CandidateAttempt>,
    ready: bool,
    present: Arc<AtomicBool>,
    cancel: Cancellation,
    wake: mpsc::SyncSender<()>,
    events: mpsc::Receiver<Event>,
    _thread: thread::JoinHandle<()>,
    persistent: bool,
}
impl Active {
    fn cancel(&self) {
        self.cancel.0.store(true, Ordering::Release);
        let _ = self.wake.try_send(());
    }
}
impl Drop for Active {
    fn drop(&mut self) {
        self.cancel();
    }
}
pub struct ResourceOwner {
    observation: ObservedOwner,
    active: Option<Active>,
    next_id: u64,
    failed: bool,
    operation: Option<BoundOperation>,
    next_operation: u64,
}
struct BoundOperation {
    id: u64,
    token: Token,
    binding: BindingEvidence,
    attempt: Option<CandidateAttempt>,
    worker_instance: u64,
    deadline: u64,
    started: Instant,
    cancel: Cancellation,
}
impl Drop for BoundOperation {
    fn drop(&mut self) {
        self.cancel.0.store(true, Ordering::Release);
    }
}
/// Operation authority inside a persistent aggregate. Not a worker-liveness
/// proof or final selector/persistence permission. Keep until the I/O receipt.
pub struct OperationTicket {
    id: u64,
    worker_instance: u64,
    token: Token,
    monitor: BoundCancellation,
}
impl OperationTicket {
    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn worker_instance(&self) -> u64 {
        self.worker_instance
    }
    pub fn token(&self) -> &Token {
        &self.token
    }
    pub fn is_cancelled(&self) -> bool {
        self.monitor.is_cancelled()
    }
}
impl ResourceOwner {
    pub fn new(observation: ObservedOwner) -> Self {
        Self {
            observation,
            active: None,
            next_id: 0,
            failed: false,
            operation: None,
            next_operation: 0,
        }
    }
    pub fn state(&self) -> &State {
        self.observation.state()
    }
    pub fn state_mut(&mut self) -> &mut State {
        self.observation.state_mut()
    }
    pub fn observation(&self) -> &ObservedOwner {
        &self.observation
    }
    pub fn has_active_resource(&self) -> bool {
        self.active.is_some()
    }
    pub fn replacement_blocked(&self) -> bool {
        self.failed
    }
    pub fn busy(&self) -> bool {
        self.active.is_some() || self.failed
    }
    pub fn cancel(&self) {
        self.cancel_current_operation();
        if let Some(active) = &self.active {
            active.cancel();
        }
    }
    pub fn start<R: Resource>(
        &mut self,
        build: impl FnOnce(Cancellation) -> Result<R, Failure> + Send + 'static,
    ) -> io::Result<u64> {
        self.start_cancellable(move |cancel| build(cancel).map(BuildOutcome::Ready))
    }
    pub fn start_cancellable<R: Resource>(
        &mut self,
        build: impl FnOnce(Cancellation) -> Result<BuildOutcome<R>, Failure> + Send + 'static,
    ) -> io::Result<u64> {
        self.start_inner(build, None, None, false)
    }
    /// One lifetime-owned aggregate holding the fixed front and at most one
    /// identity-exclusive worker. Physical outages/generation changes cancel
    /// operations, not this lifetime. Explicit stop and sticky failures remain.
    pub fn start_persistent<R: Resource>(
        &mut self,
        build: impl FnOnce(Cancellation) -> Result<BuildOutcome<R>, Failure> + Send + 'static,
    ) -> io::Result<u64> {
        self.start_inner(build, None, None, true)
    }
    pub fn cancel_current_operation(&self) {
        if let Some(operation) = &self.operation {
            operation.cancel.0.store(true, Ordering::Release);
        }
    }
    /// Mint a fresh call-level network guard without transferring any resource.
    /// Registry remains occupied after cancellation until the host receives the
    /// matching I/O completion and calls finish_operation. No replacement owner.
    pub fn begin_operation(
        &mut self,
        binding: PhysicalBinding,
        worker_instance: u64,
        attempt: Option<&CandidateAttempt>,
    ) -> io::Result<(OperationTicket, BoundNetwork)> {
        let active = self
            .active
            .as_ref()
            .filter(|a| {
                a.persistent
                    && a.ready
                    && a.present.load(Ordering::Acquire)
                    && !a.cancel.is_cancelled()
            })
            .ok_or_else(|| io::Error::other("persistent aggregate unavailable"))?;
        let _ = active;
        if self.operation.is_some() || self.failed || worker_instance == 0 || self.state().paused {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "operation unavailable",
            ));
        }
        let now = self.observation.now();
        if attempt.is_some_and(|a| {
            !self.state().candidate_is_current(a, now) || a.path.instance != worker_instance
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "candidate attempt is not current",
            ));
        }
        let evidence = self
            .observation
            .binding_evidence()
            .filter(|e| e.bindings.contains(&binding))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::WouldBlock, "fresh physical binding required")
            })?;
        let id = self
            .next_operation
            .checked_add(1)
            .ok_or_else(|| io::Error::other("operation id exhausted"))?;
        let token = self.state().token();
        let cancel = Cancellation(Arc::new(AtomicBool::new(false)));
        let network = BoundNetwork {
            binding,
            hint: self.observation.change_hint(),
            revision: evidence.revision,
            cancel: cancel.clone(),
        };
        let ticket = OperationTicket {
            id,
            worker_instance,
            token: token.clone(),
            monitor: network.cancellation_monitor(),
        };
        self.operation = Some(BoundOperation {
            id,
            token,
            binding: evidence,
            attempt: attempt.cloned(),
            worker_instance,
            deadline: now.saturating_add(adapter_domain::ATTEMPT_TIMEOUT_MS),
            started: Instant::now(),
            cancel,
        });
        self.next_operation = id;
        Ok((ticket, network))
    }
    fn operation_current(&self, operation: &BoundOperation) -> bool {
        let now = self.observation.now();
        self.active.as_ref().is_some_and(|a| {
            a.persistent && a.ready && a.present.load(Ordering::Acquire) && !a.cancel.is_cancelled()
        }) && !operation.cancel.is_cancelled()
            && now < operation.deadline
            && self.state().current(&operation.token)
            && self.observation.binding_evidence().as_ref() == Some(&operation.binding)
            && operation
                .attempt
                .as_ref()
                .map_or(true, |a| self.state().candidate_is_current(a, now))
    }
    pub fn is_operation_current(&self, ticket: &OperationTicket) -> bool {
        self.operation.as_ref().is_some_and(|op| {
            op.id == ticket.id
                && op.worker_instance == ticket.worker_instance
                && op.token == ticket.token
                && Arc::ptr_eq(&op.cancel.0, &ticket.monitor.cancel.0)
                && !ticket.is_cancelled()
                && self.operation_current(op)
        })
    }
    /// Host calls only after the exact aggregate command has completed cleanup
    /// or reconciliation. A foreign ticket cannot cancel or free this registry.
    pub fn finish_operation(&mut self, ticket: &OperationTicket) -> bool {
        if self.operation.as_ref().is_some_and(|op| {
            op.id == ticket.id && Arc::ptr_eq(&op.cancel.0, &ticket.monitor.cancel.0)
        }) {
            self.operation = None;
            true
        } else {
            false
        }
    }
    /// Fence a candidate measurement made within the exact persistent operation.
    /// Still requires aggregate worker acknowledgement, physical egress proof,
    /// owned selector readback and durable policy reconciliation by the host.
    pub fn validate_operation_measurement<T: crate::candidate_evidence::ReadinessEvidence>(
        &self,
        ticket: &OperationTicket,
        measurement: &T,
    ) -> Result<(u64, adapter_domain::Canary), crate::candidate_evidence::SelectionCheckError> {
        self.validate_operation_readiness(ticket, measurement, false)
    }
    /// Only an exact original-path rebuild may preserve a degraded live path.
    /// Manual selection and same-city alternatives continue to require Ready.
    pub fn validate_original_preservation<T: crate::candidate_evidence::ReadinessEvidence>(
        &self,
        ticket: &OperationTicket,
        measurement: &T,
    ) -> Result<(u64, adapter_domain::Canary), crate::candidate_evidence::SelectionCheckError> {
        if self.state().stage != adapter_domain::Stage::RebuildOriginal {
            return Err(crate::candidate_evidence::SelectionCheckError::Stale);
        }
        use crate::candidate_evidence::SelectionCheckError;
        let original = self
            .state()
            .path
            .as_ref()
            .ok_or(SelectionCheckError::Stale)?;
        let attempt = self
            .operation
            .as_ref()
            .and_then(|op| op.attempt.as_ref())
            .ok_or(SelectionCheckError::Stale)?;
        let path = &attempt.path;
        if path.relay != original.relay
            || path.city != original.city
            || path.transport != original.transport
            || path.inlet != original.inlet
            || path.entry_relay != original.entry_relay
            || path.slot != original.slot
            || path.front != original.front
            || path.instance == original.instance
        {
            return Err(SelectionCheckError::Stale);
        }
        self.validate_operation_readiness(ticket, measurement, true)
    }
    fn validate_operation_readiness<T: crate::candidate_evidence::ReadinessEvidence>(
        &self,
        ticket: &OperationTicket,
        measurement: &T,
        preserve: bool,
    ) -> Result<(u64, adapter_domain::Canary), crate::candidate_evidence::SelectionCheckError> {
        use crate::candidate_evidence::{stamp_observed_at, SelectionCheckError};
        if !self.is_operation_current(ticket) {
            return Err(SelectionCheckError::Stale);
        }
        let operation = self.operation.as_ref().ok_or(SelectionCheckError::Stale)?;
        let attempt = operation
            .attempt
            .as_ref()
            .ok_or(SelectionCheckError::Stale)?;
        if self.state().protection.multihop
            || self.state().protection.post_quantum
            || attempt.path.entry_relay.is_some()
        {
            return Err(SelectionCheckError::UnsupportedProtection);
        }
        let observed = measurement.oldest_observation();
        if observed < operation.started {
            return Err(SelectionCheckError::Stale);
        }
        let now = self.observation.now();
        let observed_at = stamp_observed_at(now, Instant::now(), observed)
            .map_err(|_| SelectionCheckError::Stale)?;
        if !self
            .state()
            .candidate_evidence_is_current(attempt, observed_at, now)
        {
            return Err(SelectionCheckError::Stale);
        }
        let canary = measurement
            .fresh_canary()
            .ok_or(SelectionCheckError::Stale)?;
        if if preserve {
            !canary.alive()
        } else {
            canary.readiness() != adapter_domain::Readiness::Ready
        } {
            return Err(SelectionCheckError::NotReady(canary.readiness()));
        }
        if !self.is_operation_current(ticket) {
            return Err(SelectionCheckError::Stale);
        }
        Ok((observed_at, canary))
    }
    pub fn now(&self) -> u64 {
        self.observation.now()
    }
    /// For network-bound candidates: both the domain token and fresh physical
    /// evidence revision/identity must remain current. Unknown is not an outage.
    pub fn start_network_bound<R: Resource>(
        &mut self,
        build: impl FnOnce(Cancellation) -> Result<R, Failure> + Send + 'static,
    ) -> io::Result<u64> {
        self.start_network_bound_cancellable(move |cancel| build(cancel).map(BuildOutcome::Ready))
    }
    pub fn start_network_bound_cancellable<R: Resource>(
        &mut self,
        build: impl FnOnce(Cancellation) -> Result<BuildOutcome<R>, Failure> + Send + 'static,
    ) -> io::Result<u64> {
        let binding = self.observation.binding_evidence().ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "fresh physical binding required")
        })?;
        self.start_inner(build, Some(binding), None, false)
    }
    /// The selected identity must belong to this owner observation. The worker
    /// receives an operation-scoped binding guard, never a caller-made snapshot.
    pub fn start_on_binding<R: Resource>(
        &mut self,
        binding: PhysicalBinding,
        build: impl FnOnce(BoundNetwork) -> Result<BuildOutcome<R>, Failure> + Send + 'static,
    ) -> io::Result<u64> {
        self.start_selected_binding(binding, None, build)
    }
    pub fn start_candidate_on_binding<R: Resource, T: MeasuredEvidence>(
        &mut self,
        binding: PhysicalBinding,
        attempt: &CandidateAttempt,
        build: impl FnOnce(BoundNetwork, CandidateSender<T>) -> Result<BuildOutcome<R>, Failure>
            + Send
            + 'static,
    ) -> io::Result<CandidateReceiver<T>> {
        if !self
            .state()
            .candidate_is_current(attempt, self.observation.now())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "candidate attempt is not current",
            ));
        }
        let id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("resource id exhausted"))?;
        let (send, channel) = mpsc::sync_channel(1);
        let worker_attempt = attempt.clone();
        let clock = self.observation.evidence_clock();
        let actual =
            self.start_selected_binding(binding, Some(attempt.clone()), move |network| {
                let sender = CandidateSender::new(
                    send,
                    id,
                    worker_attempt,
                    clock,
                    network.cancellation_monitor(),
                );
                build(network, sender)
            })?;
        debug_assert_eq!(actual, id);
        Ok(CandidateReceiver {
            operation: self
                .active
                .as_ref()
                .expect("started resource")
                .cancel
                .clone(),
            channel: Some(channel),
            resource: id,
            attempt: attempt.clone(),
        })
    }
    fn start_selected_binding<R: Resource>(
        &mut self,
        binding: PhysicalBinding,
        candidate: Option<CandidateAttempt>,
        build: impl FnOnce(BoundNetwork) -> Result<BuildOutcome<R>, Failure> + Send + 'static,
    ) -> io::Result<u64> {
        let evidence = self
            .observation
            .binding_evidence()
            .filter(|e| e.bindings.contains(&binding))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "selected physical binding is not current",
                )
            })?;
        let hint = self.observation.change_hint();
        let revision = evidence.revision;
        self.start_inner(
            move |cancel| {
                build(BoundNetwork {
                    binding,
                    hint,
                    revision,
                    cancel,
                })
            },
            Some(evidence),
            candidate,
            false,
        )
    }
    fn start_inner<R: Resource>(
        &mut self,
        build: impl FnOnce(Cancellation) -> Result<BuildOutcome<R>, Failure> + Send + 'static,
        binding: Option<BindingEvidence>,
        candidate: Option<CandidateAttempt>,
        persistent: bool,
    ) -> io::Result<u64> {
        if self.busy() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "resource still owned",
            ));
        }
        if self.state().paused && !persistent {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "physical offline latch",
            ));
        }
        let id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("resource id exhausted"))?;
        let token = self.state().token();
        let cancel = Cancellation(Arc::new(AtomicBool::new(false)));
        let worker_cancel = cancel.clone();
        let present = Arc::new(AtomicBool::new(false));
        let worker_present = present.clone();
        let (send, events) = mpsc::sync_channel(2);
        let (wake, receive) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("owned-resource".into())
            .spawn(move || {
                let mut resource = match build(worker_cancel.clone()) {
                    Ok(BuildOutcome::Ready(resource)) => resource,
                    Ok(BuildOutcome::CancelledClean) => {
                        // The factory certifies cleanup; require actual owner
                        // cancellation as well. Unexpected absence is not success.
                        let result = if worker_cancel.is_cancelled() {
                            Ok(())
                        } else {
                            Err(Failure::Start)
                        };
                        let _ = send.try_send(Event::Finished(id, result));
                        return;
                    }
                    Err(error) => {
                        let _ = send.try_send(Event::Finished(id, Err(error)));
                        return;
                    }
                };
                let presence = ResourcePresence::new(worker_present);
                let mut health = Ok(());
                if !worker_cancel.is_cancelled() && send.try_send(Event::Ready(id)).is_ok() {
                    while !worker_cancel.is_cancelled() {
                        health = resource.check();
                        if health.is_err() {
                            break;
                        }
                        match receive.recv_timeout(Duration::from_millis(50)) {
                            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                            Err(mpsc::RecvTimeoutError::Timeout) => {}
                        }
                    }
                }
                presence.0.store(false, Ordering::Release);
                let result = resource.stop().and(health);
                drop(resource);
                // Finish certifies that the worker has dropped its resource before
                // the owner may start another. No resource crosses the thread edge.
                let _ = send.try_send(Event::Finished(id, result));
            })?;
        self.next_id = id;
        self.active = Some(Active {
            id,
            token,
            binding,
            candidate,
            ready: false,
            present,
            cancel,
            wake,
            events,
            _thread: worker,
            persistent,
        });
        Ok(id)
    }
    fn current(&self, active: &Active) -> bool {
        if active.persistent {
            return !active.cancel.is_cancelled();
        }
        self.state().current(&active.token)
            && active.candidate.as_ref().map_or(true, |attempt| {
                self.state()
                    .candidate_is_current(attempt, self.observation.now())
            })
            && active.binding.as_ref().map_or(true, |binding| {
                self.observation.binding_evidence().as_ref() == Some(binding)
            })
    }
    /// Recheck immediately before the owner's final transaction; receipt alone
    /// never makes an old token safe for later selection or persistence.
    pub fn candidate_evidence_is_current<T>(&self, evidence: &CandidateEvidence<T>) -> bool {
        let Some(active) = self.active.as_ref() else {
            return false;
        };
        Arc::ptr_eq(&active.cancel.0, &evidence.operation.0)
            && active.id == evidence.resource
            && active.ready
            && active.candidate.as_ref() == Some(&evidence.attempt)
            && !active.cancel.is_cancelled()
            && self.state().candidate_evidence_is_current(
                &evidence.attempt,
                evidence.observed_at,
                self.observation.now(),
            )
            && self.current(active)
            && active.present.load(Ordering::Acquire)
    }
    /// Read-only preflight for a NEW selection, including original-path rebuilds.
    /// This does not select a front, persist policy, mutate domain state or stop
    /// the current path. Re-run it at the actual transaction boundary.
    pub fn check_candidate_for_selection<T: crate::candidate_evidence::ReadinessEvidence>(
        &self,
        evidence: &CandidateEvidence<T>,
    ) -> Result<(), crate::candidate_evidence::SelectionCheckError> {
        use crate::candidate_evidence::SelectionCheckError;
        if !self.candidate_evidence_is_current(evidence) {
            return Err(SelectionCheckError::Stale);
        }
        // A plain canary cannot certify negotiated PQ or an owned multihop graph.
        // Those Windows commit transactions are not implemented yet.
        if self.state().protection.post_quantum
            || self.state().protection.multihop
            || evidence.attempt.path.entry_relay.is_some()
        {
            return Err(SelectionCheckError::UnsupportedProtection);
        }
        let canary = evidence
            .value
            .fresh_canary()
            .ok_or(SelectionCheckError::Stale)?;
        if !self.candidate_evidence_is_current(evidence) {
            return Err(SelectionCheckError::Stale);
        }
        if canary.readiness() != adapter_domain::Readiness::Ready {
            return Err(SelectionCheckError::NotReady(canary.readiness()));
        }
        Ok(())
    }
    pub fn take_candidate_evidence<T: MeasuredEvidence>(
        &mut self,
        receiver: &mut CandidateReceiver<T>,
    ) -> Result<Option<CandidateEvidence<T>>, EvidenceError> {
        if receiver.channel.is_none() {
            return Err(EvidenceError::Closed);
        }
        let Some(active) = self.active.as_ref() else {
            return Err(EvidenceError::Closed);
        };
        // Local ids and domain tokens can repeat across owner instances. Keep
        // the operation allocation alive and compare it before consuming a
        // foreign mailbox or cancelling either operation.
        if !Arc::ptr_eq(&active.cancel.0, &receiver.operation.0) {
            return Err(EvidenceError::Stale);
        }
        if active.id != receiver.resource
            || active.candidate.as_ref() != Some(&receiver.attempt)
            || active.cancel.is_cancelled()
            || !self.current(active)
        {
            if active.id == receiver.resource {
                active.cancel();
            }
            receiver.discard();
            return Err(EvidenceError::Stale);
        }
        if !active.ready {
            return Ok(None);
        }
        if !active.present.load(Ordering::Acquire) {
            receiver.discard();
            return Err(EvidenceError::Stale);
        }
        let message = match receiver.channel.as_ref().unwrap().try_recv() {
            Ok(message) => message,
            Err(TryRecvError::Empty) => return Ok(None),
            Err(TryRecvError::Disconnected) => {
                receiver.discard();
                return Err(EvidenceError::Closed);
            }
        };
        receiver.discard();
        if !Arc::ptr_eq(&active.cancel.0, &message.operation.0) {
            return Err(EvidenceError::Stale);
        }
        let now = self.observation.now();
        if message.resource != active.id
            || message.attempt != receiver.attempt
            || !self.state().candidate_evidence_is_current(
                &message.attempt,
                message.observed_at,
                now,
            )
            || active.cancel.is_cancelled()
            || !self.current(active)
            || !active.present.load(Ordering::Acquire)
        {
            active.cancel();
            return Err(EvidenceError::Stale);
        }
        Ok(Some(CandidateEvidence {
            operation: message.operation,
            resource: active.id,
            attempt: message.attempt,
            observed_at: message.observed_at,
            value: message.value,
        }))
    }
    pub fn poll(&mut self) -> (Option<Effect>, Option<Event>) {
        let effect = self.observation.poll();
        if self
            .operation
            .as_ref()
            .is_some_and(|op| !self.operation_current(op))
        {
            self.cancel_current_operation();
        }
        let Some(active) = &self.active else {
            return (effect, None);
        };
        if !self.current(active) {
            active.cancel();
        }
        let event = match active.events.try_recv() {
            Ok(Event::Ready(id)) if self.current(active) && !active.cancel.is_cancelled() => {
                Some(Event::Ready(id))
            }
            Ok(Event::Ready(_)) => {
                active.cancel();
                None
            }
            Ok(finished @ Event::Finished(..)) => Some(finished),
            Err(TryRecvError::Disconnected) => {
                Some(Event::Finished(active.id, Err(Failure::Worker)))
            }
            Err(TryRecvError::Empty) => None,
        };
        if matches!(event, Some(Event::Ready(_))) {
            if let Some(active) = self.active.as_mut() {
                active.ready = true;
            }
        }
        if let Some(Event::Finished(_, result)) = event {
            // Failed stop/worker teardown is not proof that another resource
            // can safely replace it. Remain blocked until process restart.
            self.failed = result.is_err();
            self.cancel_current_operation();
            self.active = None;
        }
        (effect, event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adapter_domain::Attachment;
    use adapter_platform::physical_attachment::{Attachment as Physical, Observation};
    use std::{rc::Rc, time::Instant};
    struct Fixture {
        _not_send: Rc<()>,
        stopped: mpsc::Sender<()>,
        fail: bool,
    }
    impl Resource for Fixture {
        fn stop(&mut self) -> Result<(), Failure> {
            self.stopped.send(()).unwrap();
            if self.fail {
                Err(Failure::Stop)
            } else {
                Ok(())
            }
        }
    }
    fn owner() -> ResourceOwner {
        ResourceOwner::new(
            ObservedOwner::new(State::new("test".into()), || Observation {
                attachment: Physical::Unknown,
                bindings: vec![],
            })
            .unwrap(),
        )
    }
    fn next(owner: &mut ResourceOwner) -> Event {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(event) = owner.poll().1 {
                return event;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
    }
    #[test]
    fn blocked_start_keeps_owner_responsive_and_late_resource_is_stopped() {
        let mut owner = owner();
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let (stopped_tx, stopped) = mpsc::channel();
        let id = owner
            .start(move |_| {
                entered_tx.send(()).unwrap();
                release.recv().unwrap();
                Ok(Fixture {
                    _not_send: Rc::new(()),
                    stopped: stopped_tx,
                    fail: false,
                })
            })
            .unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        owner.state_mut().observe(Attachment::Unavailable, 0);
        for _ in 0..1000 {
            assert!(owner.poll().1.is_none());
        }
        assert!(owner.state().paused);
        assert!(owner.start::<Fixture>(|_| unreachable!()).is_err());
        release_tx.send(()).unwrap();
        assert_eq!(next(&mut owner), Event::Finished(id, Ok(())));
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!owner.busy());
        assert!(owner.state().paused);
    }
    #[test]
    fn completed_build_is_rejected_after_generation_change() {
        let mut owner = owner();
        let (built_tx, built) = mpsc::channel();
        let (stopped_tx, stopped) = mpsc::channel();
        let id = owner
            .start(move |_| {
                built_tx.send(()).unwrap();
                Ok(Fixture {
                    _not_send: Rc::new(()),
                    stopped: stopped_tx,
                    fail: false,
                })
            })
            .unwrap();
        built.recv_timeout(Duration::from_secs(1)).unwrap();
        owner.state_mut().generation += 1;
        assert_eq!(next(&mut owner), Event::Finished(id, Ok(())));
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn ready_resource_is_stopped_after_confirmed_outage() {
        let mut owner = owner();
        let (stopped_tx, stopped) = mpsc::channel();
        let id = owner
            .start(move |_| {
                Ok(Fixture {
                    _not_send: Rc::new(()),
                    stopped: stopped_tx,
                    fail: false,
                })
            })
            .unwrap();
        assert_eq!(next(&mut owner), Event::Ready(id));
        assert!(owner.busy());
        owner.state_mut().observe(Attachment::Unavailable, 0);
        assert_eq!(next(&mut owner), Event::Finished(id, Ok(())));
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn failed_stop_prevents_replacement() {
        let mut owner = owner();
        let (stopped_tx, stopped) = mpsc::channel();
        let id = owner
            .start(move |_| {
                Ok(Fixture {
                    _not_send: Rc::new(()),
                    stopped: stopped_tx,
                    fail: true,
                })
            })
            .unwrap();
        assert_eq!(next(&mut owner), Event::Ready(id));
        owner.cancel();
        assert_eq!(next(&mut owner), Event::Finished(id, Err(Failure::Stop)));
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(owner.busy());
        assert!(owner.start::<Fixture>(|_| unreachable!()).is_err());
    }
    #[test]
    fn worker_panic_is_sticky_failure() {
        let mut owner = owner();
        let id = owner
            .start::<Fixture>(|_| panic!("synthetic startup panic"))
            .unwrap();
        assert_eq!(next(&mut owner), Event::Finished(id, Err(Failure::Worker)));
        assert!(owner.busy());
    }
    #[test]
    fn dropping_owner_never_joins_a_blocked_start_but_stops_its_late_resource() {
        let mut owner = owner();
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let (stopped_tx, stopped) = mpsc::channel();
        owner
            .start(move |_| {
                entered_tx.send(()).unwrap();
                release.recv().unwrap();
                Ok(Fixture {
                    _not_send: Rc::new(()),
                    stopped: stopped_tx,
                    fail: false,
                })
            })
            .unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(owner);
        release_tx.send(()).unwrap();
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn blocked_stop_keeps_slot_until_resource_drop() {
        struct Stopping {
            entered: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
            dropped: mpsc::Sender<()>,
        }
        impl Resource for Stopping {
            fn stop(&mut self) -> Result<(), Failure> {
                self.entered.send(()).unwrap();
                self.release.recv().unwrap();
                Ok(())
            }
        }
        impl Drop for Stopping {
            fn drop(&mut self) {
                self.dropped.send(()).unwrap();
            }
        }
        let mut owner = owner();
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let (dropped_tx, dropped) = mpsc::channel();
        let id = owner
            .start(move |_| {
                Ok(Stopping {
                    entered: entered_tx,
                    release,
                    dropped: dropped_tx,
                })
            })
            .unwrap();
        assert_eq!(next(&mut owner), Event::Ready(id));
        owner.cancel();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        for _ in 0..1000 {
            assert!(owner.poll().1.is_none());
        }
        assert!(owner.start::<Fixture>(|_| unreachable!()).is_err());
        release_tx.send(()).unwrap();
        assert_eq!(next(&mut owner), Event::Finished(id, Ok(())));
        dropped.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!owner.busy());
    }
    #[test]
    fn unexpected_resource_exit_is_stopped_and_blocks_replacement() {
        struct Exited(mpsc::Sender<()>);
        impl Resource for Exited {
            fn check(&mut self) -> Result<(), Failure> {
                Err(Failure::Worker)
            }
            fn stop(&mut self) -> Result<(), Failure> {
                self.0.send(()).unwrap();
                Ok(())
            }
        }
        let mut owner = owner();
        let (stopped_tx, stopped) = mpsc::channel();
        let id = owner.start(move |_| Ok(Exited(stopped_tx))).unwrap();
        assert_eq!(next(&mut owner), Event::Ready(id));
        assert_eq!(next(&mut owner), Event::Finished(id, Err(Failure::Worker)));
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(owner.busy());
    }
    fn available_owner() -> ResourceOwner {
        use adapter_platform::physical_attachment::PhysicalBinding;
        let mut owner = ResourceOwner::new(
            ObservedOwner::new(State::new("bound".into()), || Observation {
                attachment: Physical::Available,
                bindings: vec![PhysicalBinding {
                    luid: 1,
                    index: 2,
                    ipv4: true,
                    ipv6: false,
                }],
            })
            .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while owner.observation.binding_evidence().is_none() {
            owner.poll();
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        owner
    }
    #[test]
    fn bound_start_requires_current_available_evidence() {
        let mut owner = owner();
        assert!(owner
            .start_network_bound::<Fixture>(|_| unreachable!())
            .is_err());
        assert!(!owner.state().paused);
    }
    #[test]
    fn network_hint_cancels_late_bound_result_without_fabricating_outage() {
        let mut owner = available_owner();
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let (stopped_tx, stopped) = mpsc::channel();
        let id = owner
            .start_network_bound(move |_| {
                entered_tx.send(()).unwrap();
                release.recv().unwrap();
                Ok(Fixture {
                    _not_send: Rc::new(()),
                    stopped: stopped_tx,
                    fail: false,
                })
            })
            .unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        owner.observation().change_hint().notify();
        assert!(owner.poll().1.is_none());
        assert!(!owner.state().paused);
        assert_eq!(owner.state().epoch, 0);
        release_tx.send(()).unwrap();
        assert_eq!(next(&mut owner), Event::Finished(id, Ok(())));
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn ordinary_front_resource_does_not_gain_a_binding_requirement() {
        let mut owner = available_owner();
        let (stopped_tx, stopped) = mpsc::channel();
        let id = owner
            .start(move |_| {
                Ok(Fixture {
                    _not_send: Rc::new(()),
                    stopped: stopped_tx,
                    fail: false,
                })
            })
            .unwrap();
        assert_eq!(next(&mut owner), Event::Ready(id));
        owner.observation().change_hint().notify();
        for _ in 0..100 {
            assert!(owner.poll().1.is_none());
        }
        assert!(owner.busy());
        assert!(!owner.state().paused);
        assert_eq!(owner.state().epoch, 0);
        owner.cancel();
        assert_eq!(next(&mut owner), Event::Finished(id, Ok(())));
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn changed_binding_cancels_resource_in_same_online_epoch_without_hint() {
        use adapter_platform::physical_attachment::PhysicalBinding;
        use std::sync::atomic::AtomicU64;
        let now = Arc::new(AtomicU64::new(0));
        let index = Arc::new(AtomicU64::new(2));
        let read = index.clone();
        let mut owner = ResourceOwner::new(
            ObservedOwner::with_test_clock(
                State::new("switch".into()),
                move || Observation {
                    attachment: Physical::Available,
                    bindings: vec![PhysicalBinding {
                        luid: 1,
                        index: read.load(Ordering::SeqCst) as u32,
                        ipv4: true,
                        ipv6: false,
                    }],
                },
                now.clone(),
            )
            .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while owner.observation.binding_evidence().is_none() {
            owner.poll();
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        let (stopped_tx, stopped) = mpsc::channel();
        let id = owner
            .start_network_bound(move |_| {
                Ok(Fixture {
                    _not_send: Rc::new(()),
                    stopped: stopped_tx,
                    fail: false,
                })
            })
            .unwrap();
        assert_eq!(next(&mut owner), Event::Ready(id));
        index.store(3, Ordering::SeqCst);
        now.store(500, Ordering::SeqCst);
        assert_eq!(next(&mut owner), Event::Finished(id, Ok(())));
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!owner.state().paused);
        assert_eq!(owner.state().epoch, 0);
    }
    #[test]
    fn review_expired_evidence_gap_must_cancel_late_bound_ready() {
        use adapter_platform::physical_attachment::PhysicalBinding;
        use std::sync::atomic::AtomicU64;
        let now = Arc::new(AtomicU64::new(0));
        let calls = Arc::new(AtomicU64::new(0));
        let count = calls.clone();
        let mut owner = ResourceOwner::new(
            ObservedOwner::with_test_clock(
                State::new("gap".into()),
                move || {
                    count.fetch_add(1, Ordering::SeqCst);
                    Observation {
                        attachment: Physical::Available,
                        bindings: vec![PhysicalBinding {
                            luid: 1,
                            index: 2,
                            ipv4: true,
                            ipv6: false,
                        }],
                    }
                },
                now.clone(),
            )
            .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while owner.observation.binding_evidence().is_none() {
            owner.poll();
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let (stopped_tx, stopped) = mpsc::channel();
        let id = owner
            .start_network_bound(move |cancel| {
                entered_tx.send(cancel).unwrap();
                release.recv().unwrap();
                Ok(Fixture {
                    _not_send: Rc::new(()),
                    stopped: stopped_tx,
                    fail: false,
                })
            })
            .unwrap();
        let cancellation = entered.recv_timeout(Duration::from_secs(1)).unwrap();
        now.store(1500, Ordering::SeqCst);
        owner.poll(); // Dispatch second observation; first evidence still fresh.
        while calls.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        thread::sleep(Duration::from_millis(50)); // Allow second result to queue.
        now.store(2500, Ordering::SeqCst); // Exercise the old evidence TTL boundary.
        assert!(owner.observation.binding_evidence().is_none());
        owner.poll(); // Consume queued same-identity Available result.
        assert!(owner.observation.binding_evidence().is_some());
        release_tx.send(()).unwrap();
        let event = next(&mut owner);
        assert_eq!(event, Event::Finished(id, Ok(())));
        assert!(cancellation.is_cancelled());
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(owner.state().epoch, 0);
        assert!(!owner.state().paused);
    }
    #[test]
    fn review_fresh_same_binding_refresh_keeps_candidate() {
        use adapter_platform::physical_attachment::PhysicalBinding;
        use std::sync::atomic::AtomicU64;
        let now = Arc::new(AtomicU64::new(0));
        let calls = Arc::new(AtomicU64::new(0));
        let count = calls.clone();
        let mut owner = ResourceOwner::new(
            ObservedOwner::with_test_clock(
                State::new("gap".into()),
                move || {
                    count.fetch_add(1, Ordering::SeqCst);
                    Observation {
                        attachment: Physical::Available,
                        bindings: vec![PhysicalBinding {
                            luid: 1,
                            index: 2,
                            ipv4: true,
                            ipv6: false,
                        }],
                    }
                },
                now.clone(),
            )
            .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while owner.observation.binding_evidence().is_none() {
            owner.poll();
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let (stopped_tx, _stopped) = mpsc::channel();
        let id = owner
            .start_network_bound(move |cancel| {
                entered_tx.send(cancel).unwrap();
                release.recv().unwrap();
                Ok(Fixture {
                    _not_send: Rc::new(()),
                    stopped: stopped_tx,
                    fail: false,
                })
            })
            .unwrap();
        let cancellation = entered.recv_timeout(Duration::from_secs(1)).unwrap();
        now.store(1500, Ordering::SeqCst);
        owner.poll(); // Dispatch second observation; first evidence still fresh.
        while calls.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        thread::sleep(Duration::from_millis(50)); // Allow second result to queue.
        now.store(1999, Ordering::SeqCst); // Exercise the old evidence TTL boundary.
        assert!(owner.observation.binding_evidence().is_some());
        owner.poll(); // Consume queued same-identity Available result.
        assert!(owner.observation.binding_evidence().is_some());
        release_tx.send(()).unwrap();
        let event = next(&mut owner);
        eprintln!(
            "late result={event:?}; cancellation={}; online epoch={}",
            cancellation.is_cancelled(),
            owner.state().epoch
        );
        owner.cancel();
        if event == Event::Ready(id) {
            let _ = next(&mut owner);
        }
        assert_eq!(
            event,
            Event::Ready(id),
            "Fresh same-identity evidence must preserve the candidate"
        );
    }
    #[test]
    fn cancelled_build_releases_slot_only_after_clean_finish() {
        let mut owner = owner();
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let (dropped_tx, dropped) = mpsc::channel();
        struct Partial(mpsc::Sender<()>);
        impl Drop for Partial {
            fn drop(&mut self) {
                self.0.send(()).unwrap();
            }
        }
        let id = owner
            .start_cancellable::<Fixture>(move |cancel| {
                let partial = Partial(dropped_tx);
                entered_tx.send(cancel.clone()).unwrap();
                release.recv_timeout(Duration::from_secs(2)).unwrap();
                assert!(cancel.is_cancelled());
                drop(partial);
                Ok(BuildOutcome::CancelledClean)
            })
            .unwrap();
        let cancel = entered.recv_timeout(Duration::from_secs(1)).unwrap();
        owner.cancel();
        assert!(cancel.is_cancelled());
        assert!(owner.busy());
        assert!(owner.poll().1.is_none());
        assert!(owner
            .start_cancellable::<Fixture>(|_| Ok(BuildOutcome::CancelledClean))
            .is_err());
        assert!(dropped.try_recv().is_err());
        release_tx.send(()).unwrap();
        assert_eq!(next(&mut owner), Event::Finished(id, Ok(())));
        dropped.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!owner.busy());
        let (stopped_tx, stopped) = mpsc::channel();
        let next_id = owner
            .start(move |_| {
                Ok(Fixture {
                    _not_send: Rc::new(()),
                    stopped: stopped_tx,
                    fail: false,
                })
            })
            .unwrap();
        assert!(next_id > id);
        assert_eq!(next(&mut owner), Event::Ready(next_id));
        owner.cancel();
        assert_eq!(next(&mut owner), Event::Finished(next_id, Ok(())));
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn clean_cancel_without_owner_cancellation_is_sticky_failure() {
        let mut owner = owner();
        let id = owner
            .start_cancellable::<Fixture>(|_| Ok(BuildOutcome::CancelledClean))
            .unwrap();
        assert_eq!(next(&mut owner), Event::Finished(id, Err(Failure::Start)));
        assert!(owner.busy());
    }
    #[test]
    fn uncertain_cancel_cleanup_remains_sticky() {
        let mut owner = owner();
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let id = owner
            .start_cancellable::<Fixture>(move |cancel| {
                entered_tx.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(2)).unwrap();
                assert!(cancel.is_cancelled());
                Err(Failure::Stop)
            })
            .unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        owner.cancel();
        release_tx.send(()).unwrap();
        assert_eq!(next(&mut owner), Event::Finished(id, Err(Failure::Stop)));
        assert!(owner.busy());
    }
    fn bound_owner() -> (ResourceOwner, PhysicalBinding) {
        let binding = PhysicalBinding {
            luid: 5,
            index: 7,
            ipv4: true,
            ipv6: false,
        };
        let mut owner = ResourceOwner::new(
            ObservedOwner::new(State::new("bound-factory".into()), move || Observation {
                attachment: Physical::Available,
                bindings: vec![binding],
            })
            .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while owner.observation.binding_evidence().is_none() {
            owner.poll();
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        (owner, binding)
    }
    #[test]
    fn selected_binding_must_belong_to_observed_evidence() {
        let (mut owner, binding) = bound_owner();
        assert!(owner
            .start_on_binding::<Fixture>(
                PhysicalBinding {
                    index: 9,
                    ..binding
                },
                |_| panic!("unobserved binding must not reach factory")
            )
            .is_err());
        assert!(!owner.busy());
    }
    #[test]
    fn bound_factory_sees_notification_without_owner_poll_and_cleans_cancel() {
        let (mut owner, binding) = bound_owner();
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let (cancelled_tx, cancelled) = mpsc::channel();
        let id = owner
            .start_on_binding::<Fixture>(binding, move |network| {
                assert!(network.binding() == binding);
                assert!(!network.is_cancelled());
                entered_tx.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(2)).unwrap();
                assert!(network.is_cancelled());
                cancelled_tx.send(()).unwrap();
                Ok(BuildOutcome::CancelledClean)
            })
            .unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        owner.observation.change_hint().notify();
        release_tx.send(()).unwrap();
        cancelled.recv_timeout(Duration::from_secs(1)).unwrap(); // No owner poll yet.
        assert_eq!(next(&mut owner), Event::Finished(id, Ok(())));
        assert!(!owner.busy());
        assert_eq!(owner.state().epoch, 0);
    }
    #[test]
    fn detached_readonly_monitor_tracks_hint_and_owner_cancel_without_poll() {
        for use_hint in [false, true] {
            let (mut owner, binding) = bound_owner();
            let (entered_tx, entered) = mpsc::channel();
            let (release_tx, release) = mpsc::channel();
            let id = owner
                .start_on_binding::<Fixture>(binding, move |network| {
                    let monitor = network.cancellation_monitor();
                    let copy = monitor.clone();
                    drop(network);
                    let thread = std::thread::spawn(move || {
                        assert!(!monitor.is_cancelled());
                        entered_tx.send(()).unwrap();
                        release.recv_timeout(Duration::from_secs(2)).unwrap();
                        assert!(monitor.is_cancelled());
                        assert!(copy.is_cancelled());
                    });
                    thread.join().unwrap();
                    Ok(BuildOutcome::CancelledClean)
                })
                .unwrap();
            entered.recv_timeout(Duration::from_secs(1)).unwrap();
            if use_hint {
                owner.observation.change_hint().notify();
            } else {
                owner.cancel();
            }
            release_tx.send(()).unwrap();
            assert_eq!(next(&mut owner), Event::Finished(id, Ok(())));
            assert!(!owner.busy());
        }
    }
    #[derive(Debug)]
    struct Evidence(Instant);
    impl MeasuredEvidence for Evidence {
        fn oldest_observation(&self) -> Instant {
            self.0
        }
    }
    fn candidate_owner() -> (
        ResourceOwner,
        PhysicalBinding,
        CandidateAttempt,
        std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) {
        use adapter_domain::{Canary, Path};
        let original = Path {
            relay: "one".into(),
            city: "us-sjc".into(),
            transport: "ss".into(),
            inlet: "192.0.2.2:20484".into(),
            entry_relay: None,
            slot: "a".into(),
            instance: 1,
            front: 1,
        };
        let mut state = State::new("candidate".into());
        state.path = Some(original.clone());
        state.city = Some(original.city.clone());
        state.observe(Attachment::Unavailable, 0);
        state.observe(Attachment::Available, 10);
        state.tick(2010);
        let token = state.token();
        state.original_verified(
            &token,
            Canary {
                ip: false,
                dns: false,
                https: false,
            },
            2010,
            2010,
            true,
        );
        let attempt = state
            .begin_original_rebuild(
                Path {
                    instance: 2,
                    ..original
                },
                2010,
            )
            .unwrap();
        let binding = PhysicalBinding {
            luid: 1,
            index: 2,
            ipv4: true,
            ipv6: false,
        };
        let now = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(10000));
        let mut owner = ResourceOwner::new(
            ObservedOwner::with_test_clock(
                state,
                move || Observation {
                    attachment: Physical::Available,
                    bindings: vec![binding],
                },
                now.clone(),
            )
            .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while owner.observation.binding_evidence().is_none() {
            owner.poll();
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        (owner, binding, attempt, now)
    }
    fn persistent_fixture(owner: &mut ResourceOwner) -> mpsc::Receiver<()> {
        let (stopped_tx, stopped) = mpsc::channel();
        let id = owner
            .start_persistent(move |_| {
                Ok(BuildOutcome::Ready(Fixture {
                    _not_send: Rc::new(()),
                    stopped: stopped_tx,
                    fail: false,
                }))
            })
            .unwrap();
        assert_eq!(next(owner), Event::Ready(id));
        stopped
    }
    #[test]
    fn persistent_aggregate_starts_offline_and_survives_generation_until_explicit_stop() {
        let mut owner = owner();
        owner.state_mut().observe(Attachment::Unavailable, 0);
        let stopped = persistent_fixture(&mut owner);
        owner.state_mut().generation += 1;
        for _ in 0..50 {
            assert!(owner.poll().1.is_none());
        }
        assert!(owner.state().paused);
        assert!(owner.busy());
        assert_eq!(stopped.try_recv(), Err(mpsc::TryRecvError::Empty));
        owner.cancel();
        assert!(matches!(next(&mut owner), Event::Finished(_, Ok(()))));
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn persistent_operation_invalidation_never_kills_aggregate_or_frees_pending_io() {
        for change in 0..4 {
            let (mut owner, binding, attempt, clock) = candidate_owner();
            let stopped = persistent_fixture(&mut owner);
            let (ticket, network) = owner
                .begin_operation(binding, attempt.path.instance, Some(&attempt))
                .unwrap();
            assert!(owner.is_operation_current(&ticket));
            match change {
                0 => owner.state_mut().generation += 1,
                1 => owner.state_mut().observe(Attachment::Unavailable, 10000),
                2 => owner.observation().change_hint().notify(),
                _ => clock.store(
                    10000 + adapter_domain::ATTEMPT_TIMEOUT_MS,
                    Ordering::Release,
                ),
            }
            assert!(!owner.is_operation_current(&ticket));
            owner.poll();
            assert!(network.is_cancelled());
            assert!(owner.begin_operation(binding, 3, None).is_err());
            assert_eq!(stopped.try_recv(), Err(mpsc::TryRecvError::Empty));
            assert!(owner.finish_operation(&ticket));
            assert!(!owner.finish_operation(&ticket));
            owner.cancel();
            assert!(matches!(next(&mut owner), Event::Finished(_, Ok(()))));
            stopped.recv_timeout(Duration::from_secs(1)).unwrap();
        }
    }
    #[test]
    fn operation_tickets_are_owner_unique_even_when_every_public_id_collides() {
        let (mut a, binding, attempt_a, _) = candidate_owner();
        let (mut b, _, attempt_b, _) = candidate_owner();
        let a_stop = persistent_fixture(&mut a);
        let b_stop = persistent_fixture(&mut b);
        let (ta, na) = a.begin_operation(binding, 2, Some(&attempt_a)).unwrap();
        let (tb, nb) = b.begin_operation(binding, 2, Some(&attempt_b)).unwrap();
        assert_eq!(ta.id(), tb.id());
        assert_eq!(ta.token(), tb.token());
        assert!(!a.is_operation_current(&tb));
        assert!(!a.finish_operation(&tb));
        assert!(a.is_operation_current(&ta));
        assert!(b.is_operation_current(&tb));
        assert!(!na.is_cancelled() && !nb.is_cancelled());
        assert!(a.finish_operation(&ta));
        assert!(na.is_cancelled());
        assert!(!nb.is_cancelled());
        assert!(b.finish_operation(&tb));
        a.cancel();
        b.cancel();
        assert!(matches!(next(&mut a), Event::Finished(_, Ok(()))));
        assert!(matches!(next(&mut b), Event::Finished(_, Ok(()))));
        a_stop.recv_timeout(Duration::from_secs(1)).unwrap();
        b_stop.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    fn candidate_fixture(stopped: mpsc::Sender<()>) -> Fixture {
        Fixture {
            _not_send: Rc::new(()),
            stopped,
            fail: false,
        }
    }
    #[test]
    fn candidate_payload_waits_for_accepted_ready_and_is_one_shot() {
        let (mut owner, binding, attempt, _) = candidate_owner();
        let (sent_tx, sent) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let (stopped_tx, stopped) = mpsc::channel();
        let mut receiver = owner
            .start_candidate_on_binding(binding, &attempt, move |_, sender| {
                assert_eq!(sender.attempt().path.instance, 2);
                sender.submit(Evidence(Instant::now())).unwrap();
                sent_tx.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(2)).unwrap();
                Ok(BuildOutcome::Ready(candidate_fixture(stopped_tx)))
            })
            .unwrap();
        sent.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(owner
            .take_candidate_evidence(&mut receiver)
            .unwrap()
            .is_none());
        release_tx.send(()).unwrap();
        assert_eq!(next(&mut owner), Event::Ready(receiver.resource()));
        let evidence = owner
            .take_candidate_evidence(&mut receiver)
            .unwrap()
            .unwrap();
        assert_eq!(evidence.attempt(), &attempt);
        assert!(evidence.observed_at() <= 10000);
        assert!(evidence.observed_at() >= attempt.started_at);
        assert!(matches!(
            owner.take_candidate_evidence(&mut receiver),
            Err(EvidenceError::Closed)
        ));
        assert_eq!(
            owner.state().path.as_ref().unwrap().instance,
            1,
            "receipt must not publish candidate path"
        );
        owner.cancel();
        assert_eq!(
            next(&mut owner),
            Event::Finished(receiver.resource(), Ok(()))
        );
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn candidate_identity_and_deadline_checked_before_factory() {
        let (mut owner, binding, attempt, now) = candidate_owner();
        for field in 0..4 {
            let mut wrong = attempt.clone();
            match field {
                0 => wrong.id += 1,
                1 => wrong.path.instance += 1,
                2 => wrong.owner.front += 1,
                _ => wrong.started_at += 1,
            };
            assert!(owner
                .start_candidate_on_binding::<Fixture, Evidence>(binding, &wrong, |_, _| panic!(
                    "stale factory"
                ))
                .is_err());
        }
        now.store(attempt.deadline, std::sync::atomic::Ordering::SeqCst);
        assert!(owner
            .start_candidate_on_binding::<Fixture, Evidence>(binding, &attempt, |_, _| panic!(
                "expired factory"
            ))
            .is_err());
        assert!(!owner.busy());
    }
    #[test]
    fn changing_registered_attempt_cancels_old_resource_and_discards_payload() {
        let (mut owner, binding, attempt, _) = candidate_owner();
        let (stopped_tx, stopped) = mpsc::channel();
        let mut receiver = owner
            .start_candidate_on_binding(binding, &attempt, move |_, sender| {
                sender.submit(Evidence(Instant::now())).unwrap();
                Ok(BuildOutcome::Ready(candidate_fixture(stopped_tx)))
            })
            .unwrap();
        assert_eq!(next(&mut owner), Event::Ready(receiver.resource()));
        let mut path = attempt.path.clone();
        path.instance = 3;
        let new = owner
            .state_mut()
            .begin_original_rebuild(path, 10000)
            .unwrap();
        assert_ne!(new.id, attempt.id);
        assert!(matches!(
            owner.take_candidate_evidence(&mut receiver),
            Err(EvidenceError::Stale)
        ));
        assert_eq!(
            next(&mut owner),
            Event::Finished(receiver.resource(), Ok(()))
        );
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn old_phase_timestamp_is_not_refreshed_by_mailbox_submission() {
        let (mut owner, binding, attempt, _) = candidate_owner();
        let (stopped_tx, stopped) = mpsc::channel();
        let mut receiver = owner
            .start_candidate_on_binding(binding, &attempt, move |_, sender| {
                sender
                    .submit(Evidence(Instant::now() - Duration::from_secs(6)))
                    .unwrap();
                Ok(BuildOutcome::Ready(candidate_fixture(stopped_tx)))
            })
            .unwrap();
        assert_eq!(next(&mut owner), Event::Ready(receiver.resource()));
        assert!(matches!(
            owner.take_candidate_evidence(&mut receiver),
            Err(EvidenceError::Stale)
        ));
        assert_eq!(
            next(&mut owner),
            Event::Finished(receiver.resource(), Ok(()))
        );
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn new_hint_rejects_queued_candidate_without_inventing_an_outage() {
        let (mut owner, binding, attempt, _) = candidate_owner();
        let epoch = owner.state().epoch;
        let (stopped_tx, stopped) = mpsc::channel();
        let mut receiver = owner
            .start_candidate_on_binding(binding, &attempt, move |_, sender| {
                sender.submit(Evidence(Instant::now())).unwrap();
                Ok(BuildOutcome::Ready(candidate_fixture(stopped_tx)))
            })
            .unwrap();
        assert_eq!(next(&mut owner), Event::Ready(receiver.resource()));
        let hint = owner.observation().change_hint();
        thread::spawn(move || hint.notify()).join().unwrap();
        assert!(matches!(
            owner.take_candidate_evidence(&mut receiver),
            Err(EvidenceError::Stale)
        ));
        assert_eq!(owner.state().epoch, epoch);
        assert_eq!(
            next(&mut owner),
            Event::Finished(receiver.resource(), Ok(()))
        );
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn invalid_clock_observations_never_enter_mailbox() {
        for future in [true, false] {
            let (mut owner, binding, attempt, _) = candidate_owner();
            let (stopped_tx, stopped) = mpsc::channel();
            let (result_tx, result) = mpsc::channel();
            let mut receiver = owner
                .start_candidate_on_binding(binding, &attempt, move |_, sender| {
                    let time = if future {
                        Instant::now() + Duration::from_secs(1)
                    } else {
                        Instant::now() - Duration::from_secs(20)
                    };
                    result_tx.send(sender.submit(Evidence(time))).unwrap();
                    Ok(BuildOutcome::Ready(candidate_fixture(stopped_tx)))
                })
                .unwrap();
            assert_eq!(next(&mut owner), Event::Ready(receiver.resource()));
            assert_eq!(
                result.recv_timeout(Duration::from_secs(1)).unwrap(),
                Err(if future {
                    EvidenceError::FutureObservation
                } else {
                    EvidenceError::BeforeOwnerClock
                })
            );
            assert!(matches!(
                owner.take_candidate_evidence(&mut receiver),
                Err(EvidenceError::Closed)
            ));
            owner.cancel();
            assert_eq!(
                next(&mut owner),
                Event::Finished(receiver.resource(), Ok(()))
            );
            stopped.recv_timeout(Duration::from_secs(1)).unwrap();
        }
    }
    #[test]
    fn failed_build_cannot_publish_queued_evidence_and_cleanup_stays_sticky() {
        let (mut owner, binding, attempt, _) = candidate_owner();
        let mut receiver = owner
            .start_candidate_on_binding::<Fixture, Evidence>(binding, &attempt, move |_, sender| {
                sender.submit(Evidence(Instant::now())).unwrap();
                Err(Failure::Stop)
            })
            .unwrap();
        assert_eq!(
            next(&mut owner),
            Event::Finished(receiver.resource(), Err(Failure::Stop))
        );
        assert!(matches!(
            owner.take_candidate_evidence(&mut receiver),
            Err(EvidenceError::Closed)
        ));
        assert!(owner.busy());
    }
    #[test]
    fn old_mailbox_does_not_cancel_an_unrelated_replacement_resource() {
        let (mut owner, binding, attempt, _) = candidate_owner();
        let (stopped_tx, stopped) = mpsc::channel();
        let mut receiver = owner
            .start_candidate_on_binding(binding, &attempt, move |_, sender| {
                sender.submit(Evidence(Instant::now())).unwrap();
                Ok(BuildOutcome::Ready(candidate_fixture(stopped_tx)))
            })
            .unwrap();
        assert_eq!(next(&mut owner), Event::Ready(receiver.resource()));
        owner.cancel();
        assert_eq!(
            next(&mut owner),
            Event::Finished(receiver.resource(), Ok(()))
        );
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
        let (stopped_tx, stopped) = mpsc::channel();
        let id = owner
            .start(move |_| Ok(candidate_fixture(stopped_tx)))
            .unwrap();
        assert_eq!(next(&mut owner), Event::Ready(id));
        assert!(matches!(
            owner.take_candidate_evidence(&mut receiver),
            Err(EvidenceError::Stale)
        ));
        assert!(!owner.active.as_ref().unwrap().cancel.is_cancelled());
        owner.cancel();
        assert_eq!(next(&mut owner), Event::Finished(id, Ok(())));
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn notification_during_stamp_is_rechecked_before_publication() {
        struct BlockedEvidence {
            old: Instant,
            entered: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
        }
        impl MeasuredEvidence for BlockedEvidence {
            fn oldest_observation(&self) -> Instant {
                self.entered.send(()).unwrap();
                self.release.recv_timeout(Duration::from_secs(2)).unwrap();
                self.old
            }
        }
        let (mut owner, binding, attempt, _) = candidate_owner();
        let hint = owner.observation().change_hint();
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let (result_tx, result) = mpsc::channel();
        let mut receiver = owner
            .start_candidate_on_binding::<Fixture, BlockedEvidence>(
                binding,
                &attempt,
                move |network, sender| {
                    let result = sender.submit(BlockedEvidence {
                        old: Instant::now(),
                        entered: entered_tx,
                        release,
                    });
                    result_tx.send(result).unwrap();
                    assert!(network.is_cancelled());
                    Ok(BuildOutcome::CancelledClean)
                },
            )
            .unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        thread::spawn(move || {
            hint.notify();
            release_tx.send(()).unwrap();
        })
        .join()
        .unwrap();
        assert_eq!(
            result.recv_timeout(Duration::from_secs(1)).unwrap(),
            Err(EvidenceError::Cancelled)
        );
        assert_eq!(
            next(&mut owner),
            Event::Finished(receiver.resource(), Ok(()))
        );
        assert!(matches!(
            owner.take_candidate_evidence(&mut receiver),
            Err(EvidenceError::Closed)
        ));
    }
    #[test]
    fn already_stopped_resource_cannot_publish_even_before_owner_drains_finished() {
        struct Stops {
            allow: mpsc::Receiver<()>,
            stopped: mpsc::Sender<()>,
        }
        impl Resource for Stops {
            fn check(&mut self) -> Result<(), Failure> {
                self.allow.recv_timeout(Duration::from_secs(2)).unwrap();
                Err(Failure::Worker)
            }
            fn stop(&mut self) -> Result<(), Failure> {
                self.stopped.send(()).unwrap();
                Ok(())
            }
        }
        let (mut owner, binding, attempt, _) = candidate_owner();
        let (allow_tx, allow) = mpsc::channel();
        let (stopped_tx, stopped) = mpsc::channel();
        let mut receiver = owner
            .start_candidate_on_binding(binding, &attempt, move |_, sender| {
                sender.submit(Evidence(Instant::now())).unwrap();
                Ok(BuildOutcome::Ready(Stops {
                    allow,
                    stopped: stopped_tx,
                }))
            })
            .unwrap();
        assert_eq!(next(&mut owner), Event::Ready(receiver.resource()));
        allow_tx.send(()).unwrap();
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            owner.take_candidate_evidence(&mut receiver),
            Err(EvidenceError::Stale)
        ));
        assert_eq!(
            next(&mut owner),
            Event::Finished(receiver.resource(), Err(Failure::Worker))
        );
        assert!(owner.busy());
    }
    #[test]
    fn every_owner_token_dimension_fences_a_queued_candidate() {
        for dimension in 0..8 {
            let (mut owner, binding, attempt, _) = candidate_owner();
            let (stopped_tx, stopped) = mpsc::channel();
            let mut receiver = owner
                .start_candidate_on_binding(binding, &attempt, move |_, sender| {
                    sender.submit(Evidence(Instant::now())).unwrap();
                    Ok(BuildOutcome::Ready(candidate_fixture(stopped_tx)))
                })
                .unwrap();
            assert_eq!(next(&mut owner), Event::Ready(receiver.resource()));
            let state = owner.state_mut();
            match dimension {
                0 => state.boot = "other-boot".into(),
                1 => state.generation += 1,
                2 => state.epoch += 1,
                3 => state.operation += 1,
                4 => state.path.as_mut().unwrap().slot = "b".into(),
                5 => state.path.as_mut().unwrap().instance += 1,
                6 => state.path.as_mut().unwrap().front += 1,
                _ => state.paused = true,
            }
            assert!(
                matches!(
                    owner.take_candidate_evidence(&mut receiver),
                    Err(EvidenceError::Stale)
                ),
                "dimension {dimension}"
            );
            assert_eq!(
                next(&mut owner),
                Event::Finished(receiver.resource(), Ok(()))
            );
            stopped.recv_timeout(Duration::from_secs(1)).unwrap();
        }
    }
    #[test]
    fn expired_physical_evidence_rejects_an_otherwise_fresh_candidate_report() {
        let (mut owner, binding, attempt, now) = candidate_owner();
        let (stopped_tx, stopped) = mpsc::channel();
        let mut receiver = owner
            .start_candidate_on_binding(binding, &attempt, move |_, sender| {
                sender.submit(Evidence(Instant::now())).unwrap();
                Ok(BuildOutcome::Ready(candidate_fixture(stopped_tx)))
            })
            .unwrap();
        assert_eq!(next(&mut owner), Event::Ready(receiver.resource()));
        now.store(12000, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            owner.take_candidate_evidence(&mut receiver),
            Err(EvidenceError::Stale)
        ));
        assert_eq!(
            next(&mut owner),
            Event::Finished(receiver.resource(), Ok(()))
        );
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn received_evidence_must_be_revalidated_before_a_later_owner_transaction() {
        let (mut owner, binding, attempt, _) = candidate_owner();
        let (stopped_tx, stopped) = mpsc::channel();
        let mut receiver = owner
            .start_candidate_on_binding(binding, &attempt, move |_, sender| {
                sender.submit(Evidence(Instant::now())).unwrap();
                Ok(BuildOutcome::Ready(candidate_fixture(stopped_tx)))
            })
            .unwrap();
        assert_eq!(next(&mut owner), Event::Ready(receiver.resource()));
        let evidence = owner
            .take_candidate_evidence(&mut receiver)
            .unwrap()
            .unwrap();
        assert!(owner.candidate_evidence_is_current(&evidence));
        assert_eq!(evidence.resource(), receiver.resource());
        let hint = owner.observation().change_hint();
        thread::spawn(move || hint.notify()).join().unwrap();
        assert!(!owner.candidate_evidence_is_current(&evidence));
        assert_eq!(
            next(&mut owner),
            Event::Finished(receiver.resource(), Ok(()))
        );
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!owner.candidate_evidence_is_current(&evidence));
    }
    #[test]
    fn candidate_sender_cannot_label_a_different_bound_operation() {
        let (mut first, binding, attempt, _) = candidate_owner();
        let (network_tx, network_rx) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let (stopped_tx, stopped) = mpsc::channel();
        let first_receiver = first
            .start_candidate_on_binding::<Fixture, Evidence>(
                binding,
                &attempt,
                move |network, sender| {
                    assert!(sender.accepts_network(&network));
                    network_tx.send(network).unwrap();
                    release.recv_timeout(Duration::from_secs(2)).unwrap();
                    Ok(BuildOutcome::Ready(candidate_fixture(stopped_tx)))
                },
            )
            .unwrap();
        let other = network_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let (mut second, binding, attempt, _) = candidate_owner();
        let (second_stopped_tx, second_stopped) = mpsc::channel();
        let receiver = second
            .start_candidate_on_binding::<Fixture, Evidence>(
                binding,
                &attempt,
                move |network, sender| {
                    assert!(sender.accepts_network(&network));
                    assert!(!sender.accepts_network(&other));
                    Ok(BuildOutcome::Ready(candidate_fixture(second_stopped_tx)))
                },
            )
            .unwrap();
        assert_eq!(next(&mut second), Event::Ready(receiver.resource()));
        second.cancel();
        assert_eq!(
            next(&mut second),
            Event::Finished(receiver.resource(), Ok(()))
        );
        second_stopped.recv_timeout(Duration::from_secs(1)).unwrap();
        first.cancel();
        release_tx.send(()).unwrap();
        assert_eq!(
            next(&mut first),
            Event::Finished(first_receiver.resource(), Ok(()))
        );
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    fn production_candidate_pair() -> (
        ResourceOwner,
        ResourceOwner,
        PhysicalBinding,
        CandidateAttempt,
    ) {
        let (template, binding, attempt, _) = candidate_owner();
        let state = template.state().clone();
        drop(template);
        let create = || {
            ResourceOwner::new(
                ObservedOwner::new(state.clone(), move || Observation {
                    attachment: Physical::Available,
                    bindings: vec![binding],
                })
                .unwrap(),
            )
        };
        let mut first = create();
        let mut second = create();
        // The prepared recovery attempt starts at owner time 2010ms. Use both
        // real monotonic clocks, not an injected clock, for receipt/freshness.
        thread::sleep(Duration::from_millis(2020));
        let deadline = Instant::now() + Duration::from_secs(2);
        while first.observation.binding_evidence().is_none()
            || second.observation.binding_evidence().is_none()
        {
            first.poll();
            second.poll();
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        (first, second, binding, attempt)
    }
    fn publish_real_candidate(
        owner: &mut ResourceOwner,
        binding: PhysicalBinding,
        attempt: &CandidateAttempt,
    ) -> (
        CandidateReceiver<Evidence>,
        BoundCancellation,
        mpsc::Receiver<()>,
    ) {
        let (monitor_tx, monitor_rx) = mpsc::channel();
        let (stopped_tx, stopped) = mpsc::channel();
        let receiver = owner
            .start_candidate_on_binding(binding, attempt, move |network, sender| {
                monitor_tx.send(network.cancellation_monitor()).unwrap();
                sender.submit(Evidence(Instant::now())).unwrap();
                Ok(BuildOutcome::Ready(candidate_fixture(stopped_tx)))
            })
            .unwrap();
        let monitor = monitor_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(next(owner), Event::Ready(receiver.resource()));
        (receiver, monitor, stopped)
    }
    #[test]
    fn cross_owner_equal_ids_cannot_receive_or_consume_foreign_mailbox() {
        let (mut first, mut second, binding, attempt) = production_candidate_pair();
        let (mut receiver, first_monitor, first_stopped) =
            publish_real_candidate(&mut first, binding, &attempt);
        let (second_receiver, second_monitor, second_stopped) =
            publish_real_candidate(&mut second, binding, &attempt);
        assert_eq!(receiver.resource(), second_receiver.resource());
        let mut empty = owner();
        assert!(matches!(
            empty.take_candidate_evidence(&mut receiver),
            Err(EvidenceError::Closed)
        ));
        drop(empty);
        assert!(matches!(
            second.take_candidate_evidence(&mut receiver),
            Err(EvidenceError::Stale)
        ));
        assert!(!first_monitor.is_cancelled());
        assert!(!second_monitor.is_cancelled());
        // Wrong-owner use must not drain or close the rightful owner's mailbox.
        let evidence = first
            .take_candidate_evidence(&mut receiver)
            .unwrap()
            .unwrap();
        assert!(first.candidate_evidence_is_current(&evidence));
        drop(receiver);
        drop(second_receiver);
        assert!(!first_monitor.is_cancelled());
        assert!(!second_monitor.is_cancelled());
        first.cancel();
        next(&mut first);
        first_stopped.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!second_monitor.is_cancelled());
        second.cancel();
        next(&mut second);
        second_stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn cross_owner_equal_ids_cannot_revalidate_taken_evidence() {
        let (mut first, mut second, binding, attempt) = production_candidate_pair();
        let (mut receiver, _, first_stopped) =
            publish_real_candidate(&mut first, binding, &attempt);
        let (second_receiver, second_monitor, second_stopped) =
            publish_real_candidate(&mut second, binding, &attempt);
        let evidence = first
            .take_candidate_evidence(&mut receiver)
            .unwrap()
            .unwrap();
        assert!(first.candidate_evidence_is_current(&evidence));
        assert!(!second.candidate_evidence_is_current(&evidence));
        first.cancel();
        next(&mut first);
        first_stopped.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(first);
        drop(receiver);
        drop(evidence);
        drop(second_receiver);
        assert!(!second_monitor.is_cancelled());
        second.cancel();
        next(&mut second);
        second_stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn cross_owner_stale_receiver_cannot_cancel_colliding_new_owner() {
        let (mut first, mut second, binding, attempt) = production_candidate_pair();
        let (mut receiver, _, first_stopped) =
            publish_real_candidate(&mut first, binding, &attempt);
        let (second_receiver, second_monitor, second_stopped) =
            publish_real_candidate(&mut second, binding, &attempt);
        first.cancel();
        next(&mut first);
        first_stopped.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(first);
        // Make the second owner's candidate different while keeping its local id.
        second.state_mut().operation += 1;
        assert!(matches!(
            second.take_candidate_evidence(&mut receiver),
            Err(EvidenceError::Stale)
        ));
        assert!(!second_monitor.is_cancelled());
        drop(receiver);
        drop(second_receiver);
        assert!(!second_monitor.is_cancelled());
        second.cancel();
        next(&mut second);
        second_stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    }

    struct FullCanary(Instant, Option<adapter_domain::Canary>);
    #[test]
    fn persistent_measurements_require_the_matching_operation_and_actual_measurement_time() {
        use crate::candidate_evidence::SelectionCheckError;
        let (mut owner, binding, attempt, _) = candidate_owner();
        let stopped = persistent_fixture(&mut owner);
        let before = Instant::now() - Duration::from_millis(1);
        let (ticket, _network) = owner.begin_operation(binding, 2, Some(&attempt)).unwrap();
        let ready = adapter_domain::Canary {
            ip: true,
            dns: true,
            https: true,
        };
        assert_eq!(
            owner.validate_operation_measurement(&ticket, &FullCanary(before, Some(ready))),
            Err(SelectionCheckError::Stale)
        );
        assert_eq!(
            owner.validate_operation_measurement(
                &ticket,
                &FullCanary(Instant::now() + Duration::from_secs(1), Some(ready))
            ),
            Err(SelectionCheckError::Stale)
        );
        let evidence = FullCanary(Instant::now(), Some(ready));
        let (at, checked) = owner
            .validate_operation_measurement(&ticket, &evidence)
            .unwrap();
        assert!(at <= owner.now());
        assert_eq!(checked, ready);
        let degraded = FullCanary(
            Instant::now(),
            Some(adapter_domain::Canary {
                dns: false,
                ..ready
            }),
        );
        assert_eq!(
            owner.validate_operation_measurement(&ticket, &degraded),
            Err(SelectionCheckError::NotReady(
                adapter_domain::Readiness::DegradedDns
            ))
        );
        assert!(owner
            .validate_original_preservation(&ticket, &degraded)
            .is_ok());
        owner.state_mut().stage = adapter_domain::Stage::Fallback;
        assert_eq!(
            owner.validate_original_preservation(&ticket, &degraded),
            Err(SelectionCheckError::Stale)
        );
        owner.state_mut().stage = adapter_domain::Stage::RebuildOriginal;
        owner.state_mut().protection.multihop = true;
        assert_eq!(
            owner.validate_operation_measurement(&ticket, &evidence),
            Err(SelectionCheckError::UnsupportedProtection)
        );
        owner.state_mut().protection.multihop = false;
        owner.state_mut().manual_preempt();
        assert_eq!(
            owner.validate_operation_measurement(&ticket, &evidence),
            Err(SelectionCheckError::Stale)
        );
        assert!(owner.finish_operation(&ticket));
        owner.cancel();
        next(&mut owner);
        stopped.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    impl MeasuredEvidence for FullCanary {
        fn oldest_observation(&self) -> Instant {
            self.0
        }
    }
    impl crate::candidate_evidence::ReadinessEvidence for FullCanary {
        fn fresh_canary(&self) -> Option<adapter_domain::Canary> {
            self.1
        }
    }
    fn measured_candidate(
        canary: Option<adapter_domain::Canary>,
    ) -> (
        ResourceOwner,
        CandidateEvidence<FullCanary>,
        Arc<std::sync::atomic::AtomicU64>,
        mpsc::Receiver<()>,
    ) {
        let (mut owner, binding, attempt, clock) = candidate_owner();
        let (stopped, stop_rx) = mpsc::channel();
        let mut receiver = owner
            .start_candidate_on_binding(binding, &attempt, move |_, sender| {
                sender.submit(FullCanary(Instant::now(), canary)).unwrap();
                Ok(BuildOutcome::Ready(candidate_fixture(stopped)))
            })
            .unwrap();
        assert_eq!(next(&mut owner), Event::Ready(receiver.resource()));
        let evidence = owner
            .take_candidate_evidence(&mut receiver)
            .unwrap()
            .unwrap();
        (owner, evidence, clock, stop_rx)
    }
    fn ready_canary() -> adapter_domain::Canary {
        adapter_domain::Canary {
            ip: true,
            dns: true,
            https: true,
        }
    }
    fn stop_measured(owner: &mut ResourceOwner) {
        owner.cancel();
        assert!(matches!(next(owner), Event::Finished(_, Ok(()))));
        assert!(!owner.busy());
    }
    #[test]
    fn new_selection_requires_full_readiness_for_all_eight_canary_combinations() {
        use crate::candidate_evidence::SelectionCheckError;
        for ip in [false, true] {
            for dns in [false, true] {
                for https in [false, true] {
                    let canary = adapter_domain::Canary { ip, dns, https };
                    let (mut owner, evidence, _, _stopped) = measured_candidate(Some(canary));
                    let before = owner.state().token();
                    let path = owner.state().path.clone();
                    let expected = if canary.readiness() == adapter_domain::Readiness::Ready {
                        Ok(())
                    } else {
                        Err(SelectionCheckError::NotReady(canary.readiness()))
                    };
                    assert_eq!(owner.check_candidate_for_selection(&evidence), expected);
                    assert_eq!(owner.state().token(), before);
                    assert_eq!(owner.state().path, path);
                    assert!(owner.busy()); // Rejection doesn't discard a live original path.
                    stop_measured(&mut owner);
                }
            }
        }
    }
    #[test]
    fn selection_rechecks_expiry_after_successful_receipt() {
        use crate::candidate_evidence::SelectionCheckError;
        let (mut owner, evidence, clock, _stopped) = measured_candidate(Some(ready_canary()));
        assert_eq!(owner.check_candidate_for_selection(&evidence), Ok(()));
        clock.fetch_add(adapter_domain::PROBE_TTL_MS + 1, Ordering::SeqCst);
        assert_eq!(
            owner.check_candidate_for_selection(&evidence),
            Err(SelectionCheckError::Stale)
        );
        stop_measured(&mut owner);
    }
    #[test]
    fn plain_ready_canary_cannot_satisfy_unimplemented_protection_transactions() {
        use crate::candidate_evidence::SelectionCheckError;
        for (multihop, post_quantum) in [(true, false), (false, true), (true, true)] {
            let (mut owner, evidence, _, _stopped) = measured_candidate(Some(ready_canary()));
            owner.state_mut().protection = adapter_domain::Protection {
                multihop,
                post_quantum,
            };
            assert_eq!(
                owner.check_candidate_for_selection(&evidence),
                Err(SelectionCheckError::UnsupportedProtection)
            );
            assert_eq!(
                owner.state().protection,
                adapter_domain::Protection {
                    multihop,
                    post_quantum
                }
            );
            stop_measured(&mut owner);
        }
    }
    #[test]
    fn selection_rejects_cancel_network_hint_preemption_and_foreign_owner() {
        use crate::candidate_evidence::SelectionCheckError;
        for mode in 0..3 {
            let (mut owner, evidence, _, _stopped) = measured_candidate(Some(ready_canary()));
            let (foreign, _, _, _) = candidate_owner();
            assert_eq!(
                foreign.check_candidate_for_selection(&evidence),
                Err(SelectionCheckError::Stale)
            );
            assert_eq!(owner.check_candidate_for_selection(&evidence), Ok(()));
            match mode {
                0 => owner.cancel(),
                1 => owner.observation().change_hint().notify(),
                _ => owner.state_mut().manual_preempt(),
            }
            assert_eq!(
                owner.check_candidate_for_selection(&evidence),
                Err(SelectionCheckError::Stale)
            );
            assert!(!foreign.busy());
            stop_measured(&mut owner);
            foreign.cancel();
        }
    }
    #[test]
    fn selection_rejects_phase_expiry_even_with_fresh_mailbox_stamp() {
        use crate::candidate_evidence::SelectionCheckError;
        let (mut owner, evidence, _, _stopped) = measured_candidate(None);
        assert!(owner.candidate_evidence_is_current(&evidence));
        assert_eq!(
            owner.check_candidate_for_selection(&evidence),
            Err(SelectionCheckError::Stale)
        );
        stop_measured(&mut owner);
    }
    #[test]
    fn multihop_candidate_graph_is_blocked_even_without_a_policy_flag() {
        use crate::candidate_evidence::SelectionCheckError;
        let (mut owner, binding, _, _) = candidate_owner();
        owner.state_mut().path.as_mut().unwrap().entry_relay = Some("entry".into());
        let mut path = owner.state().path.as_ref().unwrap().clone();
        path.instance = 2;
        let attempt = owner
            .state_mut()
            .begin_original_rebuild(path, 2010)
            .unwrap();
        let (stopped, _stop_rx) = mpsc::channel();
        let mut receiver = owner
            .start_candidate_on_binding(binding, &attempt, move |_, sender| {
                sender
                    .submit(FullCanary(Instant::now(), Some(ready_canary())))
                    .unwrap();
                Ok(BuildOutcome::Ready(candidate_fixture(stopped)))
            })
            .unwrap();
        assert_eq!(next(&mut owner), Event::Ready(receiver.resource()));
        let evidence = owner
            .take_candidate_evidence(&mut receiver)
            .unwrap()
            .unwrap();
        assert!(!owner.state().protection.multihop);
        assert!(owner.candidate_evidence_is_current(&evidence));
        assert_eq!(
            owner.check_candidate_for_selection(&evidence),
            Err(SelectionCheckError::UnsupportedProtection)
        );
        stop_measured(&mut owner);
    }
}
