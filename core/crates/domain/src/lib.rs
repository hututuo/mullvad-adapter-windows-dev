//! Pure lifecycle policy. No sockets, clocks, OS processes, UI, or persistence.
//! Callers own a single State and supply monotonic milliseconds and typed evidence.
use std::collections::BTreeMap;

pub const SETTLE_MS: u64 = 2_000;
pub const RECOVERY_BUDGET_MS: u64 = 45_000;
pub const PROBE_TTL_MS: u64 = 5_000;
pub const LOCAL_RETRY_MS: u64 = 250;
/// Prototype hard I/O-attempt ceiling, not a measured recovery-performance promise.
pub const ATTEMPT_TIMEOUT_MS: u64 = 90_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Attachment {
    Available,
    Unavailable,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Readiness {
    Ready,
    DegradedDns,
    DegradedService,
    DataFail,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Canary {
    pub ip: bool,
    pub dns: bool,
    pub https: bool,
}
impl Canary {
    pub fn alive(self) -> bool {
        self.ip || self.https
    }
    pub fn readiness(self) -> Readiness {
        if !self.alive() {
            Readiness::DataFail
        } else if !self.dns {
            Readiness::DegradedDns
        } else if !self.https {
            Readiness::DegradedService
        } else {
            Readiness::Ready
        }
    }
    pub fn accepts_new(self, policy: Protection, require_ready: bool) -> bool {
        self.alive()
            && (!(require_ready || policy.post_quantum) || self.readiness() == Readiness::Ready)
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Protection {
    pub multihop: bool,
    pub post_quantum: bool,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Capabilities {
    pub multihop: bool,
    pub post_quantum: bool,
}
impl Capabilities {
    pub fn supports(self, profile: Protection) -> bool {
        !(profile.multihop && profile.post_quantum)
            && (!profile.multihop || self.multihop)
            && (!profile.post_quantum || self.post_quantum)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Path {
    pub relay: String,
    pub city: String,
    pub transport: String,
    pub inlet: String,
    pub entry_relay: Option<String>,
    pub slot: String,
    pub instance: u64,
    pub front: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Token {
    pub boot: String,
    pub generation: u64,
    pub epoch: u64,
    pub operation: u64,
    pub slot: String,
    pub instance: u64,
    pub front: u64,
}
/// State-owner reservation for one new candidate, separate from the old active path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateAttempt {
    pub owner: Token,
    pub id: u64,
    pub path: Path,
    pub started_at: u64,
    pub deadline: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Idle,
    ManualSelection,
    Waiting,
    Settling,
    VerifyOriginal,
    RebuildOriginal,
    Fallback,
    Deferred,
    Disconnected,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Effect {
    Verify(Path, Token),
    Rebuild(Path, Token),
    SameCity(String, Token),
    Deferred(u64),
    Preserved(Readiness),
    Disconnected,
    Stale,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RebuildResult {
    Canary { path: Path, canary: Canary },
    LocalFailure,
    Busy,
}

#[derive(Clone, Debug)]
pub struct State {
    pub boot: String,
    pub generation: u64,
    pub epoch: u64,
    pub operation: u64,
    pub attachment: Attachment,
    pub paused: bool,
    pub stage: Stage,
    pub path: Option<Path>,
    pub city: Option<String>,
    pub protection: Protection,
    pub readiness: Option<Readiness>,
    available_since: Option<u64>,
    recovery_started: Option<u64>,
    deferred_until: Option<u64>,
    deferred_stage: Option<Stage>,
    next_candidate: u64,
    candidate: Option<CandidateAttempt>,
}
impl State {
    pub fn new(boot: String) -> Self {
        Self {
            boot,
            generation: 0,
            epoch: 0,
            operation: 0,
            attachment: Attachment::Unknown,
            paused: false,
            stage: Stage::Idle,
            path: None,
            city: None,
            protection: Protection::default(),
            readiness: None,
            available_since: None,
            recovery_started: None,
            deferred_until: None,
            deferred_stage: None,
            next_candidate: 0,
            candidate: None,
        }
    }
    pub fn token(&self) -> Token {
        Token {
            boot: self.boot.clone(),
            generation: self.generation,
            epoch: self.epoch,
            operation: self.operation,
            slot: self.path.as_ref().map_or(String::new(), |p| p.slot.clone()),
            instance: self.path.as_ref().map_or(0, |p| p.instance),
            front: self.path.as_ref().map_or(0, |p| p.front),
        }
    }
    pub fn current(&self, token: &Token) -> bool {
        !self.paused && *token == self.token()
    }
    pub fn observe(&mut self, attachment: Attachment, now: u64) {
        self.attachment = attachment;
        match attachment {
            Attachment::Unavailable => {
                if !self.paused || self.available_since.is_some() {
                    self.epoch += 1;
                }
                self.paused = true;
                self.stage = Stage::Waiting;
                self.available_since = None;
                self.readiness = None;
                self.recovery_started = None;
                self.deferred_until = None;
            }
            Attachment::Unknown => {
                // An interrupted positive interval must begin again. Unknown never releases a latch.
                self.available_since = None;
                if self.paused {
                    self.stage = Stage::Waiting;
                }
            }
            Attachment::Available if self.paused => {
                self.available_since.get_or_insert(now);
                self.stage = Stage::Settling;
            }
            Attachment::Available => {}
        }
    }
    pub fn tick(&mut self, now: u64) -> Option<Effect> {
        if self.paused {
            if self.attachment != Attachment::Available
                || now.saturating_sub(self.available_since?) < SETTLE_MS
            {
                return None;
            }
            self.paused = false;
            self.operation += 1;
            self.recovery_started = Some(now);
            self.stage = Stage::VerifyOriginal;
            return Some(self.original_effect(false));
        }
        if self.stage == Stage::Deferred && now >= self.deferred_until? {
            if self.budget_expired(now) {
                self.stage = Stage::Disconnected;
                return Some(Effect::Disconnected);
            }
            self.stage = self.deferred_stage.take().unwrap_or(Stage::VerifyOriginal);
            return Some(self.original_effect(self.stage == Stage::RebuildOriginal));
        }
        None
    }
    fn original_effect(&mut self, rebuild: bool) -> Effect {
        match self.path.clone() {
            Some(path) => {
                if rebuild {
                    Effect::Rebuild(path, self.token())
                } else {
                    Effect::Verify(path, self.token())
                }
            }
            None => {
                self.stage = Stage::Disconnected;
                Effect::Disconnected
            }
        }
    }
    pub fn original_verified(
        &mut self,
        token: &Token,
        canary: Canary,
        observed_at: u64,
        now: u64,
        metadata_valid: bool,
    ) -> Effect {
        if !self.current(token)
            || self.stage != Stage::VerifyOriginal
            || now.saturating_sub(observed_at) > PROBE_TTL_MS
            || observed_at > now
        {
            return Effect::Stale;
        }
        if !metadata_valid {
            return self.fallback(now);
        }
        if canary.alive() {
            self.stage = Stage::Idle;
            self.readiness = Some(canary.readiness());
            return Effect::Preserved(canary.readiness());
        }
        if self.budget_expired(now) {
            self.stage = Stage::Disconnected;
            return Effect::Disconnected;
        }
        self.stage = Stage::RebuildOriginal;
        self.original_effect(true)
    }
    /// An active-path probe could not preserve service. Start recovery at the
    /// original path without pretending that the physical network went offline.
    pub fn request_original_rebuild(&mut self, now: u64) -> Result<Effect, &'static str> {
        if self.paused || self.attachment != Attachment::Available {
            return Err("waiting_network");
        }
        if self.path.is_none() {
            return Err("original_path_missing");
        }
        if !matches!(self.stage, Stage::Idle | Stage::VerifyOriginal) {
            return Err("recovery_busy");
        }
        self.operation += 1;
        if self.stage == Stage::Idle {
            // A later, independent outage gets its own budget. Do not inherit
            // the timestamp of a recovery which already preserved service.
            self.recovery_started = Some(now);
        } else {
            self.recovery_started.get_or_insert(now);
        }
        self.stage = Stage::RebuildOriginal;
        Ok(self.original_effect(true))
    }
    pub fn original_withdrawn(&mut self, token: &Token, now: u64) -> Effect {
        if !self.current(token)
            || !matches!(self.stage, Stage::VerifyOriginal | Stage::RebuildOriginal)
        {
            return Effect::Stale;
        }
        self.fallback(now)
    }
    pub fn begin_original_rebuild(
        &mut self,
        path: Path,
        now: u64,
    ) -> Result<CandidateAttempt, &'static str> {
        if self.paused || self.stage != Stage::RebuildOriginal {
            return Err("stale_attempt");
        }
        if self.budget_expired(now) {
            return Err("recovery_budget_exhausted");
        }
        if self.path.as_ref().map_or(true, |original| {
            path.slot != original.slot
                || path.relay != original.relay
                || path.city != original.city
                || path.transport != original.transport
                || path.inlet != original.inlet
                || path.entry_relay != original.entry_relay
                || path.front != original.front
                || path.instance == 0
                || path.instance == original.instance
        }) {
            return Err("invalid_original_path");
        }
        Ok(self.register_candidate(path, now))
    }
    fn register_candidate(&mut self, path: Path, now: u64) -> CandidateAttempt {
        self.next_candidate += 1;
        let attempt = CandidateAttempt {
            owner: self.token(),
            id: self.next_candidate,
            path,
            started_at: now,
            deadline: now.saturating_add(ATTEMPT_TIMEOUT_MS),
        };
        self.candidate = Some(attempt.clone());
        attempt
    }
    /// Read-only ownership/time fence for the resource-owner evidence mailbox.
    pub fn candidate_is_current(&self, attempt: &CandidateAttempt, now: u64) -> bool {
        self.candidate_evidence_is_current(attempt, now, now)
    }
    pub fn candidate_evidence_is_current(
        &self,
        attempt: &CandidateAttempt,
        observed_at: u64,
        now: u64,
    ) -> bool {
        matches!(
            self.stage,
            Stage::RebuildOriginal | Stage::Fallback | Stage::ManualSelection
        ) && self.validate_candidate(attempt, observed_at, now).is_ok()
    }
    fn validate_candidate(
        &self,
        attempt: &CandidateAttempt,
        observed_at: u64,
        now: u64,
    ) -> Result<(), &'static str> {
        if !self.current(&attempt.owner) || self.candidate.as_ref() != Some(attempt) {
            return Err("stale_attempt");
        }
        if observed_at < attempt.started_at
            || observed_at > now
            || now.saturating_sub(observed_at) > PROBE_TTL_MS
        {
            return Err("stale_candidate_evidence");
        }
        if now >= attempt.deadline {
            return Err("candidate_deadline");
        }
        Ok(())
    }
    pub fn original_rebuilt(
        &mut self,
        attempt: &CandidateAttempt,
        result: RebuildResult,
        observed_at: u64,
        now: u64,
    ) -> Effect {
        if self.stage != Stage::RebuildOriginal
            || self.validate_candidate(attempt, observed_at, now).is_err()
        {
            return Effect::Stale;
        }
        if let RebuildResult::Canary { ref path, .. } = result {
            if path != &attempt.path {
                return Effect::Stale;
            }
        }
        self.candidate = None;
        match result {
            RebuildResult::LocalFailure | RebuildResult::Busy => {
                self.deferred_stage = Some(Stage::RebuildOriginal);
                self.stage = Stage::Deferred;
                self.deferred_until = Some(now.saturating_add(LOCAL_RETRY_MS));
                Effect::Deferred(LOCAL_RETRY_MS)
            }
            RebuildResult::Canary { path, canary }
                if canary.accepts_new(self.protection, false) =>
            {
                self.path = Some(path);
                self.generation += 1;
                self.stage = Stage::Idle;
                self.readiness = Some(canary.readiness());
                Effect::Preserved(canary.readiness())
            }
            RebuildResult::Canary { canary, .. } if canary.alive() => {
                self.stage = Stage::Disconnected;
                self.readiness = Some(canary.readiness());
                Effect::Disconnected
            }
            RebuildResult::Canary { .. } => self.fallback(now),
        }
    }
    fn budget_expired(&self, now: u64) -> bool {
        self.recovery_started.map_or(true, |start| {
            now.saturating_sub(start) >= RECOVERY_BUDGET_MS
        })
    }
    fn fallback(&mut self, now: u64) -> Effect {
        if self.budget_expired(now) || self.city.is_none() {
            self.stage = Stage::Disconnected;
            return Effect::Disconnected;
        }
        self.stage = Stage::Fallback;
        Effect::SameCity(self.city.clone().unwrap(), self.token())
    }
    pub fn begin_fallback(
        &mut self,
        path: Path,
        now: u64,
    ) -> Result<CandidateAttempt, &'static str> {
        if self.paused || self.stage != Stage::Fallback {
            return Err("stale_attempt");
        }
        if self.budget_expired(now) {
            return Err("recovery_budget_exhausted");
        }
        if self.city.as_ref() != Some(&path.city) {
            return Err("outside_selected_city");
        }
        if !matches!(path.slot.as_str(), "a" | "b")
            || path.instance == 0
            || self
                .path
                .as_ref()
                .is_some_and(|old| path.instance == old.instance || path.front != old.front)
        {
            return Err("invalid_candidate_identity");
        }
        Ok(self.register_candidate(path, now))
    }
    pub fn commit_fallback(
        &mut self,
        attempt: &CandidateAttempt,
        canary: Canary,
        observed_at: u64,
        now: u64,
    ) -> Result<(), &'static str> {
        if self.stage != Stage::Fallback {
            return Err("stale_attempt");
        }
        self.validate_candidate(attempt, observed_at, now)?;
        // The budget gates starting work; an already running bounded canary may finish later.
        if !canary.accepts_new(self.protection, true) {
            return Err("candidate_not_ready");
        }
        self.path = Some(attempt.path.clone());
        self.candidate = None;
        self.generation += 1;
        self.stage = Stage::Idle;
        self.readiness = Some(Readiness::Ready);
        Ok(())
    }
    /// Explicit user selection; old committed path/city remain rollback facts.
    /// The host must drain/reconcile an earlier I/O operation before issuing this.
    pub fn begin_manual_selection(
        &mut self,
        path: Path,
        now: u64,
    ) -> Result<CandidateAttempt, &'static str> {
        if self.paused || self.attachment != Attachment::Available {
            return Err("waiting_network");
        }
        if path.city.is_empty()
            || path.relay.is_empty()
            || path.front == 0
            || path.instance == 0
            || !matches!(path.slot.as_str(), "a" | "b")
            || self
                .path
                .as_ref()
                .is_some_and(|old| old.instance == path.instance || old.front != path.front)
        {
            return Err("invalid_candidate_identity");
        }
        self.manual_preempt();
        self.stage = Stage::ManualSelection;
        Ok(self.register_candidate(path, now))
    }
    /// Call only after owned front readback and durable policy reconciliation.
    /// This function validates policy evidence, not external process or file I/O.
    pub fn commit_manual_selection(
        &mut self,
        attempt: &CandidateAttempt,
        canary: Canary,
        observed_at: u64,
        now: u64,
    ) -> Result<(), &'static str> {
        if self.stage != Stage::ManualSelection {
            return Err("stale_attempt");
        }
        self.validate_candidate(attempt, observed_at, now)?;
        if !canary.accepts_new(self.protection, true) {
            return Err("candidate_not_ready");
        }
        self.path = Some(attempt.path.clone());
        self.city = Some(attempt.path.city.clone());
        self.candidate = None;
        self.generation += 1;
        self.stage = Stage::Idle;
        self.readiness = Some(Readiness::Ready);
        Ok(())
    }
    pub fn manual_preempt(&mut self) {
        self.operation += 1;
        self.stage = if self.paused {
            Stage::Waiting
        } else {
            Stage::Idle
        };
        self.recovery_started = None;
        self.candidate = None;
    }
}

/// A reservation survives PQ bootstrap, negotiation and final process replacement.
/// The executor releases it only after owned process handles confirm termination.
#[derive(Default, Debug)]
pub struct PeerReservations(BTreeMap<String, u64>);
impl PeerReservations {
    pub fn reserve(&mut self, peers: &[String], owner: u64) -> Result<(), &'static str> {
        if peers.is_empty()
            || peers
                .iter()
                .any(|peer| peer.is_empty() || self.0.contains_key(peer))
        {
            return Err("peer_busy_or_invalid");
        }
        let unique: std::collections::BTreeSet<_> = peers.iter().collect();
        if unique.len() != peers.len() {
            return Err("duplicate_peer");
        }
        for peer in peers {
            self.0.insert(peer.clone(), owner);
        }
        Ok(())
    }
    pub fn release(&mut self, owner: u64) {
        self.0.retain(|_, value| *value != owner);
    }
}

#[cfg(test)]
mod tests;
