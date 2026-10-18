//! A candidate worker startup chain. Control-plane startup is not tunnel readiness.
use crate::{
    controller::{Controller, ControllerError},
    worker_with_route, Egress, Identity, Listener, Protection, Transport, WorkerInput,
};
use adapter_control::owned_lifecycle::{BoundNetwork, BuildOutcome, Failure, Resource};
use adapter_platform::{
    egress::windows::snapshot, windows_process::OwnedProcess, windows_runtime::PrivateRuntime,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddrV4, TcpStream},
    path::Path,
    time::{Duration, Instant},
};

/// Borrowed only on the I/O worker; callers retain responsibility for secret storage.
/// There is no caller-supplied alias or cached route snapshot.
pub use crate::carrier::windows::Snapshot as CarrierSnapshot;
pub struct WorkerRequest<'a> {
    pub identity: Identity<'a>,
    pub relay_public_key: &'a str,
    pub transport: Transport,
    pub protection: Protection,
    pub listener: Listener<'a>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerStartError {
    Cancelled,
    Route,
    Configuration,
    Peer,
    Start,
    Controller,
    Deadline,
    Cleanup,
}
impl WorkerStartError {
    /// Closed diagnostics shared by product and explicit maintenance probes.
    /// Never expose engine stderr, paths, credentials or remote response bodies.
    pub fn code(self) -> &'static str {
        match self {
            Self::Cancelled => "worker_start_cancelled",
            Self::Route => "worker_route_unavailable",
            Self::Configuration => "worker_configuration_rejected",
            Self::Peer => "peer_reservation_unavailable",
            Self::Start => "worker_start_failed",
            Self::Controller => "worker_controller_unavailable",
            Self::Deadline => "worker_start_deadline",
            Self::Cleanup => "cleanup_uncertain",
        }
    }
}
pub struct Worker {
    process: OwnedProcess,
    network: BoundNetwork,
    mixed_port: u16,
    carrier: Option<crate::carrier::windows::Run>,
    _peer: adapter_platform::windows::PeerLease,
}
impl Worker {
    /// Use only inside ResourceOwner::start_on_binding. The caller verifies the
    /// official executable and private-runtime ancestors before this operation.
    /// No frontend IPC enables this path yet. Ready still requires domain canaries
    /// and actual socket-binding proof before selecting a worker in the front.
    pub fn start(
        executable: &Path,
        runtime: &PrivateRuntime,
        request: &WorkerRequest<'_>,
        network: BoundNetwork,
    ) -> Result<Self, WorkerStartError> {
        Self::start_config(executable, runtime, request, network, false, false)
    }
    /// Only for the explicit maintenance probe; raw diagnostics never escape.
    pub fn start_diagnostic(
        executable: &Path,
        runtime: &PrivateRuntime,
        request: &WorkerRequest<'_>,
        network: BoundNetwork,
    ) -> Result<Self, WorkerStartError> {
        Self::start_config(executable, runtime, request, network, true, false)
    }
    /// Own the physical outer socket; this alone is not candidate readiness.
    pub fn start_carried(
        executable: &Path,
        runtime: &PrivateRuntime,
        request: &WorkerRequest<'_>,
        network: BoundNetwork,
    ) -> Result<Self, WorkerStartError> {
        Self::start_config(executable, runtime, request, network, true, true)
    }
    fn start_config(
        executable: &Path,
        runtime: &PrivateRuntime,
        request: &WorkerRequest<'_>,
        network: BoundNetwork,
        diagnostic: bool,
        carried: bool,
    ) -> Result<Self, WorkerStartError> {
        let deadline = Instant::now() + Duration::from_secs(15);
        let checkpoint = || {
            if network.is_cancelled() {
                Err(WorkerStartError::Cancelled)
            } else if Instant::now() >= deadline {
                Err(WorkerStartError::Deadline)
            } else {
                Ok(())
            }
        };
        checkpoint()?;
        let destination = match request.transport {
            Transport::DirectV4 { endpoint, .. } | Transport::Shadowsocks { endpoint, .. } => {
                IpAddr::V4(endpoint)
            }
            Transport::DirectV6 { endpoint, .. } => IpAddr::V6(endpoint),
        };
        // Acquire within the captured operation, never from an earlier factory.
        let route = snapshot(network.binding(), destination);
        checkpoint()?;
        let route = route.map_err(|_| WorkerStartError::Route)?;
        let binding = route.binding();
        let input = WorkerInput {
            identity: Identity {
                private_key: request.identity.private_key,
                preshared_key: request.identity.preshared_key,
                ipv4: request.identity.ipv4,
                ipv6: request.identity.ipv6,
            },
            relay_public_key: request.relay_public_key,
            transport: request.transport,
            protection: request.protection,
            egress: Egress {
                alias: route.alias(),
                luid: binding.luid,
                index: binding.index,
                ipv4: binding.ipv4,
                ipv6: binding.ipv6,
            },
            listener: Listener {
                mixed_port: request.listener.mixed_port,
                controller_port: request.listener.controller_port,
                controller_secret: request.listener.controller_secret,
            },
        };
        let peer = adapter_platform::windows::PeerLease::acquire(
            &crate::device_identity::fingerprint(request.identity.private_key)
                .map_err(|_| WorkerStartError::Configuration)?,
        )
        .map_err(|_| WorkerStartError::Peer)?;
        checkpoint()?;
        let outer_port = match request.transport {
            Transport::DirectV4 { port, .. }
            | Transport::DirectV6 { port, .. }
            | Transport::Shadowsocks { port, .. } => port,
        };
        let mut carrier = if carried {
            Some(
                crate::carrier::windows::Run::open(&route, outer_port)
                    .map_err(|_| WorkerStartError::Route)?,
            )
        } else {
            None
        };
        let prepared = (|| {
            let config = if let Some(carrier) = &carrier {
                crate::worker_with_carrier_route(&input, &route, &carrier.config())
            } else if diagnostic {
                crate::worker_with_route_diagnostic(&input, &route)
            } else {
                worker_with_route(&input, &route)
            }
            .map_err(|_| WorkerStartError::Configuration)?;
            let secret = runtime
                .prepare_input(config.expose())
                .map_err(|_| WorkerStartError::Start)?;
            drop(config);
            checkpoint()?;
            if !route.is_fresh() {
                return Err(WorkerStartError::Route);
            }
            let directory = runtime
                .path()
                .to_str()
                .ok_or(WorkerStartError::Configuration)?;
            let preflight_error = std::cell::Cell::new(None);
            OwnedProcess::spawn_with_secret_input_and_peer_checked(
                executable,
                &["-f".into(), "-".into(), "-d".into(), directory.into()],
                secret,
                &peer,
                || {
                    let result = checkpoint().and_then(|()| {
                        if route.is_fresh() {
                            Ok(())
                        } else {
                            Err(WorkerStartError::Route)
                        }
                    });
                    result.map_err(|error| {
                        preflight_error.set(Some(error));
                        std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "worker preflight rejected",
                        )
                    })
                },
            )
            .map_err(|_| preflight_error.get().unwrap_or(WorkerStartError::Start))
        })();
        let process = match prepared {
            Ok(process) => process,
            Err(error) => {
                if carrier
                    .as_mut()
                    .is_some_and(|carrier| carrier.stop_confirmed().is_err())
                {
                    return Err(WorkerStartError::Cleanup);
                }
                return Err(error);
            }
        };
        let ready = (|| {
            if let Some(carrier) = &carrier {
                carrier
                    .attach(
                        process
                            .controller_owner()
                            .map_err(|_| WorkerStartError::Start)?,
                    )
                    .map_err(|_| WorkerStartError::Start)?;
            }
            let controller = Controller::for_process(
                &process,
                request.listener.controller_port,
                request.listener.controller_secret,
            )
            .map_err(|_| WorkerStartError::Controller)?;
            let owner = process
                .controller_owner()
                .map_err(|_| WorkerStartError::Controller)?;
            loop {
                checkpoint()?;
                if process
                    .wait(Duration::ZERO)
                    .map_err(|_| WorkerStartError::Start)?
                    .is_some()
                {
                    return Err(WorkerStartError::Start);
                }
                match controller.check_version() {
                    Ok(()) => {}
                    Err(ControllerError::Unavailable) => {
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                    Err(_) => return Err(WorkerStartError::Controller),
                }
                checkpoint()?;
                match controller.check_worker_graph() {
                    Ok(()) => {}
                    Err(ControllerError::Unavailable | ControllerError::UnexpectedResponse) => {
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                    Err(_) => return Err(WorkerStartError::Controller),
                }
                checkpoint()?;
                let stream = TcpStream::connect_timeout(
                    &SocketAddrV4::new(Ipv4Addr::LOCALHOST, request.listener.mixed_port).into(),
                    Duration::from_millis(500),
                );
                match stream.and_then(|stream| owner.verify_connected(&stream)) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                        return Err(WorkerStartError::Controller)
                    }
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                }
                checkpoint()?;
                let again = snapshot(network.binding(), destination);
                checkpoint()?;
                let again = again.map_err(|_| WorkerStartError::Route)?;
                if !again.is_fresh() || !route.same_path(&again) {
                    return Err(WorkerStartError::Route);
                }
                return Ok(());
            }
        })();
        match ready {
            Ok(()) => Ok(Self {
                process,
                network,
                mixed_port: request.listener.mixed_port,
                carrier,
                _peer: peer,
            }),
            Err(error) => {
                // Close the forwarding boundary even if child termination fails.
                let carrier_failed = carrier
                    .as_mut()
                    .is_some_and(|c| c.stop_confirmed().is_err());
                let process_failed = process.terminate(Duration::from_secs(5)).is_err();
                if carrier_failed || process_failed {
                    return Err(WorkerStartError::Cleanup);
                }
                Err(error)
            }
        }
    }
    /// Blocking worker-local measurements only; no front selection or domain commit.
    pub fn probe(
        &mut self,
    ) -> Result<crate::canary_batch::Report, crate::canary_batch::BatchError> {
        crate::canary_batch::for_worker(&self.process, &self.network, self.mixed_port)
    }
    pub fn output_snapshot(&self) -> adapter_platform::engine_output::Snapshot {
        self.process.output_snapshot()
    }
    pub fn probe_bound(&mut self) -> Result<BoundReport, crate::canary_batch::BatchError> {
        self.probe_bound_on(&self.network)
    }
    pub fn probe_bound_on(
        &self,
        operation: &BoundNetwork,
    ) -> Result<BoundReport, crate::canary_batch::BatchError> {
        use crate::canary_batch::BatchError;
        if operation.is_cancelled() {
            return Err(BatchError::Cancelled);
        }
        if operation.binding() != self.network.binding() {
            return Err(BatchError::LocalFailure);
        }
        let carrier = self.carrier.as_ref().ok_or(BatchError::LocalFailure)?;
        let window = carrier
            .begin(operation.cancellation_monitor())
            .map_err(|_| BatchError::LocalFailure)?;
        let report = crate::canary_batch::for_worker(&self.process, operation, self.mixed_port)?;
        if operation.is_cancelled() {
            return Err(BatchError::Cancelled);
        }
        let observed = carrier
            .verify(window)
            .map_err(|_| BatchError::LocalFailure)?;
        if operation.is_cancelled() {
            return Err(BatchError::Cancelled);
        }
        Ok(BoundReport {
            report,
            carrier_instance: carrier.instance(),
            window,
            observed,
        })
    }
    /// Preserve the distinction between a local failure and measured failure of
    /// this path. The negative variant cannot be used to authorize promotion.
    pub fn assess_on(
        &self,
        operation: &BoundNetwork,
    ) -> Result<Assessment, crate::canary_batch::BatchError> {
        use crate::canary_batch::BatchError;
        if operation.is_cancelled() {
            return Err(BatchError::Cancelled);
        }
        if operation.binding() != self.network.binding() {
            return Err(BatchError::LocalFailure);
        }
        let carrier = self.carrier.as_ref().ok_or(BatchError::LocalFailure)?;
        let window = carrier
            .begin(operation.cancellation_monitor())
            .map_err(|_| BatchError::LocalFailure)?;
        let report = crate::canary_batch::for_worker(&self.process, operation, self.mixed_port)?;
        if operation.is_cancelled() {
            return Err(BatchError::Cancelled);
        }
        if let Ok(observed) = carrier.verify(window) {
            return Ok(Assessment::Bound(BoundReport {
                report,
                carrier_instance: carrier.instance(),
                window,
                observed,
            }));
        }
        if report.fresh_canary(Instant::now())?.alive() {
            return Err(BatchError::LocalFailure);
        }
        let observed = carrier
            .verify_activity(window)
            .map_err(|_| BatchError::LocalFailure)?;
        if operation.is_cancelled() {
            return Err(BatchError::Cancelled);
        }
        Ok(Assessment::Unready(UnreadyReport { report, observed }))
    }
    pub fn assess(&self) -> Result<Assessment, crate::canary_batch::BatchError> {
        self.assess_on(&self.network)
    }
    /// Revalidate the still-owned carrier before selector or durable commit.
    pub fn verify_bound_report(&self, report: &BoundReport) -> bool {
        report.observed.elapsed() < Duration::from_secs(2)
            && self.carrier.as_ref().is_some_and(|c| {
                c.instance() == report.carrier_instance && c.verify(report.window).is_ok()
            })
            && self.is_running()
    }
    /// Verify an already selected process using a NEW call-level operation.
    /// An expired startup guard must not kill the selected data plane or be
    /// refreshed. A changed physical binding requires original-path rebuild.
    pub fn probe_on(
        &mut self,
        operation: &BoundNetwork,
    ) -> Result<crate::canary_batch::Report, crate::canary_batch::BatchError> {
        if operation.binding() != self.network.binding() {
            return Err(crate::canary_batch::BatchError::LocalFailure);
        }
        crate::canary_batch::for_worker(&self.process, operation, self.mixed_port)
    }
    pub fn carrier_snapshot(&self) -> Option<CarrierSnapshot> {
        self.carrier.as_ref().map(|c| c.snapshot())
    }
    pub fn is_running(&self) -> bool {
        matches!(self.process.wait(Duration::ZERO), Ok(None))
            && self
                .carrier
                .as_ref()
                .is_none_or(|carrier| carrier.is_running())
    }
    pub fn binding(&self) -> adapter_platform::physical_attachment::PhysicalBinding {
        self.network.binding()
    }
    /// Keep the identity reservation until this returns success. Do not replace
    /// the aggregate or release a peer after an uncertain process-tree stop.
    pub fn stop_confirmed(&mut self) -> Result<(), Failure> {
        self.stop()
    }
    /// Candidate-only factory: construct, measure, publish once, then retain the
    /// resource. Publication errors/cancellation clean up before returning.
    pub fn build_candidate(
        executable: &Path,
        runtime: &PrivateRuntime,
        request: &WorkerRequest<'_>,
        network: BoundNetwork,
        sender: adapter_control::candidate_evidence::CandidateSender<crate::canary_batch::Report>,
    ) -> Result<BuildOutcome<Self>, Failure> {
        if !sender.accepts_network(&network) {
            return Err(Failure::Start);
        }
        let mut worker = match Self::start(executable, runtime, request, network) {
            Ok(worker) => worker,
            Err(error) => return Self::into_build(Err(error)),
        };
        let published = worker
            .probe()
            .ok()
            .and_then(|report| sender.submit(report).ok())
            .is_some();
        if published && !worker.network.is_cancelled() {
            return Ok(BuildOutcome::Ready(worker));
        }
        let stopped = worker.stop();
        let cancelled = worker.network.is_cancelled();
        drop(worker);
        stopped?;
        if cancelled {
            Ok(BuildOutcome::CancelledClean)
        } else {
            Err(Failure::Worker)
        }
    }
    pub fn into_build(
        result: Result<Self, WorkerStartError>,
    ) -> Result<BuildOutcome<Self>, Failure> {
        match result {
            Ok(worker) => Ok(BuildOutcome::Ready(worker)),
            Err(WorkerStartError::Cancelled) => Ok(BuildOutcome::CancelledClean),
            Err(WorkerStartError::Cleanup) => Err(Failure::Stop),
            Err(_) => Err(Failure::Start),
        }
    }
}
impl Resource for Worker {
    fn check(&mut self) -> Result<(), Failure> {
        // Notification detection sets the shared cancellation flag. The resource
        // loop then follows the normal stop path, not a fabricated health failure.
        if self.network.is_cancelled() {
            return Ok(());
        }
        if self.is_running() {
            Ok(())
        } else {
            Err(Failure::Worker)
        }
    }
    fn stop(&mut self) -> Result<(), Failure> {
        let carrier_failed = self
            .carrier
            .as_mut()
            .is_some_and(|c| c.stop_confirmed().is_err());
        let process_failed = self.process.terminate(Duration::from_secs(5)).is_err();
        if carrier_failed || process_failed {
            Err(Failure::Stop)
        } else {
            Ok(())
        }
    }
}

/// Same-call canary plus witness of this still-owned physical socket. Not
/// serializable or constructible by callers; not permission to skip host fences.
pub enum Assessment {
    Bound(BoundReport),
    Unready(UnreadyReport),
}
/// Own-process canaries failed despite a submission in their exact bound window.
/// This is negative path evidence, never an incoming-packet or Ready claim.
pub struct UnreadyReport {
    report: crate::canary_batch::Report,
    observed: Instant,
}
impl UnreadyReport {
    pub fn failed_canary(&self) -> Option<adapter_domain::Canary> {
        self.report
            .fresh_canary(Instant::now())
            .ok()
            .filter(|c| !c.alive())
    }
}
impl adapter_control::candidate_evidence::MeasuredEvidence for UnreadyReport {
    fn oldest_observation(&self) -> Instant {
        self.report.oldest_observation().min(self.observed)
    }
}

pub struct BoundReport {
    report: crate::canary_batch::Report,
    carrier_instance: u64,
    window: u64,
    observed: Instant,
}
impl BoundReport {
    pub fn into_report(self) -> crate::canary_batch::Report {
        self.report
    }
    pub fn report(&self) -> &crate::canary_batch::Report {
        &self.report
    }
}
impl adapter_control::candidate_evidence::MeasuredEvidence for BoundReport {
    fn oldest_observation(&self) -> Instant {
        self.report.oldest_observation().min(self.observed)
    }
}
impl adapter_control::candidate_evidence::ReadinessEvidence for BoundReport {
    fn fresh_canary(&self) -> Option<adapter_domain::Canary> {
        if self.observed.elapsed() >= Duration::from_secs(2) {
            return None;
        }
        self.report.fresh_canary(Instant::now()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adapter_control::{
        observer::ObservedOwner,
        owned_lifecycle::{Event, ResourceOwner},
    };
    use adapter_domain::State;
    use adapter_platform::{
        physical_attachment::{Attachment, Observation, PhysicalBinding},
        windows::boot_id,
    };
    use std::sync::mpsc;
    fn negative_start(cancel_first: bool) {
        let root =
            std::env::temp_dir().join(format!("adapter-worker-negative-{}", boot_id().unwrap()));
        std::fs::create_dir(&root).unwrap();
        let runtime = PrivateRuntime::open(&root.join("runtime")).unwrap();
        // Synthetic observation is intentional: this only proves refusal before
        // input/launch, never a positive physical-interface or worker acceptance.
        let binding = PhysicalBinding {
            luid: 9,
            index: 3,
            ipv4: true,
            ipv6: false,
        };
        let mut owner = ResourceOwner::new(
            ObservedOwner::new(State::new("negative".into()), move || Observation {
                attachment: Attachment::Available,
                bindings: vec![binding],
            })
            .unwrap(),
        );
        let end = Instant::now() + Duration::from_secs(3);
        while owner.observation().bindings().is_empty() {
            owner.poll();
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(1));
        }
        let (entered_tx, entered) = mpsc::channel();
        let (release_tx, release) = mpsc::channel();
        let worker_runtime = runtime.clone();
        let missing_executable = root.join("never-created.exe");
        let id = owner
            .start_on_binding(binding, move |network| {
                entered_tx.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(2)).unwrap();
                let request = WorkerRequest {
                    identity: Identity {
                        private_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                        preshared_key: None,
                        ipv4: "10.64.0.2".parse().unwrap(),
                        ipv6: None,
                    },
                    relay_public_key: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
                    transport: Transport::DirectV4 {
                        endpoint: Ipv4Addr::LOCALHOST,
                        port: 51820,
                    },
                    protection: Protection::Standard,
                    listener: Listener {
                        mixed_port: 51001,
                        controller_port: 51002,
                        controller_secret:
                            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    },
                };
                let result = Worker::start(&missing_executable, &worker_runtime, &request, network);
                let expected = if cancel_first {
                    WorkerStartError::Cancelled
                } else {
                    WorkerStartError::Route
                };
                assert!(matches!(&result, Err(error) if *error == expected));
                Worker::into_build(result)
            })
            .unwrap();
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        if cancel_first {
            owner.observation().change_hint().notify();
        }
        release_tx.send(()).unwrap();
        let end = Instant::now() + Duration::from_secs(3);
        loop {
            assert!(Instant::now() < end);
            match owner.poll().1 {
                Some(Event::Ready(_)) => panic!("negative factory must never be ready"),
                Some(Event::Finished(actual, result)) => {
                    assert_eq!(actual, id);
                    assert_eq!(
                        result,
                        if cancel_first {
                            Ok(())
                        } else {
                            Err(Failure::Start)
                        }
                    );
                    break;
                }
                None => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        assert!(!std::fs::read_dir(runtime.path()).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".input-")));
        assert_eq!(owner.busy(), !cancel_first);
        drop(owner);
        drop(runtime);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn cancelled_bound_factory_never_prepares_input_or_starts_process() {
        negative_start(true);
    }
    #[test]
    fn rejected_route_never_prepares_input_or_starts_process() {
        negative_start(false);
    }
}
