//! Worker-local probe collection. No candidate publication or front selection.
use crate::{dns_transport::DnsResult, https_probe::HttpsResult};
use adapter_domain::Canary;
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchError {
    Cancelled,
    LocalFailure,
    Stale,
}
/// Closed diagnostic labels. No endpoint, payload, account or engine text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    Passed,
    Rejected,
    Cancelled,
    Deadline,
    Timeout,
    Unavailable,
    NotRunDnsFailed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ProbeOutcomes {
    pub ip: ProbeOutcome,
    pub dns: ProbeOutcome,
    pub hostname: ProbeOutcome,
}
fn https_outcome(result: HttpsResult) -> ProbeOutcome {
    match result {
        HttpsResult::Passed(_) => ProbeOutcome::Passed,
        HttpsResult::Rejected => ProbeOutcome::Rejected,
        HttpsResult::Cancelled => ProbeOutcome::Cancelled,
        HttpsResult::Deadline => ProbeOutcome::Deadline,
    }
}
#[derive(Debug)]
pub struct Measurement<T> {
    value: T,
    completed: Instant,
}
impl<T: Copy> Measurement<T> {
    pub fn value(&self) -> T {
        self.value
    }
    pub fn completed(&self) -> Instant {
        self.completed
    }
}
/// Immutable observations tied to this worker call, not an operation/attempt token.
/// The host must attach its captured identity and fence it before any domain use.
#[derive(Debug)]
pub struct Report {
    started: Instant,
    finished: Instant,
    ip: Measurement<HttpsResult>,
    dns: Measurement<DnsResult>,
    hostname: Option<Measurement<HttpsResult>>,
}
impl Report {
    pub fn outcomes(&self) -> ProbeOutcomes {
        ProbeOutcomes {
            ip: https_outcome(self.ip.value),
            dns: match self.dns.value {
                DnsResult::ValidatedA(n) if n > 0 => ProbeOutcome::Passed,
                DnsResult::ValidatedA(_) | DnsResult::Rejected => ProbeOutcome::Rejected,
                DnsResult::Cancelled => ProbeOutcome::Cancelled,
                DnsResult::Timeout => ProbeOutcome::Timeout,
                DnsResult::Unavailable => ProbeOutcome::Unavailable,
            },
            hostname: self
                .hostname
                .as_ref()
                .map_or(ProbeOutcome::NotRunDnsFailed, |m| https_outcome(m.value)),
        }
    }
    pub fn started(&self) -> Instant {
        self.started
    }
    pub fn finished(&self) -> Instant {
        self.finished
    }
    pub fn ip(&self) -> &Measurement<HttpsResult> {
        &self.ip
    }
    pub fn dns(&self) -> &Measurement<DnsResult> {
        &self.dns
    }
    pub fn hostname(&self) -> Option<&Measurement<HttpsResult>> {
        self.hostname.as_ref()
    }
    /// No early observation is refreshed by the later completion of the batch.
    /// Expiry is local stale evidence, never a newly measured relay failure.
    pub fn fresh_canary(&self, now: Instant) -> Result<Canary, BatchError> {
        if now < self.finished {
            return Err(BatchError::Stale);
        }
        let ttl = Duration::from_millis(adapter_domain::PROBE_TTL_MS);
        for completed in [
            Some(self.ip.completed),
            Some(self.dns.completed),
            self.hostname.as_ref().map(|m| m.completed),
        ]
        .into_iter()
        .flatten()
        {
            if completed > now || now.duration_since(completed) > ttl {
                return Err(BatchError::Stale);
            }
        }
        Ok(Canary {
            ip: matches!(self.ip.value, HttpsResult::Passed(_)),
            dns: matches!(self.dns.value, DnsResult::ValidatedA(n) if n > 0),
            https: self
                .hostname
                .as_ref()
                .is_some_and(|m| matches!(m.value, HttpsResult::Passed(_))),
        })
    }
}
impl adapter_control::candidate_evidence::MeasuredEvidence for Report {
    fn oldest_observation(&self) -> Instant {
        let oldest = self.ip.completed.min(self.dns.completed);
        self.hostname
            .as_ref()
            .map_or(oldest, |m| oldest.min(m.completed))
    }
}
impl adapter_control::candidate_evidence::ReadinessEvidence for Report {
    fn fresh_canary(&self) -> Option<Canary> {
        self.fresh_canary(Instant::now()).ok()
    }
}
trait Driver: Sync {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn ip(&self) -> HttpsResult;
    fn dns(&self) -> DnsResult;
    fn hostname(&self) -> HttpsResult;
    fn cancelled(&self) -> bool;
    fn abort(&self);
}
fn measured<T>(
    driver: &impl Driver,
    probe: impl FnOnce() -> T,
) -> Result<Measurement<T>, BatchError> {
    if driver.cancelled() {
        return Err(BatchError::Cancelled);
    }
    match catch_unwind(AssertUnwindSafe(probe)) {
        Ok(value) => Ok(Measurement {
            value,
            completed: driver.now(),
        }),
        Err(_) => {
            driver.abort();
            Err(BatchError::LocalFailure)
        }
    }
}
fn collect(driver: &impl Driver) -> Result<Report, BatchError> {
    if driver.cancelled() {
        return Err(BatchError::Cancelled);
    }
    let started = driver.now();
    let report = std::thread::scope(|scope| {
        let ip = std::thread::Builder::new()
            .name("canary-ip".into())
            .spawn_scoped(scope, || measured(driver, || driver.ip()))
            .map_err(|_| BatchError::LocalFailure)?;
        let dns = match std::thread::Builder::new()
            .name("canary-dns".into())
            .spawn_scoped(scope, || measured(driver, || driver.dns()))
        {
            Ok(thread) => thread,
            Err(_) => {
                driver.abort();
                let _ = ip.join();
                return Err(BatchError::LocalFailure);
            }
        };
        // Join DNS first so hostname can overlap an in-flight IP probe, but never
        // run a hostname query after a failed inner-DNS dependency.
        let dns = dns.join().unwrap_or_else(|_| {
            driver.abort();
            Err(BatchError::LocalFailure)
        });
        let hostname = match &dns {
            Ok(m) if matches!(m.value,DnsResult::ValidatedA(n) if n > 0) && !driver.cancelled() => {
                measured(driver, || driver.hostname()).map(Some)
            }
            _ => Ok(None),
        };
        let ip = ip.join().unwrap_or_else(|_| {
            driver.abort();
            Err(BatchError::LocalFailure)
        });
        if matches!(ip, Err(BatchError::LocalFailure))
            || matches!(dns, Err(BatchError::LocalFailure))
            || matches!(hostname, Err(BatchError::LocalFailure))
        {
            return Err(BatchError::LocalFailure);
        }
        // All threads and their sockets are gone before any result leaves scope.
        Ok(Report {
            started,
            finished: driver.now(),
            ip: ip?,
            dns: dns?,
            hostname: hostname?,
        })
    });
    let report = refresh_early_phases(driver, report?, driver.now())?;
    if driver.cancelled()
        || matches!(report.ip.value, HttpsResult::Cancelled)
        || matches!(report.dns.value, DnsResult::Cancelled)
        || report
            .hostname
            .as_ref()
            .is_some_and(|m| m.value == HttpsResult::Cancelled)
    {
        return Err(BatchError::Cancelled);
    }
    Ok(report)
}

/// A slow successful hostname probe can outlive the earlier IP/DNS evidence.
/// Take at most one additional sample of those expired phases on this SAME
/// owned worker. Never refresh a timestamp without performing its probe, change
/// the shared TTL, or loop until a path appears healthy. Production drivers
/// retain their IP/DNS deadlines and the enclosing operation cancellation.
fn refresh_early_phases(
    driver: &impl Driver,
    mut report: Report,
    now: Instant,
) -> Result<Report, BatchError> {
    let ttl = Duration::from_millis(adapter_domain::PROBE_TTL_MS);
    let expired = |at: Instant| now.checked_duration_since(at).is_some_and(|age| age > ttl);
    if !report.hostname.as_ref().is_some_and(|host| {
        matches!(host.value, HttpsResult::Passed(_))
            && host.completed <= now
            && !expired(host.completed)
    }) {
        return Ok(report);
    }
    let ip = expired(report.ip.completed);
    let dns = expired(report.dns.completed);
    if !ip && !dns {
        return Ok(report);
    }
    if driver.cancelled() {
        return Err(BatchError::Cancelled);
    }
    std::thread::scope(|scope| {
        let ip_worker = if ip {
            Some(
                std::thread::Builder::new()
                    .name("canary-ip-refresh".into())
                    .spawn_scoped(scope, || measured(driver, || driver.ip()))
                    .map_err(|_| BatchError::LocalFailure)?,
            )
        } else {
            None
        };
        let dns_result = if dns {
            Some(measured(driver, || driver.dns()))
        } else {
            None
        };
        let ip_result = ip_worker.map(|thread| {
            thread.join().unwrap_or_else(|_| {
                driver.abort();
                Err(BatchError::LocalFailure)
            })
        });
        // All started work is joined before returning cancellation/failure.
        if let Some(value) = ip_result {
            report.ip = value?;
        }
        if let Some(value) = dns_result {
            report.dns = value?;
        }
        Ok::<(), BatchError>(())
    })?;
    report.finished = driver.now();
    // A new DNS observation is independent evidence; it did not bootstrap the
    // earlier HTTPS transaction. Failed fresh DNS cannot retain a ready result.
    if dns && !matches!(report.dns.value, DnsResult::ValidatedA(n) if n > 0) {
        report.hostname = None;
    }
    Ok(report)
}

#[cfg(any(windows, feature = "windows-api-check"))]
pub(crate) fn for_worker(
    process: &adapter_platform::windows_process::OwnedProcess,
    network: &adapter_control::owned_lifecycle::BoundNetwork,
    port: u16,
) -> Result<Report, BatchError> {
    use adapter_platform::windows_controller_owner::ControllerOwner;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    struct OwnedDriver {
        owner: Arc<ControllerOwner>,
        monitor: adapter_control::owned_lifecycle::BoundCancellation,
        abort: Arc<AtomicBool>,
        wrong_owner: Arc<AtomicBool>,
        port: u16,
    }
    impl OwnedDriver {
        fn https(&self, target: crate::https_probe::Target) -> HttpsResult {
            let owner = self.owner.clone();
            let wrong_owner = self.wrong_owner.clone();
            let cancel_wrong_owner = self.wrong_owner.clone();
            let monitor = self.monitor.clone();
            let abort = self.abort.clone();
            crate::https_probe::run(
                self.port,
                target,
                Arc::new(move |s| {
                    let result = owner.verify_connected(s);
                    if result.is_err() {
                        wrong_owner.store(true, Ordering::Release);
                    }
                    result
                }),
                Arc::new(move || {
                    abort.load(Ordering::Acquire)
                        || cancel_wrong_owner.load(Ordering::Acquire)
                        || monitor.is_cancelled()
                }),
                crate::https_probe::verified_tls(),
                target.budget(),
                || self.owner.is_alive(),
            )
        }
    }
    impl Driver for OwnedDriver {
        fn ip(&self) -> HttpsResult {
            self.https(crate::https_probe::Target::Ip)
        }
        fn dns(&self) -> DnsResult {
            crate::dns_transport::run(
                self.port,
                |s| {
                    let result = self.owner.verify_connected(s);
                    if result.is_err() {
                        self.wrong_owner.store(true, Ordering::Release);
                    }
                    result
                },
                || self.cancelled(),
                || self.owner.is_alive(),
            )
        }
        fn hostname(&self) -> HttpsResult {
            self.https(crate::https_probe::Target::Hostname)
        }
        fn cancelled(&self) -> bool {
            self.abort.load(Ordering::Acquire)
                || self.wrong_owner.load(Ordering::Acquire)
                || self.monitor.is_cancelled()
        }
        fn abort(&self) {
            self.abort.store(true, Ordering::Release);
        }
    }
    if port < 1024 {
        return Err(BatchError::LocalFailure);
    }
    let driver = OwnedDriver {
        owner: Arc::new(
            process
                .controller_owner()
                .map_err(|_| BatchError::LocalFailure)?,
        ),
        monitor: network.cancellation_monitor(),
        abort: Arc::new(AtomicBool::new(false)),
        wrong_owner: Arc::new(AtomicBool::new(false)),
        port,
    };
    let result = collect(&driver);
    let live = driver.owner.is_alive();
    if network.is_cancelled() {
        return Err(BatchError::Cancelled);
    }
    if driver.wrong_owner.load(Ordering::Acquire) || !live {
        return Err(BatchError::LocalFailure);
    }
    result.and_then(|report| {
        report.fresh_canary(Instant::now())?;
        Ok(report)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn slow_hostname_report(now: Instant) -> Report {
        let early = now - Duration::from_secs(6);
        Report {
            started: early,
            finished: now,
            ip: Measurement {
                value: HttpsResult::Passed(200),
                completed: early,
            },
            dns: Measurement {
                value: DnsResult::ValidatedA(1),
                completed: early,
            },
            hostname: Some(Measurement {
                value: HttpsResult::Passed(204),
                completed: now,
            }),
        }
    }
    #[test]
    fn slow_successful_hostname_remeasures_expired_phases_without_relaxing_ttl() {
        let now = Instant::now();
        let before = slow_hostname_report(now);
        assert_eq!(before.fresh_canary(now), Err(BatchError::Stale));
        let ip_calls = Arc::new(AtomicUsize::new(0));
        let dns_calls = Arc::new(AtomicUsize::new(0));
        let (ip, dns) = (ip_calls.clone(), dns_calls.clone());
        let fake = Fake::new(
            move || {
                ip.fetch_add(1, Ordering::SeqCst);
                HttpsResult::Passed(200)
            },
            move || {
                dns.fetch_add(1, Ordering::SeqCst);
                DnsResult::ValidatedA(1)
            },
            || panic!("hostname already freshly passed"),
        );
        let refreshed = refresh_early_phases(&fake, before, now).unwrap();
        assert_eq!(
            (
                ip_calls.load(Ordering::SeqCst),
                dns_calls.load(Ordering::SeqCst)
            ),
            (1, 1)
        );
        assert!(refreshed.ip.completed >= now && refreshed.dns.completed >= now);
        assert_eq!(refreshed.hostname.as_ref().unwrap().completed, now);
        assert_eq!(
            refreshed.fresh_canary(Instant::now()).unwrap().readiness(),
            adapter_domain::Readiness::Ready
        );
        // The unchanged 5s gate still rejects this exact report later.
        assert_eq!(
            refreshed.fresh_canary(
                refreshed.finished() + Duration::from_millis(adapter_domain::PROBE_TTL_MS + 1)
            ),
            Err(BatchError::Stale)
        );
    }
    #[test]
    fn fresh_dns_failure_after_slow_hostname_cannot_reuse_old_dns_success() {
        let now = Instant::now();
        let fake = Fake::new(
            || HttpsResult::Passed(200),
            || DnsResult::Timeout,
            || panic!("no replay"),
        );
        let report = refresh_early_phases(&fake, slow_hostname_report(now), now).unwrap();
        assert!(report.hostname.is_none());
        assert_eq!(
            report.fresh_canary(Instant::now()).unwrap(),
            Canary {
                ip: true,
                dns: false,
                https: false
            }
        );
        assert_eq!(report.outcomes().dns, ProbeOutcome::Timeout);
    }
    #[test]
    fn one_refresh_wave_can_still_be_stale_and_never_loops_or_relabels_it_as_failure() {
        struct Late {
            inner: Fake,
            at: Instant,
        }
        impl Driver for Late {
            fn now(&self) -> Instant {
                self.at
            }
            fn ip(&self) -> HttpsResult {
                self.inner.ip()
            }
            fn dns(&self) -> DnsResult {
                self.inner.dns()
            }
            fn hostname(&self) -> HttpsResult {
                panic!("bounded refresh only")
            }
            fn cancelled(&self) -> bool {
                self.inner.cancelled()
            }
            fn abort(&self) {
                self.inner.abort()
            }
        }
        let now = Instant::now();
        let driver = Late {
            inner: Fake::new(
                || HttpsResult::Passed(200),
                || DnsResult::ValidatedA(1),
                || panic!("no replay"),
            ),
            at: now + Duration::from_secs(6),
        };
        let report = refresh_early_phases(&driver, slow_hostname_report(now), now).unwrap();
        assert_eq!(report.fresh_canary(driver.at), Err(BatchError::Stale));
        assert_eq!(report.hostname.as_ref().unwrap().completed, now);
        assert_eq!(
            report.outcomes(),
            ProbeOutcomes {
                ip: ProbeOutcome::Passed,
                dns: ProbeOutcome::Passed,
                hostname: ProbeOutcome::Passed
            }
        );
    }
    #[test]
    fn selection_adapter_uses_existing_full_readiness_matrix() {
        use adapter_control::candidate_evidence::ReadinessEvidence;
        for ip in [false, true] {
            for dns in [false, true] {
                for https in [false, true] {
                    let at = Instant::now();
                    let report = Report {
                        started: at,
                        finished: at,
                        ip: Measurement {
                            value: if ip {
                                HttpsResult::Passed(200)
                            } else {
                                HttpsResult::Rejected
                            },
                            completed: at,
                        },
                        dns: Measurement {
                            value: if dns {
                                DnsResult::ValidatedA(1)
                            } else {
                                DnsResult::Rejected
                            },
                            completed: at,
                        },
                        hostname: if dns {
                            Some(Measurement {
                                value: if https {
                                    HttpsResult::Passed(200)
                                } else {
                                    HttpsResult::Rejected
                                },
                                completed: at,
                            })
                        } else {
                            None
                        },
                    };
                    assert_eq!(
                        ReadinessEvidence::fresh_canary(&report),
                        Some(Canary {
                            ip,
                            dns,
                            https: dns && https
                        })
                    );
                }
            }
        }
    }
    #[test]
    fn selection_adapter_rejects_oldest_phase_and_future_completion() {
        use adapter_control::candidate_evidence::ReadinessEvidence;
        let at = Instant::now();
        for phase in 0..3 {
            let invalid = if phase == 2 {
                at + Duration::from_secs(1)
            } else {
                at - Duration::from_secs(6)
            };
            let report = Report {
                started: at - Duration::from_secs(6),
                finished: at,
                ip: Measurement {
                    value: HttpsResult::Passed(200),
                    completed: if phase == 0 { invalid } else { at },
                },
                dns: Measurement {
                    value: DnsResult::ValidatedA(1),
                    completed: if phase == 1 { invalid } else { at },
                },
                hostname: Some(Measurement {
                    value: HttpsResult::Passed(200),
                    completed: if phase == 2 { invalid } else { at },
                }),
            };
            assert_eq!(ReadinessEvidence::fresh_canary(&report), None);
        }
    }
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Condvar, Mutex,
    };
    struct Gate {
        count: Mutex<usize>,
        wake: Condvar,
        goal: usize,
    }
    impl Gate {
        fn new(goal: usize) -> Self {
            Self {
                count: Mutex::new(0),
                wake: Condvar::new(),
                goal,
            }
        }
        fn wait(&self) {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut count = self.count.lock().unwrap();
            *count += 1;
            self.wake.notify_all();
            while *count < self.goal {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .expect("test gate deadline");
                let (next, timeout) = self.wake.wait_timeout(count, remaining).unwrap();
                count = next;
                assert!(
                    !timeout.timed_out() || *count >= self.goal,
                    "test gate deadline"
                );
            }
        }
    }
    struct Fake {
        cancel: AtomicBool,
        active: AtomicUsize,
        calls: AtomicUsize,
        ip: Box<dyn Fn() -> HttpsResult + Send + Sync>,
        dns: Box<dyn Fn() -> DnsResult + Send + Sync>,
        hostname: Box<dyn Fn() -> HttpsResult + Send + Sync>,
    }
    struct Active<'a>(&'a AtomicUsize);
    impl Drop for Active<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    impl Fake {
        fn enter(&self) -> Active<'_> {
            self.active.fetch_add(1, Ordering::SeqCst);
            Active(&self.active)
        }
        fn new(
            ip: impl Fn() -> HttpsResult + Send + Sync + 'static,
            dns: impl Fn() -> DnsResult + Send + Sync + 'static,
            hostname: impl Fn() -> HttpsResult + Send + Sync + 'static,
        ) -> Self {
            Self {
                cancel: AtomicBool::new(false),
                active: AtomicUsize::new(0),
                calls: AtomicUsize::new(0),
                ip: Box::new(ip),
                dns: Box::new(dns),
                hostname: Box::new(hostname),
            }
        }
    }
    impl Driver for Fake {
        fn ip(&self) -> HttpsResult {
            let _guard = self.enter();
            (self.ip)()
        }
        fn dns(&self) -> DnsResult {
            let _guard = self.enter();
            (self.dns)()
        }
        fn hostname(&self) -> HttpsResult {
            let _guard = self.enter();
            self.calls.fetch_add(1, Ordering::SeqCst);
            (self.hostname)()
        }
        fn cancelled(&self) -> bool {
            self.cancel.load(Ordering::Acquire)
        }
        fn abort(&self) {
            self.cancel.store(true, Ordering::Release);
        }
    }
    #[test]
    fn dns_and_ip_overlap_and_hostname_waits_only_for_dns() {
        let simultaneous = Arc::new(Gate::new(2));
        let host = Arc::new(Gate::new(2));
        let (a, b, c) = (simultaneous.clone(), simultaneous.clone(), host.clone());
        let fake = Fake::new(
            move || {
                a.wait();
                c.wait();
                HttpsResult::Passed(200)
            },
            move || {
                b.wait();
                DnsResult::ValidatedA(1)
            },
            move || {
                host.wait();
                HttpsResult::Passed(204)
            },
        );
        let report = collect(&fake).unwrap();
        assert_eq!(fake.active.load(Ordering::SeqCst), 0);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            report.fresh_canary(Instant::now()).unwrap(),
            Canary {
                ip: true,
                dns: true,
                https: true
            }
        );
    }
    #[test]
    fn failed_dns_skips_hostname_but_preserves_ip_degraded_evidence() {
        for ip in [false, true] {
            let fake = Fake::new(
                move || {
                    if ip {
                        HttpsResult::Passed(200)
                    } else {
                        HttpsResult::Rejected
                    }
                },
                || DnsResult::Rejected,
                || panic!("hostname dependency failed"),
            );
            let report = collect(&fake).unwrap();
            assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
            assert!(report.hostname().is_none());
            let canary = report.fresh_canary(Instant::now()).unwrap();
            assert_eq!(
                canary,
                Canary {
                    ip,
                    dns: false,
                    https: false
                }
            );
            assert_eq!(
                canary.readiness(),
                if ip {
                    adapter_domain::Readiness::DegradedDns
                } else {
                    adapter_domain::Readiness::DataFail
                }
            );
        }
    }
    #[test]
    fn diagnostics_separate_dns_timeout_unavailable_and_skipped_https() {
        for (dns, expected) in [
            (DnsResult::Timeout, "timeout"),
            (DnsResult::Unavailable, "unavailable"),
            (DnsResult::ValidatedA(0), "rejected"),
        ] {
            let fake = Fake::new(
                || HttpsResult::Rejected,
                move || dns,
                || panic!("DNS dependency did not pass"),
            );
            let report = collect(&fake).unwrap();
            let public = serde_json::to_value(report.outcomes()).unwrap();
            assert_eq!(
                public,
                serde_json::json!({"ip":"rejected","dns":expected,"hostname":"not_run_dns_failed"})
            );
            assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                report.fresh_canary(Instant::now()).unwrap().readiness(),
                adapter_domain::Readiness::DataFail
            );
        }
    }
    #[test]
    fn failed_ip_with_dns_and_hostname_still_uses_existing_ready_matrix() {
        let fake = Fake::new(
            || HttpsResult::Rejected,
            || DnsResult::ValidatedA(1),
            || HttpsResult::Passed(204),
        );
        let canary = collect(&fake)
            .unwrap()
            .fresh_canary(Instant::now())
            .unwrap();
        assert!(!canary.ip);
        assert_eq!(canary.readiness(), adapter_domain::Readiness::Ready);
    }
    #[test]
    fn cancellation_waits_for_started_threads_and_rejects_late_success() {
        let entered = Arc::new(Gate::new(3));
        let release = Arc::new(Gate::new(3));
        let (a, b, c, d) = (
            entered.clone(),
            entered.clone(),
            release.clone(),
            release.clone(),
        );
        let fake = Arc::new(Fake::new(
            move || {
                a.wait();
                c.wait();
                HttpsResult::Passed(200)
            },
            move || {
                b.wait();
                d.wait();
                DnsResult::ValidatedA(1)
            },
            || panic!("cancelled hostname"),
        ));
        let worker = fake.clone();
        let thread = std::thread::spawn(move || collect(worker.as_ref()));
        entered.wait();
        fake.abort();
        assert_eq!(fake.active.load(Ordering::SeqCst), 2);
        assert!(!thread.is_finished());
        release.wait();
        assert!(matches!(thread.join().unwrap(), Err(BatchError::Cancelled)));
        assert_eq!(fake.active.load(Ordering::SeqCst), 0);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn panic_is_local_failure_and_all_siblings_finish() {
        let fake = Fake::new(
            || HttpsResult::Rejected,
            || panic!("injected probe panic"),
            || panic!("no hostname after local error"),
        );
        assert!(matches!(collect(&fake), Err(BatchError::LocalFailure)));
        assert_eq!(fake.active.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn each_phase_keeps_its_own_age_at_ttl_boundary() {
        let start = Instant::now();
        let end = start + Duration::from_secs(4);
        let report = Report {
            started: start,
            finished: end,
            ip: Measurement {
                value: HttpsResult::Passed(200),
                completed: start,
            },
            dns: Measurement {
                value: DnsResult::ValidatedA(1),
                completed: start,
            },
            hostname: Some(Measurement {
                value: HttpsResult::Passed(204),
                completed: end,
            }),
        };
        assert!(report.fresh_canary(start + Duration::from_secs(5)).is_ok());
        assert_eq!(
            report.fresh_canary(start + Duration::from_millis(5001)),
            Err(BatchError::Stale)
        );
        assert_eq!(
            report.fresh_canary(start + Duration::from_secs(3)),
            Err(BatchError::Stale)
        );
    }
    #[test]
    fn cancellation_status_is_not_a_negative_relay_measurement() {
        let fake = Fake::new(
            || HttpsResult::Cancelled,
            || DnsResult::Rejected,
            || panic!("DNS dependency failed"),
        );
        assert!(matches!(collect(&fake), Err(BatchError::Cancelled)));
        let fake = Fake::new(
            || panic!("must not start"),
            || panic!("must not start"),
            || panic!("must not start"),
        );
        fake.abort();
        assert!(matches!(collect(&fake), Err(BatchError::Cancelled)));
        assert_eq!(fake.active.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn ip_panic_stays_local_even_if_it_cancels_dns_before_start() {
        let fake = Fake::new(
            || panic!("injected IP panic"),
            || DnsResult::Cancelled,
            || panic!("must skip hostname"),
        );
        assert!(matches!(collect(&fake), Err(BatchError::LocalFailure)));
        assert_eq!(fake.active.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn review_all_dns_dependency_refusals_skip_hostname() {
        for dns in [
            DnsResult::ValidatedA(0),
            DnsResult::Rejected,
            DnsResult::Timeout,
            DnsResult::Unavailable,
            DnsResult::Cancelled,
        ] {
            let fake = Fake::new(
                || HttpsResult::Passed(200),
                move || dns,
                || panic!("hostname must be gated"),
            );
            let result = collect(&fake);
            assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
            assert_eq!(fake.active.load(Ordering::SeqCst), 0);
            if dns == DnsResult::Cancelled {
                assert!(matches!(result, Err(BatchError::Cancelled)));
            } else {
                assert_eq!(
                    result
                        .unwrap()
                        .fresh_canary(Instant::now())
                        .unwrap()
                        .readiness(),
                    adapter_domain::Readiness::DegradedDns
                );
            }
        }
    }
    #[test]
    fn review_hostname_panic_joins_inflight_ip() {
        let gate = Arc::new(Gate::new(2));
        let ip_gate = gate.clone();
        let fake = Fake::new(
            move || {
                ip_gate.wait();
                HttpsResult::Passed(200)
            },
            || DnsResult::ValidatedA(1),
            move || {
                gate.wait();
                panic!("hostname local failure")
            },
        );
        assert!(matches!(collect(&fake), Err(BatchError::LocalFailure)));
        assert_eq!(fake.active.load(Ordering::SeqCst), 0);
        assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn review_every_phase_ttl_and_future_boundary() {
        let now = Instant::now() + Duration::from_secs(10);
        for phase in 0..3 {
            for (age, valid) in [
                (Duration::from_secs(5), true),
                (Duration::from_secs(5) + Duration::from_nanos(1), false),
            ] {
                let mut report = Report {
                    started: now - Duration::from_secs(10),
                    finished: now,
                    ip: Measurement {
                        value: HttpsResult::Passed(200),
                        completed: now,
                    },
                    dns: Measurement {
                        value: DnsResult::ValidatedA(1),
                        completed: now,
                    },
                    hostname: Some(Measurement {
                        value: HttpsResult::Passed(204),
                        completed: now,
                    }),
                };
                match phase {
                    0 => report.ip.completed = now - age,
                    1 => report.dns.completed = now - age,
                    _ => report.hostname.as_mut().unwrap().completed = now - age,
                }
                assert_eq!(report.fresh_canary(now).is_ok(), valid);
                match phase {
                    0 => report.ip.completed = now + Duration::from_nanos(1),
                    1 => report.dns.completed = now + Duration::from_nanos(1),
                    _ => {
                        report.hostname.as_mut().unwrap().completed = now + Duration::from_nanos(1)
                    }
                }
                assert_eq!(report.fresh_canary(now), Err(BatchError::Stale));
            }
        }
    }
    #[test]
    fn review_all_feasible_matrix_results_and_completion_order() {
        for ip_ok in [false, true] {
            for dns_ok in [false, true] {
                for host_ok in [false, true] {
                    let fake = Fake::new(
                        move || {
                            if ip_ok {
                                HttpsResult::Passed(200)
                            } else {
                                HttpsResult::Rejected
                            }
                        },
                        move || {
                            if dns_ok {
                                DnsResult::ValidatedA(1)
                            } else {
                                DnsResult::Rejected
                            }
                        },
                        move || {
                            if host_ok {
                                HttpsResult::Passed(204)
                            } else {
                                HttpsResult::Rejected
                            }
                        },
                    );
                    let report = collect(&fake).unwrap();
                    assert!(
                        report.ip.completed >= report.started
                            && report.ip.completed <= report.finished
                    );
                    assert!(
                        report.dns.completed >= report.started
                            && report.dns.completed <= report.finished
                    );
                    if let Some(host) = report.hostname() {
                        assert!(
                            host.completed >= report.dns.completed
                                && host.completed <= report.finished
                        );
                    }
                    assert_eq!(
                        report.fresh_canary(Instant::now()).unwrap(),
                        Canary {
                            ip: ip_ok,
                            dns: dns_ok,
                            https: dns_ok && host_ok
                        }
                    );
                }
            }
        }
    }
}
