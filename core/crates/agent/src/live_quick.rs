//! City-scoped ICMP only. Four bounded lanes; no peer, engine or account access.
use adapter_control::owned_lifecycle::BoundNetwork;
use adapter_platform::windows_icmp::PingResult;
use std::{
    collections::VecDeque,
    net::Ipv4Addr,
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

pub const LANES: usize = 4;
pub const BUDGET: Duration = Duration::from_secs(45);
pub const MAX_CITY_RELAYS: usize = 256;
pub struct Target {
    pub hostname: String,
    pub address: Ipv4Addr,
}
pub enum Message {
    Observed {
        hostname: String,
        result: Result<PingResult, &'static str>,
        measured: Instant,
    },
    // Sent only after every started native call has returned. Cancellation must
    // not free the operation registry while one of those calls is still alive.
    Finished {
        unmeasured: usize,
    },
}
pub struct Run {
    pub receive: mpsc::Receiver<Message>,
}
impl Run {
    #[cfg(any(windows, feature = "windows-api-check"))]
    pub fn start(targets: Vec<Target>, network: BoundNetwork) -> std::io::Result<Self> {
        let network = Arc::new(network);
        let monitor = network.clone();
        spawn(targets, move || monitor.is_cancelled(), {
            let network = network.clone();
            move |target, cancel| {
                if cancel() {
                    return Err("icmp_cancelled");
                }
                let route = adapter_platform::egress::windows::snapshot(
                    network.binding(),
                    target.address.into(),
                )
                .map_err(|_| "icmp_route_unavailable")?;
                adapter_platform::windows_icmp::probe_v4(&route, cancel).map_err(|e| e.code())
            }
        })
    }
}
fn spawn(
    targets: Vec<Target>,
    cancel: impl Fn() -> bool + Send + Sync + 'static,
    probe: impl Fn(&Target, &dyn Fn() -> bool) -> Result<PingResult, &'static str>
        + Send
        + Sync
        + 'static,
) -> std::io::Result<Run> {
    if targets.is_empty() || targets.len() > MAX_CITY_RELAYS {
        return Err(std::io::Error::other("quick_targets_invalid"));
    }
    let (send, receive) = mpsc::sync_channel(8);
    thread::Builder::new()
        .name("city-icmp".into())
        .spawn(move || {
            let deadline = Instant::now() + BUDGET;
            let queue = Mutex::new(VecDeque::from(targets));
            let cancelled = || cancel() || Instant::now() >= deadline;
            thread::scope(|scope| {
                for _ in 0..LANES {
                    let send = &send;
                    let queue = &queue;
                    let cancelled = &cancelled;
                    let probe = &probe;
                    scope.spawn(move || loop {
                        if cancelled() {
                            break;
                        }
                        // Only pop under the lock. Never hold it during native I/O.
                        let target = queue.lock().ok().and_then(|mut q| q.pop_front());
                        let Some(target) = target else {
                            break;
                        };
                        let result = probe(&target, cancelled);
                        if send
                            .send(Message::Observed {
                                hostname: target.hostname,
                                result,
                                measured: Instant::now(),
                            })
                            .is_err()
                        {
                            break;
                        }
                    });
                }
            });
            let unmeasured = queue.lock().map_or(0, |q| q.len());
            let _ = send.send(Message::Finished { unmeasured });
        })?;
    Ok(Run { receive })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    fn targets(count: usize) -> Vec<Target> {
        (0..count)
            .map(|i| Target {
                hostname: format!("relay-{i}"),
                address: Ipv4Addr::new(203, 0, 113, 1),
            })
            .collect()
    }
    #[test]
    fn concurrency_is_bounded_and_completion_covers_all_native_calls() {
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let a = active.clone();
        let m = maximum.clone();
        let run = spawn(
            targets(12),
            || false,
            move |_, _| {
                let now = a.fetch_add(1, Ordering::SeqCst) + 1;
                m.fetch_max(now, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(15));
                a.fetch_sub(1, Ordering::SeqCst);
                Ok(PingResult::Reply { rtt_ms: 1 })
            },
        )
        .unwrap();
        let mut observed = 0;
        loop {
            match run.receive.recv_timeout(Duration::from_secs(2)).unwrap() {
                Message::Observed { .. } => observed += 1,
                Message::Finished { unmeasured } => {
                    assert_eq!(unmeasured, 0);
                    break;
                }
            }
        }
        assert_eq!(observed, 12);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!(maximum.load(Ordering::SeqCst) <= LANES);
        assert!(maximum.load(Ordering::SeqCst) > 1);
    }
    #[test]
    fn cancelled_queue_starts_no_probe_and_still_acknowledges_cleanup() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let run = spawn(
            targets(9),
            || true,
            move |_, _| {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(PingResult::NoReply { status: 11010 })
            },
        )
        .unwrap();
        assert!(matches!(
            run.receive.recv().unwrap(),
            Message::Finished { unmeasured: 9 }
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn cancellation_during_io_waits_for_calls_to_return() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let read = cancelled.clone();
        let (entered, starts) = mpsc::channel();
        let run = spawn(
            targets(32),
            move || read.load(Ordering::SeqCst),
            move |_, cancel| {
                entered.send(()).unwrap();
                while !cancel() {
                    thread::sleep(Duration::from_millis(1));
                }
                Err("icmp_cancelled")
            },
        )
        .unwrap();
        starts.recv_timeout(Duration::from_secs(1)).unwrap();
        cancelled.store(true, Ordering::SeqCst);
        let mut observed = 0;
        loop {
            match run.receive.recv_timeout(Duration::from_secs(1)).unwrap() {
                Message::Observed { result, .. } => {
                    assert_eq!(result, Err("icmp_cancelled"));
                    observed += 1;
                }
                Message::Finished { .. } => break,
            }
        }
        assert!(observed <= LANES);
    }
    #[test]
    fn cancellation_receipt_cannot_release_a_still_running_native_call() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let read = cancelled.clone();
        let native_return = release.clone();
        let (entered, started) = mpsc::channel();
        let run = spawn(
            targets(1),
            move || read.load(Ordering::SeqCst),
            move |_, cancel| {
                entered.send(()).unwrap();
                // Model an in-flight native call that cannot return at the
                // instant the connection request cancels background ICMP.
                while !native_return.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(1));
                }
                assert!(cancel());
                Err("icmp_cancelled")
            },
        )
        .unwrap();
        started.recv_timeout(Duration::from_secs(1)).unwrap();
        cancelled.store(true, Ordering::SeqCst);
        assert!(matches!(
            run.receive.recv_timeout(Duration::from_millis(30)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        release.store(true, Ordering::SeqCst);
        assert!(matches!(
            run.receive.recv_timeout(Duration::from_secs(1)).unwrap(),
            Message::Observed {
                result: Err("icmp_cancelled"),
                ..
            }
        ));
        assert!(matches!(
            run.receive.recv_timeout(Duration::from_secs(1)).unwrap(),
            Message::Finished { unmeasured: 0 }
        ));
    }
    #[test]
    fn empty_or_unbounded_jobs_are_rejected() {
        for count in [0, MAX_CITY_RELAYS + 1] {
            assert!(spawn(
                targets(count),
                || false,
                |_, _| Ok(PingResult::Reply { rtt_ms: 1 })
            )
            .is_err());
        }
    }
}
