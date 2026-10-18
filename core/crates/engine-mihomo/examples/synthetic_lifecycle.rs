//! CI-only front/REJECT fixture. Public synthetic capability, no VPN peers or routes.
#[cfg(not(any(windows, feature = "windows-api-check")))]
fn main() {
    eprintln!("Windows-only synthetic lifecycle fixture");
    std::process::exit(2);
}
#[cfg(any(windows, feature = "windows-api-check"))]
fn main() {
    use adapter_control::{
        observer::ObservedOwner,
        owned_lifecycle::{BuildOutcome, Event, Failure, Resource, ResourceOwner},
    };
    use adapter_domain::State;
    use adapter_engine_mihomo::{
        controller::{Controller, ControllerError, Selected},
        lifecycle::{Front, StartError, StartPhase},
        Listener,
    };
    use adapter_platform::{
        physical_attachment::{Attachment, Observation},
        windows::boot_id,
        windows_runtime::PrivateRuntime,
    };
    use std::{
        net::{Ipv4Addr, TcpListener},
        path::PathBuf,
        time::{Duration, Instant},
    };
    struct LiveFront(Front);
    impl Resource for LiveFront {
        fn check(&mut self) -> Result<(), Failure> {
            match self.0.process().wait(Duration::ZERO) {
                Ok(None) => Ok(()),
                _ => Err(Failure::Worker),
            }
        }
        fn stop(&mut self) -> Result<(), Failure> {
            self.0.stop().map_err(|_| Failure::Stop)?;
            assert_eq!(
                self.0.controller().check_version(),
                Err(ControllerError::Unavailable)
            );
            Ok(())
        }
    }
    // The Python gate downloads and verifies the exact official archive/hash and
    // version before invoking this fixture. This is not a production binary loader.
    let executable = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .expect("verified official binary path required"),
    );
    assert!(executable.is_absolute() && executable.is_file());
    let mode = std::env::args_os().nth(2);
    let conflict = mode.as_deref() == Some(std::ffi::OsStr::new("--occupy-mixed"));
    let late = mode.as_deref() == Some(std::ffi::OsStr::new("--cancel-before-ready"));
    let cancel_phase = match mode.as_deref().and_then(|m| m.to_str()) {
        Some("--cancel-before-input") => Some(StartPhase::BeforeInput),
        Some("--cancel-before-spawn") => Some(StartPhase::BeforeSpawn),
        Some("--cancel-after-spawn") => Some(StartPhase::Starting),
        Some("--cancel-ready-checkpoint") => Some(StartPhase::Ready),
        _ => None,
    };
    assert!(
        mode.is_none() || conflict || late || cancel_phase.is_some(),
        "unsupported synthetic mode"
    );
    assert!(std::env::args_os().count() <= 3);
    struct Temp(PathBuf);
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let temp =
        Temp(std::env::temp_dir().join(format!("adapter-real-front-{}", boot_id().unwrap())));
    std::fs::create_dir(&temp.0).unwrap();
    let runtime = PrivateRuntime::open(&temp.0.join("runtime")).unwrap();
    let mut listeners: Vec<_> = (0..4)
        .map(|_| TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
        .collect();
    let ports: Vec<_> = listeners
        .iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect();
    let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    // Release only immediately before launch; any collision fails closed through
    // pinned process ownership or startup failure, never authorizes another server.
    let _occupied_mixed = if conflict {
        Some(listeners.remove(0))
    } else {
        None
    };
    drop(listeners);
    let observation = ObservedOwner::new(State::new("real-front-fixture".into()), || Observation {
        attachment: Attachment::Unknown,
        bindings: vec![],
    })
    .unwrap();
    let mut owner = ResourceOwner::new(observation);
    let worker_runtime = runtime.clone();
    let (built_tx, built) = std::sync::mpsc::channel();
    let (release_tx, release) = std::sync::mpsc::channel();
    let id = owner
        .start_cancellable(move |cancel| {
            let result = Front::start_with_checkpoint(
                &executable,
                &worker_runtime,
                &Listener {
                    mixed_port: ports[0],
                    controller_port: ports[1],
                    controller_secret: secret,
                },
                ports[2],
                ports[3],
                |phase| {
                    if Some(phase) == cancel_phase {
                        let inputs = std::fs::read_dir(worker_runtime.path())
                            .unwrap()
                            .filter(|e| {
                                e.as_ref()
                                    .unwrap()
                                    .file_name()
                                    .to_string_lossy()
                                    .starts_with(".input-")
                            })
                            .count();
                        assert_eq!(inputs, usize::from(phase != StartPhase::BeforeInput));
                        built_tx.send(()).unwrap();
                        release.recv_timeout(Duration::from_secs(5)).unwrap();
                        assert!(cancel.is_cancelled());
                    }
                    cancel.is_cancelled()
                },
            );
            if cancel_phase.is_some() {
                assert!(
                    matches!(result, Err(StartError::Cancelled)),
                    "only positively cleaned cancellation permits reuse"
                );
                return Ok(BuildOutcome::CancelledClean);
            }
            if conflict {
                assert!(
                    matches!(result, Err(StartError::WrongMixedOwner)),
                    "occupied mixed must fail owned readiness"
                );
                return Err(Failure::Start);
            }
            let front = result.expect("official front startup");
            assert_eq!(front.controller().select(Selected::Reject), Ok(()));
            assert_eq!(front.controller().selected(), Ok(Selected::Reject));
            let wrong = Controller::for_process(
                front.process(),
                ports[1],
                "1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap();
            assert_eq!(wrong.check_version(), Err(ControllerError::Unauthorized));
            if late {
                built_tx.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            Ok(BuildOutcome::Ready(LiveFront(front)))
        })
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(40);
    let mut ready = false;
    let mut late_released = false;
    loop {
        assert!(Instant::now() < deadline, "front owner completion deadline");
        if (late || cancel_phase.is_some()) && !late_released && built.try_recv().is_ok() {
            owner.state_mut().generation += 1;
            // Apply invalidation before releasing a fully started real front.
            assert!(owner.poll().1.is_none());
            late_released = true;
            release_tx.send(()).unwrap();
        }
        match owner.poll().1 {
            Some(Event::Ready(actual)) => {
                assert!(!conflict && !late && cancel_phase.is_none() && !ready);
                assert_eq!(actual, id);
                ready = true;
                // Simulate manual preemption after real ready: generation change
                // invalidates this resource's owner token and requests worker stop.
                owner.state_mut().generation += 1;
            }
            Some(Event::Finished(actual, result)) => {
                assert_eq!(actual, id);
                if conflict {
                    assert_eq!(result, Err(Failure::Start));
                } else {
                    assert!(ready || late_released);
                    assert_eq!(result, Ok(()));
                }
                break;
            }
            None => std::thread::sleep(Duration::from_millis(1)),
        }
    }
    // Check after Finished and before any retry for every lifecycle mode.
    assert!(
        !std::fs::read_dir(runtime.path()).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".input-")),
        "private input must be gone before retry"
    );
    if cancel_phase.is_some() {
        assert!(
            !owner.busy(),
            "clean cancellation must release the owner slot"
        );
        // Re-enter the same owner; never construct a replacement to evade sticky failures.
        struct Noop;
        impl Resource for Noop {
            fn stop(&mut self) -> Result<(), Failure> {
                Ok(())
            }
        }
        let retry = owner.start(|_| Ok(Noop)).unwrap();
        let end = Instant::now() + Duration::from_secs(2);
        loop {
            assert!(Instant::now() < end);
            match owner.poll().1 {
                Some(Event::Ready(actual)) => {
                    assert_eq!(actual, retry);
                    owner.cancel();
                }
                Some(Event::Finished(actual, result)) => {
                    assert_eq!(actual, retry);
                    assert_eq!(result, Ok(()));
                    break;
                }
                None => std::thread::sleep(Duration::from_millis(1)),
            }
        }
    }
    drop(runtime);
    println!("Windows official front: controller/mixed ownership/readiness/auth/owner generation preemption/stop/input cleanup PASS (occupied mixed: {conflict}, cancellation checkpoint: {cancel_phase:?}); no tunnel or route acceptance");
}
