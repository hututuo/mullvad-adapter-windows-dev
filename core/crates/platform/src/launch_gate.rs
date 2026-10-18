//! Cancellable process-creation gate. OS CreateProcess itself is not cancellable.
use std::{
    io,
    sync::{Mutex, MutexGuard, TryLockError},
    time::Duration,
};
pub(crate) fn acquire<'a, T>(
    gate: &'a Mutex<T>,
    check: &mut impl FnMut() -> io::Result<()>,
) -> io::Result<MutexGuard<'a, T>> {
    loop {
        check()?;
        match gate.try_lock() {
            Ok(guard) => {
                check()?;
                return Ok(guard);
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(io::Error::other("process creation gate poisoned"))
            }
            Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expired_or_cancelled_waiter_returns_while_other_launcher_still_owns_gate() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            mpsc, Arc,
        };
        use std::time::Instant;
        for cancelled in [true, false] {
            let gate = Arc::new(Mutex::new(()));
            let guard = gate.lock().unwrap();
            let other = gate.clone();
            let cancel = Arc::new(AtomicBool::new(false));
            let c = cancel.clone();
            let deadline = Instant::now() + Duration::from_millis(120);
            let (tx, rx) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                let result = acquire(&other, &mut || {
                    if c.load(Ordering::Acquire) {
                        Err(io::ErrorKind::Interrupted.into())
                    } else if Instant::now() >= deadline {
                        Err(io::ErrorKind::TimedOut.into())
                    } else {
                        Ok(())
                    }
                });
                tx.send(result.err().map(|e| e.kind())).unwrap();
            });
            if cancelled {
                cancel.store(true, Ordering::Release);
            }
            assert_eq!(
                rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                Some(if cancelled {
                    io::ErrorKind::Interrupted
                } else {
                    io::ErrorKind::TimedOut
                })
            );
            // Gate is deliberately still owned when the waiter has finished.
            drop(guard);
            worker.join().unwrap();
            assert!(gate.try_lock().is_ok());
        }
    }
    #[test]
    fn successful_acquisition_checks_again_inside_gate() {
        let gate = Mutex::new(());
        let mut calls = 0;
        let guard = acquire(&gate, &mut || {
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert!(gate.try_lock().is_err());
        drop(guard);
    }
}
