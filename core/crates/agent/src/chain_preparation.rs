//! Cancellation and the durable chain commit have one ordering boundary.
use std::sync::Mutex;

#[derive(Default)]
pub(crate) struct PreparationFence(Mutex<Option<String>>);
impl PreparationFence {
    pub fn begin(&self, ticket: String) -> Result<(), &'static str> {
        *self.0.try_lock().map_err(|_| "operation_busy")? = Some(ticket);
        Ok(())
    }
    pub fn cancel(&self) -> Result<bool, &'static str> {
        Ok(self
            .0
            .try_lock()
            .map_err(|_| "operation_busy")?
            .take()
            .is_some())
    }
    pub fn commit<T>(
        &self,
        ticket: &str,
        write: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        let mut current = self.0.lock().map_err(|_| "operation_busy")?;
        if current.as_deref() != Some(ticket) {
            return Err("connection_cancelled");
        }
        let result = write();
        *current = None;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_after_qualification_rejects_late_write() {
        let fence = PreparationFence::default();
        fence.begin("old".into()).unwrap();
        assert!(fence.cancel().unwrap());
        assert_eq!(
            fence.commit("old", || panic!("cancelled write")),
            Err::<(), _>("connection_cancelled")
        );
        fence.begin("new".into()).unwrap();
        assert_eq!(
            fence.commit("old", || panic!("superseded write")),
            Err::<(), _>("connection_cancelled")
        );
        assert_eq!(fence.commit("new", || Ok(7)), Ok(7));
        assert_eq!(
            fence.commit("new", || panic!("replayed write")),
            Err::<(), _>("connection_cancelled")
        );
    }
    #[test]
    fn cancellation_does_not_acknowledge_before_an_existing_commit_finishes() {
        let fence = PreparationFence::default();
        fence.begin("commit".into()).unwrap();
        fence
            .commit("commit", || {
                assert_eq!(fence.cancel(), Err("operation_busy"));
                assert_eq!(fence.begin("new".into()), Err("operation_busy"));
                Ok(())
            })
            .unwrap();
        assert!(!fence.cancel().unwrap());
    }
    #[test]
    fn slow_commit_does_not_block_the_owner_and_cancelled_qualification_cannot_write() {
        use std::sync::{mpsc, Arc};
        let fence = Arc::new(PreparationFence::default());
        fence.begin("old".into()).unwrap();
        let worker = fence.clone();
        let (started, running) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let join = std::thread::spawn(move || {
            worker.commit("old", || {
                started.send(()).unwrap();
                resume.recv().unwrap();
                Ok(())
            })
        });
        running
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        assert_eq!(fence.cancel(), Err("operation_busy"));
        release.send(()).unwrap();
        join.join().unwrap().unwrap();
        fence.begin("qualified".into()).unwrap();
        assert!(fence.cancel().unwrap());
        let worker = fence.clone();
        assert_eq!(
            std::thread::spawn(move || worker.commit("qualified", || panic!("late commit")))
                .join()
                .unwrap(),
            Err::<(), _>("connection_cancelled")
        );
    }
}
