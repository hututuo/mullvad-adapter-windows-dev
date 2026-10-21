//! Read-only observations cannot reserve or wait for the control lane.
use adapter_protocol::app::AppCommand;
use std::{
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

pub(crate) fn hello_error(error: &std::io::Error, status_read: bool) -> &'static str {
    if error.kind() == std::io::ErrorKind::InvalidData {
        "invalid_handshake"
    } else if status_read {
        "status_response_read_failed"
    } else {
        "backend_handshake_unavailable"
    }
}

pub(crate) struct BridgeLanes {
    control: Mutex<()>,
    status: Mutex<()>,
    pub startup: Mutex<Option<Instant>>,
}
impl BridgeLanes {
    pub const fn new() -> Self {
        Self {
            control: Mutex::new(()),
            status: Mutex::new(()),
            startup: Mutex::new(None),
        }
    }
    pub fn launch_due(last: Option<Instant>, now: Instant) -> bool {
        last.is_none_or(|at| now.saturating_duration_since(at) >= Duration::from_secs(5))
    }
    pub fn enter(&self, command: &AppCommand) -> Result<MutexGuard<'_, ()>, &'static str> {
        if matches!(command, AppCommand::Dashboard) {
            self.status.try_lock().map_err(|_| "status_read_busy")
        } else {
            self.control.try_lock().map_err(|_| "operation_busy")
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_missing_or_timed_out_hello_is_not_a_rejected_identity() {
        for kind in [
            std::io::ErrorKind::TimedOut,
            std::io::ErrorKind::UnexpectedEof,
            std::io::ErrorKind::BrokenPipe,
        ] {
            let error = std::io::Error::from(kind);
            assert_eq!(hello_error(&error, true), "status_response_read_failed");
            assert_eq!(hello_error(&error, false), "backend_handshake_unavailable");
        }
        let malformed = std::io::Error::from(std::io::ErrorKind::InvalidData);
        assert_eq!(hello_error(&malformed, true), "invalid_handshake");
        assert_eq!(hello_error(&malformed, false), "invalid_handshake");
    }
    #[test]
    fn startup_is_debounced_without_taking_a_control_or_status_lane() {
        let lanes = BridgeLanes::new();
        let now = Instant::now();
        let mut startup = lanes.startup.lock().unwrap();
        assert!(BridgeLanes::launch_due(*startup, now));
        *startup = Some(now);
        assert!(!BridgeLanes::launch_due(
            *startup,
            now + Duration::from_secs(4)
        ));
        assert!(BridgeLanes::launch_due(
            *startup,
            now + Duration::from_secs(5)
        ));
        assert!(lanes.enter(&AppCommand::Dashboard).is_ok());
        assert!(lanes.enter(&AppCommand::CancelOperation).is_ok());
    }
    #[test]
    fn control_busy_does_not_reject_status_and_status_busy_does_not_reject_control() {
        let lanes = BridgeLanes::new();
        let control = lanes.enter(&AppCommand::Connect).unwrap();
        assert!(lanes.enter(&AppCommand::Dashboard).is_ok());
        assert_eq!(
            lanes.enter(&AppCommand::Connect).unwrap_err(),
            "operation_busy"
        );
        drop(control);
        let _status = lanes.enter(&AppCommand::Dashboard).unwrap();
        assert!(lanes.enter(&AppCommand::CancelOperation).is_ok());
        assert_eq!(
            lanes.enter(&AppCommand::Dashboard).unwrap_err(),
            "status_read_busy"
        );
    }
}
