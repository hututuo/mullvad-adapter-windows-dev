//! Blocking front-only lifecycle. Run on an I/O worker, never the domain owner.
use crate::{
    controller::{Controller, ControllerError, Selected},
    front, Listener,
};
use adapter_platform::{windows_process::OwnedProcess, windows_runtime::PrivateRuntime};
use std::{
    net::{Ipv4Addr, SocketAddrV4, TcpStream},
    path::Path,
    time::{Duration, Instant},
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartError {
    InvalidInput,
    Cancelled,
    Unavailable,
    WrongMixedOwner,
    ControllerContract,
    Deadline,
    Cleanup,
}
/// Checkpoints are called on the I/O worker. They may request cancellation but
/// must not perform unbounded work; Ready still precedes the final acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartPhase {
    BeforeInput,
    BeforeSpawn,
    Starting,
    Ready,
}
pub struct Front {
    process: OwnedProcess,
    controller: Controller,
}
impl Front {
    /// Caller verifies the packaged executable/hash and trusted runtime ancestors.
    /// Starts only a REJECT front: no worker, tunnel, DNS or route mutation.
    pub fn start(
        executable: &Path,
        runtime: &PrivateRuntime,
        listener: &Listener<'_>,
        slot_a: u16,
        slot_b: u16,
        cancelled: impl Fn() -> bool,
    ) -> Result<Self, StartError> {
        Self::start_with_checkpoint(executable, runtime, listener, slot_a, slot_b, |_| {
            cancelled()
        })
    }
    pub fn start_with_checkpoint(
        executable: &Path,
        runtime: &PrivateRuntime,
        listener: &Listener<'_>,
        slot_a: u16,
        slot_b: u16,
        cancelled: impl Fn(StartPhase) -> bool,
    ) -> Result<Self, StartError> {
        let deadline = Instant::now() + Duration::from_secs(15);
        let checkpoint = |phase| {
            if cancelled(phase) {
                Err(StartError::Cancelled)
            } else if Instant::now() >= deadline {
                Err(StartError::Deadline)
            } else {
                Ok(())
            }
        };
        checkpoint(StartPhase::BeforeInput)?;
        let config = front(listener, slot_a, slot_b).map_err(|_| StartError::InvalidInput)?;
        let input = runtime
            .prepare_input(config.expose())
            .map_err(|_| StartError::Unavailable)?;
        drop(config);
        checkpoint(StartPhase::BeforeSpawn)?;
        let directory = runtime.path().to_str().ok_or(StartError::InvalidInput)?;
        let process = OwnedProcess::spawn_with_secret_input(
            executable,
            &["-f".into(), "-".into(), "-d".into(), directory.into()],
            input,
        )
        .map_err(|_| StartError::Unavailable)?;
        let ready = (|| {
            let controller = Controller::for_process(
                &process,
                listener.controller_port,
                listener.controller_secret,
            )
            .map_err(|_| StartError::Unavailable)?;
            let owner = process
                .controller_owner()
                .map_err(|_| StartError::Unavailable)?;
            loop {
                checkpoint(StartPhase::Starting)?;
                if process
                    .wait(Duration::ZERO)
                    .map_err(|_| StartError::Unavailable)?
                    .is_some()
                {
                    return Err(StartError::Unavailable);
                }
                match controller.check_version() {
                    Ok(()) => {}
                    Err(ControllerError::Unavailable) => {
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                    Err(_) => return Err(StartError::ControllerContract),
                }
                checkpoint(StartPhase::Starting)?;
                match controller.selected() {
                    Ok(Selected::Reject) => {}
                    Err(ControllerError::Unavailable | ControllerError::UnexpectedResponse) => {
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                    _ => return Err(StartError::ControllerContract),
                }
                checkpoint(StartPhase::Starting)?;
                let stream = TcpStream::connect_timeout(
                    &SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.mixed_port).into(),
                    Duration::from_millis(500),
                );
                match stream.and_then(|stream| owner.verify_connected(&stream)) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                        return Err(StartError::WrongMixedOwner)
                    }
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                }
                checkpoint(StartPhase::Ready)?;
                return Ok(controller);
            }
        })();
        match ready {
            Ok(controller) => Ok(Self {
                process,
                controller,
            }),
            Err(error) => {
                if process.terminate(Duration::from_secs(5)).is_err() {
                    return Err(StartError::Cleanup);
                }
                Err(error)
            }
        }
    }
    pub fn controller(&self) -> &Controller {
        &self.controller
    }
    pub fn process(&self) -> &OwnedProcess {
        &self.process
    }
    pub fn stop(&self) -> std::io::Result<()> {
        self.process.terminate(Duration::from_secs(5))
    }
}
