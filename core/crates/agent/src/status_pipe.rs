//! Independent authenticated public-state IPC. No control queue or key access.
use adapter_platform::windows::{Identity, Pipe};
use adapter_protocol::{
    app::*, app_status::StatusPublication, read_frame, write_frame, ResponseAck,
};
use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

pub(crate) struct StatusServer {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl StatusServer {
    pub fn start(
        identity: &Identity,
        boot: String,
        publication: StatusPublication,
    ) -> io::Result<Self> {
        let identity = identity.status_channel();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = thread::Builder::new()
            .name("public-status-pipe".into())
            .spawn(move || {
                while !stopped.load(Ordering::Acquire) {
                    let Ok(mut pipe) = Pipe::accept(&identity, Duration::from_secs(1)) else {
                        // Permission/name failures can return immediately; never
                        // spin a CPU while the local listener is unavailable.
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    };
                    if stopped.load(Ordering::Acquire) {
                        break;
                    }
                    let hello = AppReply::Hello {
                        major: APP_API_MAJOR,
                        boot_id: boot.clone(),
                        build: env!("CARGO_PKG_VERSION").into(),
                        source_sha: option_env!("ADAPTER_SOURCE_SHA")
                            .unwrap_or("unknown")
                            .into(),
                    };
                    if write_frame(&mut pipe, &hello).is_err() {
                        continue;
                    }
                    let Ok(request) = read_frame::<AppRequest>(&mut pipe) else {
                        continue;
                    };
                    if publication
                        .respond(&request, &boot, Instant::now(), &mut pipe)
                        .is_ok()
                    {
                        let ack: io::Result<ResponseAck> = read_frame(&mut pipe);
                        if !matches!(ack, Ok(ref ack) if ack.request_id == request.request_id) {
                            continue;
                        }
                    }
                }
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
    #[cfg(test)]
    pub fn stop_for_test(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
impl Drop for StatusServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Dropping the handle detaches a bounded pipe wait. Owner shutdown must
        // not wait for an unresponsive status client or its five-second ACK.
        let _ = self.thread.take();
    }
}

#[cfg(test)]
#[path = "status_pipe_tests.rs"]
mod tests;
