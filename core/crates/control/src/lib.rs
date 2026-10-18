//! Single-owner command coordinator. No engine is enabled by the mock agent.
pub mod candidate_evidence;
pub mod observer;
pub mod owned_lifecycle;

use adapter_protocol::{Command, Operation, Request, Response, Snapshot};
use std::collections::BTreeMap;
const MAX_OPERATIONS: usize = 128;
const OPERATION_TTL_MS: u64 = 600_000;
struct Cached {
    request: Request,
    operation: Operation,
    expires: u64,
}
pub struct MockControl {
    snapshot: Snapshot,
    operations: BTreeMap<String, Cached>,
    next_id: u64,
}
impl MockControl {
    pub fn new(boot: String) -> Self {
        Self {
            snapshot: Snapshot {
                sequence: 0,
                generation: 0,
                network_epoch: 0,
                boot_id: boot,
                mode: "mock_no_tunnel".into(),
                status: "unavailable_mock_backend".into(),
                selected_city: None,
                capabilities: vec!["mock_snapshots".into()],
            },
            operations: BTreeMap::new(),
            next_id: 0,
        }
    }
    pub fn handle(&mut self, request: Request, now: u64) -> Response {
        let error = |code: &str| Response::Error { code: code.into() };
        if let Err(code) = request.validate(&self.snapshot.boot_id) {
            return error(code);
        }
        self.operations.retain(|_, entry| entry.expires > now);
        if let Some(entry) = self.operations.get(&request.request_id) {
            return if entry.request == request {
                Response::Operation(entry.operation.clone())
            } else {
                error("request_id_conflict")
            };
        }
        match &request.command {
            Command::Snapshot => Response::Snapshot(self.snapshot.clone()),
            Command::Operation { operation_id } => self
                .operations
                .values()
                .find(|entry| &entry.operation.id == operation_id)
                .map_or_else(
                    || error("unknown_outcome_reconcile"),
                    |entry| Response::Operation(entry.operation.clone()),
                ),
            Command::SelectCity { .. } | Command::Stop => {
                if self.operations.len() >= MAX_OPERATIONS {
                    return error("operation_capacity");
                }
                self.next_id += 1;
                let operation = Operation {
                    id: format!("{}-{}", self.snapshot.boot_id, self.next_id),
                    boot_id: self.snapshot.boot_id.clone(),
                    request_id: request.request_id.clone(),
                    state: "failed".into(),
                    code: "unavailable_mock_backend".into(),
                };
                self.operations.insert(
                    request.request_id.clone(),
                    Cached {
                        request,
                        operation: operation.clone(),
                        expires: now.saturating_add(OPERATION_TTL_MS),
                    },
                );
                Response::Operation(operation)
            }
        }
    }
}

/// Bounded work handoff; lifecycle decisions remain on the caller/state-owner thread.
/// I/O jobs must enforce their own deadlines and output caps. Drop does not block on I/O.
pub struct Executor<T: Send + 'static> {
    jobs: std::sync::mpsc::SyncSender<Box<dyn FnOnce() -> T + Send>>,
    results: std::sync::mpsc::Receiver<T>,
}
impl<T: Send + 'static> Executor<T> {
    pub fn new(workers: usize, capacity: usize) -> Result<Self, &'static str> {
        if workers == 0 || workers > 8 || capacity == 0 || capacity > 64 {
            return Err("invalid_executor_bounds");
        }
        let (send, receive) =
            std::sync::mpsc::sync_channel::<Box<dyn FnOnce() -> T + Send>>(capacity);
        let receive = std::sync::Arc::new(std::sync::Mutex::new(receive));
        let (results_send, results) = std::sync::mpsc::sync_channel(capacity);
        for _ in 0..workers {
            let receive = receive.clone();
            let results_send = results_send.clone();
            std::thread::spawn(move || loop {
                let job = match receive.lock().unwrap().recv() {
                    Ok(job) => job,
                    Err(_) => return,
                };
                if results_send.send(job()).is_err() {
                    return;
                }
            });
        }
        Ok(Self {
            jobs: send,
            results,
        })
    }
    pub fn submit(&self, job: impl FnOnce() -> T + Send + 'static) -> Result<(), &'static str> {
        self.jobs
            .try_send(Box::new(job))
            .map_err(|_| "executor_busy")
    }
    pub fn try_result(&self) -> Option<T> {
        self.results.try_recv().ok()
    }
}
