//! Candidate transactions inside the persistent front's I/O owner.
//! The state owner must fence the returned evidence before and after promotion.
use crate::{
    controller::Selected,
    lifecycle::Front,
    worker_lifecycle::{Assessment, BoundReport, UnreadyReport, Worker, WorkerRequest},
    Identity, Listener, Protection, Transport,
};
use adapter_control::owned_lifecycle::{BoundCancellation, BoundNetwork, Failure};
use adapter_platform::{
    storage_record::RecordKind, windows_runtime::PrivateRuntime, windows_store::PrivateStore,
};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::{mpsc, Arc},
};
use zeroize::Zeroizing;

pub struct TunnelSpec {
    pub instance: u64,
    pub runtime: PrivateRuntime,
    pub private_key: Zeroizing<String>,
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
    pub relay_public_key: String,
    pub transport: Transport,
    pub slot: Selected,
    pub mixed_port: u16,
    pub controller_port: u16,
    pub controller_secret: Zeroizing<String>,
    // Public last-path facts. Never used to restore traffic without a new probe.
    pub policy: Vec<u8>,
}
pub enum Command {
    Prepare {
        id: u64,
        spec: Box<TunnelSpec>,
        network: BoundNetwork,
    },
    Promote {
        id: u64,
        proof: Arc<BoundReport>,
    },
    Abort {
        id: u64,
    },
    Verify {
        id: u64,
        instance: u64,
        network: BoundNetwork,
    },
}
pub enum Reply {
    Prepared { id: u64, proof: Arc<BoundReport> },
    Promoted { id: u64, proof: Arc<BoundReport> },
    Verified { id: u64, proof: Arc<BoundReport> },
    Stopped { id: u64 },
    Unready { id: u64, proof: UnreadyReport },
    Lost { instance: u64 },
    Failed { id: u64, code: &'static str },
}
#[derive(Clone)]
pub struct Client(mpsc::SyncSender<Command>);
impl Client {
    pub fn submit(&self, command: Command) -> Result<(), &'static str> {
        self.0.try_send(command).map_err(|_| "tunnel_command_busy")
    }
}
pub struct Events(mpsc::Receiver<Reply>);
impl Events {
    pub fn poll(&self) -> Option<Reply> {
        self.0.try_recv().ok()
    }
}
pub struct Mailbox {
    commands: mpsc::Receiver<Command>,
    replies: mpsc::SyncSender<Reply>,
}
pub fn mailbox() -> (Client, Events, Mailbox) {
    let (send, commands) = mpsc::sync_channel(4);
    let (replies, receive) = mpsc::sync_channel(4);
    (Client(send), Events(receive), Mailbox { commands, replies })
}
struct Held {
    worker: Worker,
    instance: u64,
    operation: u64,
    slot: Selected,
    policy: Vec<u8>,
    monitor: BoundCancellation,
    proof: Option<Arc<BoundReport>>,
    selected: bool,
    loss_reported: bool,
}
pub(crate) struct Manager {
    executable: PathBuf,
    store: PrivateStore,
    mailbox: Mailbox,
    held: Option<Held>,
}
impl Manager {
    pub(crate) fn new(executable: PathBuf, store: PrivateStore, mailbox: Mailbox) -> Self {
        Self {
            executable,
            store,
            mailbox,
            held: None,
        }
    }
    pub(crate) fn stop(&mut self, front: &Front) -> Result<(), Failure> {
        // Readback is mandatory even if the PUT result is uncertain.
        let _ = front.controller().select(Selected::Reject);
        let rejected = front.controller().selected().ok() == Some(Selected::Reject);
        let stopped = self
            .held
            .as_mut()
            .map_or(Ok(()), |h| h.worker.stop_confirmed());
        if stopped.is_ok() {
            self.held = None;
        }
        if rejected && stopped.is_ok() {
            Ok(())
        } else {
            Err(Failure::Stop)
        }
    }

    pub(crate) fn poll(&mut self, front: &Front) -> Result<(), Failure> {
        if self
            .held
            .as_ref()
            .is_some_and(|h| !h.selected && h.monitor.is_cancelled())
        {
            self.stop(front)?;
        }
        if let Some(held) = &mut self.held {
            if held.selected && !held.loss_reported && !held.worker.is_running() {
                if self
                    .mailbox
                    .replies
                    .try_send(Reply::Lost {
                        instance: held.instance,
                    })
                    .is_ok()
                {
                    held.loss_reported = true;
                }
            }
        }
        let Ok(command) = self.mailbox.commands.try_recv() else {
            return Ok(());
        };
        let id = match &command {
            Command::Prepare { id, .. }
            | Command::Promote { id, .. }
            | Command::Abort { id }
            | Command::Verify { id, .. } => *id,
        };
        let result = self.execute(front, command);
        let reply = match result {
            Ok(reply) => reply,
            Err(Failure::Stop) => return Err(Failure::Stop),
            Err(_) => Reply::Failed {
                id,
                code: "tunnel_transaction_failed",
            },
        };
        // A dropped reply must reconcile; the state owner cannot accept it.
        if self.mailbox.replies.try_send(reply).is_err() {
            self.stop(front)?;
        }
        Ok(())
    }
    fn execute(&mut self, front: &Front, command: Command) -> Result<Reply, Failure> {
        match command {
            Command::Abort { id } => {
                self.stop(front)?;
                Ok(Reply::Stopped { id })
            }
            Command::Prepare { id, spec, network } => {
                self.stop(front)?;
                if network.is_cancelled()
                    || spec.instance == 0
                    || !matches!(spec.slot, Selected::SlotA | Selected::SlotB)
                {
                    return Ok(Reply::Failed {
                        id,
                        code: "candidate_cancelled",
                    });
                }
                let monitor = network.cancellation_monitor();
                let worker = Worker::start_carried(
                    &self.executable,
                    &spec.runtime,
                    &WorkerRequest {
                        identity: Identity {
                            private_key: &spec.private_key,
                            preshared_key: None,
                            ipv4: spec.ipv4,
                            ipv6: Some(spec.ipv6),
                        },
                        relay_public_key: &spec.relay_public_key,
                        transport: spec.transport,
                        protection: Protection::Standard,
                        listener: Listener {
                            mixed_port: spec.mixed_port,
                            controller_port: spec.controller_port,
                            controller_secret: &spec.controller_secret,
                        },
                    },
                    network,
                );
                let worker = match worker {
                    Ok(worker) => worker,
                    Err(crate::worker_lifecycle::WorkerStartError::Cleanup) => {
                        return Err(Failure::Stop)
                    }
                    Err(error) => {
                        return Ok(Reply::Failed {
                            id,
                            code: error.code(),
                        })
                    }
                };
                self.held = Some(Held {
                    worker,
                    instance: spec.instance,
                    operation: id,
                    slot: spec.slot,
                    policy: spec.policy,
                    monitor,
                    proof: None,
                    selected: false,
                    loss_reported: false,
                });
                let held = self.held.as_mut().unwrap();
                let proof = match held.worker.assess() {
                    Err(crate::canary_batch::BatchError::Stale) => {
                        self.stop(front)?;
                        return Ok(Reply::Failed {
                            id,
                            code: "candidate_evidence_stale",
                        });
                    }
                    Ok(Assessment::Unready(proof)) => {
                        self.stop(front)?;
                        return Ok(Reply::Unready { id, proof });
                    }
                    Ok(Assessment::Bound(proof))
                        if !held.monitor.is_cancelled()
                            && held.worker.verify_bound_report(&proof) =>
                    {
                        Arc::new(proof)
                    }
                    _ => {
                        self.stop(front)?;
                        return Ok(Reply::Failed {
                            id,
                            code: "candidate_probe_failed",
                        });
                    }
                };
                held.proof = Some(proof.clone());
                Ok(Reply::Prepared { id, proof })
            }
            Command::Promote { id, proof } => {
                let valid = self.held.as_ref().is_some_and(|h| {
                    h.operation == id
                        && !h.selected
                        && !h.monitor.is_cancelled()
                        && h.proof.as_ref().is_some_and(|p| Arc::ptr_eq(p, &proof))
                        && h.worker.verify_bound_report(&proof)
                });
                if !valid {
                    return Ok(Reply::Failed {
                        id,
                        code: "candidate_stale",
                    });
                }
                let held = self.held.as_mut().unwrap();
                // Crash-safe last-path receipt is committed and read back while
                // the front still rejects. Startup never auto-selects this file.
                let promoted = crate::promotion_gate::promote(
                    || {
                        proof
                            .report()
                            .fresh_canary(std::time::Instant::now())
                            .is_ok()
                    },
                    || {
                        let stored = (|| -> std::io::Result<()> {
                            self.store
                                .prepare(RecordKind::Connection, &held.policy)?
                                .commit()?;
                            if self.store.load(RecordKind::Connection)?.expose() != held.policy {
                                return Err(std::io::Error::other("connection_readback_failed"));
                            }
                            Ok(())
                        })();
                        stored.is_ok()
                            && !held.monitor.is_cancelled()
                            && held.worker.verify_bound_report(&proof)
                    },
                    || {
                        let _ = front.controller().select(held.slot);
                        !held.monitor.is_cancelled()
                            && held.worker.verify_bound_report(&proof)
                            && front.controller().selected().ok() == Some(held.slot)
                    },
                );
                if let Err(error) = promoted {
                    self.stop(front)?;
                    return Ok(Reply::Failed {
                        id,
                        code: match error {
                            crate::promotion_gate::Error::Stale => "candidate_evidence_stale",
                            crate::promotion_gate::Error::Commit => "candidate_commit_failed",
                            crate::promotion_gate::Error::Selection => "candidate_selection_failed",
                        },
                    });
                }
                held.selected = true;
                held.proof = None;
                Ok(Reply::Promoted { id, proof })
            }
            Command::Verify {
                id,
                instance,
                network,
            } => {
                let Some(held) = self
                    .held
                    .as_ref()
                    .filter(|h| h.instance == instance && h.selected)
                else {
                    return Ok(Reply::Failed {
                        id,
                        code: "active_worker_missing",
                    });
                };
                let proof = held.worker.probe_bound_on(&network);
                match proof {
                    Err(crate::canary_batch::BatchError::Stale) => Ok(Reply::Failed {
                        id,
                        code: "active_evidence_stale",
                    }),
                    Ok(proof)
                        if !network.is_cancelled() && held.worker.verify_bound_report(&proof) =>
                    {
                        Ok(Reply::Verified {
                            id,
                            proof: Arc::new(proof),
                        })
                    }
                    _ => Ok(Reply::Failed {
                        id,
                        code: "active_probe_failed",
                    }),
                }
            }
        }
    }
}
