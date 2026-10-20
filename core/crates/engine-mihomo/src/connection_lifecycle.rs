//! Persistent fixed front. Bounded commands run on its resource I/O thread.
//! Front readiness is NOT a tunnel/identity/candidate acceptance claim.
use crate::{controller::Selected, lifecycle::Front, Listener};
use adapter_control::owned_lifecycle::{BuildOutcome, Cancellation, Failure, Resource};
use adapter_platform::windows_runtime::PrivateRuntime;
use std::{path::PathBuf, sync::mpsc, time::Duration};
use zeroize::Zeroizing;

pub struct FrontConfig {
    pub executable: PathBuf,
    pub runtime: PrivateRuntime,
    pub mixed_port: u16,
    pub controller_port: u16,
    pub slot_a: u16,
    pub slot_b: u16,
    pub controller_secret: Zeroizing<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontStatus {
    Reject,
    SlotA,
    SlotB,
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontCommand {
    Inspect(u64),
    Reject(u64),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrontReply {
    pub request_id: u64,
    pub status: FrontStatus,
}
#[derive(Clone)]
pub struct FrontClient(mpsc::SyncSender<FrontCommand>);
impl FrontClient {
    pub fn submit(&self, command: FrontCommand) -> Result<(), &'static str> {
        self.0.try_send(command).map_err(|_| "front_command_busy")
    }
}
pub struct FrontEvents(mpsc::Receiver<FrontReply>);
impl FrontEvents {
    pub fn poll(&self) -> Option<FrontReply> {
        self.0.try_recv().ok()
    }
}
pub struct FrontMailbox {
    commands: mpsc::Receiver<FrontCommand>,
    replies: mpsc::SyncSender<FrontReply>,
}
pub fn mailbox() -> (FrontClient, FrontEvents, FrontMailbox) {
    let (send, commands) = mpsc::sync_channel(4);
    let (replies, receive) = mpsc::sync_channel(4);
    (
        FrontClient(send),
        FrontEvents(receive),
        FrontMailbox { commands, replies },
    )
}
pub struct ConnectionResource {
    front: Front,
    mailbox: FrontMailbox,
    tunnel: Option<crate::connection_tunnel::Manager>,
    config: FrontConfig,
    lifetime: Cancellation,
}
impl ConnectionResource {
    pub fn build(
        config: FrontConfig,
        mailbox: FrontMailbox,
        lifetime: Cancellation,
    ) -> Result<BuildOutcome<Self>, Failure> {
        let front = match Front::start(
            &config.executable,
            &config.runtime,
            &Listener {
                mixed_port: config.mixed_port,
                controller_port: config.controller_port,
                controller_secret: &config.controller_secret,
            },
            config.slot_a,
            config.slot_b,
            || lifetime.is_cancelled(),
        ) {
            Ok(front) => front,
            Err(crate::lifecycle::StartError::Cancelled) => {
                return Ok(BuildOutcome::CancelledClean)
            }
            Err(crate::lifecycle::StartError::Cleanup) => return Err(Failure::Stop),
            Err(_) => return Err(Failure::Start),
        };
        // Front::start positively validated REJECT/mixed/controller ownership.
        Ok(BuildOutcome::Ready(Self {
            front,
            mailbox,
            tunnel: None,
            config,
            lifetime,
        }))
    }
    pub fn attach_tunnels(
        &mut self,
        executable: PathBuf,
        store: adapter_platform::windows_store::PrivateStore,
        mailbox: crate::connection_tunnel::Mailbox,
    ) {
        self.tunnel = Some(crate::connection_tunnel::Manager::new(
            executable, store, mailbox,
        ));
    }
    fn inspect(&self) -> FrontStatus {
        match self.front.controller().selected() {
            Ok(Selected::Reject) => FrontStatus::Reject,
            Ok(Selected::SlotA) => FrontStatus::SlotA,
            Ok(Selected::SlotB) => FrontStatus::SlotB,
            Err(_) => FrontStatus::Unavailable,
        }
    }
}
impl Resource for ConnectionResource {
    fn check(&mut self) -> Result<(), Failure> {
        if !matches!(self.front.process().wait(Duration::ZERO), Ok(None)) {
            // Confirm only this exact front's absence, then recreate the local
            // entry with REJECT. The existing WG worker remains owned/alive;
            // its next fresh Verify can reselect it without changing the exit.
            self.front.stop().map_err(|_| Failure::Stop)?;
            let c = &self.config;
            self.front = Front::start(
                &c.executable,
                &c.runtime,
                &Listener {
                    mixed_port: c.mixed_port,
                    controller_port: c.controller_port,
                    controller_secret: &c.controller_secret,
                },
                c.slot_a,
                c.slot_b,
                || self.lifetime.is_cancelled(),
            )
            .map_err(|e| match e {
                crate::lifecycle::StartError::Cleanup => Failure::Stop,
                _ => Failure::Worker,
            })?;
            let _ = self.mailbox.replies.try_send(FrontReply {
                request_id: 0,
                status: FrontStatus::Reject,
            });
        }
        if let Some(tunnel) = &mut self.tunnel {
            tunnel.poll(&self.front)?;
        }
        if let Ok(command) = self.mailbox.commands.try_recv() {
            let request_id = match command {
                FrontCommand::Inspect(id) | FrontCommand::Reject(id) => id,
            };
            if matches!(command, FrontCommand::Reject(_)) {
                // One mutation, then readback even on OutcomeUnknown. No retry
                // loop and never a DIRECT target. A failure is reported, not
                // treated as confirmed selection or confirmed process absence.
                let _ = self.front.controller().select(Selected::Reject);
            }
            let reply = FrontReply {
                request_id,
                status: self.inspect(),
            };
            // A slow or departed observer cannot block this I/O lifecycle.
            let _ = self.mailbox.replies.try_send(reply);
        }
        Ok(())
    }
    fn stop(&mut self) -> Result<(), Failure> {
        let tunnel = self.tunnel.as_mut().map_or(Ok(()), |t| t.stop(&self.front));
        let front = self.front.stop().map_err(|_| Failure::Stop);
        if tunnel.is_ok() && front.is_ok() {
            Ok(())
        } else {
            Err(Failure::Stop)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mailbox_has_bounded_nonblocking_backpressure() {
        let (client, _events, mailbox) = mailbox();
        for id in 0..4 {
            client.submit(FrontCommand::Inspect(id)).unwrap();
        }
        assert_eq!(
            client.submit(FrontCommand::Inspect(4)),
            Err("front_command_busy")
        );
        assert_eq!(mailbox.commands.recv().unwrap(), FrontCommand::Inspect(0));
        client.submit(FrontCommand::Reject(5)).unwrap();
    }
    #[test]
    fn stopped_observer_never_blocks_reply_publication() {
        let (_client, events, mailbox) = mailbox();
        drop(events);
        assert!(mailbox
            .replies
            .try_send(FrontReply {
                request_id: 1,
                status: FrontStatus::Reject
            })
            .is_err());
    }
}
