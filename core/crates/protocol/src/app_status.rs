//! Public observations only. This cache never owns a connection or executes commands.
use crate::{app::*, write_frame, MAX_FRAME};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Write},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

pub const MAX_STATUS_AGE: Duration = Duration::from_secs(3);
pub const STATUS_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StatusReply {
    Snapshot {
        age_ms: u64,
        capture_ms: u64,
        dashboard: Box<Dashboard>,
    },
    Error {
        code: String,
    },
}
impl StatusReply {
    pub fn into_dashboard(
        self,
        boot: &str,
        source: &str,
        build: &str,
        delivery: Duration,
    ) -> Result<Dashboard, &'static str> {
        match self {
            Self::Error { code } => Err(match code.as_str() {
                "status_snapshot_stale" => "status_snapshot_stale",
                "status_snapshot_unavailable" => "status_snapshot_unavailable",
                "status_read_busy" => "status_read_busy",
                "status_read_only" => "status_read_only",
                "boot_changed_reconcile" => "boot_changed_reconcile",
                "incompatible_protocol" => "incompatible_protocol",
                "invalid_request_id" => "invalid_request_id",
                _ => "status_response_invalid",
            }),
            Self::Snapshot {
                age_ms,
                capture_ms,
                mut dashboard,
            } => {
                if dashboard.boot_id != boot
                    || dashboard.source_sha != source
                    || dashboard.build != build
                {
                    return Err("status_identity_mismatch");
                }
                let age_ms =
                    age_ms.saturating_add(delivery.as_millis().min(u64::MAX as u128) as u64);
                if age_ms > MAX_STATUS_AGE.as_millis() as u64 || capture_ms > age_ms {
                    return Err("status_snapshot_stale");
                }
                dashboard.status_observation = Some(StatusObservation {
                    age_ms,
                    capture_ms,
                    native_elapsed_ms: delivery.as_millis().min(u64::MAX as u128) as u64,
                });
                Ok(*dashboard)
            }
        }
    }
}

struct Published {
    json: Vec<u8>,
    captured: Instant,
    capture_ms: u64,
}
#[derive(Clone, Default)]
pub struct StatusPublication(Arc<RwLock<Option<Arc<Published>>>>);
impl StatusPublication {
    /// Encode before the tiny pointer swap; neither side waits on a cache lock.
    /// A failed/busy publication retains its old capture time.
    pub fn publish(&self, dashboard: &Dashboard, captured: Instant) -> Result<(), &'static str> {
        let json = serde_json::to_vec(dashboard).map_err(|_| "status_response_invalid")?;
        if json.len() > MAX_FRAME - 128 {
            return Err("status_response_invalid");
        }
        let value = Arc::new(Published {
            json,
            captured,
            capture_ms: captured.elapsed().as_millis().min(u64::MAX as u128) as u64,
        });
        let mut slot = self.0.try_write().map_err(|_| "status_read_busy")?;
        *slot = Some(value);
        Ok(())
    }

    /// Validate the same boot/request fence, then serve cached bytes outside locks.
    /// In particular, private-key and mutation commands never reach a state owner.
    pub fn respond(
        &self,
        request: &AppRequest,
        boot: &str,
        now: Instant,
        writer: &mut impl Write,
    ) -> io::Result<()> {
        let fail = |writer: &mut _, code: &str| {
            write_frame(writer, &StatusReply::Error { code: code.into() })
        };
        if let Err(code) = request.validate(boot) {
            return fail(writer, code);
        }
        if !matches!(request.command, AppCommand::Dashboard) {
            return fail(writer, "status_read_only");
        }
        let value = match self.0.try_read() {
            Ok(slot) => slot.clone(),
            Err(_) => return fail(writer, "status_read_busy"),
        };
        let Some(value) = value else {
            return fail(writer, "status_snapshot_unavailable");
        };
        let age = now
            .saturating_duration_since(value.captured)
            .max(Duration::from_millis(value.capture_ms));
        if age > MAX_STATUS_AGE {
            return fail(writer, "status_snapshot_stale");
        }
        let prefix = format!(
            "{{\"kind\":\"snapshot\",\"age_ms\":{},\"capture_ms\":{},\"dashboard\":",
            age.as_millis(),
            value.capture_ms
        );
        let size = prefix.len() + value.json.len() + 1;
        if size > MAX_FRAME {
            return fail(writer, "status_response_invalid");
        }
        writer.write_all(&(size as u32).to_le_bytes())?;
        writer.write_all(prefix.as_bytes())?;
        writer.write_all(&value.json)?;
        writer.write_all(b"}")?;
        writer.flush()
    }
}

#[cfg(test)]
#[path = "app_status_tests.rs"]
mod tests;
