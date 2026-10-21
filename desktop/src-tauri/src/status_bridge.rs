//! This uses a different pipe from control, with the same identity/build fences.
use adapter_platform::windows::{Identity, Pipe, SingleInstance};
use adapter_protocol::{app::*, app_status::StatusReply, read_frame, write_frame, ResponseAck};
use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

pub(crate) fn launch_if_absent(identity: &Identity) -> Result<(), String> {
    let mut start = super::BRIDGE_LANES
        .startup
        .try_lock()
        .map_err(|_| "backend_starting")?;
    if super::STOPPING.load(Ordering::Acquire) {
        return Err("backend_stopping".into());
    }
    if SingleInstance::exists(identity).map_err(|_| "backend_identity_or_pipe_rejected")? {
        return Ok(());
    }
    if !super::bridge_lanes::BridgeLanes::launch_due(*start, Instant::now()) {
        return Err("backend_starting".into());
    }
    let sha = option_env!("ADAPTER_SOURCE_SHA").ok_or("runtime_invalid")?;
    let exe = std::env::current_exe().map_err(|_| "runtime_invalid")?;
    let runtime = super::live_runtime::verify_runtime_dir(
        &exe.parent().ok_or("runtime_invalid")?.join("runtime"),
        sha,
        env!("CARGO_PKG_VERSION"),
    )
    .map_err(|_| "runtime_invalid")?;
    use sha2::{Digest, Sha256};
    let expected =
        option_env!("ADAPTER_RUNTIME_MANIFEST_SHA256").ok_or("runtime_manifest_unpinned")?;
    let manifest =
        std::fs::read(runtime.runtime_dir.join("manifest.json")).map_err(|_| "runtime_invalid")?;
    if manifest.len() > 1024 * 1024 || format!("{:x}", Sha256::digest(&manifest)) != expected {
        return Err("runtime_manifest_pin_mismatch".into());
    }
    if super::STOPPING.load(Ordering::Acquire) {
        return Err("backend_stopping".into());
    }
    use std::{
        os::windows::process::CommandExt,
        process::{Command, Stdio},
    };
    Command::new(&runtime.adapter_agent)
        .arg("--serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x08000000 | 0x00000200)
        .spawn()
        .map_err(|_| "backend_start_failed")?;
    *start = Some(Instant::now());
    Ok(())
}

pub(crate) fn read() -> Result<AppReply, String> {
    let started = Instant::now();
    let identity = Identity::current()
        .and_then(|i| i.with_scope("Windows"))
        .map_err(|_| "user_identity_unavailable")?;
    let status = identity.status_channel();
    let mut pipe = match Pipe::connect(&status, Duration::from_millis(100)) {
        Ok(pipe) => pipe,
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            // A live control owner with a missing/busy read endpoint is not an
            // absent backend. Never start another process because of that read.
            if SingleInstance::exists(&identity).map_err(|_| "backend_identity_or_pipe_rejected")? {
                return Err("status_channel_unavailable".into());
            }
            launch_if_absent(&identity)?;
            Pipe::connect(&status, Duration::from_secs(3))
                .map_err(|_| "status_channel_unavailable")?
        }
        Err(_) => return Err("backend_identity_or_pipe_rejected".into()),
    };
    let hello: AppReply = read_frame(&mut pipe).map_err(|_| "invalid_handshake")?;
    let source = option_env!("ADAPTER_SOURCE_SHA").ok_or("runtime_build_identity_missing")?;
    let build = env!("CARGO_PKG_VERSION");
    let boot = hello.verified_boot_id(source, build)?.to_owned();
    if super::STOPPING.load(Ordering::Acquire) {
        return Err("backend_stopping".into());
    }
    let request = AppRequest {
        major: APP_API_MAJOR,
        boot_id: boot.clone(),
        request_id: adapter_platform::windows::boot_id().map_err(|_| "request_id_unavailable")?,
        command: AppCommand::Dashboard,
    };
    let sent = Instant::now();
    write_frame(&mut pipe, &request).map_err(|_| "status_request_write_failed")?;
    let reply: StatusReply = read_frame(&mut pipe).map_err(|e| {
        if e.kind() == std::io::ErrorKind::InvalidData {
            "status_response_invalid"
        } else {
            "status_response_read_failed"
        }
    })?;
    // A fully read response is acknowledged even if it is stale/rejected.
    write_frame(
        &mut pipe,
        &ResponseAck {
            request_id: request.request_id,
        },
    )
    .map_err(|_| "status_response_ack_failed")?;
    let mut dashboard = reply.into_dashboard(&boot, source, build, sent.elapsed())?;
    if let Some(timing) = &mut dashboard.status_observation {
        timing.native_elapsed_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    }
    if super::STOPPING.load(Ordering::Acquire) {
        return Err("backend_stopping".into());
    }
    Ok(AppReply::Dashboard {
        dashboard: Box::new(dashboard),
    })
}
