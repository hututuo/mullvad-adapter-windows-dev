//! OS boundaries. No live engine support is advertised by this skeleton.
#[cfg(any(windows, feature = "windows-api-check"))]
pub mod windows;

#[cfg(any(windows, feature = "windows-api-check"))]
pub mod windows_process;

#[cfg(any(windows, feature = "windows-api-check"))]
pub mod windows_secret;

pub mod engine_output;
pub mod storage_record;

#[cfg(any(windows, feature = "windows-api-check"))]
pub mod windows_store;

pub mod physical_attachment;
#[cfg(any(windows, feature = "windows-api-check"))]
pub mod windows_clash_uri;
pub mod windows_clipboard;
pub mod windows_icmp;

#[cfg(any(test, windows, feature = "windows-api-check"))]
pub mod windows_datagram;

#[cfg(any(windows, feature = "windows-api-check"))]
pub mod windows_controller_owner;

#[cfg(any(windows, feature = "windows-api-check"))]
mod windows_private;
#[cfg(any(windows, feature = "windows-api-check"))]
pub mod windows_runtime;

#[cfg(any(windows, feature = "windows-api-check"))]
pub mod windows_paths;

#[cfg(any(windows, feature = "windows-api-check"))]
pub mod windows_user_file;

#[cfg(any(windows, feature = "windows-api-check"))]
pub mod windows_network_changes;

pub mod egress;
#[cfg(any(test, windows, feature = "windows-api-check"))]
mod launch_gate;

#[cfg(any(windows, feature = "windows-api-check"))]
pub mod windows_control_pipe;
