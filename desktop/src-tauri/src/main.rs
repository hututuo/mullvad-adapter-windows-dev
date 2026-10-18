#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use adapter_protocol::app::{AppCommand, AppReply, AppRequest, APP_API_MAJOR};
mod clash;
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Emitter, Manager,
};
#[cfg(windows)]
#[path = "../../../core/crates/agent/src/live_runtime.rs"]
mod live_runtime;
static BRIDGE_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
static STOPPING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static STOP_IN_FLIGHT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn begin_shutdown(app: tauri::AppHandle) -> Result<(), String> {
    use std::sync::atomic::Ordering;
    STOP_IN_FLIGHT
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| "operation_busy".to_owned())?;
    STOPPING.store(true, Ordering::Release);
    let _ = app.emit("backend-stopping", "stopping");
    let handle = app.clone();
    std::thread::Builder::new()
        .name("backend-stop-confirm".into())
        .spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            let result = loop {
                let result = transact(AppCommand::Shutdown);
                if result.as_ref().err().is_some_and(|e| e == "operation_busy")
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    continue;
                }
                break result;
            };
            STOP_IN_FLIGHT.store(false, Ordering::Release);
            match result {
                Ok(_) => handle.exit(0),
                Err(code) => {
                    let _ = handle.emit("backend-stopping", code);
                }
            }
        })
        .map_err(|_| {
            STOP_IN_FLIGHT.store(false, Ordering::Release);
            let _ = app.emit("backend-stopping", "backend_stop_worker_failed");
            "backend_stop_worker_failed".to_owned()
        })?;
    // STOPPING remains set after an uncertain confirmation: explicit retry is
    // possible, while ordinary requests cannot automatically restart the backend.
    Ok(())
}

#[tauri::command]
fn stop_backend_and_exit(app: tauri::AppHandle) -> Result<(), String> {
    begin_shutdown(app)
}
#[tauri::command]
async fn copy_last_report(
    window: tauri::Window,
    expected_report: String,
) -> Result<String, String> {
    #[cfg(windows)]
    {
        let owner = window.hwnd().map_err(|_| "clipboard_window_unavailable")?.0 as isize;
        tauri::async_runtime::spawn_blocking(move || {
            let reply = transact(AppCommand::Dashboard)?;
            let dashboard = match reply {
                AppReply::Dashboard { dashboard } => dashboard,
                AppReply::Error { code } => return Err(code),
                _ => return Err("invalid_response".into()),
            };
            let path = dashboard
                .report_path(&expected_report)
                .map_err(str::to_owned)?;
            adapter_platform::windows_clipboard::copy_public_text(owner, path)
                .map_err(|e| e.to_string())?;
            Ok(path.to_owned())
        })
        .await
        .map_err(|_| "bridge_worker_failed".to_owned())?
    }
    #[cfg(not(windows))]
    {
        let _ = (window, expected_report);
        Err("backend_unavailable".into())
    }
}
#[tauri::command]
async fn app_request(command: AppCommand) -> Result<AppReply, String> {
    // Serialize native bridge only; secrets are never formatted or stored in UI state.
    tauri::async_runtime::spawn_blocking(move || transact(command))
        .await
        .map_err(|_| "bridge_worker_failed".to_owned())?
}
#[cfg(windows)]
fn transact(command: AppCommand) -> Result<AppReply, String> {
    let shutdown = matches!(command, AppCommand::Shutdown);
    if STOPPING.load(std::sync::atomic::Ordering::Acquire) && !shutdown {
        return Err("backend_stopping".into());
    }
    let _gate = BRIDGE_GATE.try_lock().map_err(|_| "operation_busy")?;
    if shutdown {
        STOPPING.store(true, std::sync::atomic::Ordering::Release);
    }
    use adapter_platform::windows::{boot_id, Identity, Pipe};
    use adapter_protocol::{read_frame, write_frame, ResponseAck};
    use std::{
        os::windows::process::CommandExt,
        process::{Command, Stdio},
        time::Duration,
    };
    let identity = Identity::current()
        .and_then(|i| i.with_scope("Windows"))
        .map_err(|_| "user_identity_unavailable")?;
    let pipe = Pipe::connect(
        &identity,
        if shutdown {
            Duration::from_secs(3)
        } else {
            Duration::from_millis(100)
        },
    );
    let mut pipe = match pipe {
        Ok(pipe) => pipe,
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            if shutdown {
                return Err("backend_stop_unconfirmed".into());
            }
            let sha = option_env!("ADAPTER_SOURCE_SHA").ok_or("runtime_invalid")?;
            let exe = std::env::current_exe().map_err(|_| "runtime_invalid")?;
            let runtime = live_runtime::verify_runtime_dir(
                &exe.parent().ok_or("runtime_invalid")?.join("runtime"),
                sha,
                env!("CARGO_PKG_VERSION"),
            )
            .map_err(|_| "runtime_invalid")?;
            use sha2::{Digest, Sha256};
            let expected = option_env!("ADAPTER_RUNTIME_MANIFEST_SHA256")
                .ok_or("runtime_manifest_unpinned")?;
            let manifest = std::fs::read(runtime.runtime_dir.join("manifest.json"))
                .map_err(|_| "runtime_invalid")?;
            if manifest.len() > 1024 * 1024
                || format!("{:x}", Sha256::digest(&manifest)) != expected
            {
                return Err("runtime_manifest_pin_mismatch".into());
            }
            Command::new(&runtime.adapter_agent)
                .arg("--serve")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(0x08000000 | 0x00000200)
                .spawn()
                .map_err(|_| "backend_start_failed")?;
            Pipe::connect(&identity, Duration::from_secs(3)).map_err(|_| "backend_unavailable")?
        }
        Err(_) => return Err("backend_identity_or_pipe_rejected".into()),
    };
    let hello = read_frame::<AppReply>(&mut pipe).map_err(|_| "invalid_handshake")?;
    let boot = hello
        .verified_boot_id(
            option_env!("ADAPTER_SOURCE_SHA").ok_or("runtime_build_identity_missing")?,
            env!("CARGO_PKG_VERSION"),
        )?
        .to_owned();
    let request = AppRequest {
        major: APP_API_MAJOR,
        boot_id: boot,
        request_id: boot_id().map_err(|_| "request_id_unavailable")?,
        command,
    };
    let exit = if shutdown {
        Some(
            pipe.server_exit_waiter()
                .map_err(|_| "backend_stop_unconfirmed")?,
        )
    } else {
        None
    };
    write_frame(&mut pipe, &request).map_err(|_| "request_write_failed")?;
    let reply = read_frame(&mut pipe).map_err(|_| "response_read_failed")?;
    write_frame(
        &mut pipe,
        &ResponseAck {
            request_id: request.request_id,
        },
    )
    .map_err(|_| "response_ack_failed")?;
    if let Some(exit) = exit {
        if !matches!(reply, AppReply::Accepted { .. }) {
            return Err("backend_stop_unconfirmed".into());
        }
        drop(pipe);
        exit.confirm(Duration::from_secs(15))
            .map_err(|_| "backend_stop_unconfirmed")?;
    }
    Ok(reply)
}
#[cfg(not(windows))]
fn transact(_command: AppCommand) -> Result<AppReply, String> {
    Err("Windows backend is required".into())
}
fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            app_request,
            copy_last_report,
            stop_backend_and_exit,
            clash::clash_request,
            clash::copy_clash_config
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(|app| {
            #[cfg(windows)]
            clash::restore_profile_service();
            let show = MenuItem::with_id(app, "show", "打开连接工作台", true, None::<&str>)?;
            let quit =
                MenuItem::with_id(app, "quit", "退出界面（后台继续运行）", true, None::<&str>)?;
            let stop = MenuItem::with_id(app, "stop", "停止后台并退出", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &stop, &quit])?;
            TrayIconBuilder::new()
                .icon(tauri::image::Image::new_owned(
                    vec![180; 16 * 16 * 4],
                    16,
                    16,
                ))
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    "stop" => {
                        let _ = begin_shutdown(app.clone());
                    }
                    _ => {}
                })
                .build(app)?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("desktop initialization failed");
}
