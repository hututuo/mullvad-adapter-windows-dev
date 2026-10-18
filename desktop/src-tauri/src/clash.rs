//! Optional external-client integration; independent of the tunnel owner lock.
use adapter_clash_integration::{Choice, Integration};
use serde::Deserialize;
use serde_json::{json, Value};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    kind: String,
    directory: Option<String>,
    choice: Option<Choice>,
    preview_id: Option<String>,
    selection: Option<adapter_clash_integration::portable::Selection>,
}
static GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(windows)]
static PROFILE_SERVICE: std::sync::Mutex<
    Option<adapter_clash_integration::profile_service::Service>,
> = std::sync::Mutex::new(None);

/// Restore the same durable subscription URL when the tray process restarts.
/// No deep link, activation, credentials or network probe is sent at startup.
#[cfg(windows)]
pub fn restore_profile_service() {
    let _ = (|| -> Result<(), String> {
        let root = adapter_platform::windows_paths::AppRoot::open("WindowsClash")
            .map_err(|_| "clash_private_store_unavailable")?;
        let store = root.path().join("clash-integration");
        if store.join("profile-service.json").is_file() {
            ensure_profile_service(store)?;
        }
        Ok(())
    })();
}
#[cfg(windows)]
fn ensure_profile_service(store: std::path::PathBuf) -> Result<(), String> {
    let mut server = PROFILE_SERVICE.lock().map_err(|_| "clash_busy")?;
    if server.is_none() {
        *server = Some(adapter_clash_integration::profile_service::Service::start(
            store,
            || {
                let a = adapter_platform::windows::boot_id().map_err(|_| "random_unavailable")?;
                let b = adapter_platform::windows::boot_id().map_err(|_| "random_unavailable")?;
                use sha2::{Digest, Sha256};
                Ok(format!(
                    "{:x}",
                    Sha256::digest(format!("{a}{b}").as_bytes())
                ))
            },
        )?);
    }
    Ok(())
}
#[tauri::command]
pub async fn copy_clash_config(window: tauri::Window) -> Result<(), String> {
    #[cfg(windows)]
    {
        let owner = window.hwnd().map_err(|_| "clipboard_window_unavailable")?.0 as isize;
        return tauri::async_runtime::spawn_blocking(move || {
            let dashboard = match super::transact(adapter_protocol::app::AppCommand::Dashboard)? {
                adapter_protocol::app::AppReply::Dashboard { dashboard } => dashboard,
                _ => return Err("backend_unavailable".into()),
            };
            let text = adapter_clash_integration::export(dashboard.settings.front_port)?;
            adapter_platform::windows_clipboard::copy_public_text(owner, &text)
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|_| "clash_worker_failed".to_owned())?;
    }
    #[cfg(not(windows))]
    {
        let _ = window;
        Err("clash_windows_required".into())
    }
}
#[tauri::command]
pub async fn clash_request(input: Request) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || execute(input))
        .await
        .map_err(|_| "clash_worker_failed".to_owned())?
}
#[cfg(not(windows))]
fn execute(_input: Request) -> Result<Value, String> {
    Err("clash_windows_required".into())
}
#[cfg(windows)]
fn execute(input: Request) -> Result<Value, String> {
    use std::path::PathBuf;
    let _gate = GATE.try_lock().map_err(|_| "clash_busy")?;
    if super::STOPPING.load(std::sync::atomic::Ordering::Acquire) {
        return Err("backend_stopping".into());
    }
    if input.kind == "setup_download" {
        adapter_platform::windows_clash_uri::open_download_page()
            .map_err(|_| "clash_download_page_unavailable")?;
        return Ok(json!({"opened":true}));
    }
    if input.kind == "setup_status" {
        let (installed, protocol_registered) = adapter_platform::windows_clash_uri::installation()
            .map_err(|_| "clash_detection_unavailable")?;
        let appdata = std::env::var_os("APPDATA").ok_or("clash_detection_unavailable")?;
        let user = std::env::var_os("USERPROFILE").ok_or("clash_detection_unavailable")?;
        let roots = [
            PathBuf::from(&appdata).join("io.github.clash-verge-rev.clash-verge-rev"),
            PathBuf::from(&appdata).join("io.github.clash-verge.clash-verge"),
            PathBuf::from(user).join(".config/clash-verge"),
        ];
        let count = roots
            .iter()
            .filter(|root| root.join("profiles.yaml").is_file())
            .count();
        return Ok(
            json!({"installed":installed,"protocol_registered":protocol_registered,"configuration_count":count}),
        );
    }
    let dashboard = match super::transact(adapter_protocol::app::AppCommand::Dashboard)? {
        adapter_protocol::app::AppReply::Dashboard { dashboard } => dashboard,
        adapter_protocol::app::AppReply::Error { code } => return Err(code),
        _ => return Err("invalid_response".into()),
    };
    let front = dashboard.settings.front_port;
    if matches!(input.kind.as_str(), "apply" | "enable" | "profile_import")
        && (!dashboard.front_ready
            || dashboard.status != "connected"
            || dashboard.front_selected == "reject")
    {
        // Do not redirect a working Clash selector to an idle REJECT front.
        // Detection, preview, export and undo remain available while disconnected.
        return Err("clash_tunnel_required".into());
    }
    if input.kind == "export" {
        return Ok(json!({"config":adapter_clash_integration::export(front)?}));
    }
    let root = if let Some(path) = input.directory.filter(|s| !s.trim().is_empty()) {
        if path.len() > 2048 || path.starts_with("\\\\") || path.starts_with("//") {
            return Err("clash_unsafe_path".into());
        }
        PathBuf::from(path)
    } else {
        let appdata = std::env::var_os("APPDATA").ok_or("clash_not_found")?;
        let user = std::env::var_os("USERPROFILE").ok_or("clash_not_found")?;
        let candidates = [
            PathBuf::from(&appdata).join("io.github.clash-verge-rev.clash-verge-rev"),
            PathBuf::from(&appdata).join("io.github.clash-verge.clash-verge"),
            PathBuf::from(user).join(".config/clash-verge"),
        ];
        let found: Vec<_> = candidates
            .into_iter()
            .filter(|p| p.join("profiles.yaml").is_file())
            .collect();
        if found.len() != 1 {
            return Err(if found.is_empty() {
                "clash_not_found"
            } else {
                "clash_multiple_clients"
            }
            .into());
        }
        found.into_iter().next().unwrap()
    };
    let app_root = adapter_platform::windows_paths::AppRoot::open("WindowsClash")
        .map_err(|_| "clash_private_store_unavailable")?;
    let store = app_root.path().join("clash-integration");
    if !store.exists() {
        std::fs::create_dir(&store).map_err(|_| "clash_private_store_unavailable")?;
    }
    if input.kind.starts_with("profile_") {
        if input.kind == "profile_status" {
            ensure_profile_service(store.clone())?;
            let service = PROFILE_SERVICE.lock().map_err(|_| "clash_busy")?;
            let service = service
                .as_ref()
                .ok_or("clash_profile_service_unavailable")?;
            let id = input
                .preview_id
                .as_deref()
                .ok_or("clash_preview_required")?;
            let registered =
                adapter_clash_integration::portable::registration(&root, &service.url(id)?, id)?;
            return Ok(
                json!({"id":id,"registered":registered.registered,"selected":registered.selected,"runtime_verified":false}),
            );
        }
        let source = adapter_clash_integration::portable_source(&root)?;
        let selection = input.selection.unwrap_or_default();
        let profile =
            adapter_clash_integration::portable::generate(source.as_ref(), front, &selection)?;
        let id = profile.fingerprint();
        if input.kind == "profile_preview" {
            let service = PROFILE_SERVICE.lock().map_err(|_| "clash_busy")?;
            let registered = match service.as_ref() {
                Some(service) => adapter_clash_integration::portable::registration(
                    &root,
                    &service.url(&id)?,
                    &id,
                )?,
                None => Default::default(),
            };
            return Ok(
                json!({"id": id,"summary":profile.summary,"directory":root.to_string_lossy(),
                "proxy_port":source.as_ref().and_then(|v|v["mixed-port"].as_u64()).filter(|p|*p>=1024&&*p<=65535),
                "registered":registered.registered,"selected":registered.selected}),
            );
        }
        if !matches!(input.kind.as_str(), "profile_export" | "profile_import") {
            return Err("clash_invalid_command".into());
        }
        if input.preview_id.as_deref() != Some(id.as_str()) {
            return Err("clash_config_changed".into());
        }
        ensure_profile_service(store.clone())?;
        let service = PROFILE_SERVICE.lock().map_err(|_| "clash_busy")?;
        let service = service
            .as_ref()
            .ok_or("clash_profile_service_unavailable")?;
        let url = service.url(&id)?;
        let previous = adapter_clash_integration::portable::registration(&root, &url, &id)?;
        // Immutable candidate and official engine check precede protocol launch.
        let path = service.save(profile.bytes())?;
        let sha = option_env!("ADAPTER_SOURCE_SHA").ok_or("runtime_invalid")?;
        let exe = std::env::current_exe().map_err(|_| "runtime_invalid")?;
        let runtime = super::live_runtime::verify_runtime_dir(
            &exe.parent().ok_or("runtime_invalid")?.join("runtime"),
            sha,
            env!("CARGO_PKG_VERSION"),
        )
        .map_err(|_| "runtime_invalid")?;
        use adapter_clash_integration::Controller;
        // validate() uses only the pinned engine, never this virtual control URL.
        adapter_clash_integration::LocalController::from_config(
            &json!({"external-controller":"127.0.0.1:19991"}),
            front,
        )?
        .with_engine(runtime.mihomo, root.clone())
        .validate(&path)?;
        let launched = input.kind == "profile_import" && !previous.registered;
        if launched {
            adapter_platform::windows_clash_uri::open(&service.import_uri(&id)?)
                .map_err(|_| "clash_import_handler_missing")?;
        }
        // ShellExecute only acknowledges dispatch. Let the official client own
        // the import, then confirm the downloaded bytes without touching its
        // profile index or replacing the user's selected subscription.
        let mut registered = previous;
        if launched {
            let until = std::time::Instant::now() + std::time::Duration::from_secs(20);
            loop {
                registered = adapter_clash_integration::portable::registration(&root, &url, &id)?;
                if registered.registered || std::time::Instant::now() >= until {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
        return Ok(
            json!({"id":id,"path":path.to_string_lossy(),"summary":profile.summary,"import_requested":launched,
            "registered":registered.registered,"selected":registered.selected,"runtime_verified":false}),
        );
    }
    let integration = Integration::open(root.clone(), store)?;
    let controller = integration.controller(front)?;
    if input.kind == "detect" {
        return serde_json::to_value(integration.view(&controller, front)?)
            .map_err(|_| "clash_invalid_response".into());
    }
    if input.kind == "enable" {
        return serde_json::to_value(integration.enable(&controller)?)
            .map_err(|_| "clash_invalid_response".into());
    }
    let sha = option_env!("ADAPTER_SOURCE_SHA").ok_or("runtime_invalid")?;
    let exe = std::env::current_exe().map_err(|_| "runtime_invalid")?;
    let runtime = super::live_runtime::verify_runtime_dir(
        &exe.parent().ok_or("runtime_invalid")?.join("runtime"),
        sha,
        env!("CARGO_PKG_VERSION"),
    )
    .map_err(|_| "runtime_invalid")?;
    let controller = controller.with_engine(runtime.mihomo, root);
    if input.kind == "undo" {
        return serde_json::to_value(integration.undo(&controller)?)
            .map_err(|_| "clash_invalid_response".into());
    }
    let mut choice = input.choice.ok_or("clash_invalid_choice")?;
    // Authoritative front comes from the current verified backend, not renderer.
    choice.front_port = front;
    match input.kind.as_str() {
        "preview" => serde_json::to_value(integration.preview(&controller, &choice)?),
        "apply" => serde_json::to_value(
            integration.apply(
                &controller,
                &choice,
                input
                    .preview_id
                    .as_deref()
                    .ok_or("clash_preview_required")?,
            )?,
        ),
        _ => return Err("clash_invalid_command".into()),
    }
    .map_err(|_| "clash_invalid_response".into())
}
