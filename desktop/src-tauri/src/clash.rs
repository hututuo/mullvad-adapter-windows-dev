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
    chain_name: Option<String>,
    chain_fingerprint: Option<String>,
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
    if input.kind == "chain_auto" {
        return automatic_chain(
            &root,
            &dashboard,
            input.chain_name.as_deref(),
            input.chain_fingerprint.as_deref(),
        );
    }
    if input.kind == "chain_list" {
        let choices = adapter_clash_integration::chain_source::list(&root, front)?;
        return Ok(json!({"choices":choices}));
    }
    if input.kind == "chain_configure" {
        let selected = adapter_clash_integration::chain_source::selected(
            &root,
            front,
            input
                .chain_name
                .as_deref()
                .ok_or("clash_chain_choice_missing")?,
        )?;
        if input.chain_fingerprint.as_deref() != Some(selected.fingerprint.as_str()) {
            return Err("clash_config_changed".into());
        }
        #[derive(serde::Serialize)]
        struct NativeChain<'a> {
            name: &'a str,
            server: &'a str,
            port: u16,
            cipher: &'a str,
            password: &'a str,
        }
        let bytes = serde_json::to_string(&NativeChain {
            name: &selected.name,
            server: &selected.server,
            port: selected.port,
            cipher: &selected.cipher,
            password: &selected.password,
        })
        .map_err(|_| "clash_chain_configuration_invalid")?;
        return match super::transact(adapter_protocol::app::AppCommand::ConfigureChain {
            proxy: adapter_protocol::app::SecretText::new(bytes),
        })? {
            adapter_protocol::app::AppReply::Accepted { .. } => Ok(json!({"accepted":true})),
            adapter_protocol::app::AppReply::Error { code } => Err(code),
            _ => Err("invalid_response".into()),
        };
    }
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

/// Names are preference hints, never proof of a server's geography/readiness.
fn chain_preference(name: &str) -> u8 {
    let name = name.to_lowercase();
    if [
        "美国",
        "美國",
        "🇺🇸",
        "united states",
        "usa",
        "us ",
        "us-",
        "us_",
        "洛杉矶",
        "西雅图",
        "硅谷",
        "圣何塞",
        "new york",
        "los angeles",
        "seattle",
        "san jose",
    ]
    .iter()
    .any(|s| name.contains(s))
    {
        0
    } else if [
        "新加坡",
        "狮城",
        "獅城",
        "🇸🇬",
        "singapore",
        "sg ",
        "sg-",
        "sg_",
    ]
    .iter()
    .any(|s| name.contains(s))
    {
        1
    } else if [
        "英国",
        "英國",
        "🇬🇧",
        "united kingdom",
        "london",
        "uk ",
        "uk-",
        "gb-",
        "伦敦",
    ]
    .iter()
    .any(|s| name.contains(s))
    {
        2
    } else {
        3
    }
}

#[cfg(windows)]
fn automatic_chain(
    root: &std::path::Path,
    dashboard: &adapter_protocol::app::Dashboard,
    selected_name: Option<&str>,
    fingerprint: Option<&str>,
) -> Result<Value, String> {
    use adapter_clash_integration::chain_source;
    use adapter_control::{observer::ObservedOwner, owned_lifecycle::BoundNetwork};
    use adapter_platform::{
        windows::boot_id, windows_paths::AppRoot, windows_runtime::PrivateRuntime,
    };
    use std::time::{Duration, Instant};
    if dashboard.connection.as_ref().is_some_and(|c| c.chained) && dashboard.active_relay.is_some()
    {
        return Ok(json!({"selected":dashboard.chain_node,"kept":true}));
    }
    if dashboard.operation.is_some() {
        return Err("operation_busy".into());
    }
    let mut choices = chain_source::list(root, dashboard.settings.front_port)?;
    choices.sort_by_key(|c| (chain_preference(&c.name), c.name.clone()));
    let preferred_name = selected_name.or(dashboard.settings.chain_selection.as_deref());
    if let Some(name) = preferred_name {
        choices.retain(|c| c.name == name && fingerprint.is_none_or(|fp| c.fingerprint == fp));
    }
    if choices.is_empty() {
        return Err("clash_chain_no_compatible_nodes".into());
    }
    // Bound work without hiding compatible choices from the advanced selector.
    // Round-robin within preference classes prevents one huge region using all
    // slots, while still trying US before Singapore before UK.
    let mut candidates = Vec::new();
    for region in 0..=3 {
        candidates.extend(
            choices
                .iter()
                .filter(|c| chain_preference(&c.name) == region)
                .take(2)
                .cloned(),
        );
    }
    let expected_sha = option_env!("ADAPTER_SOURCE_SHA").ok_or("runtime_invalid")?;
    let exe = std::env::current_exe().map_err(|_| "runtime_invalid")?;
    let runtime_dir = exe.parent().ok_or("runtime_invalid")?.join("runtime");
    let runtime = super::live_runtime::verify_runtime_dir(
        &runtime_dir,
        expected_sha,
        env!("CARGO_PKG_VERSION"),
    )
    .map_err(|_| "runtime_invalid")?;
    use sha2::{Digest, Sha256};
    let manifest =
        std::fs::read(runtime_dir.join("manifest.json")).map_err(|_| "runtime_invalid")?;
    if manifest.len() > 1024 * 1024
        || Some(format!("{:x}", Sha256::digest(&manifest)).as_str())
            != option_env!("ADAPTER_RUNTIME_MANIFEST_SHA256")
    {
        return Err("runtime_manifest_pin_mismatch".into());
    }
    let mut observation = ObservedOwner::windows(adapter_domain::State::new(
        boot_id().map_err(|_| "random_unavailable")?,
    ))
    .map_err(|_| "physical_binding_unavailable")?;
    let settle_deadline = Instant::now() + Duration::from_secs(5);
    while !observation.binding_settled() {
        observation.poll();
        if super::STOPPING.load(std::sync::atomic::Ordering::Acquire)
            || Instant::now() >= settle_deadline
        {
            return Err("waiting_network".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let binding = observation
        .bindings()
        .iter()
        .copied()
        .find(|b| b.ipv4)
        .ok_or("physical_binding_unavailable")?;
    let network = BoundNetwork::for_auxiliary_probe(&observation, binding)
        .map_err(|_| "physical_binding_unavailable")?;
    let private = AppRoot::open("WindowsClash").map_err(|_| "clash_private_store_unavailable")?;
    let deadline = Instant::now() + Duration::from_secs(45);
    for choice in candidates {
        if network.is_cancelled() {
            return Err("network_binding_changed".into());
        }
        if super::STOPPING.load(std::sync::atomic::Ordering::Acquire) || Instant::now() >= deadline
        {
            break;
        }
        let selected = chain_source::selected(root, dashboard.settings.front_port, &choice.name)?;
        if selected.fingerprint != choice.fingerprint {
            return Err("clash_config_changed".into());
        }
        let bytes = adapter_protocol::app::SecretText::new(serde_json::to_string(&json!({
            "name":selected.name,"server":selected.server,"port":selected.port,"cipher":selected.cipher,"password":selected.password
        })).map_err(|_| "clash_chain_configuration_invalid")?).into_value();
        let proxy = adapter_engine_mihomo::chain::UpstreamSs::decode(bytes.as_bytes())
            .map_err(|_| "clash_chain_configuration_invalid")?;
        let probe_root = private.path().join(format!(
            "chain-probe-{}",
            boot_id().map_err(|_| "random_unavailable")?
        ));
        let probe_runtime =
            PrivateRuntime::open(&probe_root).map_err(|_| "clash_private_store_unavailable")?;
        let measured = adapter_engine_mihomo::chain_probe::qualify_udp(
            &runtime.mihomo,
            &probe_runtime,
            &proxy,
            &network,
            deadline.min(Instant::now() + Duration::from_secs(12)),
        );
        match measured {
            Err(adapter_engine_mihomo::chain_probe::ProbeError::Cleanup) => {
                return Err("cleanup_uncertain".into())
            }
            Err(_) => continue,
            Ok(_) => {}
        }
        if network.is_cancelled() || super::STOPPING.load(std::sync::atomic::Ordering::Acquire) {
            return Err("network_binding_changed".into());
        }
        let current = chain_source::selected(root, dashboard.settings.front_port, &choice.name)?;
        if current.fingerprint != choice.fingerprint {
            return Err("clash_config_changed".into());
        }
        let latest = match super::transact(adapter_protocol::app::AppCommand::Dashboard)? {
            adapter_protocol::app::AppReply::Dashboard { dashboard } => dashboard,
            _ => return Err("backend_unavailable".into()),
        };
        if latest.boot_id != dashboard.boot_id
            || latest.settings.chain_selection != dashboard.settings.chain_selection
        {
            return Err("clash_config_changed".into());
        }
        if latest.operation.is_some() {
            return Err("operation_busy".into());
        }
        return match super::transact(adapter_protocol::app::AppCommand::ConfigureChain {
            proxy: adapter_protocol::app::SecretText::from_protected(bytes),
        })? {
            adapter_protocol::app::AppReply::Accepted { .. } => {
                Ok(json!({"accepted":true,"selected":choice.name,"udp_verified":true}))
            }
            adapter_protocol::app::AppReply::Error { code } => Err(code),
            _ => Err("invalid_response".into()),
        };
    }
    Err("clash_chain_no_working_route".into())
}

#[cfg(test)]
mod chain_preferences {
    use super::*;
    #[test]
    fn real_names_supply_only_ordering_hints() {
        assert_eq!(chain_preference("🇺🇸 美国 Y02"), 0);
        assert_eq!(chain_preference("Singapore 03"), 1);
        assert_eq!(chain_preference("英国Y01"), 2);
        assert_eq!(chain_preference("Unknown"), 3);
    }
}
