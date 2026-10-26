//! Read-only activity, per-user login preferences and passive tray/widget status.
use adapter_protocol::app::Dashboard;
use serde::Serialize;
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager,
};

#[cfg(windows)]
#[path = "../../../core/crates/agent/src/live_diagnostics.rs"]
mod event_store;

#[derive(Clone, Debug, Serialize)]
pub struct DesktopStatus {
    headline: String,
    relay: Option<String>,
    ping_ms: Option<u32>,
    ping_age_seconds: Option<u64>,
    state: String,
    stale: bool,
    status_age_seconds: Option<u64>,
}
impl Default for DesktopStatus {
    fn default() -> Self {
        Self {
            headline: "正在读取本机状态".into(),
            relay: None,
            ping_ms: None,
            ping_age_seconds: None,
            state: "unknown".into(),
            stale: true,
            status_age_seconds: None,
        }
    }
}
fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
fn snapshot(d: &Dashboard, now: u64) -> DesktopStatus {
    let relay = d
        .active_relay
        .as_ref()
        .filter(|s| {
            s.len() <= 128
                && s.contains('-')
                && s.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        .cloned();
    let connected = d.status == "connected" && d.physical_attachment == "available";
    let ping = d
        .connection
        .as_ref()
        .filter(|c| connected && Some(&c.relay) == relay.as_ref())
        .and_then(|c| c.ping)
        .filter(|p| p.rtt_ms <= 60_000 && p.measured_at <= now && now - p.measured_at <= 180);
    let (headline, state) = if d.physical_attachment == "unavailable" {
        ("本机离线，暂停恢复", "offline")
    } else if connected && !d.front_ready {
        ("本机转发入口待恢复", "degraded")
    } else if connected {
        match d.readiness.as_deref() {
            Some("ready") => (
                if d.connection.as_ref().is_some_and(|c| c.chained) {
                    "已连接 · 链式保底"
                } else {
                    match d.connection.as_ref().and_then(|c| c.transport.as_deref()) {
                        Some("wireguard-ipv6") => "已连接 · 原生 IPv6",
                        Some("wireguard-ipv4") => "已连接 · 原生 IPv4",
                        _ => "已连接 · SS 直连",
                    }
                },
                "connected",
            ),
            Some("degraded_dns") => ("已连接，DNS 待复测", "degraded"),
            _ => ("已连接，继续复测", "degraded"),
        }
    } else if let Some(p) = &d.recovery {
        (
            match p.stage.as_str() {
                "original_inlet" => "正在重试原入口",
                "same_relay_inlets" => "尝试同节点其他入口",
                "same_city" => "尝试同城备用节点",
                "native_ipv6" => "正在尝试原生 IPv6",
                "native_ipv4" => "正在尝试原生 IPv4",
                "chain_fallback" => "正在尝试链式保底",
                "returning_direct" => "正在尝试恢复直连",
                "verifying_original" | "confirming" => "正在复测原连接",
                "exhausted" => "本轮未恢复，等待重试",
                "waiting_network" => "等待本机网络稳定",
                _ => "正在恢复连接",
            },
            "recovering",
        )
    } else {
        ("尚未连接", "disconnected")
    };
    DesktopStatus {
        headline: headline.into(),
        relay,
        ping_ms: ping.map(|p| p.rtt_ms),
        ping_age_seconds: ping.map(|p| now - p.measured_at),
        state: state.into(),
        stale: false,
        status_age_seconds: None,
    }
}
struct StatusCache {
    dashboard: Option<(Dashboard, Instant)>,
}
pub struct UiState {
    cache: Mutex<StatusCache>,
    status_item: MenuItem<tauri::Wry>,
    ping_item: MenuItem<tauri::Wry>,
}
fn observation_instant(dashboard: &Dashboard, received: Instant) -> Option<Instant> {
    let timing = dashboard.status_observation.as_ref()?;
    if timing.age_ms > 3000 || timing.capture_ms > timing.age_ms {
        return None;
    }
    received.checked_sub(Duration::from_millis(timing.age_ms))
}
pub fn capture(app: &tauri::AppHandle, dashboard: &Dashboard) {
    let Some(observed) = observation_instant(dashboard, Instant::now()) else {
        return;
    };
    if let Some(state) = app.try_state::<UiState>() {
        if let Ok(mut cache) = state.cache.lock() {
            cache.dashboard = Some((dashboard.clone(), observed));
        };
    }
}
fn needs_poll(main_visible: bool, age: Option<Duration>) -> bool {
    match age {
        None => !main_visible,
        Some(age) => age >= Duration::from_millis(if main_visible { 2500 } else { 1000 }),
    }
}
fn current(app: &tauri::AppHandle) -> DesktopStatus {
    if crate::STOPPING.load(std::sync::atomic::Ordering::Acquire) {
        return DesktopStatus {
            headline: "正在停止后台，等待确认".into(),
            ..DesktopStatus::default()
        };
    }
    let state = app.state::<UiState>();
    let Ok(cache) = state.cache.lock() else {
        return DesktopStatus::default();
    };
    let Some((dashboard, received)) = &cache.dashboard else {
        return DesktopStatus::default();
    };
    with_freshness(snapshot(dashboard, unix_seconds()), received.elapsed())
}
fn with_freshness(mut s: DesktopStatus, age: Duration) -> DesktopStatus {
    s.status_age_seconds = Some(age.as_secs());
    if age > adapter_protocol::app_status::MAX_STATUS_AGE {
        s.stale = true;
        s.ping_ms = None;
        s.ping_age_seconds = None;
        s.state = "unknown".into();
        s.headline = "状态暂未更新".into();
    }
    s
}
fn tooltip(s: &DesktopStatus) -> String {
    let relay = s
        .relay
        .as_deref()
        .unwrap_or("暂无节点")
        .chars()
        .take(42)
        .collect::<String>();
    let latency = s.ping_ms.map_or_else(
        || "暂无近期 ICMP 测量".into(),
        |ms| format!("ICMP {ms} ms（{}秒前）", s.ping_age_seconds.unwrap_or(0)),
    );
    let age = s
        .status_age_seconds
        .map_or_else(|| "尚无状态记录".to_owned(), |age| format!("状态{age}秒前"));
    format!(
        "Mullvad Adapter\n{} · {}\n{}\n{}",
        s.headline, age, relay, latency
    )
    .chars()
    .take(120)
    .collect()
}
fn icon(state: &str) -> Vec<u8> {
    let dot = match state {
        "connected" => [25, 146, 111],
        "recovering" | "degraded" => [210, 143, 45],
        "offline" => [175, 82, 78],
        _ => [129, 146, 140],
    };
    let mut bytes = vec![0u8; 32 * 32 * 4];
    for y in 0..32 {
        for x in 0..32 {
            let dx = x as f32 - 14.0;
            let dy = y as f32 - 14.0;
            let r = (dx * dx + dy * dy).sqrt();
            let ring = (r - 11.5).abs() < 1.0;
            let meridian = ((dx / 5.3).powi(2) + (dy / 11.5).powi(2) - 1.0).abs() < 0.22;
            let latitude =
                r < 11.5 && ((dy - 5.0).abs() < 0.8 || (dy + 5.0).abs() < 0.8 || dy.abs() < 0.8);
            let distance = ((x as f32 - 25.0).powi(2) + (y as f32 - 25.0).powi(2)).sqrt();
            let color = if distance < 4.5 {
                Some(dot)
            } else if distance < 5.8 {
                Some([246, 250, 248])
            } else if ring || meridian || latitude {
                Some([43, 128, 119])
            } else {
                None
            };
            if let Some(c) = color {
                let i = (y * 32 + x) * 4;
                bytes[i..i + 4].copy_from_slice(&[c[0], c[1], c[2], 255]);
            }
        }
    }
    bytes
}
fn publish(app: &tauri::AppHandle) {
    let status = current(app);
    if let Some(tray) = app.tray_by_id("adapter-status") {
        let _ = tray.set_tooltip(Some(tooltip(&status)));
        let _ = tray.set_icon(Some(tauri::image::Image::new_owned(
            icon(&status.state),
            32,
            32,
        )));
    }
    let state = app.state::<UiState>();
    let _ = state.status_item.set_text(&status.headline);
    let _ = state.ping_item.set_text(status.ping_ms.map_or_else(
        || "ICMP：暂无近期测量".into(),
        |ms| {
            format!(
                "ICMP：{ms} ms · {}秒前",
                status.ping_age_seconds.unwrap_or(0)
            )
        },
    ));
    let _ = app.emit_to("status-widget", "desktop-status", &status);
}
fn main_window(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

static WIDGET_GATE: Mutex<()> = Mutex::new(());

fn show_widget(app: &tauri::AppHandle, enabled: bool) -> Result<(), String> {
    if !enabled {
        if let Some(w) = app.get_webview_window("status-widget") {
            w.destroy().map_err(|_| "widget_close_failed")?;
        }
        return Ok(());
    }
    if app.get_webview_window("status-widget").is_some() {
        return Ok(());
    }
    let window = tauri::WebviewWindowBuilder::new(
        app,
        "status-widget",
        tauri::WebviewUrl::App("index.html#status-widget".into()),
    )
    .title("Mullvad 连接状态")
    .inner_size(260.0, 80.0)
    .resizable(false)
    .decorations(false)
    .always_on_top(true)
    .skip_taskbar(true)
    .focused(false)
    .visible(false)
    .build()
    .map_err(|_| "widget_create_failed")?;
    if let Ok(Some(monitor)) = window.primary_monitor() {
        let area = monitor.work_area();
        let scale = monitor.scale_factor();
        let x = area.position.x + area.size.width as i32 - (276.0 * scale) as i32;
        let y = area.position.y + (60.0 * scale) as i32;
        let _ = window.set_position(tauri::PhysicalPosition::new(x, y));
    }
    window.show().map_err(|_| "widget_show_failed".into())
}

#[derive(Serialize)]
pub struct DesktopPreferences {
    autostart: bool,
    widget: bool,
    startup_error: Option<String>,
}
#[tauri::command]
pub async fn desktop_preferences() -> Result<DesktopPreferences, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let startup = adapter_platform::windows_startup::status();
        let widget = adapter_platform::windows_startup::widget_enabled();
        DesktopPreferences {
            autostart: startup.as_ref().copied().unwrap_or(false),
            widget: widget.as_ref().copied().unwrap_or(false),
            startup_error: startup.err().or_else(|| widget.err()),
        }
    })
    .await
    .map_err(|_| "desktop_request_failed".into())
}
#[tauri::command]
pub async fn set_autostart(window: tauri::Window, enabled: bool) -> Result<bool, String> {
    if window.label() != "main" {
        return Err("window_not_authorized".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        adapter_platform::windows_startup::set_enabled(enabled)
    })
    .await
    .map_err(|_| "desktop_request_failed".to_owned())?
}
#[tauri::command]
pub async fn set_status_widget(
    app: tauri::AppHandle,
    window: tauri::Window,
    enabled: bool,
) -> Result<bool, String> {
    if window.label() != "main" {
        return Err("window_not_authorized".into());
    }
    let _guard = WIDGET_GATE.try_lock().map_err(|_| "operation_busy")?;
    let previous = adapter_platform::windows_startup::widget_enabled()?;
    let actual = adapter_platform::windows_startup::set_widget_enabled(enabled)?;
    if let Err(error) = show_widget(&app, actual) {
        let _ = adapter_platform::windows_startup::set_widget_enabled(previous);
        return Err(error);
    }
    Ok(actual)
}
#[tauri::command]
pub fn desktop_status(app: tauri::AppHandle) -> DesktopStatus {
    current(&app)
}
#[tauri::command]
pub fn hide_status_widget(app: tauri::AppHandle, window: tauri::Window) -> Result<(), String> {
    if window.label() != "status-widget" {
        return Err("window_not_authorized".into());
    }
    let _guard = WIDGET_GATE.try_lock().map_err(|_| "operation_busy")?;
    adapter_platform::windows_startup::set_widget_enabled(false)?;
    show_widget(&app, false)
}
#[tauri::command]
pub fn drag_status_widget(window: tauri::Window) -> Result<(), String> {
    if window.label() != "status-widget" {
        return Err("window_not_authorized".into());
    }
    window
        .start_dragging()
        .map_err(|_| "widget_drag_failed".into())
}
#[tauri::command]
pub fn open_workspace(app: tauri::AppHandle) -> Result<(), String> {
    main_window(&app);
    Ok(())
}

#[cfg(windows)]
fn event_root() -> Result<std::path::PathBuf, String> {
    use windows_sys::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath},
    };
    let mut value = std::ptr::null_mut();
    if unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, std::ptr::null_mut(), &mut value) }
        < 0
        || value.is_null()
    {
        return Err("event_log_unavailable".into());
    }
    let result = unsafe {
        let mut len = 0;
        while len < 32768 && *value.add(len) != 0 {
            len += 1
        }
        let text = if len == 32768 {
            None
        } else {
            String::from_utf16(std::slice::from_raw_parts(value, len)).ok()
        };
        CoTaskMemFree(value.cast());
        text
    };
    Ok(
        std::path::PathBuf::from(result.ok_or("event_log_unavailable")?)
            .join("MullvadAdapter-Windows"),
    )
}
#[cfg(windows)]
#[tauri::command]
pub async fn read_recent_events() -> Result<event_store::EventPage, String> {
    tauri::async_runtime::spawn_blocking(|| {
        event_store::recent_events(&event_root()?, 500).map_err(|_| "event_log_unavailable".into())
    })
    .await
    .map_err(|_| "desktop_request_failed".to_owned())?
}
#[cfg(not(windows))]
#[tauri::command]
pub async fn read_recent_events() -> Result<serde_json::Value, String> {
    Err("event_log_unavailable".into())
}

pub fn setup(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let status = MenuItem::with_id(app, "status", "正在读取状态", false, None::<&str>)?;
    let ping = MenuItem::with_id(app, "ping", "ICMP：暂无近期测量", false, None::<&str>)?;
    let show = MenuItem::with_id(app, "show", "打开连接工作台", true, None::<&str>)?;
    let widget = MenuItem::with_id(app, "widget", "显示／隐藏小状态窗", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出界面（后台继续运行）", true, None::<&str>)?;
    let stop = MenuItem::with_id(app, "stop", "停止后台并退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&status, &ping, &show, &widget, &stop, &quit])?;
    app.manage(UiState {
        cache: Mutex::new(StatusCache { dashboard: None }),
        status_item: status,
        ping_item: ping,
    });
    TrayIconBuilder::with_id("adapter-status")
        .icon(tauri::image::Image::new_owned(icon("unknown"), 32, 32))
        .tooltip("Mullvad Adapter · 正在读取本机状态")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                main_window(tray.app_handle())
            }
        })
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => main_window(app),
            "quit" => app.exit(0),
            "stop" => {
                let _ = crate::begin_shutdown(app.clone());
            }
            "widget" => {
                // WebView2 creation in a synchronous event handler can deadlock.
                // A separate worker also keeps tray handling responsive.
                let handle = app.clone();
                tauri::async_runtime::spawn_blocking(move || {
                    let Ok(_guard) = WIDGET_GATE.try_lock() else {
                        return;
                    };
                    if let Ok(previous) = adapter_platform::windows_startup::widget_enabled() {
                        let enabled = !previous;
                        if adapter_platform::windows_startup::set_widget_enabled(enabled).is_ok()
                            && show_widget(&handle, enabled).is_err()
                        {
                            let _ = adapter_platform::windows_startup::set_widget_enabled(previous);
                        }
                    }
                });
            }
            _ => {}
        })
        .build(app)?;
    if !std::env::args_os().any(|arg| arg == "--autostart") {
        main_window(app.handle());
    }
    if adapter_platform::windows_startup::widget_enabled().unwrap_or(false) {
        let _ = show_widget(app.handle(), true);
    }
    let handle = app.handle().clone();
    std::thread::Builder::new()
        .name("desktop-passive-status".into())
        .spawn(move || loop {
            if !crate::STOPPING.load(std::sync::atomic::Ordering::Acquire) {
                let main_visible = handle
                    .get_webview_window("main")
                    .and_then(|w| Some(w.is_visible().ok()? && !w.is_minimized().ok()?))
                    .unwrap_or(true);
                let age = handle
                    .state::<UiState>()
                    .cache
                    .lock()
                    .ok()
                    .and_then(|cache| cache.dashboard.as_ref().map(|(_, at)| at.elapsed()));
                // Reuse recent main-window observations. An old cache also needs
                // refreshing when the window's renderer is stalled. Reads use
                // their own pipe/gate, never the foreground control lane.
                if needs_poll(main_visible, age) {
                    if let Ok(adapter_protocol::app::AppReply::Dashboard { dashboard }) =
                        crate::transact(adapter_protocol::app::AppCommand::Dashboard)
                    {
                        capture(&handle, &dashboard);
                    }
                }
            }
            // Explicit stop can remain unconfirmed; do not freeze a healthy icon.
            publish(&handle);
            std::thread::sleep(Duration::from_millis(1500));
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observation_age_is_not_reset_by_tray_capture_and_unknown_timing_is_rejected() {
        let mut d = dashboard();
        let now = Instant::now();
        assert!(observation_instant(&d, now).is_none());
        d.status_observation = Some(adapter_protocol::app::StatusObservation {
            age_ms: 2400,
            capture_ms: 2,
            native_elapsed_ms: 0,
        });
        let observed = observation_instant(&d, now).unwrap();
        assert_eq!(now.duration_since(observed), Duration::from_millis(2400));
        let s = with_freshness(
            snapshot(&d, 1000),
            now.duration_since(observed) + Duration::from_secs(1),
        );
        assert!(s.stale);
        assert_eq!(s.status_age_seconds, Some(3));
        assert_eq!(s.ping_ms, None);
        d.status_observation.as_mut().unwrap().age_ms = 3001;
        assert!(observation_instant(&d, now).is_none());
    }
    #[test]
    fn foreground_replies_are_reused_without_an_extra_bridge_poll() {
        assert!(!needs_poll(true, None));
        assert!(needs_poll(true, Some(Duration::from_secs(99))));
        assert!(!needs_poll(false, Some(Duration::from_millis(500))));
        assert!(needs_poll(false, Some(Duration::from_secs(1))));
        assert!(needs_poll(false, None));
        assert!(needs_poll(false, Some(Duration::from_secs(7))));
    }
    #[test]
    fn icon_is_a_real_globe_with_status_colour() {
        let a = icon("connected");
        let b = icon("offline");
        assert_eq!(a.len(), 32 * 32 * 4);
        assert_ne!(a, b);
        assert!(a.chunks_exact(4).any(|p| p[3] == 255));
        assert!(a.chunks_exact(4).any(|p| p[3] == 0));
    }
    fn dashboard() -> Dashboard {
        serde_json::from_value(serde_json::json!({
            "sequence":1,"boot_id":"test","build":"test","source_sha":"test",
            "status":"connected","physical_attachment":"available",
            "settings":adapter_protocol::app::Settings::default(),
            "front_ready":true,"front_selected":"adapter","identity_configured":true,
            "device_name":null,"public_key":null,"active_relay":"test-city-wg-001",
            "connection":{"relay":"test-city-wg-001","city":"test-city","inlet":"test","interface_index":1,"instance":1,"phase":"connected","ip":true,"dns":true,"https":true,"ping":{"rtt_ms":38,"measured_at":990}},
            "readiness":"ready","cities":[],"metadata_source":"test","metadata_updated_at":null,
            "account":adapter_protocol::app::Account::default(),"operation":null,"last_error":null,
            "logs_path":"","last_report_path":null,"logging_degraded":false,"logging_dropped":0,
            "quick_test":null,"city_candidates":[]
        })).unwrap()
    }
    #[test]
    fn latency_requires_fresh_current_relay_and_physical_network() {
        let mut d = dashboard();
        assert_eq!(snapshot(&d, 1000).ping_ms, Some(38));
        assert_eq!(snapshot(&d, 1171).ping_ms, None);
        assert_eq!(snapshot(&d, 989).ping_ms, None);
        d.active_relay = Some("test-city-wg-002".into());
        assert_eq!(snapshot(&d, 1000).ping_ms, None);
        d.active_relay = Some("test-city-wg-001".into());
        d.physical_attachment = "unavailable".into();
        let s = snapshot(&d, 1000);
        assert_eq!(s.ping_ms, None);
        assert_eq!(s.state, "offline");
    }
    #[test]
    fn backend_connected_with_broken_front_cannot_look_fully_ready() {
        let mut d = dashboard();
        d.front_ready = false;
        let s = snapshot(&d, 1000);
        assert_eq!(s.state, "degraded");
        assert!(s.headline.contains("入口待恢复"));
    }
    #[test]
    fn stale_snapshot_cannot_report_current_latency_or_disconnect() {
        let s = with_freshness(snapshot(&dashboard(), 1000), Duration::from_secs(16));
        assert!(s.stale);
        assert_eq!(s.state, "unknown");
        assert_eq!(s.ping_ms, None);
        assert_eq!(s.relay.as_deref(), Some("test-city-wg-001"));
        assert!(s.headline.contains("未更新"));
    }
    #[test]
    fn no_fake_latency_in_tooltip() {
        let s = DesktopStatus::default();
        let t = tooltip(&s);
        assert!(t.contains("暂无近期"));
        assert!(!t.contains("0 ms"));
        assert!(t.encode_utf16().count() < 128);
    }
}
