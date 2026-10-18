//! Version-2 application IPC; separate from the retained mock protocol.
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
pub const APP_API_MAJOR: u16 = 2;

/// Explicit secret IPC value; Debug is always redacted. Never put it in receipt caches.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretText(#[serde(deserialize_with = "secret")] Zeroizing<String>);
fn secret<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
impl std::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}
impl SecretText {
    pub fn from_protected(value: Zeroizing<String>) -> Self {
        Self(value)
    }
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }
    pub fn into_value(self) -> Zeroizing<String> {
        self.0
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub favorite_cities: Vec<String>,
    pub selected_city: Option<String>,
    pub bootstrap_port: Option<u16>,
    pub front_port: u16,
    pub automatic_recovery: bool,
    pub required_multihop: bool,
    pub required_pq: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            favorite_cities: vec![],
            selected_city: None,
            bootstrap_port: None,
            front_port: 17890,
            automatic_recovery: true,
            required_multihop: false,
            required_pq: false,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.favorite_cities.len() > 3
            || !(1024..=65533).contains(&self.front_port)
            || [17920, 17921, 17930, 17931].contains(&self.front_port)
            || [17920, 17921, 17930, 17931].contains(&self.front_port.saturating_add(2))
            || self.bootstrap_port.is_some_and(|p| {
                p < 1024
                    || p == self.front_port
                    || p == self.front_port.saturating_add(2)
                    || [17920, 17921, 17930, 17931].contains(&p)
            })
            || self.favorite_cities.iter().any(|c| !super::valid_city(c))
            || self
                .favorite_cities
                .iter()
                .enumerate()
                .any(|(i, c)| self.favorite_cities[..i].contains(c))
            || self
                .selected_city
                .as_ref()
                .is_some_and(|c| !self.favorite_cities.contains(c))
        {
            return Err("invalid_settings");
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppRequest {
    pub major: u16,
    pub boot_id: String,
    pub request_id: String,
    pub command: AppCommand,
}
impl AppRequest {
    pub fn validate(&self, boot: &str) -> Result<(), &'static str> {
        if self.major != APP_API_MAJOR {
            return Err("incompatible_protocol");
        }
        if self.boot_id != boot {
            return Err("boot_changed_reconcile");
        }
        if self.request_id.is_empty()
            || self.request_id.len() > 64
            || !self
                .request_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("invalid_request_id");
        }
        match &self.command {
            AppCommand::CreateDevice { confirm: false }
            | AppCommand::UseCreatedDevice { confirm: false }
            | AppCommand::RevealKey { confirm: false } => Err("confirmation_required"),
            AppCommand::SaveSettings { settings } => settings.validate(),
            AppCommand::ConnectRelay { hostname }
                if hostname.is_empty()
                    || hostname.len() > 128
                    || !hostname
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') =>
            {
                Err("invalid_relay")
            }
            AppCommand::Relays { page, .. } if *page > 128 => Err("invalid_page"),
            AppCommand::SelectCity { city } if !super::valid_city(city) => Err("invalid_city"),
            AppCommand::QuickTest { city } | AppCommand::FullTest { city }
                if !super::valid_city(city) =>
            {
                Err("invalid_city")
            }
            AppCommand::Relays {
                city: Some(city), ..
            } if !super::valid_city(city) => Err("invalid_city"),
            _ => Ok(()),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AppCommand {
    Dashboard,
    SaveSettings { settings: Settings },
    RefreshCatalogue,
    Relays { city: Option<String>, page: u16 },
    SelectCity { city: String },
    Connect,
    ConnectRelay { hostname: String },
    Disconnect,
    CancelOperation,
    QuickTest { city: String },
    FullTest { city: String },
    AccountLogin { account: SecretText },
    AccountRefresh,
    AccountLogout,
    RemoveDevice { device_id: String },
    CreateDevice { confirm: bool },
    UseCreatedDevice { confirm: bool },
    RevealKey { confirm: bool },
    RedeemVoucher { voucher: SecretText },
    ExportReport,
    Shutdown,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct City {
    pub id: String,
    pub name: String,
    pub country: String,
    pub relay_count: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Relay {
    pub hostname: String,
    pub city: String,
    pub active: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub shadowsocks: bool,
    pub last_ping_ms: Option<u64>,
    pub readiness: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub created: String,
    pub current: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceDraft {
    pub state: String,
    pub public_key: String,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Account {
    pub authenticated: bool,
    pub expiry: Option<String>,
    pub devices: Vec<Device>,
    pub error_code: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuickTestState {
    pub city: String,
    pub total: usize,
    pub completed: usize,
    pub replies: usize,
    pub no_reply: usize,
    pub local_errors: usize,
    pub discarded: usize,
    pub unmeasured: usize,
    pub active: bool,
    pub cancelled: bool,
    pub finished_at: Option<u64>,
}
impl QuickTestState {
    pub fn valid(&self) -> bool {
        super::valid_city(&self.city)
            && (1..=256).contains(&self.total)
            && self.completed <= self.total
            && [
                self.replies,
                self.no_reply,
                self.local_errors,
                self.discarded,
            ]
            .iter()
            .all(|n| *n <= self.completed)
            && self.replies + self.no_reply + self.local_errors + self.discarded == self.completed
            && self.unmeasured == self.total - self.completed
            && self.active == self.finished_at.is_none()
            && !(self.active && self.cancelled)
            && self.finished_at.is_none_or(|t| t <= 9_007_199_254_740_991)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CityCandidate {
    pub city: String,
    pub hostname: String,
    pub ping_ms: u64,
    pub measured_at: u64,
}
/// Public connection facts only, suitable for bounded diagnostics.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeMeasurements {
    pub ip: ProbeOutcome,
    pub dns: ProbeOutcome,
    pub https: ProbeOutcome,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    Passed,
    Rejected,
    Cancelled,
    Deadline,
    Timeout,
    Unavailable,
    NotRunDnsFailed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionInfo {
    pub relay: String,
    pub city: String,
    pub inlet: String,
    pub interface_index: u32,
    pub instance: u64,
    pub phase: String,
    pub ip: Option<bool>,
    pub dns: Option<bool>,
    pub https: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probes: Option<ProbeMeasurements>,
}
impl ConnectionInfo {
    pub fn valid(&self) -> bool {
        self.relay.len() <= 128
            && !self.relay.is_empty()
            && self
                .relay
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            && super::valid_city(&self.city)
            && self.inlet.parse::<std::net::SocketAddr>().is_ok()
            && self.interface_index != 0
            && self.instance != 0
            && self.probes.as_ref().is_none_or(|p| {
                self.ip == Some(matches!(p.ip, ProbeOutcome::Passed))
                    && self.dns == Some(matches!(p.dns, ProbeOutcome::Passed))
                    && self.https == Some(matches!(p.https, ProbeOutcome::Passed))
                    && !matches!(p.ip, ProbeOutcome::NotRunDnsFailed)
                    && !matches!(p.dns, ProbeOutcome::NotRunDnsFailed)
                    && (!matches!(p.https, ProbeOutcome::NotRunDnsFailed)
                        || !matches!(p.dns, ProbeOutcome::Passed))
            })
            && matches!(
                self.phase.as_str(),
                "starting" | "prepared" | "connected" | "health" | "failed" | "stopped"
            )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dashboard {
    pub sequence: u64,
    pub boot_id: String,
    pub build: String,
    pub source_sha: String,
    pub status: String,
    pub physical_attachment: String,
    pub settings: Settings,
    pub front_ready: bool,
    pub front_selected: String,
    pub identity_configured: bool,
    #[serde(default)]
    pub device_draft: Option<DeviceDraft>,
    pub device_name: Option<String>,
    pub public_key: Option<String>,
    pub active_relay: Option<String>,
    #[serde(default)]
    pub connection: Option<ConnectionInfo>,
    pub readiness: Option<String>,
    pub cities: Vec<City>,
    pub metadata_source: String,
    pub metadata_updated_at: Option<u64>,
    pub account: Account,
    pub operation: Option<String>,
    pub last_error: Option<String>,
    pub logs_path: String,
    pub last_report_path: Option<String>,
    pub logging_degraded: bool,
    pub logging_dropped: u64,
    pub quick_test: Option<QuickTestState>,
    pub city_candidates: Vec<CityCandidate>,
}
impl Dashboard {
    /// Renderer passes only an expected public report name, never a path/text.
    pub fn report_path(&self, expected_name: &str) -> Result<&str, &'static str> {
        verified_report_path(self.last_report_path.as_deref(), expected_name)
    }
}
fn verified_report_path<'a>(
    path: Option<&'a str>,
    expected_name: &str,
) -> Result<&'a str, &'static str> {
    let id = expected_name
        .strip_prefix("report-")
        .and_then(|s| s.strip_suffix(".json"))
        .ok_or("invalid_report_id")?;
    if id.len() != 36
        || !id.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err("invalid_report_id");
    }
    let path = path.ok_or("report_not_available")?;
    if path.rsplit(['\\', '/']).next() != Some(expected_name) {
        return Err("report_changed_reconcile");
    }
    Ok(path)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AppReply {
    Hello {
        major: u16,
        boot_id: String,
        build: String,
        /// Older v2 hosts decode as unknown, never as the current packaged build.
        #[serde(default)]
        source_sha: String,
    },
    Dashboard {
        dashboard: Box<Dashboard>,
    },
    Relays {
        relays: Vec<Relay>,
        page: u16,
        total: usize,
    },
    Accepted {
        operation_id: String,
    },
    Report {
        path: String,
    },
    PrivateKey {
        private_key: SecretText,
    },
    Error {
        code: String,
    },
}

impl AppReply {
    /// Fence every request (including credentials) before sending it to a host.
    /// The pipe authenticates the user/session; this also binds the packaged code.
    pub fn verified_boot_id(
        &self,
        expected_source: &str,
        expected_build: &str,
    ) -> Result<&str, &'static str> {
        if expected_source.len() != 40
            || !expected_source.bytes().all(|b| b.is_ascii_hexdigit())
            || expected_build.is_empty()
        {
            return Err("runtime_build_identity_missing");
        }
        match self {
            Self::Hello {
                major,
                boot_id,
                build,
                source_sha,
            } if *major == APP_API_MAJOR => {
                if source_sha != expected_source || build != expected_build {
                    return Err("backend_version_mismatch");
                }
                if boot_id.is_empty()
                    || boot_id.len() > 128
                    || !boot_id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                {
                    return Err("invalid_handshake");
                }
                Ok(boot_id)
            }
            _ => Err("incompatible_backend"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settings_reject_invalid_favorites_ports_and_selected_city() {
        let mut value = Settings::default();
        assert!(value.validate().is_ok());
        value.favorite_cities = vec!["us-sjc".into(), "us-sjc".into()];
        assert!(value.validate().is_err());
        value.favorite_cities = vec!["us-sjc".into()];
        value.selected_city = Some("jp-tyo".into());
        assert!(value.validate().is_err());
        value.selected_city = Some("us-sjc".into());
        value.bootstrap_port = Some(value.front_port);
        assert!(value.validate().is_err());
        value.bootstrap_port = Some(17893);
        assert!(value.validate().is_ok());
    }
    #[test]
    fn live_commands_never_decode_as_mock_commands() {
        let json = r#"{"major":2,"boot_id":"boot","request_id":"login","command":{"kind":"account_login","account":"0000000000000000"}}"#;
        let request: AppRequest = serde_json::from_str(json).unwrap();
        assert!(request.validate("boot").is_ok());
        assert!(serde_json::from_str::<super::super::Request>(json).is_err());
        assert_eq!(request.validate("other"), Err("boot_changed_reconcile"));
    }

    #[test]
    fn current_ui_rejects_old_v2_and_different_source_before_credentials() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let old: AppReply = serde_json::from_str(
            r#"{"kind":"hello","major":2,"boot_id":"boot-1","build":"0.1.0"}"#,
        )
        .unwrap();
        assert_eq!(
            old.verified_boot_id(sha, "0.1.0"),
            Err("backend_version_mismatch")
        );
        let mut value = serde_json::to_value(old).unwrap();
        value["source_sha"] = sha.into();
        let hello: AppReply = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(hello.verified_boot_id(sha, "0.1.0"), Ok("boot-1"));
        assert_eq!(
            hello.verified_boot_id("", "0.1.0"),
            Err("runtime_build_identity_missing")
        );
        for (field, replacement, error) in [
            (
                "source_sha",
                serde_json::json!("ffffffffffffffffffffffffffffffffffffffff"),
                "backend_version_mismatch",
            ),
            (
                "build",
                serde_json::json!("0.0.1"),
                "backend_version_mismatch",
            ),
            ("major", serde_json::json!(1), "incompatible_backend"),
            ("boot_id", serde_json::json!(""), "invalid_handshake"),
            (
                "boot_id",
                serde_json::json!("boot\ninvalid"),
                "invalid_handshake",
            ),
        ] {
            let mut changed = value.clone();
            changed[field] = replacement;
            let hello: AppReply = serde_json::from_value(changed).unwrap();
            assert_eq!(hello.verified_boot_id(sha, "0.1.0"), Err(error));
        }
    }
    #[test]
    fn clipboard_report_fences_name_against_current_completed_report() {
        let name = "report-12345678-abcd-1234-abcd-123456789abc.json";
        let path = format!("\\\\?\\C:\\用户\\logs\\{name}");
        assert_eq!(verified_report_path(Some(&path), name), Ok(path.as_str()));
        assert_eq!(
            verified_report_path(None, name),
            Err("report_not_available")
        );
        let old_name = "report-00000000-0000-0000-0000-000000000000.json";
        assert_eq!(
            verified_report_path(Some(&path), old_name),
            Err("report_changed_reconcile")
        );
        for bad in [
            path.as_str(),
            "report-12345678Xabcd-1234-abcd-123456789abc.json",
            "private-key.json",
        ] {
            assert_eq!(
                verified_report_path(Some(&path), bad),
                Err("invalid_report_id")
            );
        }
    }
}
