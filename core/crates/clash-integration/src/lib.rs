//! Current-profile Clash Verge integration. No account/tunnel ownership here.
//! The renderer receives allowlisted summaries, never runtime YAML or API secrets.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use serde_yaml_ng::Value as Yaml;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::Duration,
};

pub mod portable;
pub mod profile_service;

/// Optional generated source: an empty/new client does not need a selected
/// profile or extension script. Existing unreadable content is never ignored.
pub fn portable_source(root: &Path) -> Result<Option<Value>> {
    safe_path(root)?;
    let path = root.join("clash-verge.yaml");
    if !path.exists() {
        return Ok(None);
    }
    parse(&read(&path)?).map(Some)
}

#[cfg(windows)]
mod pipe_transport;

pub const NODE: &str = "Mullvad Adapter Local [managed]";
const MARKER: &str = "\n// BEGIN MULLVAD ADAPTER MANAGED v1\n";
const MAX: u64 = 16 * 1024 * 1024;
pub type Result<T> = std::result::Result<T, String>;
fn err(code: &str) -> String {
    format!("clash_{code}")
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn text<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key)?.as_str()
}
fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && !s.chars().any(|c| c.is_control() || c == ',')
}
fn ordinary_server(p: &Value, front: u16) -> bool {
    let Some(server) = text(p, "server") else {
        return false;
    };
    let Some(kind) = text(p, "type") else {
        return false;
    };
    if !matches!(
        kind,
        "ss" | "ssr"
            | "vmess"
            | "vless"
            | "trojan"
            | "hysteria"
            | "hysteria2"
            | "tuic"
            | "snell"
            | "socks5"
            | "http"
            | "ssh"
            | "anytls"
    ) {
        return false;
    }
    if server.eq_ignore_ascii_case("localhost")
        || server.to_ascii_lowercase().ends_with(".localhost")
    {
        return false;
    }
    if server.parse::<std::net::IpAddr>().ok().is_some_and(|ip|ip.is_loopback()||ip.is_unspecified()||matches!(ip,std::net::IpAddr::V6(v) if v.to_ipv4_mapped().is_some_and(|v|v.is_loopback()||v.is_unspecified()))) {return false}
    p.get("dialer-proxy").is_none()
        && p.get("underlying-proxy").is_none()
        && p["port"].as_u64() != Some(front as u64)
}
fn parse(bytes: &[u8]) -> Result<Value> {
    let y: Yaml = serde_yaml_ng::from_slice(bytes).map_err(|_| err("invalid_yaml"))?;
    let v = serde_json::to_value(y).map_err(|_| err("invalid_yaml"))?;
    if !v.is_object() {
        return Err(err("invalid_yaml"));
    }
    Ok(v)
}
fn yaml(v: &Value) -> Result<Vec<u8>> {
    serde_yaml_ng::to_string(v)
        .map(String::into_bytes)
        .map_err(|_| err("invalid_yaml"))
}
fn safe_path(path: &Path) -> Result<()> {
    if !path.is_absolute() || path.components().any(|p| matches!(p, Component::ParentDir)) {
        return Err(err("unsafe_path"));
    }
    for p in path.ancestors() {
        match fs::symlink_metadata(p) {
            Ok(m) => {
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if m.file_attributes() & 0x400 != 0 {
                        return Err(err("unsafe_path"));
                    }
                }
                if m.file_type().is_symlink() {
                    return Err(err("unsafe_path"));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(err("file_access")),
        }
    }
    Ok(())
}
fn read(path: &Path) -> Result<Vec<u8>> {
    safe_path(path)?;
    let f = fs::File::open(path).map_err(|_| err("file_access"))?;
    let m = f.metadata().map_err(|_| err("file_access"))?;
    if !m.is_file() || m.len() > MAX {
        return Err(err("file_too_large"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if m.nlink() != 1 {
            return Err(err("unsafe_path"));
        }
    }
    let mut out = Vec::new();
    f.take(MAX + 1)
        .read_to_end(&mut out)
        .map_err(|_| err("file_access"))?;
    if out.len() as u64 > MAX {
        return Err(err("file_too_large"));
    }
    Ok(out)
}
fn create(path: &Path, bytes: &[u8]) -> Result<()> {
    safe_path(path)?;
    #[cfg(windows)]
    let mut f = adapter_platform::windows_user_file::open_writer(path, false, true)
        .map_err(|_| err("write_failed"))?;
    #[cfg(not(windows))]
    let mut f = {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(path).map_err(|_| err("write_failed"))?
    };
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|_| err("write_failed"))
}
fn replace(path: &Path, expected: &[u8], replacement: &[u8]) -> Result<()> {
    if read(path)? != expected {
        return Err(err("config_changed"));
    }
    let tmp = path.with_file_name(format!(
        ".mullvad-{}-{}.tmp",
        std::process::id(),
        &hash(replacement)[..16]
    ));
    create(&tmp, replacement)?;
    let result = (|| {
        if read(path)? != expected {
            return Err(err("config_changed"));
        }
        fs::rename(&tmp, path).map_err(|_| err("write_failed"))?;
        if read(path)? != replacement {
            return Err(err("write_unconfirmed"));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Choice {
    pub target_group: String,
    pub ordinary_proxy: String,
    pub front_port: u16,
}
#[derive(Debug, Serialize)]
pub struct View {
    pub directory: String,
    pub profile: String,
    pub script: String,
    pub proxy_port: Option<u16>,
    pub tun_enabled: bool,
    pub groups: Vec<String>,
    pub ordinary_proxies: Vec<String>,
    pub managed: bool,
    pub saved: bool,
    pub conflict: bool,
    pub active: bool,
    pub target_group: Option<String>,
    pub ordinary_proxy: Option<String>,
    pub backup_path: Option<String>,
    pub other_profiles: Vec<String>,
}
#[derive(Debug, Serialize)]
pub struct Preview {
    pub id: String,
    pub config: String,
    pub summary: View,
}
#[derive(Debug, Serialize)]
pub struct Outcome {
    pub saved: bool,
    pub active: bool,
    pub code: String,
    pub backup_path: String,
}

/// Errors are closed codes; do not attach HTTP bodies, file contents or secrets.
pub trait Controller {
    fn get(&self, path: &str) -> Result<Value>;
    fn put(&self, path: &str, body: &Value) -> Result<()>;
    fn validate(&self, path: &Path) -> Result<()>;
}
#[derive(Debug, PartialEq, Eq)]
enum ControlEndpoint {
    Pipe(String),
    Http(std::net::SocketAddr),
}
fn control_endpoint(v: &Value, front: u16, windows: bool) -> Result<ControlEndpoint> {
    // Use the client's existing local mechanism; never enable a new endpoint.
    if let Some(pipe) = text(v, "external-controller-pipe").filter(|s| !s.trim().is_empty()) {
        let suffix = pipe.strip_prefix(r"\\.\pipe\").unwrap_or("");
        if suffix.is_empty()
            || suffix.len() > 200
            || suffix.contains("..")
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(err("controller_nonlocal"));
        }
        if !windows {
            return Err(err("controller_pipe_unsupported"));
        }
        return Ok(ControlEndpoint::Pipe(pipe.to_owned()));
    }
    let text = text(v, "external-controller")
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| err("controller_missing"))?;
    let address: std::net::SocketAddr = text.parse().map_err(|_| err("controller_nonlocal"))?;
    if !(address.ip().is_loopback() || address.ip().is_unspecified())
        || address.port() < 1024
        || [front, front.saturating_add(2), 17920, 17921, 17930, 17931].contains(&address.port())
    {
        return Err(err("controller_nonlocal"));
    }
    Ok(ControlEndpoint::Http(address))
}
pub struct LocalController {
    agent: ureq::Agent,
    base: String,
    authorization: Option<ureq::http::HeaderValue>,
    transport: &'static str,
    engine: Option<(PathBuf, PathBuf)>,
}
/// Compatibility name for existing isolated HTTP callers.
pub type HttpController = LocalController;
impl LocalController {
    pub fn from_config(v: &Value, front: u16) -> Result<Self> {
        let endpoint = control_endpoint(v, front, cfg!(windows))?;
        let config = ureq::Agent::config_builder()
            .proxy(None)
            .max_redirects(0)
            .max_idle_connections(0)
            .timeout_global(Some(Duration::from_secs(5)))
            .timeout_connect(Some(Duration::from_secs(1)))
            .http_status_as_error(false)
            .build();
        if let ControlEndpoint::Pipe(name) = &endpoint {
            #[cfg(windows)]
            return Ok(Self {
                agent: ureq::Agent::with_parts(
                    config,
                    pipe_transport::PipeConnector(name.clone()),
                    ureq::unversioned::resolver::DefaultResolver::default(),
                ),
                base: "http://127.0.0.1:1".into(), // virtual URI; no TCP socket
                authorization: None, // Mihomo pipe API relies on Windows access control, not secret.
                transport: "windows_pipe",
                engine: None,
            });
            #[cfg(not(windows))]
            {
                let _ = name;
                return Err(err("controller_pipe_unsupported"));
            }
        }
        let ControlEndpoint::Http(address) = endpoint else {
            unreachable!()
        };
        let secret = text(v, "secret").unwrap_or("");
        if secret.len() > 4096 || secret.chars().any(char::is_control) {
            return Err(err("controller_auth"));
        }
        let mut authorization = ureq::http::HeaderValue::from_str(&format!("Bearer {secret}"))
            .map_err(|_| err("controller_auth"))?;
        authorization.set_sensitive(true);
        let host = if address.is_ipv6() {
            "[::1]"
        } else {
            "127.0.0.1"
        };
        Ok(Self {
            agent: config.into(),
            base: format!("http://{host}:{}", address.port()),
            authorization: Some(authorization),
            transport: "loopback_http",
            engine: None,
        })
    }
    pub fn with_engine(mut self, engine: PathBuf, home: PathBuf) -> Self {
        self.engine = Some((engine, home));
        self
    }
    pub fn transport_kind(&self) -> &'static str {
        self.transport
    }
}
impl Controller for LocalController {
    fn validate(&self, path: &Path) -> Result<()> {
        use std::process::{Command, Stdio};
        let (engine, home) = self
            .engine
            .as_ref()
            .ok_or_else(|| err("validation_required"))?;
        let mut command = Command::new(engine);
        command
            .args(["-t", "-d"])
            .arg(home)
            .arg("-f")
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().map_err(|_| err("validation_failed"))?;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(s)) => {
                    return if s.success() {
                        Ok(())
                    } else {
                        Err(err("validation_failed"))
                    }
                }
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(err("validation_failed"));
                }
            }
        }
    }
    fn get(&self, path: &str) -> Result<Value> {
        let mut request = self.agent.get(format!("{}{path}", self.base));
        if let Some(auth) = &self.authorization {
            request = request.header("Authorization", auth.clone());
        }
        let mut r = request.call().map_err(|_| err("controller_unavailable"))?;
        if r.status().as_u16() != 200 {
            return Err(err(if matches!(r.status().as_u16(), 401 | 403) {
                "controller_auth"
            } else {
                "controller_response"
            }));
        }
        r.body_mut()
            .with_config()
            .limit(MAX)
            .read_json()
            .map_err(|_| err("controller_response"))
    }
    fn put(&self, path: &str, body: &Value) -> Result<()> {
        let mut request = self.agent.put(format!("{}{path}", self.base));
        if let Some(auth) = &self.authorization {
            request = request.header("Authorization", auth.clone());
        }
        let r = request
            .send_json(body)
            .map_err(|_| err("activation_unconfirmed"))?;
        if matches!(r.status().as_u16(), 200 | 204) {
            Ok(())
        } else {
            Err(err("activation_unconfirmed"))
        }
    }
}
fn encoded(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}
struct Snapshot {
    index: Vec<u8>,
    runtime: Vec<u8>,
    script: Vec<u8>,
    script_path: PathBuf,
    config: Value,
    profile: String,
}
fn preview_id(s: &Snapshot, c: &Choice) -> String {
    let mut digest = Sha256::new();
    for bytes in [
        &s.index,
        &s.runtime,
        &s.script,
        &serde_json::to_vec(c).unwrap(),
    ] {
        digest.update(bytes);
        digest.update([0]);
    }
    format!("{:x}", digest.finalize())
}
fn snapshot(root: &Path) -> Result<Snapshot> {
    let index = read(&root.join("profiles.yaml"))?;
    let profiles = parse(&index)?;
    let current = text(&profiles, "current").ok_or_else(|| err("profile_missing"))?;
    let items = profiles["items"]
        .as_array()
        .ok_or_else(|| err("profile_missing"))?;
    let profile = items
        .iter()
        .find(|p| text(p, "uid") == Some(current))
        .ok_or_else(|| err("profile_missing"))?;
    let script_id = profile["option"]["script"]
        .as_str()
        .ok_or_else(|| err("script_missing"))?;
    let script_item = items
        .iter()
        .find(|p| text(p, "uid") == Some(script_id) && text(p, "type") == Some("script"))
        .ok_or_else(|| err("script_missing"))?;
    let filename = text(script_item, "file").ok_or_else(|| err("script_missing"))?;
    if script_id == "Script"
        || items.iter().any(|p| {
            text(p, "uid") != Some(current) && p["option"]["script"].as_str() == Some(script_id)
        })
        || items
            .iter()
            .filter(|p| text(p, "type") == Some("script") && text(p, "file") == Some(filename))
            .count()
            != 1
    {
        return Err(err("script_shared"));
    }
    if filename.is_empty()
        || filename.len() > 200
        || filename.contains(['/', '\\', ':'])
        || !filename.ends_with(".js")
        || filename.contains("..")
    {
        return Err(err("unsafe_path"));
    }
    let script_path = root.join("profiles").join(filename);
    let script = read(&script_path)?;
    std::str::from_utf8(&script).map_err(|_| err("script_encoding"))?;
    let runtime = read(&root.join("clash-verge.yaml"))?;
    let config = parse(&runtime)?;
    Ok(Snapshot {
        index,
        runtime,
        script,
        script_path,
        config,
        profile: text(profile, "name")
            .filter(|n| valid_name(n))
            .unwrap_or("当前订阅")
            .to_owned(),
    })
}
fn node(front: u16) -> Value {
    json!({"name":NODE,"type":"socks5","server":"127.0.0.1","port":front,"udp":true})
}
fn options(config: &Value, front: u16) -> (Vec<String>, Vec<String>) {
    let groups = config["proxy-groups"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|g| text(g, "type") == Some("select"))
        .filter_map(|g| text(g, "name"))
        .filter(|n| valid_name(n) && *n != NODE)
        .map(str::to_owned)
        .collect();
    // A concrete, independent ordinary node avoids a selectable-group recursion.
    // Provider-only/dialer chains require a separately supported integration.
    let ordinary = config["proxies"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| ordinary_server(p, front))
        .filter_map(|p| text(p, "name"))
        .filter(|n| valid_name(n) && *n != NODE)
        .map(str::to_owned)
        .collect();
    (groups, ordinary)
}
fn check_choice(v: &Value, choice: &Choice) -> Result<()> {
    let (groups, ordinary) = options(v, choice.front_port);
    if !(1024..=65533).contains(&choice.front_port)
        || !groups.contains(&choice.target_group)
        || !ordinary.contains(&choice.ordinary_proxy)
        || choice.target_group == choice.ordinary_proxy
    {
        return Err(err("invalid_choice"));
    }
    Ok(())
}
fn rule(c: &Choice) -> String {
    format!("DOMAIN,api.mullvad.net,{}", c.ordinary_proxy)
}
fn rule_parts(rule: &str) -> Result<(String, String, String)> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (i, ch) in rule.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(rule[start..i].trim());
                start = i + 1
            }
            _ => {}
        }
        if depth < 0 {
            return Err(err("runtime_diverged"));
        }
    }
    if depth != 0 {
        return Err(err("runtime_diverged"));
    }
    parts.push(rule[start..].trim());
    let kind = parts[0].to_ascii_uppercase().replace('-', "");
    if matches!(kind.as_str(), "MATCH" | "FINAL") && parts.len() == 2 {
        return Ok(("MATCH".into(), "".into(), parts[1].into()));
    }
    if parts.len() != 3 && !(parts.len() == 4 && parts[3].eq_ignore_ascii_case("no-resolve")) {
        return Err(err("runtime_diverged"));
    }
    let kind = if kind == "IPCIDR6" {
        "IPCIDR".into()
    } else {
        kind
    };
    let payload = if matches!(kind.as_str(), "AND" | "OR" | "NOT") {
        parts[1]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect()
    } else {
        parts[1].to_owned()
    };
    Ok((kind, payload, parts[2].into()))
}
/// The generated Verge file is authoritative only while its routing graph still
/// matches the live engine. Controller-only configuration injections must be
/// re-applied through Verge first; we never overwrite a detected divergence.
fn check_runtime(s: &Snapshot, controller: &impl Controller, c: &Choice) -> Result<()> {
    let graph = controller.get("/proxies")?;
    let mut expected = s.config.clone();
    if graph["proxies"].get(NODE).is_some() {
        modify(&mut expected, c, false)?;
    }
    for group in expected["proxy-groups"].as_array().into_iter().flatten() {
        if text(group, "type") != Some("select") {
            continue;
        }
        let name = text(group, "name").ok_or_else(|| err("runtime_diverged"))?;
        let actual = graph["proxies"][name]["all"]
            .as_array()
            .ok_or_else(|| err("runtime_diverged"))?;
        let expected = group["proxies"].as_array().cloned().unwrap_or_default();
        if group.get("use").is_none() {
            if actual != &expected {
                return Err(err("runtime_diverged"));
            }
        } else if !expected.iter().all(|v| actual.contains(v)) {
            return Err(err("runtime_diverged"));
        }
    }
    let rules = controller.get("/rules")?;
    let actual = rules["rules"]
        .as_array()
        .ok_or_else(|| err("runtime_diverged"))?;
    let expected = expected["rules"]
        .as_array()
        .ok_or_else(|| err("rules_missing"))?;
    if actual.len() != expected.len() {
        return Err(err("runtime_diverged"));
    }
    for (actual, expected) in actual.iter().zip(expected) {
        let (kind, payload, target) =
            rule_parts(expected.as_str().ok_or_else(|| err("runtime_diverged"))?)?;
        let actual_kind = text(actual, "type")
            .unwrap_or("")
            .to_ascii_uppercase()
            .replace('-', "");
        let actual_payload = text(actual, "payload").unwrap_or("");
        let actual_payload = if matches!(kind.as_str(), "AND" | "OR" | "NOT") {
            actual_payload
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect::<String>()
        } else {
            actual_payload.into()
        };
        // Mihomo exposes GeoIP country codes in lowercase even when the
        // generated configuration uses uppercase (for example CN -> cn).
        // Only country-code case is insignificant; targets and rule order
        // must still match exactly.
        let payload_matches = if kind == "GEOIP" {
            payload.eq_ignore_ascii_case(&actual_payload)
        } else {
            payload == actual_payload
        };
        if kind != actual_kind || !payload_matches || text(actual, "proxy") != Some(&target) {
            return Err(err("runtime_diverged"));
        }
    }
    Ok(())
}
fn modify(v: &mut Value, c: &Choice, remove: bool) -> Result<()> {
    let proxies = v
        .get_mut("proxies")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| err("invalid_yaml"))?;
    if let Some(p) = proxies.iter().find(|p| text(p, "name") == Some(NODE)) {
        if p != &node(c.front_port) {
            return Err(err("name_conflict"));
        }
    }
    proxies.retain(|p| text(p, "name") != Some(NODE));
    if !remove {
        proxies.push(node(c.front_port));
    }
    let group = v["proxy-groups"]
        .as_array_mut()
        .and_then(|g| {
            g.iter_mut()
                .find(|g| text(g, "name") == Some(&c.target_group))
        })
        .ok_or_else(|| err("invalid_choice"))?;
    if group.get("proxies").is_none() {
        group["proxies"] = json!([]);
    }
    let choices = group["proxies"]
        .as_array_mut()
        .ok_or_else(|| err("invalid_choice"))?;
    choices.retain(|v| v.as_str() != Some(NODE));
    if !remove {
        choices.insert(0, json!(NODE));
    }
    let rules = v["rules"]
        .as_array_mut()
        .ok_or_else(|| err("rules_missing"))?;
    rules.retain(|r| r.as_str() != Some(&rule(c)));
    if !remove {
        rules.insert(0, json!(rule(c)));
    }
    Ok(())
}
fn script_block(c: &Choice) -> String {
    // JSON string literals prevent group/node names from becoming executable JS.
    format!("{MARKER}(() => {{\n  const before = main;\n  const spec = {};\n{}\n  main = function(config, ...args) {{ return integrate(before(config, ...args), spec); }};\n}})();\n// END MULLVAD ADAPTER MANAGED v1\n",serde_json::to_string(c).unwrap(),include_str!("integrate.js"))
}
#[derive(Serialize, Deserialize)]
struct Record {
    schema: u8,
    choice: Choice,
    script_hash: String,
    original_hash: String,
    previous_selection: String,
    root_hash: String,
    profile: String,
}
pub struct Integration {
    root: PathBuf,
    store: PathBuf,
    _lock: fs::File,
}
impl Integration {
    /// `store` must be a pre-established private app directory, outside Clash.
    pub fn open(root: PathBuf, store: PathBuf) -> Result<Self> {
        safe_path(&root)?;
        safe_path(&store)?;
        let mut o = fs::OpenOptions::new();
        o.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let lock = o
            .open(store.join("integration.lock"))
            .map_err(|_| err("write_failed"))?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| err("busy"))?;
        Ok(Self {
            root,
            store,
            _lock: lock,
        })
    }
    fn dir(&self, s: &Snapshot) -> PathBuf {
        // Keep native Windows file paths below legacy API length ceilings.
        self.store
            .join(&hash(s.script_path.to_string_lossy().as_bytes())[..32])
    }
    fn record(&self, s: &Snapshot) -> Result<Option<Record>> {
        let p = self.dir(s).join("record.json");
        if !p.exists() {
            return Ok(None);
        }
        let r: Record = serde_json::from_slice(&read(&p)?).map_err(|_| err("backup_invalid"))?;
        if r.schema != 1 || r.original_hash.len() != 64 || r.script_hash.len() != 64 {
            return Err(err("backup_invalid"));
        }
        Ok(Some(r))
    }
    pub fn controller(&self, front: u16) -> Result<HttpController> {
        HttpController::from_config(&snapshot(&self.root)?.config, front)
    }
    pub fn view(&self, controller: &impl Controller, front: u16) -> Result<View> {
        let s = snapshot(&self.root)?;
        let live = controller.get("/configs")?;
        let graph = controller.get("/proxies")?;
        let r = self.record(&s)?;
        let (groups, ordinary_proxies) = options(&s.config, front);
        let active = r.as_ref().is_some_and(|r| {
            graph["proxies"][&r.choice.target_group]["now"].as_str() == Some(NODE)
                && graph["proxies"][NODE]["type"]
                    .as_str()
                    .is_some_and(|s| s.eq_ignore_ascii_case("socks5"))
        });
        let managed = r.is_some();
        let saved = r.as_ref().is_some_and(|r| hash(&s.script) == r.script_hash);
        let conflict = r.as_ref().is_some_and(|r| {
            hash(&s.script) != r.script_hash && hash(&s.script) != r.original_hash
        });
        let port = live["mixed-port"]
            .as_u64()
            .filter(|p| *p >= 1024 && *p <= 65535)
            .map(|p| p as u16);
        let mut other_profiles = Vec::new();
        for entry in fs::read_dir(&self.store)
            .map_err(|_| err("file_access"))?
            .take(256)
        {
            let entry = entry.map_err(|_| err("file_access"))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.len() != 32
                || !name.bytes().all(|b| b.is_ascii_hexdigit())
                || entry.path() == self.dir(&s)
            {
                continue;
            }
            let path = entry.path().join("record.json");
            if path.exists() {
                let record: Record =
                    serde_json::from_slice(&read(&path)?).map_err(|_| err("backup_invalid"))?;
                if record.root_hash == hash(self.root.to_string_lossy().as_bytes()) {
                    other_profiles.push(record.profile);
                }
            }
        }
        Ok(View {
            directory: self.root.to_string_lossy().into_owned(),
            profile: s.profile.clone(),
            script: s
                .script_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            proxy_port: port,
            tun_enabled: live["tun"]["enable"].as_bool().unwrap_or(false),
            groups,
            ordinary_proxies,
            managed,
            saved,
            conflict,
            active,
            target_group: r.as_ref().map(|r| r.choice.target_group.clone()),
            ordinary_proxy: r.as_ref().map(|r| r.choice.ordinary_proxy.clone()),
            backup_path: managed.then(|| self.dir(&s).to_string_lossy().into_owned()),
            other_profiles,
        })
    }
    pub fn preview(&self, controller: &impl Controller, c: &Choice) -> Result<Preview> {
        let s = snapshot(&self.root)?;
        check_choice(&s.config, c)?;
        if self.record(&s)?.is_some() {
            return Err(err("already_managed"));
        }
        if std::str::from_utf8(&s.script).unwrap().contains(MARKER) {
            return Err(err("backup_missing"));
        }
        if s.config["proxies"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|p| text(p, "name") == Some(NODE))
        {
            return Err(err("name_conflict"));
        }
        if s.config["proxy-groups"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|g| {
                text(g, "name") == Some(NODE)
                    || g["proxies"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .any(|n| n.as_str() == Some(NODE))
            })
            || s.config["rules"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .any(|r| r.split(',').any(|part| part == NODE))
        {
            return Err(err("name_conflict"));
        }
        if s.config["rules"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|r| r.as_str() == Some(&rule(c)))
        {
            return Err(err("rule_conflict"));
        }
        let summary = self.view(controller, c.front_port)?;
        if controller.get("/configs")?["mode"].as_str() != Some("rule") {
            return Err(err("rule_mode_required"));
        }
        Ok(Preview {
            id: preview_id(&s, c),
            config: script_block(c),
            summary,
        })
    }
    fn stage(
        &self,
        s: &Snapshot,
        controller: &impl Controller,
        c: &Choice,
        remove: bool,
    ) -> Result<PathBuf> {
        let mut config = s.config.clone();
        check_runtime(s, controller, c)?;
        modify(&mut config, c, remove)?;
        let live = controller.get("/configs")?;
        if !remove && live["mode"].as_str() != Some("rule") {
            return Err(err("rule_mode_required"));
        }
        // Preserve current core switches, including a user change after the last
        // Verge generation. Never enable TUN/system proxy or replace DNS settings.
        for key in [
            "mode",
            "mixed-port",
            "port",
            "socks-port",
            "allow-lan",
            "ipv6",
            "log-level",
        ] {
            if let Some(v) = live.get(key) {
                config[key] = v.clone();
            }
        }
        if let Some(tun) = live.get("tun") {
            if let (Some(base), Some(current)) = (config["tun"].as_object_mut(), tun.as_object()) {
                for (key, value) in current {
                    base.insert(key.clone(), value.clone());
                }
            } else {
                config["tun"] = tun.clone();
            }
        }
        let bytes = yaml(&config)?;
        let path = self
            .dir(s)
            .join(format!("runtime-{}.yaml", &hash(&bytes)[..32]));
        if !path.exists() {
            create(&path, &bytes)?
        } else if read(&path)? != bytes {
            return Err(err("backup_invalid"));
        }
        Ok(path)
    }
    pub fn apply(
        &self,
        controller: &impl Controller,
        c: &Choice,
        expected: &str,
    ) -> Result<Outcome> {
        let p = self.preview(controller, c)?;
        if p.id != expected {
            return Err(err("config_changed"));
        }
        let s = snapshot(&self.root)?;
        if preview_id(&s, c) != expected {
            return Err(err("config_changed"));
        }
        let graph = controller.get("/proxies")?;
        let previous = text(&graph["proxies"][&c.target_group], "now")
            .filter(|v| valid_name(v))
            .ok_or_else(|| err("selection_unavailable"))?
            .to_owned();
        let dir = self.dir(&s);
        if dir.exists() {
            return Err(err("backup_exists"));
        }
        fs::create_dir(&dir).map_err(|_| err("write_failed"))?;
        let original = String::from_utf8(s.script.clone()).map_err(|_| err("script_encoding"))?;
        let updated = format!("{original}{}", script_block(c)).into_bytes();
        create(&dir.join("script.before.js"), &s.script)?;
        create(&dir.join("runtime.before.yaml"), &s.runtime)?;
        let record = Record {
            schema: 1,
            choice: c.clone(),
            script_hash: hash(&updated),
            original_hash: hash(&s.script),
            previous_selection: previous,
            root_hash: hash(self.root.to_string_lossy().as_bytes()),
            profile: s.profile.clone(),
        };
        create(
            &dir.join("record.json"),
            &serde_json::to_vec(&record).unwrap(),
        )?;
        let path = self.stage(&s, controller, c, false)?;
        controller.validate(&path)?;
        // Recheck both profile selection and source runtime immediately before
        // committing. A preview is never authority to overwrite a newer file.
        let fresh = snapshot(&self.root)?;
        if fresh.index != s.index || fresh.runtime != s.runtime {
            return Err(err("config_changed"));
        }
        replace(&s.script_path, &s.script, &updated)?;
        let result = (|| {
            controller.put("/configs?force=false", &json!({"payload":String::from_utf8(read(&path)?).map_err(|_|err("invalid_yaml"))?}))?;
            controller.put(
                &format!("/proxies/{}", encoded(&c.target_group)),
                &json!({"name":NODE}),
            )?;
            if controller.get("/proxies")?["proxies"][&c.target_group]["now"].as_str() != Some(NODE)
            {
                return Err(err("activation_unconfirmed"));
            }
            Ok(())
        })();
        Ok(Outcome {
            saved: true,
            active: result.is_ok(),
            code: result.err().unwrap_or_else(|| "clash_connected".into()),
            backup_path: dir.to_string_lossy().into_owned(),
        })
    }
    /// Explicitly restore a selector choice after Verge restored an older one.
    /// This never reloads a config or rewrites the durable extension.
    pub fn enable(&self, controller: &impl Controller) -> Result<Outcome> {
        let s = snapshot(&self.root)?;
        let r = self.record(&s)?.ok_or_else(|| err("not_managed"))?;
        if hash(&s.script) != r.script_hash {
            return Err(err("config_changed"));
        }
        if controller.get("/configs")?["mode"].as_str() != Some("rule") {
            return Err(err("rule_mode_required"));
        }
        check_runtime(&s, controller, &r.choice)?;
        let graph = controller.get("/proxies")?;
        if !graph["proxies"][&r.choice.target_group]["all"]
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(NODE)))
        {
            return Err(err("runtime_diverged"));
        }
        let result = (|| {
            controller.put(
                &format!("/proxies/{}", encoded(&r.choice.target_group)),
                &json!({"name":NODE}),
            )?;
            if controller.get("/proxies")?["proxies"][&r.choice.target_group]["now"].as_str()
                != Some(NODE)
            {
                return Err(err("activation_unconfirmed"));
            }
            Ok(())
        })();
        Ok(Outcome {
            saved: true,
            active: result.is_ok(),
            code: result.err().unwrap_or_else(|| "clash_connected".into()),
            backup_path: self.dir(&s).to_string_lossy().into_owned(),
        })
    }
    pub fn undo(&self, controller: &impl Controller) -> Result<Outcome> {
        let s = snapshot(&self.root)?;
        let r = self.record(&s)?.ok_or_else(|| err("not_managed"))?;
        let dir = self.dir(&s);
        let before = read(&dir.join("script.before.js"))?;
        if hash(&before) != r.original_hash {
            return Err(err("backup_invalid"));
        }
        // A previous partial undo can be resumed. Concurrent edits are preserved.
        if hash(&s.script) != r.script_hash && s.script != before {
            return Err(err("config_changed"));
        }
        let graph = controller.get("/proxies")?;
        if s.script == before && graph["proxies"].get(NODE).is_none() {
            let archive = self.archive(&dir)?;
            return Ok(Outcome {
                saved: false,
                active: false,
                code: "clash_removed".into(),
                backup_path: archive.to_string_lossy().into_owned(),
            });
        }
        let current = text(&graph["proxies"][&r.choice.target_group], "now")
            .unwrap_or("")
            .to_owned();
        let path = self.stage(&s, controller, &r.choice, true)?;
        controller.validate(&path)?;
        let fresh = snapshot(&self.root)?;
        if fresh.index != s.index
            || fresh.runtime != s.runtime
            || fresh.script_path != s.script_path
        {
            return Err(err("config_changed"));
        }
        if s.script != before {
            replace(&s.script_path, &s.script, &before)?;
        }
        let result = (|| {
            controller.put("/configs?force=false", &json!({"payload":String::from_utf8(read(&path)?).map_err(|_|err("invalid_yaml"))?}))?;
            let desired = if current == NODE {
                &r.previous_selection
            } else {
                &current
            };
            if !desired.is_empty() {
                controller.put(
                    &format!("/proxies/{}", encoded(&r.choice.target_group)),
                    &json!({"name":desired}),
                )?;
            }
            let graph = controller.get("/proxies")?;
            if graph["proxies"].get(NODE).is_some() {
                return Err(err("activation_unconfirmed"));
            }
            if !desired.is_empty()
                && graph["proxies"][&r.choice.target_group]["now"].as_str() != Some(desired)
            {
                return Err(err("activation_unconfirmed"));
            }
            Ok(())
        })();
        let mut backup_path = dir.clone();
        if result.is_ok() {
            // Retain the backup/evidence; move the completed transaction out of
            // the active slot so a later explicit integration is possible.
            backup_path = self.archive(&dir)?;
        }
        Ok(Outcome {
            saved: false,
            active: false,
            code: result.err().unwrap_or_else(|| "clash_removed".into()),
            backup_path: backup_path.to_string_lossy().into_owned(),
        })
    }
    fn archive(&self, dir: &Path) -> Result<PathBuf> {
        let mut n = 0;
        let mut archive = dir.with_extension("undo");
        while archive.exists() {
            n += 1;
            archive = dir.with_extension(format!("undo-{n}"));
        }
        fs::rename(dir, &archive).map_err(|_| err("write_unconfirmed"))?;
        Ok(archive)
    }
}

/// Export contains only a loopback SOCKS entry. It is safe to copy into a client
/// that is not supported by the automatic Verge integration.
pub fn export(front: u16) -> Result<String> {
    if !(1024..=65533).contains(&front) {
        return Err(err("invalid_choice"));
    }
    String::from_utf8(yaml(&json!({"proxies":[node(front)]}))?).map_err(|_| err("invalid_yaml"))
}

#[cfg(test)]
mod tests;
