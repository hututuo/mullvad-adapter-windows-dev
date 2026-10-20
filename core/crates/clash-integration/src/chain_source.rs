//! Read-only, native-only SS leaf discovery from the user's actual runtime.
//! No subscription fetch, selection mutation, raw config export or logging occurs here.
use super::{err, hash, ordinary_server, parse, read, safe_path, text, valid_name, Result, NODE};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};

const MAX_NODES: usize = 4096;
const MAX_PROVIDERS: usize = 32;
const MAX_PROVIDER_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PASSWORD_BYTES: usize = adapter_platform::chain_endpoint::MAX_PASSWORD;

/// This is the entire renderer-facing schema. The fingerprint binds the native
/// selection to the exact credential/endpoint snapshot; it is not a health claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicChoice {
    pub name: String,
    pub fingerprint: String,
}

/// Intentionally neither Serialize nor Debug. Move these fields directly into
/// the authenticated native IPC request, wrapping password in SecretText there.
/// Never return this value from a renderer command or save it in UI settings.
pub struct SecretSs {
    pub name: String,
    pub fingerprint: String,
    pub server: String,
    pub port: u16,
    pub cipher: String,
    pub password: String,
}

pub fn list(root: &Path, front: u16) -> Result<Vec<PublicChoice>> {
    let runtime = parse(&read(&root.join("clash-verge.yaml"))?)?;
    list_from_runtime(root, &runtime, front)
}

/// Re-read on every selection; caller must compare fingerprint with the displayed
/// choice before sending the secret to the agent. A name alone is not a snapshot.
pub fn selected(root: &Path, front: u16, name: &str) -> Result<SecretSs> {
    let runtime = parse(&read(&root.join("clash-verge.yaml"))?)?;
    selected_from_runtime(root, &runtime, front, name)
}

pub fn list_from_runtime(root: &Path, runtime: &Value, front: u16) -> Result<Vec<PublicChoice>> {
    Ok(leaves(root, runtime, front)?
        .into_iter()
        .map(|leaf| PublicChoice {
            name: leaf.name,
            fingerprint: leaf.fingerprint,
        })
        .collect())
}

pub fn selected_from_runtime(
    root: &Path,
    runtime: &Value,
    front: u16,
    name: &str,
) -> Result<SecretSs> {
    if !valid_name(name) || name.len() > adapter_platform::chain_endpoint::MAX_NAME {
        return Err(err("chain_choice_missing"));
    }
    leaves(root, runtime, front)?
        .into_iter()
        .find(|leaf| leaf.name == name)
        .ok_or_else(|| err("chain_choice_missing"))
}

fn rows<'a>(value: &'a Value, key: &str) -> Result<&'a [Value]> {
    match value.get(key) {
        None => Ok(&[]),
        Some(Value::Array(rows)) => Ok(rows),
        _ => Err(err("chain_invalid_source")),
    }
}

fn leaves(root: &Path, runtime: &Value, front: u16) -> Result<Vec<SecretSs>> {
    safe_path(root)?;
    if !root.is_dir() || !runtime.is_object() || front == 0 {
        return Err(err("chain_invalid_source"));
    }
    let direct = rows(runtime, "proxies")?;
    let groups = rows(runtime, "proxy-groups")?;
    let mut count = direct.len().saturating_add(groups.len());
    if count > MAX_NODES {
        return Err(err("chain_source_limit"));
    }
    let mut names = BTreeMap::<String, usize>::new();
    let mut candidates = Vec::new();
    record(direct, front, &mut names, &mut candidates);
    // Group names share the proxy namespace, including unsupported groups.
    for group in groups {
        if let Some(name) = text(group, "name") {
            *names.entry(name.to_owned()).or_default() += 1;
        }
    }
    let providers = match runtime.get("proxy-providers") {
        None => None,
        Some(Value::Object(providers)) => Some(providers),
        _ => return Err(err("chain_invalid_source")),
    };
    if let Some(providers) = providers {
        if providers.len() > MAX_PROVIDERS {
            return Err(err("chain_source_limit"));
        }
        for provider in providers.values() {
            // Transformations/filters would make the cache differ from the
            // effective runtime. Fail explicitly instead of guessing semantics.
            if !matches!(text(provider, "type"), Some("http" | "file"))
                || ["override", "filter", "exclude-filter", "exclude-type"]
                    .iter()
                    .any(|key| provider.get(key).is_some())
            {
                return Err(err("chain_provider_not_supported"));
            }
            let path = cache_path(root, text(provider, "path"))?;
            let metadata = std::fs::metadata(&path).map_err(|_| err("file_access"))?;
            if !metadata.is_file() || metadata.len() > MAX_PROVIDER_BYTES {
                return Err(err("chain_source_limit"));
            }
            let bytes = read(&path)?;
            // Also enforce after read in case the cache grew concurrently.
            if bytes.len() as u64 > MAX_PROVIDER_BYTES {
                return Err(err("chain_source_limit"));
            }
            safe_path(&path)?;
            let cache = parse(&bytes)?;
            let proxies = rows(&cache, "proxies")?;
            count = count.saturating_add(proxies.len());
            if count > MAX_NODES {
                return Err(err("chain_source_limit"));
            }
            record(proxies, front, &mut names, &mut candidates);
        }
    }
    // Ambiguous names are excluded even if only one occurrence was eligible.
    // This includes direct/provider, provider/provider and group/leaf clashes.
    candidates.retain(|leaf| names.get(&leaf.name) == Some(&1));
    candidates.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(candidates)
}

fn cache_path(root: &Path, relative: Option<&str>) -> Result<PathBuf> {
    let relative = relative.ok_or_else(|| err("chain_provider_not_supported"))?;
    // Apply Windows spelling constraints on every platform, so Unix tests cannot
    // accidentally approve a drive path, UNC path or alternate data stream.
    if relative.is_empty()
        || relative.len() > 1024
        || relative.contains(['\\', ':'])
        || relative.chars().any(char::is_control)
    {
        return Err(err("chain_provider_not_supported"));
    }
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|part| match part {
            Component::CurDir => false,
            Component::Normal(name) => {
                let Some(name) = name.to_str() else {
                    return true;
                };
                let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
                name.ends_with(['.', ' '])
                    || matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                    || stem
                        .strip_prefix("COM")
                        .or_else(|| stem.strip_prefix("LPT"))
                        .is_some_and(|n| n.len() == 1 && matches!(n.as_bytes()[0], b'1'..=b'9'))
            }
            _ => true,
        })
    {
        return Err(err("chain_provider_not_supported"));
    }
    let path = root.join(path);
    // This is deliberately limited to caches inside the known runtime root.
    // Absolute and cross-directory providers are NOT_SUPPORTED, never relocated.
    if !path.starts_with(root) {
        return Err(err("chain_provider_not_supported"));
    }
    safe_path(&path)?;
    let canonical_root = root.canonicalize().map_err(|_| err("file_access"))?;
    let canonical_path = path.canonicalize().map_err(|_| err("file_access"))?;
    if !canonical_path.starts_with(&canonical_root) {
        return Err(err("chain_provider_not_supported"));
    }
    Ok(path)
}

fn record(
    proxies: &[Value],
    front: u16,
    names: &mut BTreeMap<String, usize>,
    candidates: &mut Vec<SecretSs>,
) {
    for proxy in proxies {
        if let Some(name) = text(proxy, "name") {
            *names.entry(name.to_owned()).or_default() += 1;
        }
        if let Some(leaf) = ss_leaf(proxy, front) {
            candidates.push(leaf);
        }
    }
}

fn ss_leaf(proxy: &Value, front: u16) -> Option<SecretSs> {
    let name = text(proxy, "name")?;
    let server = text(proxy, "server")?;
    let cipher = text(proxy, "cipher")?;
    let password = text(proxy, "password")?;
    let port = u16::try_from(proxy.get("port")?.as_u64()?).ok()?;
    let lower_name = name.to_ascii_lowercase();
    // These ciphers are supported by pinned Mihomo v1.19.31 through
    // sing-shadowsocks2 v0.2.8 shadowaead.MethodList/NewMethod.
    if !valid_name(name)
        || name != name.trim()
        || name.len() > adapter_platform::chain_endpoint::MAX_NAME
        || name == NODE
        || lower_name.contains("mullvad")
        || lower_name.contains("adapter")
        || text(proxy, "type") != Some("ss")
        || !matches!(cipher, "aes-128-gcm" | "aes-256-gcm" | "chacha20-ietf-poly1305")
        || password.is_empty()
        || password.len() > MAX_PASSWORD_BYTES
        || password.chars().any(char::is_control)
        || password.eq_ignore_ascii_case("mullvad")
        || port == 0
        || !ordinary_server(proxy, front)
        || !public_endpoint(server)
        || proxy.get("udp").is_some_and(|v| v.as_bool() != Some(true))
        // Copying these would introduce another hop/transport or native binding;
        // dropping them would silently change the user's chosen node semantics.
        || [
            "plugin", "plugin-opts", "obfs", "obfs-opts", "dialer-proxy",
            "underlying-proxy", "interface-name", "routing-mark", "smux",
            "udp-over-tcp-version",
        ].iter().any(|key| proxy.get(key).is_some())
        || proxy.get("udp-over-tcp").is_some_and(|v| v.as_bool() != Some(false))
    {
        return None;
    }
    // Hash only the fields actually passed to the native SS worker. Source-only
    // display/benchmark metadata cannot change the effective identity.
    let fingerprint = hash(&serde_json::to_vec(&(name, server, port, cipher, password)).ok()?);
    Some(SecretSs {
        name: name.to_owned(),
        fingerprint,
        server: server.to_owned(),
        port,
        cipher: cipher.to_owned(),
        password: password.to_owned(),
    })
}

fn public_endpoint(server: &str) -> bool {
    adapter_platform::chain_endpoint::public_server(server)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "adapter-chain-source-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn save(&self, file: &str, value: &Value) {
            let path = self.0.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn node(name: &str) -> Value {
        json!({"name":name,"type":"ss","server":"192.0.2.8","port":443,
            "cipher":"aes-256-gcm","password":"fixture-only-password","udp":true})
    }
    fn source(proxy: Value) -> Value {
        json!({"proxies":[proxy]})
    }

    #[test]
    fn visible_choices_obey_engine_name_and_password_limits() {
        let root = Fixture::new();
        for (key, value) in [
            ("name", "n".repeat(201)),
            ("password", "secret\ncontrol".into()),
            ("password", "p".repeat(MAX_PASSWORD_BYTES + 1)),
        ] {
            let mut proxy = node("Ordinary SS");
            proxy[key] = json!(value);
            assert!(list_from_runtime(&root.0, &source(proxy), 17893)
                .unwrap()
                .is_empty());
        }
    }
    #[test]
    fn public_schema_is_only_name_and_fingerprint_and_selected_is_native() {
        let root = Fixture::new();
        root.save("clash-verge.yaml", &source(node("Ordinary SS")));
        let choices = list(&root.0, 17893).unwrap();
        assert_eq!(choices.len(), 1);
        let public = serde_json::to_value(&choices[0]).unwrap();
        assert_eq!(public.as_object().unwrap().len(), 2);
        for secret in ["192.0.2.8", "aes-256-gcm", "fixture-only-password"] {
            assert!(!public.to_string().contains(secret));
        }
        let selected = selected(&root.0, 17893, &choices[0].name).unwrap();
        assert_eq!(selected.fingerprint, choices[0].fingerprint);
        assert_eq!(selected.password, "fixture-only-password");
        assert_eq!(selected.port, 443);
    }

    #[test]
    fn supports_three_pinned_ciphers_and_udp_default() {
        let root = Fixture::new();
        for cipher in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"] {
            let mut proxy = node(cipher);
            proxy["cipher"] = json!(cipher);
            proxy.as_object_mut().unwrap().remove("udp");
            assert_eq!(
                list_from_runtime(&root.0, &source(proxy), 17893)
                    .unwrap()
                    .len(),
                1
            );
        }
    }

    #[test]
    fn rejects_nonflat_transports_and_invalid_parameters() {
        let root = Fixture::new();
        for (field, value) in [
            ("type", json!("vmess")),
            ("cipher", json!("aes-128-cfb")),
            ("password", json!("")),
            ("password", json!("mullvad")),
            ("port", json!(0)),
            ("port", json!(65536)),
            ("port", json!(17893)),
            ("port", json!("443")),
            ("udp", json!(false)),
            ("udp", json!(null)),
            ("plugin", json!("")),
            ("obfs", json!("tls")),
            ("dialer-proxy", json!("other")),
            ("underlying-proxy", json!(null)),
            ("interface-name", json!("eth0")),
            ("udp-over-tcp", json!(true)),
            ("name", json!(NODE)),
            ("name", json!("Mullvad spare")),
            ("name", json!("Adapter SS")),
        ] {
            let mut proxy = node("Ordinary SS");
            proxy[field] = value;
            assert!(
                list_from_runtime(&root.0, &source(proxy), 17893)
                    .unwrap()
                    .is_empty(),
                "{field}"
            );
        }
    }

    #[test]
    fn rejects_nonpublic_addresses_and_local_hostname_variants() {
        for server in [
            "127.0.0.1",
            "0.0.0.0",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.0.2",
            "100.64.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "2001:4860:4860::8888",
            "::1",
            "::",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "::ffff:192.168.1.2",
            "::127.0.0.1",
            "LOCALHOST.",
            "x.localhost",
            "router.local",
            "127.1",
            "2130706433",
            "mullvad.net",
            "se-got-wg-001.relays.mullvad.net",
            "https://example.com",
            "ss.example.com/path",
        ] {
            assert!(!public_endpoint(server), "{server}");
        }
        for server in ["192.0.2.8", "8.8.8.8", "ss.example.com"] {
            assert!(public_endpoint(server), "{server}");
        }
    }

    #[test]
    fn only_reads_named_local_provider_cache_without_url_fetch() {
        let root = Fixture::new();
        root.save("providers/cache.yaml", &source(node("Cached SS")));
        let runtime = json!({"proxy-providers":{"airport":{"type":"http",
            "url":"http://127.0.0.1:1/never-fetch", "path":"./providers/cache.yaml"}}});
        assert_eq!(
            list_from_runtime(&root.0, &runtime, 17893).unwrap()[0].name,
            "Cached SS"
        );
        assert!(root.0.join("providers/cache.yaml").is_file());
    }

    #[test]
    fn duplicate_names_in_all_namespaces_are_unselectable() {
        let root = Fixture::new();
        root.save("provider.yaml", &source(node("collision")));
        let provider = json!({"p":{"type":"file","path":"provider.yaml"}});
        for runtime in [
            json!({"proxies":[node("collision"),node("collision")]}),
            json!({"proxies":[node("collision")],"proxy-groups":[{"name":"collision","type":"select"}]}),
            json!({"proxies":[node("collision")],"proxy-providers":provider}),
            json!({"proxy-providers":{"p":{"type":"file","path":"provider.yaml"},"q":{"type":"file","path":"provider.yaml"}}}),
            json!({"proxies":[node("collision"),{"name":"collision","type":"unsupported"}]}),
        ] {
            assert!(list_from_runtime(&root.0, &runtime, 17893)
                .unwrap()
                .is_empty());
            assert_eq!(
                selected_from_runtime(&root.0, &runtime, 17893, "collision")
                    .err()
                    .as_deref(),
                Some("clash_chain_choice_missing")
            );
        }
    }

    #[test]
    fn unsupported_provider_paths_and_transforms_fail_explicitly() {
        let root = Fixture::new();
        for path in [
            "../outside.yaml",
            "/tmp/outside.yaml",
            "C:/cache.yaml",
            "\\\\server\\share",
            "cache.yaml:stream",
            "folder/.. /outside.yaml",
            "CON.yaml",
            "folder./cache.yaml",
            "",
        ] {
            let runtime = json!({"proxy-providers":{"p":{"type":"file","path":path}}});
            assert_eq!(
                list_from_runtime(&root.0, &runtime, 17893).err().as_deref(),
                Some("clash_chain_provider_not_supported")
            );
        }
        for field in ["override", "filter", "exclude-filter", "exclude-type"] {
            let mut provider = json!({"type":"http","path":"cache.yaml"});
            provider[field] = json!({});
            let runtime = json!({"proxy-providers":{"p":provider}});
            assert_eq!(
                list_from_runtime(&root.0, &runtime, 17893).err().as_deref(),
                Some("clash_chain_provider_not_supported")
            );
        }
    }

    #[test]
    fn limits_node_and_provider_file_volume() {
        let root = Fixture::new();
        let runtime = json!({"proxies":vec![node("duplicate"); MAX_NODES + 1]});
        assert_eq!(
            list_from_runtime(&root.0, &runtime, 17893).err().as_deref(),
            Some("clash_chain_source_limit")
        );
        let mut providers = serde_json::Map::new();
        for i in 0..=MAX_PROVIDERS {
            providers.insert(i.to_string(), json!({"type":"file","path":"cache.yaml"}));
        }
        assert_eq!(
            list_from_runtime(&root.0, &json!({"proxy-providers":providers}), 17893)
                .err()
                .as_deref(),
            Some("clash_chain_source_limit")
        );
        let file = std::fs::File::create(root.0.join("large.yaml")).unwrap();
        file.set_len(MAX_PROVIDER_BYTES + 1).unwrap();
        let runtime = json!({"proxy-providers":{"p":{"type":"file","path":"large.yaml"}}});
        assert_eq!(
            list_from_runtime(&root.0, &runtime, 17893).err().as_deref(),
            Some("clash_chain_source_limit")
        );
    }

    #[test]
    fn selection_fingerprint_changes_after_native_credential_refresh() {
        let root = Fixture::new();
        let mut runtime = source(node("Ordinary SS"));
        let before = list_from_runtime(&root.0, &runtime, 17893)
            .unwrap()
            .remove(0);
        runtime["proxies"][0]["password"] = json!("changed-fixture-only");
        let after = selected_from_runtime(&root.0, &runtime, 17893, &before.name).unwrap();
        assert_ne!(before.fingerprint, after.fingerprint);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_cache_and_parent_symlinks_and_hardlinks() {
        use std::os::unix::fs::symlink;
        let root = Fixture::new();
        let outside = Fixture::new();
        outside.save("cache.yaml", &source(node("outside")));
        symlink(outside.0.join("cache.yaml"), root.0.join("link.yaml")).unwrap();
        symlink(&outside.0, root.0.join("linked-directory")).unwrap();
        std::fs::hard_link(outside.0.join("cache.yaml"), root.0.join("hard.yaml")).unwrap();
        for path in ["link.yaml", "linked-directory/cache.yaml", "hard.yaml"] {
            let runtime = json!({"proxy-providers":{"p":{"type":"file","path":path}}});
            assert_eq!(
                list_from_runtime(&root.0, &runtime, 17893).err().as_deref(),
                Some("clash_unsafe_path")
            );
        }
    }
}
