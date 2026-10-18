//! Independent, portable routing profile. Never edits a user's current profile.
//! Existing proxy secrets stay native; public previews contain names/counts only.
use super::{err, hash, node, ordinary_server, text, valid_name, yaml, Result, NODE};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const AI: &str = "AI出口";
pub const ORDINARY: &str = "普通外网出口";
pub const API: &str = "账号与目录出口";
pub const CONTROL: &str = "远程控制出口";
pub const NAME: &str = "Mullvad Adapter · 分流配置";
const RULES: &str = include_str!("portable-rules.txt");

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub ai: Option<String>,
    pub ordinary: Option<String>,
    /// None means DIRECT, never implicitly the business tunnel.
    pub api: Option<String>,
}
#[derive(Serialize)]
pub struct Summary {
    pub name: &'static str,
    pub policy_sha256: String,
    pub rule_count: usize,
    pub choices: Vec<String>,
    pub api_choices: Vec<String>,
    pub provider_count: usize,
    pub skipped_nodes: usize,
    pub skipped_providers: usize,
    pub selection: Selection,
    pub requires_geodata: bool,
}
pub struct Profile {
    pub summary: Summary,
    /// Contains existing user's proxy credentials. Never send to the renderer,
    /// clipboard, logs, diagnostic bundle or public preview.
    bytes: Vec<u8>,
}
impl Profile {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn fingerprint(&self) -> String {
        hash(&self.bytes)
    }
}

fn reserved(name: &str) -> bool {
    [
        AI, ORDINARY, API, CONTROL, NODE, "DIRECT", "REJECT", "GLOBAL",
    ]
    .contains(&name)
        || name.starts_with("订阅节点 · ")
}

/// `source` is the native client's generated configuration, not renderer data.
/// With no source, the result is still a complete Mullvad-only rule profile.
/// HTTP providers retain their update URL but receive isolated cache paths;
/// providers with chained/implicit routing and file-only providers are excluded.
pub fn generate(source: Option<&Value>, front: u16, selection: &Selection) -> Result<Profile> {
    if !(1024..=65533).contains(&front) {
        return Err(err("invalid_choice"));
    }
    let empty = json!({});
    let source = source.unwrap_or(&empty);
    let mut names = BTreeSet::new();
    let mut proxies = vec![node(front)];
    let mut choices = vec![NODE.to_owned()];
    let mut api_choices = vec!["DIRECT".to_owned()];
    let mut skipped_nodes = 0;
    for proxy in source["proxies"].as_array().into_iter().flatten() {
        let Some(name) = text(proxy, "name").filter(|n| valid_name(n) && !reserved(n)) else {
            skipped_nodes += 1;
            continue;
        };
        if !ordinary_server(proxy, front) || !names.insert(name.to_owned()) {
            skipped_nodes += 1;
            continue;
        }
        proxies.push(proxy.clone());
        choices.push(name.to_owned());
        api_choices.push(name.to_owned());
    }
    let mut providers = serde_json::Map::new();
    let mut provider_groups = vec![];
    let mut skipped_providers = 0;
    for (name, p) in source["proxy-providers"].as_object().into_iter().flatten() {
        let override_safe = p.get("override").is_none_or(|v| {
            v.is_object() && v.get("dialer-proxy").is_none() && v.get("underlying-proxy").is_none()
        });
        let url_ok = text(p, "url")
            .is_some_and(|u| u.starts_with("https://") && !u.chars().any(char::is_control));
        if !valid_name(name) || text(p, "type") != Some("http") || !url_ok || !override_safe {
            skipped_providers += 1;
            continue;
        }
        let id = name.clone();
        let cache = format!("adapter-{}", &hash(name.as_bytes())[..16]);
        let group = format!("订阅节点 · {name}");
        if !valid_name(&group) {
            skipped_providers += 1;
            continue;
        }
        // A provider's existing download proxy may refer to an omitted group.
        // Do not inherit it or overwrite the original provider's cache file.
        let mut p = p.clone();
        p["path"] = json!(format!("./providers/{cache}.yaml"));
        p["proxy"] = json!(API);
        providers.insert(id.clone(), p);
        provider_groups.push(json!({"name":group,"type":"select","use":[id],"proxies":[NODE]}));
        choices.push(group);
    }
    let ai = selection.ai.as_deref().unwrap_or(NODE);
    let ordinary = selection.ordinary.as_deref().unwrap_or(NODE);
    let api = selection.api.as_deref().unwrap_or("DIRECT");
    if !choices.iter().any(|n| n == ai)
        || !choices.iter().any(|n| n == ordinary)
        || !api_choices.iter().any(|n| n == api)
    {
        return Err(err("invalid_choice"));
    }
    let ordered = |selected: &str, values: &[String]| -> Vec<String> {
        std::iter::once(selected.to_owned())
            .chain(values.iter().filter(|n| *n != selected).cloned())
            .collect()
    };
    let mut groups = vec![
        json!({"name":AI,"type":"select","proxies":ordered(ai,&choices)}),
        json!({"name":ORDINARY,"type":"select","proxies":ordered(ordinary,&choices)}),
        json!({"name":API,"type":"select","proxies":ordered(api,&api_choices)}),
        // Remote access must not depend on the business tunnel it may repair.
        // Independent concrete nodes remain selectable in Clash if direct
        // control traffic is blocked on a particular network.
        json!({"name":CONTROL,"type":"select","proxies":api_choices}),
    ];
    groups.extend(provider_groups);
    let rules: Vec<String> = RULES
        .lines()
        .map(|line| {
            if line == "DOMAIN,api.mullvad.net,DIRECT" {
                format!("DOMAIN,api.mullvad.net,{API}")
            } else {
                line.to_owned()
            }
        })
        .collect();
    let config = json!({"mode":"rule","allow-lan":false,"log-level":"warning",
        "proxies":proxies,"proxy-groups":groups,"proxy-providers":providers,"rules":rules});
    Ok(Profile {
        summary: Summary {
            name: NAME,
            policy_sha256: hash(RULES.as_bytes()),
            rule_count: rules.len(),
            choices,
            api_choices,
            provider_count: providers.len(),
            skipped_nodes,
            skipped_providers,
            selection: Selection {
                ai: Some(ai.into()),
                ordinary: Some(ordinary.into()),
                api: Some(api.into()),
            },
            requires_geodata: true,
        },
        bytes: yaml(&config)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(p: &Profile) -> Value {
        super::super::parse(p.bytes()).unwrap()
    }
    #[test]
    fn fresh_install_has_both_business_exits_and_independent_api() {
        let p = generate(None, 17890, &Selection::default()).unwrap();
        let c = config(&p);
        assert_eq!(c["proxies"].as_array().unwrap().len(), 1);
        assert_eq!(c["proxy-groups"][0]["proxies"][0], NODE);
        assert_eq!(c["proxy-groups"][1]["proxies"][0], NODE);
        assert_eq!(c["proxy-groups"][2]["proxies"], json!(["DIRECT"]));
        assert_eq!(c["rules"][0], format!("DOMAIN,api.mullvad.net,{API}"));
        assert!(p.summary.rule_count > 8000);
    }
    #[test]
    fn existing_nodes_selectable_without_credentials_in_summary_or_source_mutation() {
        let src = json!({"proxies":[{"name":"user AI","type":"ss","server":"192.0.2.1","port":443,"cipher":"aes-256-gcm","password":"secret-placeholder"},
          {"name":"loop","type":"socks5","server":"127.0.0.1","port":17890},
          {"name":"chained","type":"ss","server":"192.0.2.2","port":443,"dialer-proxy":AI}]});
        let before = src.clone();
        let p = generate(
            Some(&src),
            17890,
            &Selection {
                ai: Some("user AI".into()),
                ordinary: None,
                api: Some("user AI".into()),
            },
        )
        .unwrap();
        assert_eq!(src, before);
        assert_eq!(p.summary.skipped_nodes, 2);
        assert!(!serde_json::to_string(&p.summary)
            .unwrap()
            .contains("secret-placeholder"));
        assert_eq!(config(&p)["proxy-groups"][0]["proxies"][0], "user AI");
        assert!(generate(
            Some(&src),
            17890,
            &Selection {
                api: Some(NODE.into()),
                ..Default::default()
            }
        )
        .is_err());
    }
    #[test]
    fn provider_refresh_has_separate_cache_and_no_old_group_dependency() {
        let src = json!({"proxy-providers":{"airport":{"type":"http","url":"https://example.invalid/sub?token=secret-placeholder","path":"./old.yaml","proxy":"old group","interval":3600},
          "file":{"type":"file","path":"C:/private.yaml"}}});
        let p = generate(Some(&src), 17890, &Selection::default()).unwrap();
        let c = config(&p);
        assert_eq!(p.summary.provider_count, 1);
        assert_eq!(p.summary.skipped_providers, 1);
        let provider = c["proxy-providers"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap();
        assert_eq!(provider["proxy"], API);
        assert_ne!(provider["path"], "./old.yaml");
        assert!(!serde_json::to_string(&p.summary)
            .unwrap()
            .contains("secret-placeholder"));
        assert!(p.summary.choices.contains(&"订阅节点 · airport".into()));
    }
    #[test]
    fn mac_policy_order_and_portability_are_preserved() {
        let lines: Vec<_> = RULES.lines().collect();
        let drive = lines
            .iter()
            .position(|s| *s == "DOMAIN,www.googleapis.com,普通外网出口")
            .unwrap();
        let google_ai = lines
            .iter()
            .position(|s| *s == "DOMAIN,www.googleapis.com,AI出口")
            .unwrap();
        assert!(drive < google_ai);
        assert!(lines.contains(&"DOMAIN-SUFFIX,chatgpt.com,AI出口"));
        assert!(lines.contains(&"GEOIP,CN,DIRECT"));
        assert_eq!(lines.last(), Some(&"MATCH,普通外网出口"));
        for secret in [
            "/Users/",
            "/Applications/",
            "PROCESS-PATH",
            "UU-DIRECT-EN0",
            "fixture-user",
            "Mullvad节点",
        ] {
            assert!(!RULES.contains(secret));
        }
    }
    #[test]
    fn remote_control_and_multicast_are_independent_of_business_defaults() {
        let c = config(&generate(None, 17890, &Selection::default()).unwrap());
        let groups = c["proxy-groups"].as_array().unwrap();
        let control = groups.iter().find(|g| g["name"] == CONTROL).unwrap();
        assert_eq!(control["proxies"], json!(["DIRECT"]));
        let rules = c["rules"].as_array().unwrap();
        for process in [
            "tailscaled",
            "tailscaled.exe",
            "tailscale-ipn.exe",
            "UURemote",
            "UURemote.exe",
            "GameViewer.exe",
            "GameViewerService.exe",
            "GameViewerServer.exe",
            "GameViewerHealthd.exe",
        ] {
            let expected = json!(format!("PROCESS-NAME,{process},{CONTROL}"));
            assert!(rules.iter().position(|r| *r == expected).unwrap() < 30);
        }
        for domain in ["tailscale.com", "tailscale.io", "ts.net"] {
            let prefix = format!("DOMAIN-SUFFIX,{domain},");
            let first = rules
                .iter()
                .find_map(|r| r.as_str().filter(|s| s.starts_with(&prefix)))
                .unwrap();
            assert_eq!(first, format!("{prefix}{CONTROL}"));
        }
        assert!(rules.contains(&json!("IP-CIDR,224.0.0.0/4,REJECT,no-resolve")));
        assert_eq!(rules.last(), Some(&json!(format!("MATCH,{ORDINARY}"))));
    }
}

#[derive(Default, Serialize)]
pub struct Registration {
    pub registered: bool,
    pub selected: bool,
}
/// File readback only. Selected index is not a claim of live runtime/egress.
pub fn registration(root: &std::path::Path, url: &str, fingerprint: &str) -> Result<Registration> {
    let path = root.join("profiles.yaml");
    if !path.exists() {
        return Ok(Registration::default());
    }
    let index = super::parse(&super::read(&path)?)?;
    for item in index["items"].as_array().into_iter().flatten() {
        if text(item, "url") != Some(url) {
            continue;
        }
        let file = text(item, "file").ok_or_else(|| err("profile_missing"))?;
        if file.contains(['/', '\\', ':']) || file.contains("..") || !file.ends_with(".yaml") {
            return Err(err("unsafe_path"));
        }
        let bytes = super::read(&root.join("profiles").join(file))?;
        if hash(&bytes) != fingerprint {
            return Err(err("config_changed"));
        }
        return Ok(Registration {
            registered: true,
            selected: text(item, "uid").is_some_and(|uid| Some(uid) == text(&index, "current")),
        });
    }
    Ok(Registration::default())
}

#[cfg(test)]
mod registration_tests {
    use super::*;
    #[test]
    fn import_readback_is_not_launch_ack_and_never_changes_current_profile() {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "profile-registration-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("profiles")).unwrap();
        let bytes = b"rules: []\n";
        let fingerprint = hash(bytes);
        let url = "http://127.0.0.1:12345/synthetic-capability/profile.yaml";
        assert!(!registration(&root, url, &fingerprint).unwrap().registered);
        std::fs::write(root.join("profiles/new.yaml"), bytes).unwrap();
        let index=serde_json::to_vec(&json!({"current":"old","items":[{"uid":"new","type":"remote","file":"new.yaml","url":url}]})).unwrap();
        std::fs::write(root.join("profiles.yaml"), &index).unwrap();
        let readback = registration(&root, url, &fingerprint).unwrap();
        assert!(readback.registered);
        assert!(!readback.selected);
        assert_eq!(std::fs::read(root.join("profiles.yaml")).unwrap(), index);
        std::fs::write(root.join("profiles/new.yaml"), b"changed").unwrap();
        assert!(registration(&root, url, &fingerprint).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
