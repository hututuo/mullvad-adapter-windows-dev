//! Off-owner catalogue comparison. Status reads only copy the bounded result.
use adapter_catalogue::Catalogue;
use adapter_protocol::catalogue_changes::{
    CatalogueChanges, CatalogueFieldChange, CatalogueRelayChange,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

fn normalized(value: &Value, key: &str) -> Value {
    match value {
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(k, v)| (k.clone(), normalized(v, k)))
                .collect(),
        ),
        Value::Array(values) => {
            let mut out: Vec<_> = values.iter().map(|v| normalized(v, "")).collect();
            if key == "relays"
                || key.ends_with("port_ranges")
                || values.iter().all(Value::is_string)
            {
                out.sort_by_cached_key(Value::to_string);
                out.dedup();
            }
            Value::Array(out)
        }
        _ => value.clone(),
    }
}
fn render(value: &Value, key: &str) -> String {
    // QUIC authorization material is only an internal comparison fact. Never
    // include its token/domain (including nested `other` facts) in UI or logs.
    fn contains_quic(value: &Value) -> bool {
        match value {
            Value::Object(object) => {
                object.contains_key("quic") || object.values().any(contains_quic)
            }
            Value::Array(values) => values.iter().any(contains_quic),
            _ => false,
        }
    }
    if key == "quic" || contains_quic(value) {
        return if value.is_null() {
            "无".into()
        } else {
            "QUIC 参数已配置".into()
        };
    }

    if key == "public_key" {
        return value
            .as_str()
            .map(|v| format!("SHA256:{:x}", Sha256::digest(v.as_bytes()))[..19].to_owned())
            .unwrap_or_else(|| "无".into());
    }
    match value {
        Value::Null => "无".into(),
        Value::Bool(true) => "可用".into(),
        Value::Bool(false) => "不可用".into(),
        Value::String(v) => v.chars().take(160).collect(),
        _ => normalized(value, key)
            .to_string()
            .chars()
            .take(160)
            .collect(),
    }
}
fn array_set(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| v.to_string())
        })
        .collect()
}
fn field(key: &str, label: &str, before: &Value, after: &Value) -> CatalogueFieldChange {
    let arrays = before.is_array() || after.is_array();
    let old = array_set(before);
    let new = array_set(after);
    let added: Vec<_> = new.difference(&old).cloned().collect();
    let removed: Vec<_> = old.difference(&new).cloned().collect();
    CatalogueFieldChange {
        key: key.into(),
        label: label.chars().take(100).collect(),
        before: render(before, key),
        after: render(after, key),
        added: arrays.then(|| added.iter().take(6).cloned().collect()),
        removed: arrays.then(|| removed.iter().take(6).cloned().collect()),
        added_count: arrays.then_some(added.len()),
        removed_count: arrays.then_some(removed.len()),
    }
}
fn relays(value: &Value) -> BTreeMap<String, &Value> {
    value["wireguard"]["relays"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r["hostname"].as_str().map(|name| (name.to_owned(), r)))
        .collect()
}
fn relay_change(
    name: &str,
    state: &str,
    fields: Vec<CatalogueFieldChange>,
) -> CatalogueRelayChange {
    CatalogueRelayChange {
        relay: Some(name.into()),
        state: state.into(),
        fields,
        ss_before_count: None,
        ss_after_count: None,
    }
}
pub(crate) fn compare(
    previous: Option<&Catalogue>,
    current: &Catalogue,
    current_relay: Option<&str>,
    checked_at: u64,
) -> CatalogueChanges {
    let baseline = previous.is_some();
    let empty = Value::Null;
    let a = previous.map(Catalogue::comparison_facts).unwrap_or(&empty);
    let b = current.comparison_facts();
    let old = relays(a);
    let new = relays(b);
    let labels = [
        ("ipv4_addr_in", "IPv4 直连地址"),
        ("ipv6_addr_in", "IPv6 直连地址"),
        ("public_key", "节点公钥"),
        ("active", "官方可用状态"),
        ("location", "城市"),
        ("shadowsocks_extra_addr_in", "专用 SS 地址"),
    ];
    let mut changed = BTreeMap::new();
    let mut added_count = 0;
    let mut removed_count = 0;
    let mut changed_count = 0;
    let mut shared_changes = vec![];
    if baseline {
        for (key, label) in [
            ("shadowsocks_port_ranges", "主地址 SS 端口范围"),
            ("port_ranges", "WG 直连端口范围"),
        ] {
            if normalized(&a["wireguard"][key], key) != normalized(&b["wireguard"][key], key) {
                shared_changes.push(field(
                    key,
                    label,
                    &a["wireguard"][key],
                    &b["wireguard"][key],
                ));
            }
        }
        for (name, row) in &new {
            if let Some(prior) = old.get(name) {
                if normalized(prior, "") == normalized(row, "") {
                    continue;
                }
                let mut fields: Vec<_> = labels
                    .iter()
                    .filter(|(key, _)| normalized(&prior[*key], key) != normalized(&row[*key], key))
                    .map(|(key, label)| field(key, label, &prior[*key], &row[*key]))
                    .collect();
                if normalized(&prior["features"]["quic"], "")
                    != normalized(&row["features"]["quic"], "")
                {
                    fields.push(field(
                        "quic",
                        "QUIC 入口或认证参数",
                        &prior["features"]["quic"],
                        &row["features"]["quic"],
                    ));
                }
                let other = |r: &Value| -> Value {
                    Value::Object(
                        r.as_object()
                            .into_iter()
                            .flatten()
                            .filter(|(key, _)| {
                                key.as_str() != "hostname"
                                    && !labels.iter().any(|(k, _)| *k == key.as_str())
                            })
                            .map(|(k, v)| {
                                let mut safe = v.clone();
                                if k == "features" {
                                    if let Some(features) = safe.as_object_mut() {
                                        features.remove("quic");
                                    }
                                }
                                (k.clone(), safe)
                            })
                            .collect::<Map<_, _>>(),
                    )
                };
                if normalized(&other(prior), "") != normalized(&other(row), "") {
                    fields.push(field(
                        "other",
                        "其他官方节点参数",
                        &other(prior),
                        &other(row),
                    ));
                }
                changed.insert(name.clone(), relay_change(name, "changed", fields));
                changed_count += 1;
            } else {
                changed.insert(name.clone(), relay_change(name, "added", vec![]));
                added_count += 1;
            }
        }
        for name in old.keys().filter(|name| !new.contains_key(*name)) {
            changed.insert(name.clone(), relay_change(name, "removed", vec![]));
            removed_count += 1;
        }
        let other = |v: &Value| {
            let mut object = v.as_object().cloned().unwrap_or_default();
            if let Some(wg) = object.get_mut("wireguard").and_then(Value::as_object_mut) {
                for key in ["relays", "port_ranges", "shadowsocks_port_ranges"] {
                    wg.remove(key);
                }
            }
            Value::Object(object)
        };
        if normalized(&other(a), "") != normalized(&other(b), "") {
            shared_changes.push(field(
                "other",
                "其他目录参数",
                &Value::String("上次目录".into()),
                &Value::String("有变化".into()),
            ));
        }
    }
    let mut focus = match current_relay {
        None => CatalogueRelayChange {
            relay: None,
            state: "unselected".into(),
            fields: vec![],
            ss_before_count: None,
            ss_after_count: None,
        },
        Some(name) if !baseline => relay_change(name, "no_baseline", vec![]),
        Some(name) => changed.get(name).cloned().unwrap_or_else(|| {
            relay_change(
                name,
                if new.contains_key(name) {
                    "unchanged"
                } else {
                    "unavailable"
                },
                vec![],
            )
        }),
    };
    if current_relay.is_some_and(|r| new.contains_key(r)) {
        focus
            .fields
            .extend(shared_changes.iter().filter(|f| f.key != "other").cloned());
        if focus.state == "unchanged" && !focus.fields.is_empty() {
            focus.state = "changed".into();
        }
    }
    let count = |cat: Option<&Catalogue>| {
        cat.map(|c| {
            c.relays()
                .iter()
                .find(|r| Some(r.hostname()) == current_relay)
                .map_or(0, |r| c.shadowsocks_candidate_count(r))
        })
    };
    focus.ss_before_count = count(previous);
    focus.ss_after_count = count(Some(current));
    let total = changed.len();
    let mut changed_relays = vec![];
    if let Some(focus) = current_relay.and_then(|name| changed.remove(name)) {
        changed_relays.push(focus);
    }
    changed_relays.extend(changed.into_values().take(8 - changed_relays.len()));
    let mut report = CatalogueChanges {
        checked_at,
        baseline_available: baseline,
        catalogue_changed: baseline.then(|| normalized(a, "") != normalized(b, "")),
        added_count,
        removed_count,
        changed_count,
        shared_changes,
        current_relay: focus,
        truncated_count: total - changed_relays.len(),
        changed_relays,
    };
    // The dashboard shares a bounded IPC frame with cities and recovery state.
    while report.changed_relays.len() > 1
        && serde_json::to_vec(&report).is_ok_and(|b| b.len() > 16 * 1024)
    {
        report.changed_relays.pop();
        report.truncated_count += 1;
    }
    report
}

#[cfg(test)]
#[path = "catalogue_changes_tests.rs"]
mod tests;
