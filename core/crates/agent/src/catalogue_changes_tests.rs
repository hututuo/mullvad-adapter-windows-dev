use super::*;
use serde_json::{json, Value};

const KEY_A: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
const KEY_B: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

fn relay(hostname: &str, location: &str, public_key: &str, ipv4: &str, extras: &[&str]) -> Value {
    json!({
        "hostname": hostname,
        "location": location,
        "active": true,
        "public_key": public_key,
        "ipv4_addr_in": ipv4,
        "ipv6_addr_in": "2001:db8::10",
        "shadowsocks_extra_addr_in": extras,
    })
}

fn catalogue(relays: Vec<Value>, ss_ranges: &[[u16; 2]]) -> Catalogue {
    let payload = json!({
        "wireguard": {
            "port_ranges": [[33431, 33431], [51820, 51820]],
            "shadowsocks_port_ranges": ss_ranges,
            "relays": relays,
        }
    });
    Catalogue::parse(payload.to_string().as_bytes()).expect("fixture catalogue is valid")
}

#[test]
fn padded_public_addresses_are_canonicalized_before_bounded_change_lists() {
    let a = relay("relay-one", "us-sjc", KEY_A, "192.0.2.10", &["192.0.2.20"]);
    let mut padded = a.clone();
    padded["shadowsocks_extra_addr_in"] = json!([format!(
        "{}192.0.2.20{}",
        " ".repeat(40_000),
        " ".repeat(40_000)
    )]);
    let previous = catalogue(vec![a], &[[51900, 51901]]);
    let current = catalogue(vec![padded], &[[51900, 51901]]);
    let report = compare(Some(&previous), &current, Some("relay-one"), 42);
    assert_eq!(report.catalogue_changed, Some(false));
    assert!(serde_json::to_vec(&report).unwrap().len() < 2048);
}

fn one_relay(extras: &[&str], ipv4: &str, key: &str, ss_ranges: &[[u16; 2]]) -> Catalogue {
    catalogue(
        vec![relay("us-sea-wg-1", "us-sea", key, ipv4, extras)],
        ss_ranges,
    )
}

fn field<'a>(
    fields: &'a [adapter_protocol::catalogue_changes::CatalogueFieldChange],
    key: &str,
) -> &'a adapter_protocol::catalogue_changes::CatalogueFieldChange {
    fields
        .iter()
        .find(|field| field.key == key)
        .expect("expected field change")
}

#[test]
fn no_change_ignores_relay_and_string_array_order_and_duplicates() {
    let sea = relay(
        "us-sea-wg-1",
        "us-sea",
        KEY_A,
        "192.0.2.10",
        &["198.51.100.5", "198.51.100.6"],
    );
    let tor = relay(
        "ca-tor-wg-1",
        "ca-tor",
        KEY_A,
        "192.0.2.20",
        &["198.51.100.7"],
    );
    let previous = catalogue(
        vec![sea.clone(), tor.clone()],
        &[[20484, 20484], [20485, 20485]],
    );
    let refreshed = catalogue(
        vec![tor, sea.clone(), sea],
        &[[20485, 20485], [20484, 20484], [20484, 20484]],
    );

    let report = compare(Some(&previous), &refreshed, Some("us-sea-wg-1"), 42);

    assert_eq!(report.catalogue_changed, Some(false));
    assert_eq!(report.changed_count, 0);
    assert_eq!(report.added_count, 0);
    assert_eq!(report.removed_count, 0);
    assert_eq!(report.current_relay.state, "unchanged");
    assert!(report.shared_changes.is_empty());
    assert!(report.changed_relays.is_empty());
}

#[test]
fn changes_to_another_relay_do_not_mark_the_current_relay_changed() {
    let previous = catalogue(
        vec![
            relay("us-sea-wg-1", "us-sea", KEY_A, "192.0.2.10", &[]),
            relay("ca-tor-wg-1", "ca-tor", KEY_A, "192.0.2.20", &[]),
        ],
        &[[20484, 20484]],
    );
    let current = catalogue(
        vec![
            relay("us-sea-wg-1", "us-sea", KEY_A, "192.0.2.10", &[]),
            relay("ca-tor-wg-1", "ca-tor", KEY_A, "192.0.2.21", &[]),
        ],
        &[[20484, 20484]],
    );

    let report = compare(Some(&previous), &current, Some("us-sea-wg-1"), 43);

    assert_eq!(report.catalogue_changed, Some(true));
    assert_eq!(report.changed_count, 1);
    assert_eq!(report.current_relay.state, "unchanged");
    assert!(report.current_relay.fields.is_empty());
    assert_eq!(
        report.changed_relays[0].relay.as_deref(),
        Some("ca-tor-wg-1")
    );
}

#[test]
fn current_relay_reports_ss_address_add_remove_and_ip_change_with_windows_counts() {
    let previous = one_relay(
        &["198.51.100.5", "198.51.100.6"],
        "192.0.2.10",
        KEY_A,
        &[[20484, 20485]],
    );
    let current = one_relay(
        &["198.51.100.6", "203.0.113.7", "203.0.113.8"],
        "192.0.2.11",
        KEY_A,
        &[[20484, 20485]],
    );

    let report = compare(Some(&previous), &current, Some("us-sea-wg-1"), 44);

    assert_eq!(report.current_relay.state, "changed");
    assert_eq!(report.current_relay.ss_before_count, Some(6));
    assert_eq!(report.current_relay.ss_after_count, Some(8));
    let extras = field(&report.current_relay.fields, "shadowsocks_extra_addr_in");
    assert_eq!(extras.added_count, Some(2));
    assert_eq!(extras.removed_count, Some(1));
    assert_eq!(
        extras.added.as_ref().unwrap(),
        &vec![String::from("203.0.113.7"), String::from("203.0.113.8")]
    );
    assert_eq!(
        extras.removed.as_ref().unwrap(),
        &vec![String::from("198.51.100.5")]
    );
    assert_eq!(
        field(&report.current_relay.fields, "ipv4_addr_in").before,
        "192.0.2.10"
    );
    assert_eq!(
        field(&report.current_relay.fields, "ipv4_addr_in").after,
        "192.0.2.11"
    );
}

#[test]
fn windows_ss_candidate_count_includes_dedicated_443_and_deduplicates_address_port_pairs() {
    let current = one_relay(&["192.0.2.10"], "192.0.2.10", KEY_A, &[[20484, 20485]]);

    let report = compare(None, &current, Some("us-sea-wg-1"), 45);

    // Dedicated address contributes 20484 and 443; the official primary range
    // contributes 20484 and 20485, with the duplicate address:20484 counted once.
    assert_eq!(report.current_relay.ss_after_count, Some(3));
}

#[test]
fn public_key_change_is_rendered_as_a_digest_only() {
    let previous = one_relay(&[], "192.0.2.10", KEY_A, &[[20484, 20484]]);
    let current = one_relay(&[], "192.0.2.10", KEY_B, &[[20484, 20484]]);

    let report = compare(Some(&previous), &current, Some("us-sea-wg-1"), 46);

    let key = field(&report.current_relay.fields, "public_key");
    assert!(key.before.starts_with("SHA256:"));
    assert!(key.after.starts_with("SHA256:"));
    assert_eq!(key.before.len(), "SHA256:".len() + 12);
    assert_eq!(key.after.len(), "SHA256:".len() + 12);
    assert_ne!(key.before, key.after);
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(!serialized.contains(KEY_A));
    assert!(!serialized.contains(KEY_B));
}

#[test]
fn shared_ss_port_range_change_marks_an_unchanged_current_relay_changed() {
    let previous = one_relay(&[], "192.0.2.10", KEY_A, &[[20484, 20484]]);
    let current = one_relay(&[], "192.0.2.10", KEY_A, &[[20484, 20485]]);

    let report = compare(Some(&previous), &current, Some("us-sea-wg-1"), 47);

    assert_eq!(report.current_relay.state, "changed");
    assert_eq!(report.current_relay.ss_before_count, Some(1));
    assert_eq!(report.current_relay.ss_after_count, Some(2));
    assert!(report
        .shared_changes
        .iter()
        .any(|change| change.key == "shadowsocks_port_ranges"));
    assert_eq!(
        field(&report.current_relay.fields, "shadowsocks_port_ranges").added_count,
        Some(1)
    );
}

#[test]
fn first_comparison_has_no_baseline_and_only_current_ss_count() {
    let current = one_relay(&[], "192.0.2.10", KEY_A, &[[20484, 20484]]);

    let report = compare(None, &current, Some("us-sea-wg-1"), 48);

    assert!(!report.baseline_available);
    assert_eq!(report.catalogue_changed, None);
    assert_eq!(report.current_relay.state, "no_baseline");
    assert_eq!(report.current_relay.ss_before_count, None);
    assert_eq!(report.current_relay.ss_after_count, Some(1));
    assert!(report.shared_changes.is_empty());
}

#[test]
fn removed_current_relay_remains_visible_as_unavailable_with_zero_current_count() {
    let previous = catalogue(
        vec![
            relay("us-sea-wg-1", "us-sea", KEY_A, "192.0.2.10", &[]),
            relay("ca-tor-wg-1", "ca-tor", KEY_A, "192.0.2.20", &[]),
        ],
        &[[20484, 20484]],
    );
    let current = catalogue(
        vec![relay("ca-tor-wg-1", "ca-tor", KEY_A, "192.0.2.20", &[])],
        &[[20484, 20484]],
    );

    let report = compare(Some(&previous), &current, Some("us-sea-wg-1"), 49);

    assert_eq!(report.current_relay.state, "removed");
    assert_eq!(report.current_relay.ss_before_count, Some(1));
    assert_eq!(report.current_relay.ss_after_count, Some(0));
    assert_eq!(report.removed_count, 1);
    assert_eq!(
        report.changed_relays[0].relay.as_deref(),
        Some("us-sea-wg-1")
    );
    assert_eq!(report.changed_relays[0].state, "removed");
}

#[test]
fn changed_relay_list_is_bounded_current_first_and_json_stays_under_ipc_limit() {
    let previous = catalogue(
        (0..14)
            .map(|index| {
                relay(
                    &format!("relay-{index:02}"),
                    "us-sea",
                    KEY_A,
                    &format!("192.0.2.{}", index + 1),
                    &[],
                )
            })
            .collect(),
        &[[20484, 20484]],
    );
    let current = catalogue(
        (0..14)
            .map(|index| {
                relay(
                    &format!("relay-{index:02}"),
                    "ca-tor",
                    KEY_A,
                    &format!("192.0.2.{}", index + 1),
                    &[],
                )
            })
            .collect(),
        &[[20484, 20484]],
    );

    let report = compare(Some(&previous), &current, Some("relay-12"), 50);

    assert_eq!(report.changed_count, 14);
    assert_eq!(report.changed_relays.len(), 8);
    assert_eq!(report.changed_relays[0].relay.as_deref(), Some("relay-12"));
    assert_eq!(report.truncated_count, 6);
    assert!(serde_json::to_vec(&report).unwrap().len() < 16 * 1024);
}
