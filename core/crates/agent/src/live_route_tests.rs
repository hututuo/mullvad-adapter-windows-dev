//! Pure tests for transport-aware relay endpoint authorization.
//! No sockets, identity material, engine process, or GUI are involved.
use super::{Family, Route, CHAIN, SS, V4, V6};
use adapter_catalogue::{Catalogue, Relay};
use adapter_engine_mihomo::Transport;
use serde_json::json;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

const PUBLIC_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
const IPV4: &str = "192.0.2.10";
const IPV6: &str = "2001:db8::10";

fn make_catalogue(
    ipv4: Option<&str>,
    ipv6: Option<&str>,
    active: bool,
    wg_ports: &[[u16; 2]],
    ss_ports: &[[u16; 2]],
) -> Catalogue {
    let payload = json!({
        "wireguard": {
            "port_ranges": wg_ports,
            "shadowsocks_port_ranges": ss_ports,
            "relays": [{
                "hostname": "us-test-wg-1",
                "location": "us-test",
                "active": active,
                "public_key": PUBLIC_KEY,
                "ipv4_addr_in": ipv4,
                "ipv6_addr_in": ipv6,
                "shadowsocks_extra_addr_in": []
            }]
        }
    });
    Catalogue::parse(payload.to_string().as_bytes()).expect("synthetic relay catalogue is valid")
}

fn full_catalogue() -> Catalogue {
    // Include the WG v4 port in the SS range to exercise the same socket tuple
    // under two distinct, explicitly authorized transport kinds.
    make_catalogue(
        Some(IPV4),
        Some(IPV6),
        true,
        &[[33_431, 33_431], [51_820, 51_820]],
        &[[51_820, 51_820]],
    )
}

fn only_relay(catalogue: &Catalogue) -> &Relay {
    &catalogue.relays()[0]
}

#[test]
fn native_routes_use_the_official_family_endpoint_and_allowed_port() {
    let catalogue = full_catalogue();
    let relay = only_relay(&catalogue);

    let v6 = Route::native(&catalogue, relay, Family::V6).expect("authorized IPv6 route");
    assert_eq!(v6.kind(), V6);
    assert_eq!(v6.endpoint().to_string(), "[2001:db8::10]:33431");
    assert!(v6.ipv6());
    assert!(!v6.is_ss());
    assert!(!v6.chained);
    assert!(matches!(
        v6.transport,
        Transport::DirectV6 { endpoint, port }
            if endpoint == IPV6.parse::<Ipv6Addr>().unwrap() && port == 33_431
    ));

    let v4 = Route::native(&catalogue, relay, Family::V4).expect("authorized IPv4 route");
    assert_eq!(v4.kind(), V4);
    assert_eq!(v4.endpoint().to_string(), "192.0.2.10:51820");
    assert!(!v4.ipv6());
    assert!(!v4.is_ss());
    assert!(!v4.chained);
    assert!(matches!(
        v4.transport,
        Transport::DirectV4 { endpoint, port }
            if endpoint == IPV4.parse::<Ipv4Addr>().unwrap() && port == 51_820
    ));
}

#[test]
fn native_authorization_rejects_missing_or_withdrawn_family_and_disallowed_ports() {
    let missing_v6 = make_catalogue(
        Some(IPV4),
        None,
        true,
        &[[33_431, 33_431], [51_820, 51_820]],
        &[[51_820, 51_820]],
    );
    assert!(Route::native(&missing_v6, only_relay(&missing_v6), Family::V6).is_none());

    let missing_v4 = make_catalogue(
        None,
        Some(IPV6),
        true,
        &[[33_431, 33_431], [51_820, 51_820]],
        &[[51_820, 51_820]],
    );
    assert!(Route::native(&missing_v4, only_relay(&missing_v4), Family::V4).is_none());

    let catalogue = full_catalogue();
    let relay = only_relay(&catalogue);
    assert!(Route::authorize(&catalogue, relay, V4, "192.0.2.99:51820").is_none());
    assert!(Route::authorize(&catalogue, relay, V6, "[2001:db8::99]:33431").is_none());
    assert!(Route::authorize(&catalogue, relay, V4, "192.0.2.10:51821").is_none());
    assert!(Route::authorize(&catalogue, relay, V6, "[2001:db8::10]:33432").is_none());

    let disallowed_v6 = make_catalogue(
        Some(IPV4),
        Some(IPV6),
        true,
        &[[51_820, 51_820]],
        &[[51_820, 51_820]],
    );
    assert!(Route::native(&disallowed_v6, only_relay(&disallowed_v6), Family::V6).is_none());

    let inactive = make_catalogue(
        Some(IPV4),
        Some(IPV6),
        false,
        &[[33_431, 33_431], [51_820, 51_820]],
        &[[51_820, 51_820]],
    );
    assert!(Route::native(&inactive, only_relay(&inactive), Family::V4).is_none());
}

#[test]
fn ipv6_endpoint_roundtrips_as_bracketed_socket_address() {
    let catalogue = full_catalogue();
    let relay = only_relay(&catalogue);
    let original = Route::native(&catalogue, relay, Family::V6).unwrap();
    let endpoint = original.endpoint().to_string();

    assert_eq!(endpoint, "[2001:db8::10]:33431");
    let restored = Route::authorize(&catalogue, relay, original.kind(), &endpoint)
        .expect("bracketed IPv6 address remains authorizable");
    assert_eq!(restored.kind(), V6);
    assert_eq!(
        restored.endpoint(),
        SocketAddr::new(IPV6.parse().unwrap(), 33_431)
    );
}

#[test]
fn transport_kind_disambiguates_ss_and_native_v4_on_the_same_socket() {
    let catalogue = full_catalogue();
    let relay = only_relay(&catalogue);
    let same_socket = "192.0.2.10:51820";

    let native = Route::authorize(&catalogue, relay, V4, same_socket)
        .expect("official native V4 endpoint and WG port");
    let ss = Route::authorize(&catalogue, relay, SS, same_socket)
        .expect("same tuple is also in the synthetic official SS range");
    let chained_ss = Route::authorize(&catalogue, relay, CHAIN, same_socket)
        .expect("chain retains its distinct route kind");

    assert_eq!(native.kind(), V4);
    assert!(!native.is_ss());
    assert!(matches!(native.transport, Transport::DirectV4 { .. }));
    assert_eq!(ss.kind(), SS);
    assert!(ss.is_ss());
    assert!(!ss.chained);
    assert!(matches!(ss.transport, Transport::Shadowsocks { .. }));
    assert_eq!(chained_ss.kind(), CHAIN);
    assert!(chained_ss.is_ss());
    assert!(chained_ss.chained);
    assert_eq!(native.endpoint(), ss.endpoint());
}

#[test]
fn unknown_kind_and_foreign_scoped_ipv6_endpoint_are_rejected() {
    let catalogue = full_catalogue();
    let relay = only_relay(&catalogue);

    assert!(Route::authorize(&catalogue, relay, "wireguard-ipv7", "192.0.2.10:51820").is_none());

    let foreign_scoped = SocketAddr::V6(SocketAddrV6::new(
        "2001:db8::11".parse().unwrap(),
        33_431,
        0,
        7,
    ))
    .to_string();
    assert!(foreign_scoped.contains("%7"));
    assert!(Route::authorize(&catalogue, relay, V6, &foreign_scoped).is_none());

    // Also prove that no foreign address can pass merely by entering as a
    // scoped IP string rather than a canonical SocketAddr literal.
    assert!(Route::authorize(&catalogue, relay, V6, "[fe80::10%7]:33431").is_none());
}

#[test]
fn outer_family_requires_a_matching_physical_binding() {
    use adapter_platform::physical_attachment::PhysicalBinding;
    let cat = full_catalogue();
    let relay = only_relay(&cat);
    let v4 = Route::native(&cat, relay, Family::V4).unwrap();
    let v6 = Route::native(&cat, relay, Family::V6).unwrap();
    let v4_binding = PhysicalBinding {
        luid: 1,
        index: 1,
        ipv4: true,
        ipv6: false,
    };
    let v6_binding = PhysicalBinding {
        luid: 2,
        index: 2,
        ipv4: false,
        ipv6: true,
    };
    assert!(v6.binding(&[v4_binding]).is_none());
    assert!(v4.binding(&[v6_binding]).is_none());
    assert_eq!(v6.binding(&[v4_binding, v6_binding]).unwrap().index, 2);
    assert_eq!(v4.binding(&[v6_binding, v4_binding]).unwrap().index, 1);
}

#[test]
fn quic_endpoint_is_authorized_only_by_current_official_capability() {
    let mut payload = json!({"wireguard":{"port_ranges":[[51820,51820]],"shadowsocks_port_ranges":[[51900,51900]],"relays":[{"hostname":"us-test-wg-1","location":"us-test","active":true,"public_key":PUBLIC_KEY,"ipv4_addr_in":IPV4,"features":{"quic":{"addr_in":["192.0.2.11","2001:db8::11"],"domain":"quic.example.net","token":"not-for-logs"}}}]}});
    let cat = Catalogue::parse(payload.to_string().as_bytes()).unwrap();
    let relay = &cat.relays()[0];
    for inlet in ["192.0.2.11:443", "[2001:db8::11]:443"] {
        let route = Route::authorize(&cat, relay, super::QUIC, inlet).unwrap();
        assert_eq!(route.kind(), super::QUIC);
        assert!(!route.chained);
    }
    for inlet in ["192.0.2.10:443", "192.0.2.11:51820", "[::1]:443"] {
        assert!(Route::authorize(&cat, relay, super::QUIC, inlet).is_none());
    }
    payload["wireguard"]["relays"][0]["features"]["quic"] = serde_json::Value::Null;
    let withdrawn = Catalogue::parse(payload.to_string().as_bytes()).unwrap();
    assert!(Route::authorize(
        &withdrawn,
        &withdrawn.relays()[0],
        super::QUIC,
        "192.0.2.11:443"
    )
    .is_none());
}

#[test]
fn active_checks_keep_selected_interface_and_outer_family() {
    use adapter_platform::physical_attachment::PhysicalBinding;
    let v4 = PhysicalBinding {
        luid: 1,
        index: 1,
        ipv4: true,
        ipv6: false,
    };
    let v6 = PhysicalBinding {
        luid: 2,
        index: 2,
        ipv4: false,
        ipv6: true,
    };
    let bindings = [v4, v6];
    assert!(super::active_binding(&bindings, 2, super::QUIC, "[2001:db8::1]:443") == Some(v6));
    assert!(super::active_binding(&bindings, 1, super::QUIC, "[2001:db8::1]:443").is_none());
    assert!(super::active_binding(&bindings, 2, V6, "[2001:db8::1]:33431") == Some(v6));
    assert!(super::active_binding(&bindings, 1, SS, "192.0.2.1:443") == Some(v4));
}
