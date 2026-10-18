use serde_json::Value;
#[test]
fn legacy_fixtures_preserve_required_client_shapes_without_secret_data() {
    for (name, data, fields) in [
        (
            "status",
            include_str!("../fixtures/legacy/status.json"),
            vec!["status", "active_relay", "generation", "local_network"],
        ),
        (
            "cities",
            include_str!("../fixtures/legacy/cities.json"),
            vec![
                "favorite_cities",
                "selected_city",
                "cities",
                "auto_cross_city",
            ],
        ),
        (
            "relays",
            include_str!("../fixtures/legacy/relays.json"),
            vec![],
        ),
        (
            "protection",
            include_str!("../fixtures/legacy/protection.json"),
            vec!["profile", "effective", "capabilities"],
        ),
        (
            "account",
            include_str!("../fixtures/legacy/account.json"),
            vec!["signed_in", "verified", "device_match", "devices"],
        ),
        (
            "operation",
            include_str!("../fixtures/legacy/operation.json"),
            vec!["id", "state", "kind", "result"],
        ),
    ] {
        let value: Value = serde_json::from_str(data).unwrap();
        for field in fields {
            assert!(value.get(field).is_some(), "{name}.{field}");
        }
        for denied in [
            "private-key",
            "private_key",
            "account_number",
            "access_token",
            "Bearer ",
            "/Users/",
            "/workspace/",
            "/tmp/",
        ] {
            assert!(!data.contains(denied), "{name} contains {denied}");
        }
    }
}
