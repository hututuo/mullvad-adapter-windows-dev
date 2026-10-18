use adapter_domain::*;
#[test]
fn shared_canary_fixture_matches_ruby_classification_and_candidate_gate() {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../../protocol/fixtures/canary-cases.json")).unwrap();
    for row in rows {
        let b = |key| row[key].as_bool().unwrap();
        let canary = Canary {
            ip: b("ip"),
            dns: b("dns"),
            https: b("https"),
        };
        let expected = match row["readiness"].as_str().unwrap() {
            "ready" => Readiness::Ready,
            "degraded_dns" => Readiness::DegradedDns,
            "degraded_service" => Readiness::DegradedService,
            "data_fail" => Readiness::DataFail,
            _ => panic!("fixture"),
        };
        assert_eq!(canary.alive(), b("alive"));
        assert_eq!(canary.readiness(), expected);
        assert_eq!(
            canary.accepts_new(
                Protection {
                    multihop: false,
                    post_quantum: b("pq")
                },
                b("require_ready")
            ),
            b("accept")
        );
    }
}
