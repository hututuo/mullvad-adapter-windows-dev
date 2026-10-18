//! Bounded, read-only public history summaries. No storage, clocks, I/O or readiness authority.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

pub const MAX_BODY_BYTES: usize = 1_048_576;
pub const MAX_ROWS: usize = 1024;
pub const MAX_SOURCES: usize = 32;
/// Integers remain exact in a future JavaScript client as well as Rust and Swift.
pub const MAX_COUNTER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Limit,
    InvalidInput,
    InvalidSummary,
    DuplicateIdentity,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Transport {
    #[serde(rename = "ss")]
    Shadowsocks,
    #[serde(rename = "ipv6")]
    DirectV6,
    #[serde(rename = "ipv4")]
    DirectV4,
}
impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shadowsocks => "ss",
            Self::DirectV6 => "ipv6",
            Self::DirectV4 => "ipv4",
        }
    }
}

// Deserialization stays private: every public Summary has passed validation.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawSummary {
    relay: String,
    transport_mode: Transport,
    samples: u64,
    relay_pass_samples: u64,
    ready_samples: u64,
    failed_samples: u64,
    consecutive_failures: u64,
    latency_samples: u64,
    latency_ewma_ms: Option<f64>,
    best_delay_ms: Option<u64>,
    worst_delay_ms: Option<u64>,
    last_delay_ms: Option<u64>,
    first_tested_at: Option<String>,
    last_tested_at: Option<String>,
    last_success_at: Option<String>,
    last_failure_at: Option<String>,
    source_counts: Option<Sources>,
    readiness_rate: Option<f64>,
}

#[derive(Serialize)]
#[serde(transparent)]
struct Sources(BTreeMap<String, u64>);
impl<'de> Deserialize<'de> for Sources {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Sources;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bounded unique source counters")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, u64>()? {
                    if values.len() >= MAX_SOURCES || values.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("invalid source counters"));
                    }
                }
                Ok(Sources(values))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

#[derive(Serialize)]
#[serde(transparent)]
pub struct Summary(RawSummary);
impl Summary {
    pub fn relay(&self) -> &str {
        &self.0.relay
    }
    pub fn transport(&self) -> Transport {
        self.0.transport_mode
    }
    pub fn id(&self) -> String {
        format!("{}|{}", self.relay(), self.transport().as_str())
    }
    pub fn samples(&self) -> u64 {
        self.0.samples
    }
    pub fn ready_samples(&self) -> u64 {
        self.0.ready_samples
    }
    pub fn consecutive_failures(&self) -> u64 {
        self.0.consecutive_failures
    }
    /// None means no observations. A renderer must not paint unknown as 0% failure.
    pub fn readiness_rate(&self) -> Option<f64> {
        (self.samples() > 0).then(|| self.ready_samples() as f64 / self.samples() as f64)
    }
    /// Legacy Swift compatibility only; use readiness_rate for truthful display.
    pub fn effective_readiness_rate(&self) -> f64 {
        self.0
            .readiness_rate
            .unwrap_or_else(|| self.readiness_rate().unwrap_or(0.0))
    }
    pub fn stability_confidence_score(&self) -> f64 {
        if self.samples() == 0 {
            return -1.0;
        }
        let n = self.samples() as f64;
        let p = self.ready_samples() as f64 / n;
        let z = 1.96;
        let z2 = z * z;
        let numerator = p + z2 / (2.0 * n) - z * ((p * (1.0 - p) + z2 / (4.0 * n)) / n).sqrt();
        numerator / (1.0 + z2 / n) - self.consecutive_failures().min(3) as f64 * 0.04
    }
}

pub struct HistorySnapshot {
    rows: Vec<Summary>,
}
impl HistorySnapshot {
    /// Input must already be a normalized current public summary array, not a saved file.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_BODY_BYTES {
            return Err(Error::Limit);
        }
        // The byte cap also bounds temporary decoder allocations; rows are never truncated.
        let raw: Vec<RawSummary> =
            serde_json::from_slice(bytes).map_err(|_| Error::InvalidInput)?;
        if raw.len() > MAX_ROWS {
            return Err(Error::Limit);
        }
        let mut identities = HashSet::new();
        let mut rows = Vec::with_capacity(raw.len());
        for row in raw {
            validate(&row)?;
            let summary = Summary(row);
            if !identities.insert(summary.id()) {
                return Err(Error::DuplicateIdentity);
            }
            rows.push(summary);
        }
        rows.sort_by(|a, b| {
            (a.relay(), a.transport().as_str()).cmp(&(b.relay(), b.transport().as_str()))
        });
        Ok(Self { rows })
    }
    pub fn rows(&self) -> &[Summary] {
        &self.rows
    }
    /// Allowlisted fields only. This body is NOT an IPC frame or a persistence envelope.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        let body = serde_json::to_vec(&self.rows).map_err(|_| Error::InvalidSummary)?;
        if body.len() > MAX_BODY_BYTES {
            return Err(Error::Limit);
        }
        Ok(body)
    }
}

fn validate(row: &RawSummary) -> Result<(), Error> {
    let invalid = || Error::InvalidSummary;
    if row.relay.is_empty()
        || row.relay.len() > 255
        || !row
            .relay
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || [
            row.samples,
            row.relay_pass_samples,
            row.ready_samples,
            row.failed_samples,
            row.consecutive_failures,
            row.latency_samples,
        ]
        .iter()
        .any(|&n| n > MAX_COUNTER)
        || row.ready_samples > row.relay_pass_samples
        || row.relay_pass_samples > row.samples
        || row.failed_samples != row.samples - row.ready_samples
        || row.consecutive_failures > row.failed_samples
        || row.latency_samples > row.samples
    {
        return Err(invalid());
    }
    if let Some(rate) = row.readiness_rate {
        if row.samples == 0
            || !rate.is_finite()
            || !(0.0..=1.0).contains(&rate)
            || (rate - row.ready_samples as f64 / row.samples as f64).abs() > 1e-12
        {
            return Err(invalid());
        }
    }
    let delays = [row.best_delay_ms, row.worst_delay_ms, row.last_delay_ms];
    if delays.iter().flatten().any(|&n| n > MAX_COUNTER)
        || row
            .latency_ewma_ms
            .is_some_and(|n| !n.is_finite() || n < 0.0 || n > MAX_COUNTER as f64)
        || (row.latency_samples == 0
            && (row.latency_ewma_ms.is_some() || delays.iter().any(Option::is_some)))
        || matches!((row.best_delay_ms, row.worst_delay_ms), (Some(a), Some(b)) if a > b)
        || matches!((row.best_delay_ms, row.last_delay_ms), (Some(a), Some(b)) if a > b)
        || matches!((row.last_delay_ms, row.worst_delay_ms), (Some(a), Some(b)) if a > b)
    {
        return Err(invalid());
    }
    // Timestamps are bounded display labels only. No ordering, freshness or clock inference.
    for text in [
        &row.first_tested_at,
        &row.last_tested_at,
        &row.last_success_at,
        &row.last_failure_at,
    ]
    .into_iter()
    .flatten()
    {
        if text.is_empty() || text.len() > 64 || !text.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
            return Err(invalid());
        }
    }
    if let Some(Sources(sources)) = &row.source_counts {
        let mut sum = 0u64;
        for (name, count) in sources {
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
                || *count > row.samples
            {
                return Err(invalid());
            }
            sum = sum.checked_add(*count).ok_or_else(invalid)?;
        }
        // Legacy summaries may omit/partially retain source counters; never invent the missing part.
        if sum > row.samples {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn cases() -> Vec<Value> {
        serde_json::from_str::<Value>(include_str!("../fixtures/summary-contract.json")).unwrap()
            ["cases"]
            .as_array()
            .unwrap()
            .clone()
    }
    fn one(value: Value) -> Result<HistorySnapshot, Error> {
        HistorySnapshot::parse(&serde_json::to_vec(&vec![value]).unwrap())
    }
    fn valid() -> Value {
        cases()
            .into_iter()
            .find(|c| c["name"] == "stable_twenty")
            .unwrap()["summary"]
            .clone()
    }
    fn rejected(value: Value) {
        assert!(one(value).is_err());
    }

    #[test]
    fn shared_public_summary_fields_rates_and_scores() {
        for case in cases() {
            let snapshot = one(case["summary"].clone()).unwrap();
            let row = &snapshot.rows()[0];
            assert_eq!(
                serde_json::to_value(row).unwrap(),
                case["summary"],
                "{}",
                case["name"]
            );
            assert_eq!(row.id(), case["id"].as_str().unwrap());
            assert_eq!(
                serde_json::to_value(row.readiness_rate()).unwrap(),
                case["expected_rate"]
            );
            assert!(
                (row.effective_readiness_rate()
                    - case["expected_effective_rate"].as_f64().unwrap())
                .abs()
                    < 1e-12
            );
            assert!(
                (row.stability_confidence_score() - case["expected_score"].as_f64().unwrap()).abs()
                    < 1e-12
            );
            let roundtrip = HistorySnapshot::parse(&snapshot.to_json().unwrap()).unwrap();
            assert_eq!(roundtrip.to_json().unwrap(), snapshot.to_json().unwrap());
        }
    }

    #[test]
    fn missing_rate_uses_counts_and_zero_remains_unknown() {
        for case in cases() {
            let mut summary = case["summary"].clone();
            summary.as_object_mut().unwrap().remove("readiness_rate");
            let snapshot = one(summary).unwrap();
            let row = &snapshot.rows()[0];
            assert_eq!(
                serde_json::to_value(row.readiness_rate()).unwrap(),
                case["expected_rate"]
            );
            assert!(
                (row.effective_readiness_rate()
                    - case["expected_effective_rate"].as_f64().unwrap())
                .abs()
                    < 1e-12
            );
        }
    }

    #[test]
    fn sorting_and_identity_keep_transports_separate() {
        let mut values: Vec<_> = cases().into_iter().map(|c| c["summary"].clone()).collect();
        values.reverse();
        let snapshot = HistorySnapshot::parse(&serde_json::to_vec(&values).unwrap()).unwrap();
        let ids: Vec<_> = snapshot.rows().iter().map(Summary::id).collect();
        let mut expected = ids.clone();
        expected.sort();
        assert_eq!(ids, expected);
        assert_eq!(
            snapshot
                .rows()
                .iter()
                .filter(|s| s.relay() == "us-aaa-wg-003")
                .count(),
            3
        );
        values.push(values[0].clone());
        assert!(matches!(
            HistorySnapshot::parse(&serde_json::to_vec(&values).unwrap()),
            Err(Error::DuplicateIdentity)
        ));
    }

    #[test]
    fn wilson_confidence_and_penalty_cap_preserve_legacy_order() {
        let score = |name: &str| {
            let case = cases().into_iter().find(|c| c["name"] == name).unwrap();
            one(case["summary"].clone()).unwrap().rows()[0].stability_confidence_score()
        };
        assert!(score("stable_twenty") > score("one_success"));
        assert_eq!(score("three_failures"), score("five_failures"));
        assert!(score("zero_unknown") < score("all_failed"));
    }

    #[test]
    fn optional_labels_and_measurements_can_remain_unknown() {
        let mut row = valid();
        for field in [
            "latency_ewma_ms",
            "best_delay_ms",
            "worst_delay_ms",
            "last_delay_ms",
            "first_tested_at",
            "last_tested_at",
            "last_success_at",
            "last_failure_at",
            "source_counts",
            "readiness_rate",
        ] {
            row.as_object_mut().unwrap().remove(field);
        }
        let snapshot = one(row).unwrap();
        let public = serde_json::to_value(&snapshot.rows()[0]).unwrap();
        assert!(public["latency_ewma_ms"].is_null());
        assert!(public["last_tested_at"].is_null());
        assert!(public["source_counts"].is_null());
        assert_eq!(snapshot.rows()[0].readiness_rate(), Some(1.0));
    }

    #[test]
    fn counters_rates_and_latency_reject_impossible_values() {
        for (field, value) in [
            ("samples", json!(-1)),
            ("samples", json!(1.5)),
            ("samples", json!("20")),
            ("samples", json!(MAX_COUNTER + 1)),
            ("ready_samples", json!(21)),
            ("relay_pass_samples", json!(19)),
            ("failed_samples", json!(1)),
            ("consecutive_failures", json!(1)),
            ("latency_samples", json!(21)),
            ("readiness_rate", json!(0.5)),
            ("readiness_rate", json!(1.1)),
            ("readiness_rate", json!(-0.1)),
            ("latency_ewma_ms", json!(-1)),
            ("best_delay_ms", json!(-1)),
            ("worst_delay_ms", json!(1)),
            ("last_delay_ms", json!(999)),
            ("latency_samples", json!(0)),
            ("source_counts", json!({"synthetic":21})),
            ("source_counts", json!({"a":20,"b":1})),
        ] {
            let mut row = valid();
            row[field] = value;
            rejected(row);
        }
        let mut zero = cases()[0]["summary"].clone();
        zero["readiness_rate"] = json!(0);
        rejected(zero);
        let mut raw = serde_json::to_string(&vec![valid()]).unwrap();
        raw = raw.replace("\"readiness_rate\":1.0", "\"readiness_rate\":1e999");
        assert!(matches!(
            HistorySnapshot::parse(raw.as_bytes()),
            Err(Error::InvalidInput)
        ));
    }

    #[test]
    fn bounded_rows_body_identifiers_sources_and_labels() {
        assert!(matches!(HistorySnapshot::parse(&[]), Err(Error::Limit)));
        assert!(matches!(
            HistorySnapshot::parse(&vec![b' '; MAX_BODY_BYTES + 1]),
            Err(Error::Limit)
        ));
        let mut rows = Vec::new();
        for index in 0..=MAX_ROWS {
            let mut row = valid();
            row["relay"] = json!(format!("fixture-{index}"));
            rows.push(row);
        }
        assert!(matches!(
            HistorySnapshot::parse(&serde_json::to_vec(&rows).unwrap()),
            Err(Error::Limit)
        ));
        rows.pop();
        let at_limit = HistorySnapshot::parse(&serde_json::to_vec(&rows).unwrap()).unwrap();
        assert_eq!(at_limit.rows().len(), MAX_ROWS);
        assert_eq!(
            HistorySnapshot::parse(&at_limit.to_json().unwrap())
                .unwrap()
                .rows()
                .len(),
            MAX_ROWS
        );
        for (field, value) in [
            ("relay", json!("a".repeat(256))),
            ("relay", json!("")),
            ("relay", json!("a|ss")),
            ("relay", json!("/tmp/private")),
            ("transport_mode", json!("auto")),
            ("transport_mode", json!("IPv4")),
            ("last_tested_at", json!("x".repeat(65))),
            ("last_tested_at", json!("x\n")),
            ("source_counts", json!({"a/b":1})),
            ("source_counts", json!({"a".repeat(65):1})),
        ] {
            let mut row = valid();
            row[field] = value;
            rejected(row);
        }
        let sources: serde_json::Map<_, _> = (0..=MAX_SOURCES)
            .map(|n| (format!("source-{n}"), json!(0)))
            .collect();
        let mut row = valid();
        row["source_counts"] = Value::Object(sources);
        rejected(row);
        let mut boundary = valid();
        boundary["relay"] = json!("a".repeat(255));
        boundary["last_tested_at"] = json!("x".repeat(64));
        assert!(one(boundary).is_ok());
    }

    #[test]
    fn unknown_fields_duplicates_and_storage_envelopes_are_rejected() {
        for field in ["last_result", "private_key", "account_number", "version"] {
            let mut row = valid();
            row[field] = json!("synthetic-denied");
            rejected(row);
        }
        let body = serde_json::to_string(&vec![valid()]).unwrap();
        let duplicate_field = body.replacen("\"samples\":20", "\"samples\":20,\"samples\":20", 1);
        assert!(matches!(
            HistorySnapshot::parse(duplicate_field.as_bytes()),
            Err(Error::InvalidInput)
        ));
        let duplicate_source = body.replace("\"synthetic\":20", "\"synthetic\":20,\"synthetic\":0");
        assert!(matches!(
            HistorySnapshot::parse(duplicate_source.as_bytes()),
            Err(Error::InvalidInput)
        ));
        assert!(HistorySnapshot::parse(br#"{"version":2,"entries":{}}"#).is_err());
        assert!(HistorySnapshot::parse(br#"{"version":1,"entries":{}}"#).is_err());
        assert!(HistorySnapshot::parse(b"null").is_err());
        assert!(HistorySnapshot::parse(b"[] trailing").is_err());
        assert!(HistorySnapshot::parse(b"[]").unwrap().rows().is_empty());
    }

    #[test]
    fn exact_numeric_source_and_byte_limits_are_accepted() {
        let mut row = valid();
        row["samples"] = json!(MAX_COUNTER);
        row["relay_pass_samples"] = json!(MAX_COUNTER);
        row["ready_samples"] = json!(MAX_COUNTER);
        row["source_counts"] = json!({"synthetic":MAX_COUNTER});
        let snapshot = one(row.clone()).unwrap();
        assert_eq!(snapshot.rows()[0].samples(), MAX_COUNTER);
        assert_eq!(snapshot.rows()[0].readiness_rate(), Some(1.0));
        assert!(snapshot.rows()[0].stability_confidence_score().is_finite());
        row["source_counts"] = json!({"synthetic":MAX_COUNTER+1});
        rejected(row);

        let mut row = valid();
        let sources: serde_json::Map<_, _> = (0..MAX_SOURCES)
            .map(|n| (format!("{:0>64}", n), json!(0)))
            .collect();
        row["source_counts"] = Value::Object(sources);
        assert!(one(row).is_ok());

        let mut exact = b"[]".to_vec();
        exact.resize(MAX_BODY_BYTES, b' ');
        assert!(HistorySnapshot::parse(&exact).unwrap().rows().is_empty());
        exact.push(b' ');
        assert!(matches!(HistorySnapshot::parse(&exact), Err(Error::Limit)));
    }
}
