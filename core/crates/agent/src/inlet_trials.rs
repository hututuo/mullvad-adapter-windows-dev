//! Per-intent SS inlet failures. Metadata supplies choices; this is not readiness.
use adapter_catalogue::ShadowsocksInlet;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddrV4,
};

// Original: exact inlet + two alternatives. Other city relays: two each.
// Chain is a separate final phase, with two inlets per relay: 7 + 6 total.
const MAX_FAILED: usize = 13;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryRow {
    relay: String,
    endpoint: SocketAddrV4,
    chained: bool,
    successes: u32,
    failures: u32,
    last_success: u64,
}
#[derive(Default)]
pub(crate) struct InletTrials {
    failed: HashSet<(String, SocketAddrV4, bool)>,
    selected: HashMap<(String, bool), ShadowsocksInlet>,
    primary: Option<String>,
    history: Vec<HistoryRow>,
}
impl InletTrials {
    pub(crate) fn clear(&mut self) {
        self.failed.clear();
        self.selected.clear();
        self.primary = None;
    }
    pub(crate) fn primary(&mut self, relay: &str) {
        self.primary = Some(relay.into());
    }
    pub(crate) fn selected(&self, relay: &str) -> Option<ShadowsocksInlet> {
        self.selected_route(relay, false)
    }
    fn exhausted(&self, relay: &str, chained: bool) -> bool {
        let limit = if !chained && self.primary.as_deref() == Some(relay) {
            3
        } else {
            2
        };
        self.failed.len() >= MAX_FAILED
            || self
                .failed
                .iter()
                .filter(|(r, _, c)| r == relay && *c == chained)
                .count()
                >= limit
    }
    pub(crate) fn choose(
        &mut self,
        relay: &str,
        allowed: &[ShadowsocksInlet],
    ) -> Option<ShadowsocksInlet> {
        self.choose_route(relay, allowed, false)
    }
    pub(crate) fn selected_route(&self, relay: &str, chained: bool) -> Option<ShadowsocksInlet> {
        self.selected.get(&(relay.to_owned(), chained)).copied()
    }
    pub(crate) fn prefer(&mut self, relay: &str, inlet: ShadowsocksInlet, chained: bool) {
        if !self.failed.contains(&(
            relay.to_owned(),
            SocketAddrV4::new(inlet.address, inlet.port),
            chained,
        )) {
            self.selected.insert((relay.to_owned(), chained), inlet);
        }
    }
    pub(crate) fn choose_route(
        &mut self,
        relay: &str,
        allowed: &[ShadowsocksInlet],
        chained: bool,
    ) -> Option<ShadowsocksInlet> {
        if self.exhausted(relay, chained) {
            return None;
        }
        // Cancel/stale/local-error retries retain the exact inlet, even when
        // catalogue order changes. The caller re-authorizes this set each time.
        if let Some(selected) = self.selected_route(relay, chained).and_then(|selected| {
            allowed
                .iter()
                .copied()
                .find(|i| i.address == selected.address && i.port == selected.port)
        }) {
            self.selected.insert((relay.into(), chained), selected);
            return Some(selected);
        }
        let mut ranked = allowed.to_vec();
        ranked.sort_by_key(|inlet| {
            let row = self.history.iter().find(|row| {
                row.relay == relay
                    && row.chained == chained
                    && row.endpoint == SocketAddrV4::new(inlet.address, inlet.port)
            });
            std::cmp::Reverse(row.map_or((false, 0, 0), |row| {
                (
                    row.successes > 0 && row.failures < 2,
                    row.successes.saturating_sub(row.failures),
                    row.last_success,
                )
            }))
        });
        let next = ranked.into_iter().find(|inlet| {
            !self.failed.contains(&(
                relay.to_owned(),
                SocketAddrV4::new(inlet.address, inlet.port),
                chained,
            ))
        });
        if let Some(next) = next {
            self.selected.insert((relay.into(), chained), next);
        } else {
            self.selected.remove(&(relay.to_owned(), chained));
        }
        next
    }
    /// Call only after a fresh, owned negative measurement and confirmed cleanup.
    /// Network cancellation, stale evidence and local setup errors never consume it.
    pub(crate) fn reject(&mut self, relay: &str, inlet: &str) -> bool {
        self.reject_route(relay, inlet, false)
    }
    pub(crate) fn reject_route(&mut self, relay: &str, inlet: &str, chained: bool) -> bool {
        let Ok(endpoint) = inlet.parse::<SocketAddrV4>() else {
            return false;
        };
        if endpoint.port() == 0 || self.exhausted(relay, chained) {
            return false;
        }
        self.selected.remove(&(relay.to_owned(), chained));
        let inserted = self.failed.insert((relay.into(), endpoint, chained));
        if inserted {
            self.note(relay, endpoint, chained, false);
        }
        inserted
    }
    fn note(&mut self, relay: &str, endpoint: SocketAddrV4, chained: bool, success: bool) {
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if !self
            .history
            .iter()
            .any(|r| r.relay == relay && r.endpoint == endpoint && r.chained == chained)
        {
            if self.history.len() >= 128 {
                self.history.sort_by_key(|r| r.last_success);
                self.history.remove(0);
            }
            self.history.push(HistoryRow {
                relay: relay.into(),
                endpoint,
                chained,
                successes: 0,
                failures: 0,
                last_success: 0,
            });
        }
        let row = self
            .history
            .iter_mut()
            .find(|r| r.relay == relay && r.endpoint == endpoint && r.chained == chained)
            .unwrap();
        if success {
            row.successes = row.successes.saturating_add(1).min(64);
            row.failures = 0;
            row.last_success = at;
        } else {
            row.failures = row.failures.saturating_add(1).min(64);
        }
    }
    pub(crate) fn succeeded(&mut self, relay: &str, inlet: &str, chained: bool) {
        if let Ok(endpoint) = inlet.parse() {
            self.note(relay, endpoint, chained, true);
        }
    }
    pub(crate) fn history_bytes(&self) -> Option<Vec<u8>> {
        serde_json::to_vec(&self.history)
            .ok()
            .filter(|b| b.len() <= 32768)
    }
    pub(crate) fn restore_history(&mut self, bytes: &[u8]) {
        if bytes.len() > 32768 {
            return;
        }
        let Ok(rows) = serde_json::from_slice::<Vec<HistoryRow>>(bytes) else {
            return;
        };
        if rows.len() <= 128
            && rows.iter().all(|r| {
                !r.relay.is_empty()
                    && r.relay.len() <= 128
                    && r.relay
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                    && r.endpoint.port() != 0
                    && r.successes <= 64
                    && r.failures <= 64
            })
        {
            self.history = rows;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use adapter_catalogue::ShadowsocksInletKind;
    fn inlet(port: u16) -> ShadowsocksInlet {
        ShadowsocksInlet {
            address: "192.0.2.1".parse().unwrap(),
            port,
            kind: ShadowsocksInletKind::ExtraAddress,
        }
    }
    #[test]
    fn direct_and_chain_share_budget_without_conflating_endpoint_failures() {
        let mut t = InletTrials::default();
        let choices = [inlet(20484), inlet(443)];
        assert_eq!(t.choose_route("r", &choices, false), Some(choices[0]));
        assert!(t.reject_route("r", "192.0.2.1:20484", false));
        t.prefer("r", choices[0], true);
        assert_eq!(t.choose_route("r", &choices, true), Some(choices[0]));
        assert!(t.reject_route("r", "192.0.2.1:20484", true));
        assert_eq!(t.choose_route("r", &choices, false), Some(choices[1]));
        assert!(t.reject_route("r", "192.0.2.1:443", false));
        assert_eq!(t.choose_route("r", &choices, true), Some(choices[1]));
        assert!(t.reject_route("r", "192.0.2.1:443", true));
        assert_eq!(t.choose_route("r", &[inlet(80)], false), None);
        assert_eq!(t.choose_route("r", &[inlet(80)], true), None);
        assert_eq!(t.choose_route("another", &choices, true), Some(choices[0]));
    }
    #[test]
    fn failures_bind_exact_endpoint_not_metadata_position_or_other_relay() {
        let mut t = InletTrials::default();
        let first = inlet(20484);
        let alt = inlet(443);
        assert_eq!(t.choose("r", &[first, alt]), Some(first));
        assert!(t.reject("r", "192.0.2.1:20484"));
        assert_eq!(t.choose("r", &[alt, first]), Some(alt));
        assert_eq!(t.choose("other", &[first, alt]), Some(first));
        assert_eq!(
            t.choose("r", &[first]),
            None,
            "withdrawn alternative cannot be invented"
        );
        assert!(t.reject("r", "192.0.2.1:443"));
        assert_eq!(t.choose("r", &[first, alt]), None);
        t.clear();
        assert_eq!(t.choose("r", &[first, alt]), Some(first));
    }
    #[test]
    fn unchanged_or_cancelled_choice_does_not_consume_any_inlet() {
        let mut t = InletTrials::default();
        for _ in 0..5 {
            assert_eq!(
                t.choose("r", &[inlet(20484), inlet(443)]),
                Some(inlet(20484))
            );
        }
    }
    #[test]
    fn changed_metadata_cannot_expand_a_round_or_each_city_relay() {
        let mut t = InletTrials::default();
        t.primary("a");
        for (r, limit) in [("a", 3), ("b", 2), ("c", 2)] {
            for n in 1..=limit {
                assert!(t.reject_route(r, &format!("192.0.2.1:{n}"), false));
            }
            assert_eq!(t.choose_route(r, &[inlet(443)], false), None);
            for n in 1..=2 {
                assert!(t.reject_route(r, &format!("192.0.2.1:{n}"), true));
            }
            assert_eq!(t.choose_route(r, &[inlet(443)], true), None);
        }
        assert_eq!(t.failed.len(), 13);
        assert_eq!(t.choose("new", &[inlet(443)]), None);
        t.clear();
        assert_eq!(t.choose("a", &[inlet(443)]), Some(inlet(443)));
    }
    #[test]
    fn measured_success_history_survives_round_clear_but_never_authorizes_withdrawn_inlets() {
        let mut t = InletTrials::default();
        t.succeeded("r", "192.0.2.1:443", false);
        let saved = t.history_bytes().unwrap();
        let mut restored = InletTrials::default();
        restored.restore_history(&saved);
        assert_eq!(
            restored.choose("r", &[inlet(20484), inlet(443)]),
            Some(inlet(443))
        );
        restored.clear();
        assert_eq!(restored.choose("r", &[inlet(20484)]), Some(inlet(20484)));
        restored.restore_history(b"{invalid}");
        assert_eq!(restored.history.len(), 1);
    }
    #[test]
    fn cancellation_preserves_authorized_choice_across_metadata_reorder() {
        let mut t = InletTrials::default();
        let first = inlet(20484);
        let alt = inlet(443);
        assert_eq!(t.choose("r", &[first, alt]), Some(first));
        assert_eq!(t.choose("r", &[alt, first]), Some(first));
        assert_eq!(
            t.choose("r", &[alt]),
            Some(alt),
            "withdrawn exact choice cannot survive authorization"
        );
    }
    #[test]
    fn authorization_kind_changes_do_not_change_an_exact_endpoint() {
        let mut t = InletTrials::default();
        let first = inlet(20484);
        let alt = inlet(443);
        assert_eq!(t.choose("r", &[first, alt]), Some(first));
        let mut reauthorized = first;
        reauthorized.kind = ShadowsocksInletKind::RelayAddress;
        assert_eq!(t.choose("r", &[alt, reauthorized]), Some(reauthorized));
    }
}
