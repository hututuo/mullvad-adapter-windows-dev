//! Per-intent SS inlet failures. Metadata supplies choices; this is not readiness.
use adapter_catalogue::ShadowsocksInlet;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddrV4,
};

// At most three same-city relays, four measured inlet failures each per budget.
const MAX_FAILED: usize = 12;
#[derive(Default)]
pub(crate) struct InletTrials {
    failed: HashSet<(String, SocketAddrV4, bool)>,
    selected: HashMap<(String, bool), ShadowsocksInlet>,
}
impl InletTrials {
    pub(crate) fn clear(&mut self) {
        self.failed.clear();
        self.selected.clear();
    }
    pub(crate) fn selected(&self, relay: &str) -> Option<ShadowsocksInlet> {
        self.selected_route(relay, false)
    }
    fn exhausted(&self, relay: &str) -> bool {
        self.failed.len() >= MAX_FAILED
            || self.failed.iter().filter(|(r, _, _)| r == relay).count() >= 4
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
        if self.exhausted(relay) {
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
        let next = allowed.iter().copied().find(|inlet| {
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
        if endpoint.port() == 0 || self.exhausted(relay) {
            return false;
        }
        self.selected.remove(&(relay.to_owned(), chained));
        self.failed.insert((relay.into(), endpoint, chained))
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
    fn changed_metadata_cannot_expand_a_round_without_bound() {
        let mut t = InletTrials::default();
        for relay in ["a", "b", "c"] {
            for n in 1..=4 {
                assert!(t.reject(relay, &format!("192.0.2.1:{n}")));
            }
        }
        assert_eq!(t.choose("new", &[inlet(443)]), None);
        assert!(!t.reject("new", "192.0.2.1:13"));
        t.clear();
        for n in 1..=4 {
            assert!(t.reject("a", &format!("192.0.2.1:{n}")));
        }
        assert_eq!(
            t.choose("a", &[inlet(443)]),
            None,
            "new metadata cannot add fifth choice for one relay"
        );
        assert_eq!(t.choose("b", &[inlet(443)]), Some(inlet(443)));
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
