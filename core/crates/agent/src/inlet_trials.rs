//! Per-intent SS inlet failures. Metadata supplies choices; this is not readiness.
use adapter_catalogue::ShadowsocksInlet;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddrV4,
};

// Original: exact inlet + three alternatives. Other city relays: two each.
// Chain remains a separate final phase with two inlets per relay.
const MAX_FAILED: usize = 22;
const MAX_SAVE_BYTES: usize = 60 * 1024;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationWindow {
    relay: String,
    chained: bool,
    peer_fingerprint: Option<String>,
    seen: Vec<SocketAddrV4>,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedTrials {
    version: u8,
    history: Vec<HistoryRow>,
    windows: Vec<RotationWindow>,
}
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
    windows: Vec<RotationWindow>,
}
impl InletTrials {
    pub(crate) fn clear(&mut self) {
        // A new recovery round/user retry is not a new catalogue or identity.
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
            4
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
        if allowed.is_empty() {
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
        let index = self.window_index(relay, chained);
        let mut seen: HashSet<_> = self.windows[index].seen.iter().copied().collect();
        // Reopen only after all current authorized tuples were really consumed.
        if allowed
            .iter()
            .all(|i| seen.contains(&SocketAddrV4::new(i.address, i.port)))
        {
            self.windows[index].seen.clear();
            seen.clear();
        }
        let mut ranked: Vec<_> = allowed
            .iter()
            .copied()
            .filter(|i| !seen.contains(&SocketAddrV4::new(i.address, i.port)))
            .collect();
        ranked.sort_by_cached_key(|inlet| {
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
            self.record_seen(relay, endpoint, chained);
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
            self.record_seen(relay, endpoint, chained);
            self.note(relay, endpoint, chained, true);
        }
    }
    pub(crate) fn history_bytes(&self) -> Option<Vec<u8>> {
        #[derive(serde::Serialize)]
        struct Saved<'a> {
            version: u8,
            history: &'a [HistoryRow],
            windows: &'a [RotationWindow],
        }
        serde_json::to_vec(&Saved {
            version: 1,
            history: &self.history,
            windows: &self.windows,
        })
        .ok()
        .filter(|b| b.len() <= MAX_SAVE_BYTES)
    }
    pub(crate) fn restore_history(&mut self, bytes: &[u8]) {
        if bytes.len() > MAX_SAVE_BYTES {
            return;
        }
        let (rows, windows) = if let Ok(saved) = serde_json::from_slice::<SavedTrials>(bytes) {
            if saved.version != 1
                || saved.windows.len() > 32
                || saved.windows.iter().map(|w| w.seen.len()).sum::<usize>() > 1024
                || saved.windows.iter().any(|w| {
                    !valid_name(&w.relay)
                        || w.seen.iter().any(|a| a.port() == 0)
                        || w.peer_fingerprint.as_ref().is_some_and(|f| {
                            f.len() != 64 || !f.bytes().all(|b| b.is_ascii_hexdigit())
                        })
                })
            {
                return;
            }
            (saved.history, saved.windows)
        } else if let Ok(legacy) = serde_json::from_slice::<Vec<HistoryRow>>(bytes) {
            (legacy, vec![])
        } else {
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
            self.windows = windows;
        }
    }

    /// New metadata prunes withdrawn tuples, retains common attempts, and clears
    /// a peer's old scores/attempts only when its server key actually changes.
    pub(crate) fn reconcile(
        &mut self,
        relay: &str,
        public_key: &str,
        allowed: &[ShadowsocksInlet],
    ) {
        use sha2::{Digest, Sha256};
        let fingerprint = format!("{:x}", Sha256::digest(public_key.as_bytes()));
        let keys: HashSet<_> = allowed
            .iter()
            .map(|i| SocketAddrV4::new(i.address, i.port))
            .collect();
        let peer_changed = self.windows.iter().any(|w| {
            w.relay == relay
                && w.peer_fingerprint
                    .as_ref()
                    .is_some_and(|f| f != &fingerprint)
        });
        if peer_changed {
            self.windows.retain(|w| w.relay != relay);
            self.selected.retain(|(r, _), _| r != relay);
            self.history.retain(|r| r.relay != relay);
        }
        // `failed` also accounts for this round's spent attempts. Catalogue
        // changes cannot refund that budget, even when an inlet/key is withdrawn.
        self.selected
            .retain(|(r, _), i| r != relay || keys.contains(&SocketAddrV4::new(i.address, i.port)));
        for chained in [false, true] {
            let i = self.window_index(relay, chained);
            self.windows[i].peer_fingerprint = Some(fingerprint.clone());
            self.windows[i].seen.retain(|e| keys.contains(e));
        }
    }
    fn window_index(&mut self, relay: &str, chained: bool) -> usize {
        if let Some(i) = self
            .windows
            .iter()
            .position(|w| w.relay == relay && w.chained == chained)
        {
            return i;
        }
        if self.windows.len() >= 32 {
            self.windows.remove(0);
        }
        self.windows.push(RotationWindow {
            relay: relay.into(),
            chained,
            peer_fingerprint: None,
            seen: vec![],
        });
        self.windows.len() - 1
    }
    fn record_seen(&mut self, relay: &str, endpoint: SocketAddrV4, chained: bool) {
        let i = self.window_index(relay, chained);
        if !self.windows[i].seen.contains(&endpoint) {
            self.windows[i].seen.push(endpoint);
        }
        while self.windows.iter().map(|w| w.seen.len()).sum::<usize>() > 1024 {
            if let Some(w) = self.windows.iter_mut().find(|w| !w.seen.is_empty()) {
                w.seen.remove(0);
            } else {
                break;
            }
        }
    }
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
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
        for (r, limit) in [("a", 4), ("b", 2), ("c", 2), ("d", 2), ("e", 2)] {
            for n in 1..=limit {
                assert!(t.reject_route(r, &format!("192.0.2.1:{n}"), false));
            }
            assert_eq!(t.choose_route(r, &[inlet(443)], false), None);
            for n in 1..=2 {
                assert!(t.reject_route(r, &format!("192.0.2.1:{n}"), true));
            }
            assert_eq!(t.choose_route(r, &[inlet(443)], true), None);
        }
        assert_eq!(t.failed.len(), 22);
        assert_eq!(t.choose("new", &[inlet(443)]), None);
        t.clear();
        assert_eq!(t.choose("a", &[inlet(443)]), Some(inlet(443)));
    }
    #[test]
    fn unseen_inlet_precedes_previous_success_after_restart_without_authorizing_withdrawn_inlets() {
        let mut t = InletTrials::default();
        t.succeeded("r", "192.0.2.1:443", false);
        let saved = t.history_bytes().unwrap();
        let mut restored = InletTrials::default();
        restored.restore_history(&saved);
        assert_eq!(
            restored.choose("r", &[inlet(20484), inlet(443)]),
            Some(inlet(20484))
        );
        restored.clear();
        assert_eq!(restored.choose("r", &[inlet(20484)]), Some(inlet(20484)));
        restored.restore_history(b"{invalid}");
        assert_eq!(restored.history.len(), 1);
    }
    #[test]
    fn six_fallbacks_rotate_across_round_restart_and_only_then_begin_a_new_cycle() {
        let pool: Vec<_> = (21000..21006).map(inlet).collect();
        let mut t = InletTrials::default();
        t.reconcile("r", "server-key", &pool);
        t.primary("r");
        for expected in &pool[..3] {
            assert_eq!(t.choose("r", &pool), Some(*expected));
            assert!(t.reject("r", &format!("{}:{}", expected.address, expected.port)));
        }
        let bytes = t.history_bytes().unwrap();
        let mut next = InletTrials::default();
        next.restore_history(&bytes);
        next.reconcile("r", "server-key", &pool);
        next.primary("r");
        for expected in &pool[3..] {
            assert_eq!(next.choose("r", &pool), Some(*expected));
            assert!(next.reject("r", &format!("{}:{}", expected.address, expected.port)));
        }
        next.clear();
        next.reconcile("r", "server-key", &pool);
        assert!(next.choose("r", &pool).is_some());
    }
    #[test]
    fn additions_removals_and_identical_refresh_preserve_common_seen_tuples() {
        let mut t = InletTrials::default();
        let pool = [inlet(21000), inlet(21001), inlet(21002)];
        t.reconcile("r", "key-a", &pool);
        t.choose("r", &pool);
        assert!(t.reject("r", "192.0.2.1:21000"));
        t.clear();
        let updated = [pool[0], pool[2], inlet(21003)];
        t.reconcile("r", "key-a", &updated);
        assert_ne!(t.choose("r", &updated), Some(pool[0]));
        t.clear();
        t.reconcile("r", "key-a", &updated);
        assert_ne!(t.choose("r", &updated), Some(pool[0]));
        t.reconcile("r", "key-b", &updated);
        assert_eq!(t.choose("r", &updated), Some(pool[0]));
    }
    #[test]
    fn metadata_withdrawal_or_key_rotation_cannot_refund_the_current_round_budget() {
        let mut t = InletTrials::default();
        let pool: Vec<_> = (21000..21006).map(inlet).collect();
        t.reconcile("r", "old-key", &pool);
        t.primary("r");
        for i in &pool[..4] {
            assert!(t.reject("r", &format!("{}:{}", i.address, i.port)));
        }
        let replacement = [inlet(22000), inlet(22001)];
        t.reconcile("r", "new-key", &replacement);
        assert_eq!(t.choose("r", &replacement), None);
        t.clear();
        assert!(t.choose("r", &replacement).is_some());
    }
    #[test]
    fn planning_and_local_retry_do_not_consume_candidates_and_chain_is_independent() {
        let mut t = InletTrials::default();
        let pool = [inlet(21000), inlet(21001)];
        t.reconcile("r", "key", &pool);
        assert_eq!(t.choose("r", &pool), Some(pool[0]));
        t.clear();
        assert_eq!(t.choose("r", &pool), Some(pool[0]));
        assert!(t.reject("r", "192.0.2.1:21000"));
        t.clear();
        assert_eq!(t.choose("r", &pool), Some(pool[1]));
        assert_eq!(t.choose_route("r", &pool, true), Some(pool[0]));
    }
    #[test]
    fn legacy_scores_migrate_but_invalid_or_oversized_windows_cannot_replace_history() {
        let legacy=br#"[{"relay":"r","endpoint":"192.0.2.1:443","chained":false,"successes":1,"failures":0,"last_success":1}]"#;
        let mut t = InletTrials::default();
        t.restore_history(legacy);
        assert_eq!(t.history.len(), 1);
        assert!(t.windows.is_empty());
        t.restore_history(&vec![b' '; MAX_SAVE_BYTES + 1]);
        assert_eq!(t.history.len(), 1);
        t.restore_history(br#"{"version":99,"history":[],"windows":[]}"#);
        assert_eq!(t.history.len(), 1);
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
