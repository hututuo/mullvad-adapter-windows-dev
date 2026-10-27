//! Typed QUIC rotation. Attempts are carrier coverage, never SS/WG bad samples.
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};
const MAX_WINDOWS: usize = 8;
const MAX_ADDRESSES: usize = 128;
const PER_RELAY_ROUND: usize = 2;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Window {
    relay: String,
    peer: String,
    seen: Vec<SocketAddr>,
}
#[derive(Default)]
pub(crate) struct QuicTrials {
    windows: Vec<Window>,
    round: HashSet<(String, SocketAddr)>,
    selected: HashMap<String, SocketAddr>,
}
impl QuicTrials {
    pub(crate) fn clear_round(&mut self) {
        self.round.clear();
        self.selected.clear();
    }
    pub(crate) fn reconcile(&mut self, relay: &str, key: &str, allowed: &[SocketAddr]) -> usize {
        use sha2::{Digest, Sha256};
        let peer = format!("{:x}", Sha256::digest(key.as_bytes()));
        let index = if let Some(index) = self.windows.iter().position(|w| w.relay == relay) {
            index
        } else {
            if self.windows.len() >= MAX_WINDOWS {
                self.windows.remove(0);
            }
            self.windows.push(Window {
                relay: relay.into(),
                peer: peer.clone(),
                seen: vec![],
            });
            self.windows.len() - 1
        };
        let window = &mut self.windows[index];
        if window.peer != peer {
            window.peer = peer;
            window.seen.clear();
            self.selected.remove(relay);
        }
        window.seen.retain(|a| allowed.contains(a));
        if self
            .selected
            .get(relay)
            .is_some_and(|a| !allowed.contains(a))
        {
            self.selected.remove(relay);
        }
        index
    }
    pub(crate) fn choose(
        &mut self,
        relay: &str,
        key: &str,
        allowed: &[SocketAddr],
    ) -> Option<SocketAddr> {
        if allowed.is_empty()
            || allowed.len() > MAX_ADDRESSES
            || self.round.iter().filter(|(r, _)| r == relay).count() >= PER_RELAY_ROUND
        {
            return None;
        }
        let index = self.reconcile(relay, key, allowed);
        if let Some(selected) = self
            .selected
            .get(relay)
            .copied()
            .filter(|a| allowed.contains(a) && !self.round.contains(&(relay.into(), *a)))
        {
            return Some(selected);
        }
        // Reset a completed coverage cycle only after every current tuple was
        // consumed. Round budgets and attempts remain in force after this reset.
        if allowed.iter().all(|a| self.windows[index].seen.contains(a)) {
            self.windows[index].seen.clear();
        }
        let next = allowed.iter().copied().find(|a| self.unseen(relay, *a))?;
        self.selected.insert(relay.into(), next);
        Some(next)
    }
    pub(crate) fn unseen(&self, relay: &str, endpoint: SocketAddr) -> bool {
        !self.round.contains(&(relay.into(), endpoint))
            && !self
                .windows
                .iter()
                .find(|w| w.relay == relay)
                .is_some_and(|w| w.seen.contains(&endpoint))
    }
    pub(crate) fn prefer(&mut self, relay: &str, endpoint: SocketAddr) {
        self.selected.insert(relay.into(), endpoint);
    }
    /// Only after a real carrier attempt and positive cleanup, or accepted WG
    /// success/negative evidence. Cancellation and helper absence do not call it.
    pub(crate) fn attempted(&mut self, relay: &str, inlet: &str) -> bool {
        let Ok(endpoint) = inlet.parse::<SocketAddr>() else {
            return false;
        };
        if endpoint.port() != 443 {
            return false;
        }
        self.selected.remove(relay);
        let inserted = self.round.insert((relay.into(), endpoint));
        if let Some(window) = self.windows.iter_mut().find(|w| w.relay == relay) {
            if !window.seen.contains(&endpoint) && window.seen.len() < MAX_ADDRESSES {
                window.seen.push(endpoint);
            }
        }
        inserted
    }
    pub(crate) fn history_bytes(&self) -> Option<Vec<u8>> {
        #[derive(serde::Serialize)]
        struct Saved<'a> {
            version: u8,
            transport: &'static str,
            windows: &'a [Window],
        }
        serde_json::to_vec(&Saved {
            version: 1,
            transport: "quic",
            windows: &self.windows,
        })
        .ok()
        .filter(|b| b.len() <= 60 * 1024)
    }
    pub(crate) fn restore(&mut self, bytes: &[u8]) {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Saved {
            version: u8,
            transport: String,
            windows: Vec<Window>,
        }
        if bytes.len() > 60 * 1024 {
            return;
        }
        let Ok(saved) = serde_json::from_slice::<Saved>(bytes) else {
            return;
        };
        if saved.version != 1
            || saved.transport != "quic"
            || saved.windows.len() > MAX_WINDOWS
            || saved.windows.iter().any(|w| {
                w.relay.is_empty()
                    || w.relay.len() > 255
                    || !w
                        .relay
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    || w.peer.len() != 64
                    || !w.peer.bytes().all(|b| b.is_ascii_hexdigit())
                    || w.seen.len() > MAX_ADDRESSES
                    || w.seen.iter().any(|a| a.port() != 443)
            })
        {
            return;
        }
        self.windows = saved.windows;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn pool() -> Vec<SocketAddr> {
        (1..=9)
            .map(|n| format!("192.0.2.{n}:443").parse().unwrap())
            .collect()
    }
    #[test]
    fn complete_quic_pool_rotates_across_small_rounds_and_restart() {
        let pool = pool();
        let mut trials = QuicTrials::default();
        let mut covered = HashSet::new();
        for _ in 0..5 {
            for _ in 0..2 {
                let Some(next) = trials.choose("relay", "key", &pool) else {
                    break;
                };
                assert!(
                    covered.insert(next),
                    "no tuple repeats before full coverage"
                );
                assert!(trials.attempted("relay", &next.to_string()));
                if covered.len() == pool.len() {
                    break;
                }
            }
            let saved = trials.history_bytes().unwrap();
            trials = QuicTrials::default();
            trials.restore(&saved);
        }
        assert_eq!(covered.len(), pool.len());
    }
    #[test]
    fn fixed_five_relay_city_covers_every_address_across_restart_between_rounds() {
        let pool = pool();
        let mut trials = QuicTrials::default();
        let mut covered = HashSet::new();
        for _ in 0..5 {
            for n in 0..5 {
                let relay = format!("city-wg-{n}");
                for _ in 0..2 {
                    if covered.iter().filter(|(r, _)| r == &relay).count() == pool.len() {
                        break;
                    }
                    let next = trials.choose(&relay, "key", &pool).unwrap();
                    assert!(covered.insert((relay.clone(), next)));
                    trials.attempted(&relay, &next.to_string());
                }
            }
            let saved = trials.history_bytes().unwrap();
            trials = QuicTrials::default();
            trials.restore(&saved);
        }
        assert_eq!(covered.len(), 5 * pool.len());
    }
    #[test]
    fn refresh_preserves_common_seen_and_does_not_refund_round_budget() {
        let pool = pool();
        let mut trials = QuicTrials::default();
        let first = trials.choose("relay", "key", &pool).unwrap();
        trials.attempted("relay", &first.to_string());
        let mut updated = pool.clone();
        updated.reverse();
        updated.push("192.0.2.20:443".parse().unwrap());
        assert_ne!(trials.choose("relay", "key", &updated), Some(first));
        let second = trials.choose("relay", "key", &updated).unwrap();
        trials.attempted("relay", &second.to_string());
        assert!(trials.choose("relay", "new-key", &updated).is_none());
        trials.clear_round();
        assert_ne!(trials.choose("relay", "key", &updated), Some(first));
    }
    #[test]
    fn two_completed_carrier_attempts_end_the_relay_window_without_losing_coverage() {
        let pool = pool();
        let mut trials = QuicTrials::default();
        for next in pool.iter().take(2) {
            assert_eq!(trials.choose("relay", "key", &pool), Some(*next));
            trials.attempted("relay", &next.to_string());
        }
        assert!(trials.choose("relay", "key", &pool).is_none());
        trials.clear_round();
        assert_eq!(trials.choose("relay", "key", &pool), Some(pool[2]));
    }
    #[test]
    fn full_same_city_directory_pool_roundtrips_within_private_record_bound() {
        let mut trials = QuicTrials::default();
        for n in 0..5 {
            let relay = format!("city-wg-{n}");
            let allowed: Vec<SocketAddr> = (1..=128)
                .map(|i| format!("[2001:db8:{n:x}::{i:x}]:443").parse().unwrap())
                .collect();
            for chunk in allowed.chunks(2) {
                trials.clear_round();
                for endpoint in chunk {
                    assert_eq!(trials.choose(&relay, "key", &allowed), Some(*endpoint));
                    trials.attempted(&relay, &endpoint.to_string());
                }
            }
        }
        let bytes = trials.history_bytes().unwrap();
        assert!(bytes.len() < 60 * 1024);
        let mut restored = QuicTrials::default();
        restored.restore(&bytes);
        assert_eq!(restored.windows.len(), 5);
        assert!(restored.windows.iter().all(|w| w.seen.len() == 128));
    }
    #[test]
    fn planning_cancellation_and_other_transports_do_not_consume_quic() {
        let pool = pool();
        let mut trials = QuicTrials::default();
        let first = trials.choose("relay", "key", &pool).unwrap();
        trials.clear_round();
        assert_eq!(trials.choose("relay", "key", &pool), Some(first));
        let mut restored = QuicTrials::default();
        restored.restore(br#"{"version":1,"transport":"ss","windows":[]}"#);
        assert_eq!(restored.choose("relay", "key", &pool), Some(first));
    }
}
