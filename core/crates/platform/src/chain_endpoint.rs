//! Shared import/engine contract for the first, IPv4 UDP SS upstream path.
use std::net::{IpAddr, Ipv4Addr};
pub const MAX_NAME: usize = 200;
pub const MAX_PASSWORD: usize = 1024;
pub fn public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && a != 0
        && a < 224
        && !(a == 100 && (64..=127).contains(&b))
        && !(a == 198 && (b == 18 || b == 19))
}
pub fn public_server(server: &str) -> bool {
    if let Ok(ip) = server.parse::<IpAddr>() {
        return matches!(ip, IpAddr::V4(ip) if public_ipv4(ip));
    }
    let lower = server.to_ascii_lowercase();
    !server.is_empty()
        && server.len() <= 253
        && server.is_ascii()
        && !lower.contains("mullvad")
        && !["localhost", "local", "lan", "home", "internal"]
            .iter()
            .any(|s| lower == *s || lower.ends_with(&format!(".{s}")))
        && server.contains('.')
        && !server.ends_with('.')
        && !server.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && server.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn importer_and_engine_only_accept_the_supported_public_family() {
        for host in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.1.1",
            "198.18.0.1",
            "240.0.0.1",
            "2001:db8::1",
            "::ffff:192.0.2.1",
            "node.local",
            "node.lan",
            "api.mullvad.net",
            "node.example.",
            "999.999.999.999",
        ] {
            assert!(!public_server(host), "{host}");
        }
        assert!(public_server("node.example"));
        assert!(public_server("192.0.2.9"));
    }
}
