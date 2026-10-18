//! Pure, bounded IN/A canary response validation. No resolver, sockets or DNSSEC.
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{DNSClass, Name, RData, RecordType},
    serialize::binary::{BinDecodable, BinDecoder},
};
use std::collections::HashSet;

/// A positive result only establishes a well-formed answer to this query.
/// It is not evidence that the address is reachable or a VPN is functioning.
pub fn dns_answer_count(packet: &[u8], query_id: u16, question: &str) -> usize {
    validate(packet, query_id, question).unwrap_or(0)
}

fn validate(packet: &[u8], query_id: u16, question: &str) -> Option<usize> {
    if !(12..=65_535).contains(&packet.len()) || question.len() > 254 {
        return None;
    }
    let word = |i| u16::from_be_bytes([packet[i], packet[i + 1]]);
    let flags = word(2);
    if word(0) != query_id
        || flags & 0x8000 == 0
        || flags & (0x7800 | 0x0200 | 0x0040 | 0x000f) != 0
        || word(4) != 1
        || word(6) == 0
        || usize::from(word(6)) + usize::from(word(8)) + usize::from(word(10)) > 4096
    {
        return None;
    }
    // A bounded ASCII query contract avoids IDNA or arbitrary zone-name input.
    let text = question.strip_suffix('.').unwrap_or(question);
    if text.is_empty()
        || !text.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        })
    {
        return None;
    }
    validate_opt_envelopes(
        packet,
        usize::from(word(6)),
        usize::from(word(8)),
        usize::from(word(10)),
    )?;
    let expected = Name::from_ascii(format!("{text}.")).ok()?;
    let mut decoder = BinDecoder::new(packet);
    let message = Message::read(&mut decoder).ok()?;
    if !decoder.is_empty() || message.metadata.response_code != ResponseCode::NoError {
        return None;
    }
    let query = message.queries.first()?;
    if query.name != expected
        || query.query_type != RecordType::A
        || query.query_class != DNSClass::IN
    {
        return None;
    }
    let mut visited = HashSet::new();
    let mut current = expected;
    for _ in 0..=16 {
        if !visited.insert(current.clone()) {
            return None;
        }
        let mut addresses = 0;
        let mut alias = None;
        for record in &message.answers {
            if record.name != current || record.dns_class != DNSClass::IN {
                continue;
            }
            match &record.data {
                RData::A(_) => addresses += 1,
                RData::CNAME(target) => {
                    if alias.as_ref().is_some_and(|previous| previous != &target.0) {
                        return None;
                    }
                    alias = Some(target.0.clone());
                }
                _ => {}
            }
        }
        if addresses > 0 {
            return if alias.is_none() {
                Some(addresses)
            } else {
                None
            };
        }
        current = alias?;
    }
    None
}

// Hickory deliberately tolerates malformed option bodies. Our canary requires
// every OPT option envelope to be complete, while leaving unknown values opaque.
fn validate_opt_envelopes(
    packet: &[u8],
    answers: usize,
    authority: usize,
    additional: usize,
) -> Option<()> {
    let mut decoder = BinDecoder::new(packet);
    decoder.read_slice(12).ok()?;
    Query::read(&mut decoder).ok()?;
    let mut seen = false;
    for index in 0..answers + authority + additional {
        let owner = Name::read(&mut decoder).ok()?;
        let record_type = decoder.read_u16().ok()?.unverified();
        decoder.read_u16().ok()?; // class / OPT advertised payload size
        let ttl = decoder.read_u32().ok()?.unverified();
        let length = usize::from(decoder.read_u16().ok()?.unverified());
        let mut data = decoder.read_slice(length).ok()?.unverified();
        if record_type != 41 {
            continue;
        }
        if seen || index < answers + authority || !owner.is_root() || ttl >> 24 != 0 {
            return None;
        }
        seen = true;
        while !data.is_empty() {
            if data.len() < 4 {
                return None;
            }
            let size = usize::from(u16::from_be_bytes([data[2], data[3]]));
            data = data.get(4 + size..)?;
        }
    }
    decoder.is_empty().then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn corpus() -> Vec<serde_json::Value> {
        serde_json::from_str(include_str!("../fixtures/dns-canary.json")).unwrap()
    }
    fn bytes(value: &serde_json::Value) -> Vec<u8> {
        value["hex"]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|s| u8::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn shared_wire_contract() {
        for case in corpus() {
            assert_eq!(
                dns_answer_count(
                    &bytes(&case),
                    case["query_id"].as_u64().unwrap() as u16,
                    case["question"].as_str().unwrap()
                ),
                case["answers"].as_u64().unwrap() as usize,
                "{}",
                case["name"]
            );
        }
    }
    #[test]
    fn every_prefix_and_appended_tail_of_positive_frames_is_rejected() {
        for case in corpus()
            .into_iter()
            .filter(|c| c["answers"].as_u64().unwrap() > 0)
        {
            let packet = bytes(&case);
            for end in 0..packet.len() {
                assert_eq!(
                    dns_answer_count(&packet[..end], 123, "www.gstatic.com"),
                    0,
                    "{} prefix {end}",
                    case["name"]
                );
            }
            let mut tail = packet;
            tail.push(0);
            assert_eq!(dns_answer_count(&tail, 123, "www.gstatic.com"), 0);
        }
    }
    #[test]
    fn input_limits_and_invalid_expected_questions_are_rejected() {
        assert_eq!(dns_answer_count(&vec![0; 65536], 123, "www.gstatic.com"), 0);
        let packet = bytes(&corpus()[0]);
        for q in [
            "",
            ".",
            "www..gstatic.com",
            "www\\.gstatic.com",
            "é.example",
        ] {
            assert_eq!(dns_answer_count(&packet, 123, q), 0);
        }
    }
    #[test]
    fn edns_extended_errors_and_invalid_opt_placement_are_rejected() {
        let valid = bytes(
            &corpus()
                .into_iter()
                .find(|c| c["name"] == "ad_cd_ns_opt")
                .unwrap(),
        );
        let mut error = valid.clone();
        let offset = error.len() - 6;
        error[offset] = 1; // EDNS extended RCODE: base header alone still says zero.
        assert_eq!(dns_answer_count(&error, 123, "www.gstatic.com"), 0);
        let mut duplicate = valid.clone();
        duplicate[11] = 2;
        duplicate.extend_from_slice(&valid[valid.len() - 11..]);
        assert_eq!(dns_answer_count(&duplicate, 123, "www.gstatic.com"), 0);
        let mut misplaced = valid;
        misplaced[9] = 2;
        misplaced[11] = 0;
        assert_eq!(dns_answer_count(&misplaced, 123, "www.gstatic.com"), 0);
    }

    #[test]
    fn deterministic_wire_mutations_are_bounded_and_do_not_panic() {
        for case in corpus() {
            let original = bytes(&case);
            for i in 0..original.len() {
                let mut packet = original.clone();
                packet[i] ^= 0xff;
                assert!(dns_answer_count(&packet, 123, "www.gstatic.com") <= 4096);
            }
        }
    }
}
