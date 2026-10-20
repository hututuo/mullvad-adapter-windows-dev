//! Native DNS bootstrap only. Never borrow Clash's application-data proxy or
//! persist a resolved address as the SS server. Each new worker resolves again.
use super::{control_endpoint, err, portable_source, ControlEndpoint, LocalController, Result};
use adapter_platform::chain_endpoint::{public_ipv4, public_server};
use serde_json::Value;
use std::{net::Ipv4Addr, path::PathBuf, time::Duration};

/// Use the unique actual local Clash configuration, never a renderer URL. Pipe
/// control has no HTTP credentials and cannot recurse through the adapter front.
pub fn current_windows_ipv4(host: &str, wait: Duration) -> Result<Ipv4Addr> {
    let started = std::time::Instant::now();
    if !public_server(host) || host.parse::<std::net::IpAddr>().is_ok() || wait.is_zero() {
        return Err(err("chain_dns_unavailable"));
    }
    let appdata = std::env::var_os("APPDATA").ok_or_else(|| err("chain_dns_unavailable"))?;
    let user = std::env::var_os("USERPROFILE").ok_or_else(|| err("chain_dns_unavailable"))?;
    let roots = [
        PathBuf::from(&appdata).join("io.github.clash-verge-rev.clash-verge-rev"),
        PathBuf::from(&appdata).join("io.github.clash-verge.clash-verge"),
        PathBuf::from(user).join(".config/clash-verge"),
    ];
    let roots: Vec<_> = roots
        .into_iter()
        .filter(|root| root.join("clash-verge.yaml").is_file())
        .collect();
    if roots.len() != 1 {
        return Err(err("chain_dns_unavailable"));
    }
    let config = portable_source(&roots[0])?.ok_or_else(|| err("chain_dns_unavailable"))?;
    query_ipv4(&config, host, wait.saturating_sub(started.elapsed()))
}

fn query_ipv4(config: &Value, host: &str, wait: Duration) -> Result<Ipv4Addr> {
    if !matches!(
        control_endpoint(config, 0, cfg!(windows))?,
        ControlEndpoint::Pipe(_)
    ) {
        return Err(err("chain_dns_unavailable"));
    }
    let controller = LocalController::with_timeout(config, 0, wait)?;
    let answer = controller.read_json(
        &format!("/dns/query?name={}&type=A", super::encoded(host)),
        32 * 1024,
    )?;
    public_answer(&answer, host)
}

fn name(value: &str) -> Option<String> {
    let value = value
        .strip_suffix('.')
        .unwrap_or(value)
        .to_ascii_lowercase();
    (public_server(&value) && value.parse::<std::net::IpAddr>().is_err()).then_some(value)
}
fn public_answer(value: &Value, host: &str) -> Result<Ipv4Addr> {
    let invalid = || err("chain_dns_response");
    let mut current = name(host).ok_or_else(invalid)?;
    let question = value["Question"].as_array().ok_or_else(invalid)?;
    if value["Status"].as_u64() != Some(0)
        || value["TC"].as_bool() != Some(false)
        || question.len() != 1
        || name(question[0]["Name"].as_str().unwrap_or("")) != Some(current.clone())
        || question[0]["Qtype"].as_u64() != Some(1)
        || question[0]["Qclass"].as_u64() != Some(1)
    {
        return Err(invalid());
    }
    let answers = value["Answer"].as_array().ok_or_else(invalid)?;
    if answers.is_empty() || answers.len() > 64 {
        return Err(invalid());
    }
    let mut seen = Vec::new();
    for _ in 0..=8 {
        if seen.contains(&current) {
            return Err(invalid());
        }
        seen.push(current.clone());
        let mut alias = None;
        let mut address = None;
        for row in answers {
            if name(row["name"].as_str().unwrap_or("")) != Some(current.clone()) {
                continue;
            }
            let data = row["data"]
                .as_str()
                .filter(|s| s.len() <= 254)
                .ok_or_else(invalid)?;
            match row["type"].as_u64() {
                Some(1) => {
                    let ip: Ipv4Addr = data.trim().parse().map_err(|_| invalid())?;
                    if public_ipv4(ip) && address.is_none() {
                        address = Some(ip);
                    }
                }
                Some(5) => {
                    let target = name(data.trim()).ok_or_else(invalid)?;
                    if alias.as_ref().is_some_and(|old| old != &target) {
                        return Err(invalid());
                    }
                    alias = Some(target);
                }
                _ => {}
            }
        }
        if let Some(ip) = address {
            if alias.is_some() {
                return Err(invalid());
            }
            return Ok(ip);
        }
        current = alias.ok_or_else(invalid)?;
    }
    Err(invalid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn response() -> Value {
        json!({"Status":0,"TC":false,"Question":[{"Name":"node.example.","Qtype":1,"Qclass":1}],
            "Answer":[{"name":"node.example.","type":1,"TTL":1,"data":"203.0.113.7"}]})
    }
    #[test]
    fn accepts_only_the_requested_public_address_and_linked_aliases() {
        assert_eq!(
            public_answer(&response(), "NODE.example")
                .unwrap()
                .to_string(),
            "203.0.113.7"
        );
        let mut r = response();
        r["Answer"] = json!([
            {"name":"target.example.","type":1,"data":"203.0.113.8"},
            {"name":"node.example.","type":5,"data":"target.example."}]);
        assert_eq!(
            public_answer(&r, "node.example").unwrap().to_string(),
            "203.0.113.8"
        );
        r["Answer"][1]["data"] = json!("unrelated.example.");
        assert!(public_answer(&r, "node.example").is_err());
    }
    #[test]
    fn rejects_fake_private_mismatched_truncated_and_unbounded_answers() {
        for ip in [
            "198.18.1.2",
            "198.19.1.2",
            "127.0.0.1",
            "10.0.0.1",
            "100.64.1.1",
            "::1",
        ] {
            let mut r = response();
            r["Answer"][0]["data"] = json!(ip);
            assert!(public_answer(&r, "node.example").is_err());
        }
        for field in ["TC", "Status", "Question"] {
            let mut r = response();
            r[field] = Value::Null;
            assert!(public_answer(&r, "node.example").is_err());
        }
        assert!(public_answer(&response(), "other.example").is_err());
        let mut r = response();
        r["Answer"] = Value::Array(vec![r["Answer"][0].clone(); 65]);
        assert!(public_answer(&r, "node.example").is_err());
    }
    #[test]
    fn rejects_alias_cycles_and_http_controller_dependency() {
        let mut r = response();
        r["Answer"] = json!([
            {"name":"node.example.","type":5,"data":"other.example."},
            {"name":"other.example.","type":5,"data":"node.example."}]);
        assert!(public_answer(&r, "node.example").is_err());
        assert!(query_ipv4(
            &json!({"external-controller":"127.0.0.1:7890"}),
            "node.example",
            Duration::from_millis(1)
        )
        .is_err());
    }
}
