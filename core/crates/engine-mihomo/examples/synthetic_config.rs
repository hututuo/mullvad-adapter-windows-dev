//! Public synthetic fixture only. Never accepts actual account or key material.
use adapter_engine_mihomo::*;
use std::io::Write;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args()
        .nth(1)
        .ok_or("expected ipv4, ipv6, ss or front")?;
    let transport = match mode.as_str() {
        "ipv4" | "front" => Transport::DirectV4 {
            endpoint: "192.0.2.1".parse()?,
            port: 51820,
        },
        "ipv6" => Transport::DirectV6 {
            endpoint: "2001:db8::1".parse()?,
            port: 33431,
        },
        "ss" => Transport::Shadowsocks {
            endpoint: "198.51.100.2".parse()?,
            port: 443,
        },
        _ => return Err("unsupported synthetic fixture".into()),
    };
    let listener = Listener {
        mixed_port: 51001,
        controller_port: 51002,
        controller_secret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    };
    let output = if mode == "front" {
        front(&listener, 51003, 51005)?
    } else {
        worker(&WorkerInput {
            identity: Identity {
                private_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                preshared_key: None,
                ipv4: "10.64.0.2".parse()?,
                ipv6: Some("fc00::2".parse()?),
            },
            relay_public_key: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
            transport,
            protection: Protection::Standard,
            egress: Egress {
                alias: "synthetic-not-a-real-interface",
                luid: 7,
                index: 4,
                ipv4: true,
                ipv6: true,
            },
            listener,
        })?
    };
    std::io::stdout().write_all(output.expose())?;
    Ok(())
}
