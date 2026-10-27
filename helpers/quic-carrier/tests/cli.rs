use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn executable_reports_pinned_protocol_without_network_or_secrets() {
    let output = Command::new(env!("CARGO_BIN_EXE_mullvad-quic-carrier"))
        .arg("--version-json")
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], 1);
    assert_eq!(value["name"], "mullvad-quic-carrier");
    assert_eq!(value["upstream_sha"], mullvad_quic_carrier::UPSTREAM_SHA);
}

#[test]
fn malformed_input_reports_only_safe_error_code() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mullvad-quic-carrier"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"{\"auth_token\":\"secret-fixture\"}\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("secret-fixture"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-fixture"));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["code"], "invalid_request");
}
