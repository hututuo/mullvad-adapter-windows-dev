use adapter_protocol::*;
use std::io::Cursor;
#[test]
fn roundtrip_and_protocol_boot_validation() {
    let request = Request {
        major: 1,
        boot_id: "boot".into(),
        request_id: "request-1".into(),
        command: Command::SelectCity {
            city: "us-sjc".into(),
        },
    };
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &request).unwrap();
    let decoded: Request = read_frame(&mut Cursor::new(bytes)).unwrap();
    assert_eq!(decoded, request);
    assert!(decoded.validate("boot").is_ok());
    assert_eq!(decoded.validate("other"), Err("boot_changed_reconcile"));
    let mut wrong = decoded;
    wrong.major = 2;
    assert_eq!(wrong.validate("boot"), Err("incompatible_protocol"));
}
#[test]
fn oversize_zero_truncated_and_unknown_fields_are_rejected() {
    for bytes in [
        0u32.to_le_bytes().to_vec(),
        ((MAX_FRAME + 1) as u32).to_le_bytes().to_vec(),
        vec![12, 0, 0, 0, 123],
    ] {
        assert!(read_frame::<Request>(&mut Cursor::new(bytes)).is_err());
    }
    let invalid = br#"{"major":1,"boot_id":"b","request_id":"r","command":{"kind":"snapshot"},"secret":"rejected"}"#;
    let mut frame = (invalid.len() as u32).to_le_bytes().to_vec();
    frame.extend(invalid);
    assert!(read_frame::<Request>(&mut Cursor::new(frame)).is_err());
}
#[test]
fn arbitrary_shell_and_secret_commands_do_not_exist() {
    for kind in ["shell", "read_file", "reveal_key", "redeem_voucher"] {
        assert!(serde_json::from_str::<Command>(&format!(r#"{{"kind":"{kind}"}}"#)).is_err());
    }
}
