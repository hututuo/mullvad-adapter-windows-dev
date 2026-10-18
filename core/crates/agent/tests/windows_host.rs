#![cfg(windows)]
use adapter_platform::windows::{boot_id, Identity, Pipe};
use adapter_protocol::{read_frame, write_frame, Command, Request, Response, ResponseAck};
use std::{
    process::{Child, Command as ProcessCommand, Stdio},
    time::Duration,
};
struct Host(Child);
impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn final_response_can_be_read_late_before_ack_and_host_survives_reconnect() {
    let scope = boot_id().unwrap();
    let owner = Identity::current().unwrap().with_scope(&scope).unwrap();
    let mut host = Host(
        ProcessCommand::new(env!("CARGO_BIN_EXE_adapter-agent"))
            .args(["--mock-pipe", "--scope", &scope])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut pipe = Pipe::connect(&owner, Duration::from_secs(3)).unwrap();
    let hello = match read_frame::<Response>(&mut pipe).unwrap() {
        Response::Hello(hello) => hello,
        _ => panic!("hello"),
    };
    for i in 0..16 {
        let id = format!("test-{i}");
        write_frame(
            &mut pipe,
            &Request {
                major: 1,
                boot_id: hello.boot_id.clone(),
                request_id: id.clone(),
                command: Command::Snapshot,
            },
        )
        .unwrap();
        if i == 15 {
            std::thread::sleep(Duration::from_millis(200));
        }
        assert!(matches!(
            read_frame::<Response>(&mut pipe).unwrap(),
            Response::Snapshot(_)
        ));
        write_frame(&mut pipe, &ResponseAck { request_id: id }).unwrap();
    }
    drop(pipe);
    let mut second = Pipe::connect(&owner, Duration::from_secs(3)).unwrap();
    assert!(matches!(
        read_frame::<Response>(&mut second).unwrap(),
        Response::Hello(_)
    ));
    assert!(host.0.try_wait().unwrap().is_none());
}
