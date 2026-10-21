use super::*;
use std::{io, sync::mpsc, thread};

fn test_identity() -> Identity {
    let scope = format!("StatusTest-{}", boot_id().unwrap());
    Identity::current().unwrap().with_scope(&scope).unwrap()
}

#[test]
fn status_scope_is_distinct_and_preserves_user_session() {
    let control = test_identity();
    let status = control.status_channel();
    let nearby_control = Identity::current()
        .unwrap()
        .with_scope(&format!("{}-Status", control.scope))
        .unwrap();

    assert_ne!(control.scope, status.scope);
    assert_eq!(status.scope, format!("{}.Status", control.scope));
    assert_ne!(control.pipe_name(), status.pipe_name());
    assert_ne!(status.pipe_name(), nearby_control.pipe_name());
    assert_eq!(control.sid, status.sid);
    assert_eq!(control.session, status.session);
    assert!(control.same_user_session(&status));
}

#[test]
fn control_instance_presence_probe_is_read_only_and_scope_specific() {
    let control = test_identity();
    let status = control.status_channel();

    assert!(!SingleInstance::exists(&control).unwrap());
    let instance = SingleInstance::acquire(&control).unwrap();
    assert!(SingleInstance::exists(&control).unwrap());
    assert!(!SingleInstance::exists(&status).unwrap());
    drop(instance);
    assert!(!SingleInstance::exists(&control).unwrap());
}

#[test]
fn status_pipe_exchanges_data_while_control_pipe_remains_open() {
    let control = test_identity();
    let status = control.status_channel();

    let (control_read_tx, control_read_rx) = mpsc::sync_channel(1);
    let (release_control_tx, release_control_rx) = mpsc::sync_channel(1);
    let control_server_identity = control.clone();
    let control_server = thread::spawn(move || {
        let mut pipe = Pipe::accept(&control_server_identity, Duration::from_secs(3)).unwrap();
        let mut request = [0; 4];
        pipe.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"hold");
        control_read_tx.send(()).unwrap();
        release_control_rx
            .recv_timeout(Duration::from_secs(4))
            .unwrap();
        pipe.write_all(b"done").unwrap();
        let mut ack = [0];
        pipe.read_exact(&mut ack).unwrap();
        assert_eq!(ack, [1]);
    });

    let mut control_client = Pipe::connect(&control, Duration::from_secs(3)).unwrap();
    control_client.write_all(b"hold").unwrap();
    control_read_rx
        .recv_timeout(Duration::from_secs(3))
        .unwrap();

    let (status_accepted_tx, status_accepted_rx) = mpsc::sync_channel(1);
    let status_server_identity = status.clone();
    let status_server = thread::spawn(move || {
        let mut pipe = Pipe::accept(&status_server_identity, Duration::from_secs(3)).unwrap();
        status_accepted_tx.send(()).unwrap();
        let mut request = [0; 4];
        pipe.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"ping");
        pipe.write_all(b"pong").unwrap();
        let mut ack = [0];
        pipe.read_exact(&mut ack).unwrap();
        assert_eq!(ack, [1]);
    });

    let status_exchange = (|| -> io::Result<()> {
        let mut status_client = Pipe::connect(&status, Duration::from_secs(3))?;
        status_accepted_rx
            .recv_timeout(Duration::from_secs(3))
            .map_err(io::Error::other)?;
        status_client.write_all(b"ping")?;
        let mut response = [0; 4];
        status_client.read_exact(&mut response)?;
        if &response != b"pong" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bad_status_reply",
            ));
        }
        status_client.write_all(&[1])
    })();

    // Release the first connection even on failure so the server thread cannot
    // leave the test waiting for its timeout.
    let _ = release_control_tx.send(());
    let status_server_result = status_server.join();

    let mut control_reply = [0; 4];
    control_client.read_exact(&mut control_reply).unwrap();
    assert_eq!(&control_reply, b"done");
    control_client.write_all(&[1]).unwrap();
    let control_server_result = control_server.join();

    status_exchange.unwrap();
    status_server_result.unwrap();
    control_server_result.unwrap();
}
