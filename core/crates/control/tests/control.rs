use adapter_control::*;
use adapter_protocol::*;
fn request(id: &str) -> Request {
    Request {
        major: 1,
        boot_id: "boot".into(),
        request_id: id.into(),
        command: Command::SelectCity {
            city: "us-sjc".into(),
        },
    }
}
fn operation(response: Response) -> Operation {
    match response {
        Response::Operation(op) => op,
        _ => panic!("not operation"),
    }
}
#[test]
fn lost_response_retrieves_same_operation_and_conflicts_are_rejected() {
    let mut control = MockControl::new("boot".into());
    let first = operation(control.handle(request("one"), 0));
    assert_eq!(first, operation(control.handle(request("one"), 1)));
    let mut conflict = request("one");
    conflict.command = Command::Stop;
    assert!(
        matches!(control.handle(conflict,2),Response::Error{code} if code=="request_id_conflict")
    );
    let mut query = request("two");
    query.command = Command::Operation {
        operation_id: first.id.clone(),
    };
    assert_eq!(first, operation(control.handle(query, 3)));
    assert_eq!(first.state, "failed");
    assert_eq!(first.code, "unavailable_mock_backend");
}
#[test]
fn cache_capacity_ttl_and_restart_are_explicit() {
    let mut control = MockControl::new("boot".into());
    for i in 0..128 {
        operation(control.handle(request(&format!("r{i}")), 0));
    }
    assert!(
        matches!(control.handle(request("overflow"),1),Response::Error{code} if code=="operation_capacity")
    );
    operation(control.handle(request("fresh"), 600001));
    let mut restarted = MockControl::new("new-boot".into());
    assert!(
        matches!(restarted.handle(request("old"),0),Response::Error{code} if code=="boot_changed_reconcile")
    );
}
#[test]
fn executor_rejects_unbounded_configuration_and_delivers_off_owner_thread() {
    assert!(Executor::<u8>::new(9, 1).is_err());
    assert!(Executor::<u8>::new(1, 65).is_err());
    let executor = Executor::new(2, 2).unwrap();
    let owner = std::thread::current().id();
    executor
        .submit(move || (std::thread::current().id() != owner, 7))
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if let Some(result) = executor.try_result() {
            assert_eq!(result, (true, 7));
            break;
        }
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    }
}
