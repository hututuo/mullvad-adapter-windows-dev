//! Maintainer read-only inspection. Prints allowlisted view data only; never
//! controller headers, full runtime YAML, proxy passwords or device credentials.
use adapter_clash_integration::{Controller, Integration};
use std::path::PathBuf;
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(
        args.len(),
        4,
        "inspect_local CLASH_DIRECTORY PRIVATE_QA_STORE FRONT_PORT"
    );
    let root = PathBuf::from(&args[1]);
    let store = PathBuf::from(&args[2]);
    let front = args[3].to_str().unwrap().parse::<u16>().unwrap();
    let result = (|| {
        let integration = Integration::open(root, store)?;
        let controller = integration.controller(front)?;
        let view = integration.view(&controller, front)?;
        let version = controller.get("/version")?;
        Ok::<_, String>(
            serde_json::json!({"transport":controller.transport_kind(),"view":view,"core_version":version.get("version"),"configuration_mutated":false}),
        )
    })();
    match result {
        Ok(view) => println!("{view}"),
        Err(code) => {
            eprintln!("{code}");
            std::process::exit(1)
        }
    }
}
