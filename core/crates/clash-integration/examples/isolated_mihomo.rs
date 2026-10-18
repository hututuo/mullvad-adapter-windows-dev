//! Explicit QA harness: synthetic profile + an isolated official core. Never
//! opens a user's Clash directory, system TUN, Mullvad identity or device API.
use adapter_clash_integration::{Choice, Controller, HttpController, Integration};
use serde_json::json;
use std::{
    fs,
    io::Write,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
struct Kernel(Child);
impl Drop for Kernel {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn write(path: &Path, bytes: &[u8]) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    assert!(
        matches!(args.len(), 3 | 4),
        "isolated_mihomo ENGINE NEW_TEST_DIRECTORY [--pipe]"
    );
    let pipe = args.len() == 4;
    if pipe {
        assert!(cfg!(windows) && args[3] == "--pipe", "Windows --pipe only");
    }
    let engine = PathBuf::from(&args[1]);
    let base = PathBuf::from(&args[2]);
    assert!(engine.is_absolute() && base.is_absolute() && !base.exists());
    fs::create_dir(&base).unwrap();
    #[cfg(not(windows))]
    let base = fs::canonicalize(base).unwrap();
    let root = base.join("verge");
    let store = base.join("private");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&store).unwrap();
    fs::create_dir(root.join("profiles")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    write(&root.join("profiles.yaml"),b"current: local\nitems:\n- uid: local\n  type: local\n  name: isolated QA\n  option:\n    script: scoped\n- uid: scoped\n  type: script\n  file: scoped.js\n");
    let script = b"function main(config) { return config; }\n";
    write(&root.join("profiles/scoped.js"), script);
    let mut config = json!({"mixed-port":0,"external-controller":format!("127.0.0.1:{port}"),"secret":"isolated-public-fixture",
        "mode":"rule","log-level":"silent","tun":{"enable":false},"dns":{"enable":false},"ipv6":false,
        "proxies":[{"name":"Ordinary","type":"socks5","server":"192.0.2.1","port":1080}],
        "proxy-groups":[{"name":"QA Traffic","type":"select","proxies":["Ordinary","REJECT"]}],
        "rules":["DOMAIN,fixture.example,REJECT","MATCH,QA Traffic"]});
    if pipe {
        config["external-controller"] = json!("");
        config["external-controller-pipe"] = json!(format!(
            r"\\.\pipe\mullvad-adapter-isolated-{}-{port}",
            std::process::id()
        ));
    }
    // JSON is a supported YAML subset, and contains only synthetic credentials.
    write(
        &root.join("clash-verge.yaml"),
        &serde_json::to_vec_pretty(&config).unwrap(),
    );
    let mut command = Command::new(&engine);
    command
        .arg("-d")
        .arg(&root)
        .arg("-f")
        .arg(root.join("clash-verge.yaml"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let _kernel = Kernel(command.spawn().unwrap());
    let controller = HttpController::from_config(&config, 17890)
        .unwrap()
        .with_engine(engine, root.clone());
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        if controller.get("/version").is_ok() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "isolated controller startup failed"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let i = Integration::open(root.clone(), store).unwrap();
    let choice = Choice {
        target_group: "QA Traffic".into(),
        ordinary_proxy: "Ordinary".into(),
        front_port: 17890,
    };
    let plan = i.preview(&controller, &choice).unwrap();
    assert_eq!(fs::read(root.join("profiles/scoped.js")).unwrap(), script);
    let out = i.apply(&controller, &choice, &plan.id).unwrap();
    assert!(out.saved && out.active, "{}", out.code);
    assert!(i.view(&controller, 17890).unwrap().active);
    assert_eq!(controller.get("/configs").unwrap()["tun"]["enable"], false);
    let undo = i.undo(&controller).unwrap();
    assert_eq!(undo.code, "clash_removed");
    assert_eq!(fs::read(root.join("profiles/scoped.js")).unwrap(), script);
    assert_eq!(
        controller.get("/proxies").unwrap()["proxies"]["QA Traffic"]["now"],
        "Ordinary"
    );
    assert_eq!(controller.get("/configs").unwrap()["tun"]["enable"], false);
    println!(
        "{}",
        json!({"controller_transport":controller.transport_kind(),"isolated_official_engine":true,"preview_no_write":true,"apply_and_selection_readback":true,"undo_script_bytes_and_selection":true,"tun_remained_disabled":true,"user_configuration_opened":false,"device_api_used":false,"external_egress_test":"NOT_RUN"})
    );
}
