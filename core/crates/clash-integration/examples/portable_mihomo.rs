//! Explicit QA only: no user profile, TUN, identity, relay or external service.
use adapter_clash_integration::{
    portable::{generate, Selection, AI, API, ORDINARY},
    Controller, LocalController, NODE,
};
use serde_json::{json, Value};
use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
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
fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(
        args.len(),
        4,
        "portable_mihomo ENGINE NEW_DIRECTORY PUBLIC_GEODATA_DIRECTORY"
    );
    let engine = PathBuf::from(&args[1]);
    let root = PathBuf::from(&args[2]);
    let geodata = PathBuf::from(&args[3]);
    assert!(engine.is_absolute() && root.is_absolute() && !root.exists());
    fs::create_dir(&root).unwrap();
    #[cfg(not(windows))]
    let root = fs::canonicalize(root).unwrap();
    for name in ["Country.mmdb", "geosite.dat", "geoip.dat"] {
        fs::copy(geodata.join(name), root.join(name)).unwrap();
    }
    let validator =
        LocalController::from_config(&json!({"external-controller":"127.0.0.1:19991"}), 17890)
            .unwrap()
            .with_engine(engine.clone(), root.clone());
    let source = json!({"proxies":[{"name":"User AI fixture","type":"socks5","server":"192.0.2.1","port":1080,"udp":true}]});
    for (kind, src, selection) in [
        ("empty", None, Selection::default()),
        (
            "existing",
            Some(&source),
            Selection {
                ai: Some("User AI fixture".into()),
                ordinary: None,
                api: Some("User AI fixture".into()),
            },
        ),
    ] {
        let profile = generate(src, 17890, &selection).unwrap();
        let file = root.join(format!("{kind}.yaml"));
        fs::write(&file, profile.bytes()).unwrap();
        validator.validate(&file).unwrap();
        let mut c: Value = serde_json::to_value(
            serde_yaml_ng::from_slice::<serde_yaml_ng::Value>(profile.bytes()).unwrap(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        c["external-controller"] = json!(format!("127.0.0.1:{port}"));
        c["mixed-port"] = json!(0);
        c["tun"] = json!({"enable":false});
        c["dns"] = json!({"enable":false});
        c["log-level"] = json!("silent");
        let test = root.join(format!("{kind}-runtime.json"));
        fs::write(&test, serde_json::to_vec(&c).unwrap()).unwrap();
        let mut command = Command::new(&engine);
        command
            .arg("-d")
            .arg(&root)
            .arg("-f")
            .arg(&test)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let _kernel = Kernel(command.spawn().unwrap());
        let controller = LocalController::from_config(&c, 17890).unwrap();
        let until = Instant::now() + Duration::from_secs(12);
        while controller.get("/version").is_err() {
            assert!(Instant::now() < until, "isolated startup");
            std::thread::sleep(Duration::from_millis(50));
        }
        let graph = controller.get("/proxies").unwrap();
        let rules = controller.get("/rules").unwrap();
        assert_eq!(
            rules["rules"].as_array().unwrap().len(),
            profile.summary.rule_count
        );
        assert_eq!(
            graph["proxies"][AI]["now"],
            if kind == "empty" {
                NODE
            } else {
                "User AI fixture"
            }
        );
        assert_eq!(graph["proxies"][ORDINARY]["now"], NODE);
        assert_eq!(
            graph["proxies"][API]["now"],
            if kind == "empty" {
                "DIRECT"
            } else {
                "User AI fixture"
            }
        );
        assert_eq!(controller.get("/configs").unwrap()["tun"]["enable"], false);
        println!(
            "{}",
            json!({"case":kind,"engine":controller.get("/version").unwrap(),"rules":profile.summary.rule_count,"policy_sha256":profile.summary.policy_sha256,"validation":"PASS","runtime_graph":"PASS","tun":"disabled","real_tunnel":"NOT_RUN","user_configuration_opened":false,"device_api_used":false})
        );
    }
}
