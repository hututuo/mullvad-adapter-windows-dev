//! Explicit Windows acceptance: real official import into an existing running
//! client, preserving its selected profile. No identity, TUN or power mutation.
#[cfg(not(windows))]
fn main() {
    panic!("Windows acceptance only");
}
#[cfg(windows)]
fn main() {
    use adapter_clash_integration::{
        portable::{self, Selection},
        portable_source,
        profile_service::Service,
        Controller, LocalController,
    };
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        io::{Read, Write},
        net::TcpStream,
        path::PathBuf,
        time::{Duration, Instant},
    };
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(
        args.len(),
        5,
        "ENGINE FRONT NEW_QA_DIRECTORY --import-existing-client"
    );
    assert_eq!(args[4], "--import-existing-client");
    let engine = PathBuf::from(&args[1]);
    let front = args[2].to_str().unwrap().parse::<u16>().unwrap();
    let qa = PathBuf::from(&args[3]);
    assert!(engine.is_absolute() && qa.is_absolute() && !qa.exists());
    fs::create_dir(&qa).unwrap();
    let root = PathBuf::from(std::env::var_os("APPDATA").unwrap())
        .join("io.github.clash-verge-rev.clash-verge-rev");
    let source = portable_source(&root)
        .unwrap()
        .expect("existing generated client");
    let index = || -> Value {
        serde_json::to_value(
            serde_yaml_ng::from_slice::<serde_yaml_ng::Value>(
                &fs::read(root.join("profiles.yaml")).unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    };
    let before = index();
    let current = before["current"]
        .as_str()
        .expect("existing selected profile")
        .to_owned();
    let controller = LocalController::from_config(&source, front)
        .unwrap()
        .with_engine(engine, root.clone());
    let version = controller.get("/version").unwrap();
    let rules = controller.get("/rules").unwrap();
    let runtime_hash = Sha256::digest(fs::read(root.join("clash-verge.yaml")).unwrap()).to_vec();
    let app_root = adapter_platform::windows_paths::AppRoot::open("WindowsClash").unwrap();
    let store = app_root.path().join("clash-integration");
    if !store.exists() {
        fs::create_dir(&store).unwrap();
    }
    let service = Service::start(store.clone(), || {
        let a =
            adapter_platform::windows::boot_id().map_err(|_| "random_unavailable".to_owned())?;
        let b =
            adapter_platform::windows::boot_id().map_err(|_| "random_unavailable".to_owned())?;
        Ok(format!(
            "{:x}",
            Sha256::digest(format!("{a}{b}").as_bytes())
        ))
    })
    .unwrap();
    let profile = portable::generate(Some(&source), front, &Selection::default()).unwrap();
    let fingerprint = profile.fingerprint();
    let path = service.save(profile.bytes()).unwrap();
    controller.validate(&path).unwrap();
    let url = service.url(&fingerprint).unwrap();
    let already = portable::registration(&root, &url, &fingerprint)
        .unwrap()
        .registered;
    if !already {
        adapter_platform::windows_clash_uri::open(&service.import_uri(&fingerprint).unwrap())
            .unwrap();
    }
    let until = Instant::now() + Duration::from_secs(30);
    let registered = loop {
        let r = portable::registration(&root, &url, &fingerprint).unwrap();
        if r.registered {
            break r;
        }
        assert!(Instant::now() < until, "official import not confirmed");
        std::thread::sleep(Duration::from_millis(200));
    };
    assert!(!registered.selected);
    let after = index();
    assert_eq!(after["current"], current);
    let old_items = before["items"].as_array().unwrap();
    let items = after["items"].as_array().unwrap();
    assert!(
        old_items.iter().all(|old| items
            .iter()
            .any(|new| new["uid"] == old["uid"] && new == old)),
        "original items changed concurrently"
    );
    assert_eq!(controller.get("/rules").unwrap(), rules);
    assert_eq!(
        Sha256::digest(fs::read(root.join("clash-verge.yaml")).unwrap()).to_vec(),
        runtime_hash
    );
    drop(service);
    let service = Service::start(store, || {
        panic!("must restore durable subscription identity")
    })
    .unwrap();
    assert_eq!(service.url(&fingerprint).unwrap(), url);
    let (host, path) = url
        .strip_prefix("http://")
        .unwrap()
        .split_once('/')
        .unwrap();
    let mut stream = TcpStream::connect(host).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(stream, "GET /{path} HTTP/1.1\r\nHost: {host}\r\n\r\n").unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let body = response.windows(4).position(|s| s == b"\r\n\r\n").unwrap() + 4;
    assert_eq!(&response[body..], profile.bytes());
    let result = json!({"source_sha":option_env!("ADAPTER_SOURCE_SHA"),"engine":version,"profile_fingerprint":fingerprint,
        "rule_count":profile.summary.rule_count,"registered":true,"already_registered":already,"selected":false,
        "original_items_preserved":old_items.len(),"live_rules_unchanged":true,"generated_runtime_unchanged":true,
        "durable_service_restart":"PASS","download_hash_match":"PASS","identity_or_device_mutation":false,
        "power_or_tun_mutation":false,"actual_new_profile_egress":"NOT_RUN","frontend_interaction":"NOT_RUN",
        "subscription_refresh_requires_tray":true});
    fs::write(
        qa.join("receipt.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    println!("{result}");
}
