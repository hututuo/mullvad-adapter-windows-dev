use super::*;
use std::{
    cell::{Cell, RefCell},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    path: PathBuf,
    root: PathBuf,
    store: PathBuf,
    original: Value,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mva-clash-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        #[cfg(not(windows))]
        let path = fs::canonicalize(path).unwrap();
        let root = path.join("verge");
        let store = path.join("private");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&store).unwrap();
        fs::create_dir(root.join("profiles")).unwrap();
        create(&root.join("profiles.yaml"),b"current: local\nitems:\n- uid: local\n  name: Test profile\n  type: local\n  option:\n    script: scoped\n- uid: scoped\n  type: script\n  file: scoped.js\n").unwrap();
        create(
            &root.join("profiles/scoped.js"),
            b"function main(config) { config.keep = true; return config; }\n",
        )
        .unwrap();
        let original = json!({"mixed-port":7897,"external-controller":"127.0.0.1:9097","secret":"not-for-renderer",
            "mode":"rule","tun":{"enable":false,"mtu":1400},"dns":{"nameserver":["192.0.2.53"]},
            "proxies":[{"name":"Ordinary 🇯🇵","type":"ss","server":"192.0.2.1","port":443,"cipher":"aes-128-gcm","password":"fixture-only"},
                       {"name":"Other","type":"socks5","server":"198.51.100.1","port":1080}],
            "proxy-groups":[{"name":"AI 出口","type":"select","proxies":["Ordinary 🇯🇵","Other"],"icon":"keep-icon"},
                {"name":"自动","type":"url-test","proxies":["Other"],"url":"https://example.com"}],
            "rules":["DOMAIN,drive.google.com,Other","GEOIP,CN,DIRECT","MATCH,AI 出口"]});
        create(&root.join("clash-verge.yaml"), &yaml(&original).unwrap()).unwrap();
        Self {
            path,
            root,
            store,
            original,
        }
    }
    fn integration(&self) -> Integration {
        Integration::open(self.root.clone(), self.store.clone()).unwrap()
    }
    fn choice(&self) -> Choice {
        Choice {
            target_group: "AI 出口".into(),
            ordinary_proxy: "Ordinary 🇯🇵".into(),
            front_port: 17890,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
struct Fake {
    config: RefCell<Value>,
    selections: RefCell<Value>,
    puts: Cell<usize>,
    fail_reload: Cell<bool>,
    fail_validate: Cell<bool>,
}
impl Fake {
    fn new(v: Value) -> Self {
        Self {
            config: RefCell::new(v),
            selections: RefCell::new(json!({"AI 出口":"Ordinary 🇯🇵"})),
            puts: Cell::new(0),
            fail_reload: Cell::new(false),
            fail_validate: Cell::new(false),
        }
    }
}
impl Controller for Fake {
    fn validate(&self, _: &Path) -> Result<()> {
        if self.fail_validate.get() {
            Err(err("validation_failed"))
        } else {
            Ok(())
        }
    }
    fn get(&self, path: &str) -> Result<Value> {
        if path == "/configs" {
            return Ok(self.config.borrow().clone());
        }
        if path == "/rules" {
            return Ok(
                json!({"rules":self.config.borrow()["rules"].as_array().unwrap().iter().map(|r|{
            let (kind,payload,target)=rule_parts(r.as_str().unwrap()).unwrap();json!({"type":kind,"payload":payload,"proxy":target})}).collect::<Vec<_>>()}),
            );
        }
        assert_eq!(path, "/proxies");
        let mut proxies = serde_json::Map::new();
        for p in self.config.borrow()["proxies"].as_array().unwrap() {
            proxies.insert(
                text(p, "name").unwrap().into(),
                json!({"type":if text(p,"type")==Some("socks5"){"Socks5"}else{"Shadowsocks"}}),
            );
        }
        proxies.insert("AI 出口".into(),json!({"type":"Selector","now":self.selections.borrow()["AI 出口"],"all":self.config.borrow()["proxy-groups"][0]["proxies"]}));
        Ok(json!({"proxies":proxies}))
    }
    fn put(&self, path: &str, body: &Value) -> Result<()> {
        self.puts.set(self.puts.get() + 1);
        if path == "/configs?force=false" {
            if self.fail_reload.get() {
                return Err(err("activation_unconfirmed"));
            }
            *self.config.borrow_mut() = parse(body["payload"].as_str().unwrap().as_bytes())?;
        } else {
            assert_eq!(path, "/proxies/AI%20%E5%87%BA%E5%8F%A3");
            self.selections.borrow_mut()["AI 出口"] = body["name"].clone();
        }
        Ok(())
    }
}
#[test]
fn preview_is_public_and_apply_undo_preserve_unrelated_rules_dns_and_tun() {
    let f = Fixture::new();
    let i = f.integration();
    let c = Fake::new(f.original.clone());
    let choice = f.choice();
    let before = read(&f.root.join("profiles/scoped.js")).unwrap();
    let preview = i.preview(&c, &choice).unwrap();
    assert!(
        !preview.config.contains("fixture-only") && !preview.config.contains("not-for-renderer")
    );
    assert_eq!(read(&f.root.join("profiles/scoped.js")).unwrap(), before);
    assert_eq!(c.puts.get(), 0);
    let out = i.apply(&c, &choice, &preview.id).unwrap();
    assert!(out.saved && out.active);
    assert!(i.view(&c, 17890).unwrap().active);
    let live = c.config.borrow();
    assert_eq!(live["dns"], f.original["dns"]);
    assert_eq!(live["tun"], f.original["tun"]);
    assert_eq!(
        live["rules"].as_array().unwrap()[1..],
        f.original["rules"].as_array().unwrap()[..]
    );
    assert_eq!(live["proxy-groups"][1], f.original["proxy-groups"][1]);
    assert_eq!(live["proxy-groups"][0]["icon"], "keep-icon");
    drop(live);
    assert!(read(&f.root.join("profiles/scoped.js"))
        .unwrap()
        .starts_with(&before));
    assert_eq!(i.preview(&c, &choice).unwrap_err(), err("already_managed"));
    let undo = i.undo(&c).unwrap();
    assert_eq!(undo.code, "clash_removed");
    assert!(Path::new(&undo.backup_path).is_dir());
    assert_eq!(read(&f.root.join("profiles/scoped.js")).unwrap(), before);
    assert_eq!(*c.config.borrow(), f.original);
    assert_eq!(c.selections.borrow()["AI 出口"], "Ordinary 🇯🇵");
    assert!(!i.view(&c, 17890).unwrap().managed);
    // A subsequent explicit integration uses a new active transaction, retaining the archive.
    let preview = i.preview(&c, &choice).unwrap();
    assert!(i.apply(&c, &choice, &preview.id).unwrap().active);
}
#[test]
fn live_geoip_country_case_matches_but_changed_country_and_target_do_not() {
    struct GeoIpReply<'a> {
        inner: &'a Fake,
        country: &'a str,
        target: &'a str,
    }
    impl Controller for GeoIpReply<'_> {
        fn validate(&self, path: &Path) -> Result<()> {
            self.inner.validate(path)
        }
        fn get(&self, path: &str) -> Result<Value> {
            let mut value = self.inner.get(path)?;
            if path == "/rules" {
                value["rules"][1]["type"] = json!("GeoIP");
                value["rules"][1]["payload"] = json!(self.country);
                value["rules"][1]["proxy"] = json!(self.target);
            }
            Ok(value)
        }
        fn put(&self, path: &str, body: &Value) -> Result<()> {
            self.inner.put(path, body)
        }
    }
    let f = Fixture::new();
    let inner = Fake::new(f.original.clone());
    let snapshot = snapshot(&f.root).unwrap();
    for (country, target, matches) in [
        ("cn", "DIRECT", true),
        ("CN", "DIRECT", true),
        ("us", "DIRECT", false),
        ("cn", "REJECT", false),
    ] {
        let controller = GeoIpReply {
            inner: &inner,
            country,
            target,
        };
        assert_eq!(
            check_runtime(&snapshot, &controller, &f.choice()).is_ok(),
            matches
        );
    }
    assert_eq!(inner.puts.get(), 0);
}
#[test]
fn stale_preview_never_changes_script_or_reloads() {
    let f = Fixture::new();
    let i = f.integration();
    let c = Fake::new(f.original.clone());
    let choice = f.choice();
    let plan = i.preview(&c, &choice).unwrap();
    let script = f.root.join("profiles/scoped.js");
    let newer = b"function main(c) { c.other = true; return c; }\n";
    fs::write(&script, newer).unwrap();
    assert_eq!(
        i.apply(&c, &choice, &plan.id).unwrap_err(),
        err("config_changed")
    );
    assert_eq!(read(&script).unwrap(), newer);
    assert_eq!(c.puts.get(), 0);
}
#[test]
fn undo_does_not_clobber_later_script_edits_or_reload() {
    let f = Fixture::new();
    let i = f.integration();
    let c = Fake::new(f.original.clone());
    let choice = f.choice();
    let plan = i.preview(&c, &choice).unwrap();
    i.apply(&c, &choice, &plan.id).unwrap();
    let calls = c.puts.get();
    let script = f.root.join("profiles/scoped.js");
    let mut newer = read(&script).unwrap();
    newer.extend_from_slice(b"\n// user edit\n");
    fs::write(&script, &newer).unwrap();
    assert!(i.view(&c, 17890).unwrap().conflict);
    assert_eq!(i.undo(&c).unwrap_err(), err("config_changed"));
    assert_eq!(read(&script).unwrap(), newer);
    assert_eq!(c.puts.get(), calls);
}
#[test]
fn uncertain_reload_is_saved_but_never_reported_active_and_can_be_undone() {
    let f = Fixture::new();
    let i = f.integration();
    let c = Fake::new(f.original.clone());
    let choice = f.choice();
    let plan = i.preview(&c, &choice).unwrap();
    c.fail_reload.set(true);
    let out = i.apply(&c, &choice, &plan.id).unwrap();
    assert!(out.saved && !out.active);
    assert_eq!(out.code, err("activation_unconfirmed"));
    assert_eq!(c.puts.get(), 1);
    c.fail_reload.set(false);
    assert_eq!(i.undo(&c).unwrap().code, "clash_removed");
}
#[test]
fn failed_validation_never_changes_script_or_controller() {
    let f = Fixture::new();
    let i = f.integration();
    let c = Fake::new(f.original.clone());
    let choice = f.choice();
    let plan = i.preview(&c, &choice).unwrap();
    let before = read(&f.root.join("profiles/scoped.js")).unwrap();
    c.fail_validate.set(true);
    assert_eq!(
        i.apply(&c, &choice, &plan.id).unwrap_err(),
        err("validation_failed")
    );
    assert_eq!(read(&f.root.join("profiles/scoped.js")).unwrap(), before);
    assert_eq!(c.puts.get(), 0);
    let view = i.view(&c, 17890).unwrap();
    assert!(view.managed && !view.saved && !view.conflict);
    // No successful mutation took place; cancel the staged transaction without
    // repeating the validator/reload that just failed.
    assert_eq!(i.undo(&c).unwrap().code, "clash_removed");
    assert_eq!(c.puts.get(), 0);
}
#[test]
fn undo_retains_a_later_user_selection() {
    let f = Fixture::new();
    let i = f.integration();
    let c = Fake::new(f.original.clone());
    let choice = f.choice();
    let plan = i.preview(&c, &choice).unwrap();
    i.apply(&c, &choice, &plan.id).unwrap();
    c.selections.borrow_mut()["AI 出口"] = json!("Other");
    assert_eq!(i.undo(&c).unwrap().code, "clash_removed");
    assert_eq!(c.selections.borrow()["AI 出口"], "Other");
}
#[test]
fn generated_runtime_after_subscription_update_undo_removes_only_owned_delta() {
    let f = Fixture::new();
    let i = f.integration();
    let c = Fake::new(f.original.clone());
    let choice = f.choice();
    let plan = i.preview(&c, &choice).unwrap();
    i.apply(&c, &choice, &plan.id).unwrap();
    let mut refreshed = c.config.borrow().clone();
    refreshed["rules"]
        .as_array_mut()
        .unwrap()
        .insert(1, json!("DOMAIN,new.example,Other"));
    fs::write(f.root.join("clash-verge.yaml"), yaml(&refreshed).unwrap()).unwrap();
    *c.config.borrow_mut() = refreshed.clone();
    i.undo(&c).unwrap();
    assert!(c.config.borrow()["rules"]
        .as_array()
        .unwrap()
        .contains(&json!("DOMAIN,new.example,Other")));
    assert!(c.config.borrow()["proxies"]
        .as_array()
        .unwrap()
        .iter()
        .all(|p| text(p, "name") != Some(NODE)));
}
#[test]
fn no_global_mode_change_and_no_recursive_ordinary_nodes() {
    let f = Fixture::new();
    let i = f.integration();
    let c = Fake::new(f.original.clone());
    let choice = f.choice();
    c.config.borrow_mut()["mode"] = json!("global");
    assert_eq!(
        i.preview(&c, &choice).unwrap_err(),
        err("rule_mode_required")
    );
    assert_eq!(c.puts.get(), 0);
    let mut v = f.original.clone();
    v["proxies"][0]["dialer-proxy"] = json!("AI 出口");
    assert_eq!(check_choice(&v, &choice), Err(err("invalid_choice")));
    v["proxies"][0]
        .as_object_mut()
        .unwrap()
        .remove("dialer-proxy");
    v["proxies"][0]["server"] = json!("127.0.0.1");
    assert_eq!(check_choice(&v, &choice), Err(err("invalid_choice")));
}
#[test]
fn control_endpoint_must_be_local_and_cannot_be_own_front() {
    for s in [
        "192.0.2.1:9097",
        "127.0.0.1:17890",
        "127.0.0.1:17920",
        "http://127.0.0.1:9097",
    ] {
        assert!(HttpController::from_config(&json!({"external-controller":s}), 17890).is_err());
    }
    assert!(
        HttpController::from_config(&json!({"external-controller":"0.0.0.0:9097"}), 17890).is_ok()
    );
}
#[test]
fn empty_controller_is_missing_and_existing_local_pipe_takes_priority() {
    for config in [
        json!({}),
        json!({"external-controller":""}),
        json!({"external-controller":"  "}),
        json!({"external-controller":null,"external-controller-pipe":""}),
    ] {
        assert_eq!(
            control_endpoint(&config, 17890, true).unwrap_err(),
            "clash_controller_missing"
        );
    }
    let pipe = r"\\.\pipe\verge-mihomo";
    let config = json!({"external-controller":"","external-controller-pipe":pipe});
    assert_eq!(
        control_endpoint(&config, 17890, true).unwrap(),
        ControlEndpoint::Pipe(pipe.into())
    );
    assert_eq!(
        control_endpoint(&config, 17890, false).unwrap_err(),
        "clash_controller_pipe_unsupported"
    );
    let config = json!({"external-controller":"192.0.2.1:9090","external-controller-pipe":pipe});
    assert_eq!(
        control_endpoint(&config, 17890, true).unwrap(),
        ControlEndpoint::Pipe(pipe.into())
    );
    let config = json!({"external-controller":"127.0.0.1:9090","external-controller-pipe":""});
    assert!(matches!(
        control_endpoint(&config, 17890, true),
        Ok(ControlEndpoint::Http(_))
    ));
}
#[test]
fn nonlocal_or_ambiguous_pipe_never_falls_back_to_http() {
    for pipe in [
        r"\\remote\pipe\verge-mihomo",
        r"\\?\pipe\verge-mihomo",
        r"\\.\pipe\",
        r"\\.\pipe\..\x",
        r"\\.\pipe\a/b",
        r"\\.\pipe\a\b",
        "\\\\.\\pipe\\bad\0suffix",
    ] {
        assert_eq!(
            control_endpoint(
                &json!({"external-controller-pipe":pipe,"external-controller":"127.0.0.1:9090"}),
                17890,
                true
            )
            .unwrap_err(),
            "clash_controller_nonlocal"
        );
    }
}
#[cfg(windows)]
#[test]
fn local_pipe_never_carries_http_secret_or_falls_back_to_tcp() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let config = json!({"external-controller":listener.local_addr().unwrap().to_string(),"external-controller-pipe":format!(r"\\.\pipe\adapter-no-fallback-{}",std::process::id()),"secret":"synthetic-do-not-send"});
    let controller = LocalController::from_config(&config, 17890).unwrap();
    assert!(controller.authorization.is_none());
    assert_eq!(controller.transport_kind(), "windows_pipe");
    assert_eq!(
        controller.get("/configs").unwrap_err(),
        "clash_controller_unavailable"
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
#[test]
fn traversal_script_filename_and_unknown_owned_node_are_rejected() {
    let f = Fixture::new();
    let mut index = parse(&read(&f.root.join("profiles.yaml")).unwrap()).unwrap();
    index["items"][1]["file"] = json!("../other.js");
    fs::write(f.root.join("profiles.yaml"), yaml(&index).unwrap()).unwrap();
    assert_eq!(snapshot(&f.root).err().unwrap(), err("unsafe_path"));
    let mut v = f.original.clone();
    v["proxies"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":NODE,"type":"direct"}));
    assert_eq!(
        modify(&mut v, &f.choice(), false),
        Err(err("name_conflict"))
    );
}
#[test]
fn integration_lock_excludes_a_second_process_owner() {
    let f = Fixture::new();
    let _i = f.integration();
    assert_eq!(
        Integration::open(f.root.clone(), f.store.clone())
            .err()
            .unwrap(),
        err("busy")
    );
}
#[test]
fn runtime_control_switches_are_preserved_even_if_verge_file_is_older() {
    let f = Fixture::new();
    let i = f.integration();
    let c = Fake::new(f.original.clone());
    c.config.borrow_mut()["tun"]["enable"] = json!(true);
    let choice = f.choice();
    let plan = i.preview(&c, &choice).unwrap();
    i.apply(&c, &choice, &plan.id).unwrap();
    assert_eq!(c.config.borrow()["tun"]["enable"], true);
}

#[test]
fn preexisting_api_rule_and_reserved_references_are_not_adopted_or_deleted() {
    for reference in [false, true] {
        let f = Fixture::new();
        let i = f.integration();
        let mut config = f.original.clone();
        if reference {
            config["proxy-groups"][0]["proxies"]
                .as_array_mut()
                .unwrap()
                .push(json!(NODE));
        } else {
            config["rules"]
                .as_array_mut()
                .unwrap()
                .insert(0, json!(rule(&f.choice())));
        }
        fs::write(f.root.join("clash-verge.yaml"), yaml(&config).unwrap()).unwrap();
        let c = Fake::new(config);
        assert_eq!(
            i.preview(&c, &f.choice()).unwrap_err(),
            err(if reference {
                "name_conflict"
            } else {
                "rule_conflict"
            })
        );
        assert_eq!(c.puts.get(), 0);
    }
}
#[test]
fn controller_only_rule_or_group_changes_block_reload() {
    for group in [false, true] {
        let f = Fixture::new();
        let i = f.integration();
        let c = Fake::new(f.original.clone());
        let choice = f.choice();
        let preview = i.preview(&c, &choice).unwrap();
        if group {
            c.config.borrow_mut()["proxy-groups"][0]["proxies"] = json!(["Other", "Ordinary 🇯🇵"])
        } else {
            c.config.borrow_mut()["rules"]
                .as_array_mut()
                .unwrap()
                .insert(0, json!("DOMAIN,later.example,Other"));
        }
        let before = read(&f.root.join("profiles/scoped.js")).unwrap();
        assert_eq!(
            i.apply(&c, &choice, &preview.id).unwrap_err(),
            err("runtime_diverged")
        );
        assert_eq!(c.puts.get(), 0);
        assert_eq!(read(&f.root.join("profiles/scoped.js")).unwrap(), before);
    }
}
#[test]
fn other_profiles_remain_discoverable_after_switch() {
    let f = Fixture::new();
    let i = f.integration();
    let c = Fake::new(f.original.clone());
    let choice = f.choice();
    let preview = i.preview(&c, &choice).unwrap();
    i.apply(&c, &choice, &preview.id).unwrap();
    let p = f.root.join("profiles.yaml");
    let mut v = parse(&read(&p).unwrap()).unwrap();
    v["current"] = json!("another");
    v["items"].as_array_mut().unwrap().extend([
        json!({"uid":"another","name":"Another profile","option":{"script":"another-script"}}),
        json!({"uid":"another-script","type":"script","file":"another.js"}),
    ]);
    fs::write(&p, yaml(&v).unwrap()).unwrap();
    create(
        &f.root.join("profiles/another.js"),
        b"function main(c){return c}",
    )
    .unwrap();
    let view = i.view(&c, 17890).unwrap();
    assert!(!view.managed);
    assert_eq!(view.other_profiles, ["Test profile"]);
}

#[test]
fn explicit_reenable_only_selects_without_rewriting_or_reloading() {
    let f = Fixture::new();
    let i = f.integration();
    let c = Fake::new(f.original.clone());
    let choice = f.choice();
    let plan = i.preview(&c, &choice).unwrap();
    i.apply(&c, &choice, &plan.id).unwrap();
    let script = read(&f.root.join("profiles/scoped.js")).unwrap();
    let calls = c.puts.get();
    c.selections.borrow_mut()["AI 出口"] = json!("Other");
    assert!(i.enable(&c).unwrap().active);
    assert_eq!(c.puts.get(), calls + 1);
    assert_eq!(read(&f.root.join("profiles/scoped.js")).unwrap(), script);
}

#[test]
fn shared_profile_script_is_never_modified_by_current_profile_integration() {
    let f = Fixture::new();
    let p = f.root.join("profiles.yaml");
    let mut v = parse(&read(&p).unwrap()).unwrap();
    v["items"]
        .as_array_mut()
        .unwrap()
        .push(json!({"uid":"other","option":{"script":"scoped"}}));
    fs::write(p, yaml(&v).unwrap()).unwrap();
    assert_eq!(snapshot(&f.root).err().unwrap(), err("script_shared"));
}
