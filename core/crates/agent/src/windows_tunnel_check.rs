//! Explicit, isolated worker acceptance. Never selects a front or changes routes.
use crate::{live_diagnostics::open_log_file, live_identity::load_identity};
use adapter_control::{
    observer::ObservedOwner,
    owned_lifecycle::{BuildOutcome, Event, Failure, Resource, ResourceOwner},
};
use adapter_domain::{Attachment, State};
use adapter_engine_mihomo::{
    worker_lifecycle::{Worker, WorkerRequest, WorkerStartError},
    Identity, Listener, Protection, Transport,
};
use adapter_platform::{
    windows::{boot_id, Identity as HostIdentity, SingleInstance},
    windows_paths::AppRoot,
    windows_runtime::PrivateRuntime,
    windows_store::PrivateStore,
};
use std::{
    fs::OpenOptions,
    io::{self, Read},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

enum CheckResult {
    StartFailed(WorkerStartError),
    Probed(
        Result<
            adapter_engine_mihomo::canary_batch::Report,
            adapter_engine_mihomo::canary_batch::BatchError,
        >,
        adapter_platform::engine_output::Snapshot,
        Option<adapter_engine_mihomo::worker_lifecycle::CarrierSnapshot>,
    ),
}
fn start_error_code(error: WorkerStartError) -> &'static str {
    error.code()
}

/// This is a maintenance command, not a GUI Connect implementation. It must be
/// explicitly invoked with an existing stored identity and one metadata relay.
pub fn verify(
    scope: &str,
    hostname: &str,
    mode: &str,
    requested_port: Option<u16>,
    carried: bool,
) -> io::Result<()> {
    if hostname.len() > 128
        || hostname.is_empty()
        || !hostname
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(io::Error::other("invalid_relay"));
    }
    let _instance = SingleInstance::acquire(&HostIdentity::current()?.with_scope("TunnelCheck")?)?;
    let root = AppRoot::open(scope)?;
    let store = PrivateStore::open(&root.path().join("store"))?;
    let identity = load_identity(&store)
        .map_err(|e| io::Error::other(e.code()))?
        .ok_or_else(|| io::Error::other("identity_missing"))?;
    let runtime =
        crate::live_runtime::resolve_process().map_err(|_| io::Error::other("runtime_invalid"))?;
    let mut options = OpenOptions::new();
    options.read(true);
    let file = open_log_file(&root.path().join("relays.json"), options)?;
    let mut bytes = Vec::new();
    file.take((adapter_mullvad_api::RELAY_BODY_CAP + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > adapter_mullvad_api::RELAY_BODY_CAP {
        return Err(io::Error::other("metadata_too_large"));
    }
    let catalogue = adapter_catalogue::Catalogue::parse(&bytes)
        .map_err(|_| io::Error::other("metadata_invalid"))?;
    let relay = catalogue
        .relays()
        .iter()
        .find(|r| r.hostname() == hostname && r.active())
        .ok_or_else(|| io::Error::other("relay_not_active"))?;
    let inlet = (mode == "ss")
        .then(|| catalogue.shadowsocks_inlet(relay, requested_port))
        .flatten();
    let endpoint_kind = match inlet.map(|inlet| inlet.kind) {
        Some(adapter_catalogue::ShadowsocksInletKind::ExtraAddress) => "extra_ss_ipv4",
        Some(adapter_catalogue::ShadowsocksInletKind::RelayAddress) => "relay_ss_ipv4",
        None => "direct_wireguard",
    };
    let transport = match mode {
        "ipv4" if catalogue.wireguard_port_allowed(requested_port.unwrap_or(51820)) => {
            Transport::DirectV4 {
                endpoint: relay
                    .ipv4()
                    .ok_or_else(|| io::Error::other("relay_ipv4_missing"))?,
                port: requested_port.unwrap_or(51820),
            }
        }
        "ipv6" if catalogue.wireguard_port_allowed(requested_port.unwrap_or(33431)) => {
            Transport::DirectV6 {
                endpoint: relay
                    .ipv6()
                    .ok_or_else(|| io::Error::other("relay_ipv6_missing"))?,
                port: requested_port.unwrap_or(33431),
            }
        }
        "ss" if inlet.is_some() => {
            let inlet = inlet.expect("guarded inlet");
            Transport::Shadowsocks {
                endpoint: inlet.address,
                port: inlet.port,
            }
        }
        _ => return Err(io::Error::other("transport_not_advertised")),
    };
    let outer_port = match transport {
        Transport::DirectV4 { port, .. }
        | Transport::DirectV6 { port, .. }
        | Transport::Shadowsocks { port, .. } => port,
    };
    let outer_address = match transport {
        Transport::DirectV4 { endpoint, .. } | Transport::Shadowsocks { endpoint, .. } => {
            std::net::IpAddr::V4(endpoint)
        }
        Transport::DirectV6 { endpoint, .. } => std::net::IpAddr::V6(endpoint),
    };
    let relay_key = relay.public_key().to_owned();
    let worker_runtime = PrivateRuntime::open(&root.path().join("tunnel-check"))?;
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(|_| io::Error::other("random_unavailable"))?;
    let secret = Zeroizing::new(
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
    random.fill(0);
    let mut owner = ResourceOwner::new(ObservedOwner::windows(State::new(boot_id()?))?);
    let deadline = Instant::now() + Duration::from_secs(45);
    let binding = loop {
        owner.poll();
        if owner.state().attachment == Attachment::Available && !owner.state().paused {
            if let Some(binding) = owner
                .observation()
                .bindings()
                .iter()
                .find(|b| match transport {
                    Transport::DirectV6 { .. } => b.ipv6,
                    _ => b.ipv4,
                })
                .copied()
            {
                break binding;
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other("physical_binding_unavailable"));
        }
        thread::sleep(Duration::from_millis(20));
    };
    let stamp = owner
        .observation()
        .stamp()
        .ok_or_else(|| io::Error::other("physical_binding_unavailable"))?;
    let token = owner.state().token();
    let (send, receive) = mpsc::sync_channel(1);
    owner.start_on_binding(binding, move |network| {
        let mut worker = identity
            .with_engine_identity(|key| {
                let start = if carried {
                    Worker::start_carried
                } else {
                    Worker::start_diagnostic
                };
                start(
                    &runtime.mihomo,
                    &worker_runtime,
                    &WorkerRequest {
                        identity: Identity {
                            private_key: key.private_key,
                            preshared_key: None,
                            ipv4: key.ipv4,
                            ipv6: Some(key.ipv6),
                        },
                        relay_public_key: &relay_key,
                        transport,
                        protection: Protection::Standard,
                        listener: Listener {
                            mixed_port: 17940,
                            controller_port: 17941,
                            controller_secret: &secret,
                        },
                    },
                    network,
                )
            })
            .map_err(|error| {
                let _ = send.try_send(CheckResult::StartFailed(error));
                if error == WorkerStartError::Cleanup {
                    Failure::Stop
                } else {
                    Failure::Start
                }
            })?;
        // The parent receives only immutable public canary observations. No
        // controller, process handle, private configuration or device key escapes.
        let report = if carried {
            worker.probe_bound().map(|proof| proof.into_report())
        } else {
            worker.probe()
        };
        let _ = send.try_send(CheckResult::Probed(
            report,
            worker.output_snapshot(),
            worker.carrier_snapshot(),
        ));
        Ok(BuildOutcome::Ready(ProbeWorker(worker)))
    })?;
    let mut result = None;
    let mut outcomes = None;
    let mut startup_error = None;
    let mut probe_error = None;
    let mut carrier_output = None;
    let mut engine_output = adapter_platform::engine_output::Snapshot::default();
    let mut stop_requested = false;
    let mut cleanup_deadline = None;
    loop {
        let (_, event) = owner.poll();
        if let Ok(observation) = receive.try_recv() {
            let report = match observation {
                CheckResult::StartFailed(error) => {
                    startup_error = Some(error);
                    None
                }
                CheckResult::Probed(Ok(report), output, carrier) => {
                    engine_output = output;
                    carrier_output = carrier;
                    outcomes = Some(report.outcomes());
                    Some(report)
                }
                CheckResult::Probed(Err(error), output, carrier) => {
                    engine_output = output;
                    carrier_output = carrier;
                    probe_error = Some(match error {
                        adapter_engine_mihomo::canary_batch::BatchError::Cancelled => {
                            "canary_cancelled"
                        }
                        adapter_engine_mihomo::canary_batch::BatchError::LocalFailure => {
                            "canary_local_failure"
                        }
                        adapter_engine_mihomo::canary_batch::BatchError::Stale => "canary_stale",
                    });
                    None
                }
            };
            result = Some(
                if owner.observation().stamp().as_ref() == Some(&stamp)
                    && owner.state().current(&token)
                {
                    report.and_then(|r| r.fresh_canary(Instant::now()).ok())
                } else {
                    None
                },
            );
            owner.cancel();
            stop_requested = true;
            cleanup_deadline = Some(Instant::now() + Duration::from_secs(10));
        }
        if Instant::now() >= deadline && !stop_requested {
            owner.cancel();
            stop_requested = true;
            cleanup_deadline = Some(Instant::now() + Duration::from_secs(10));
        }
        if let Some(Event::Finished(_, stopped)) = event {
            if let Some(error) = startup_error {
                println!(
                    "{}",
                    serde_json::json!({"relay":hostname,"transport":mode,"outer_port":outer_port,"outer_address":outer_address,"endpoint_kind":endpoint_kind,"stage":"worker_start","error":start_error_code(error),"front_selection":"NOT_PERFORMED","owned_worker_stop":"NOT_CONFIRMED_BY_THIS_REPORT","physical_capture":"NOT_RUN"})
                );
                return Err(io::Error::other(start_error_code(error)));
            }
            stopped.map_err(|_| io::Error::other("cleanup_uncertain"))?;
            if let Some(error) = probe_error {
                println!(
                    "{}",
                    serde_json::json!({"relay":hostname,"transport":mode,"outer_port":outer_port,"outer_address":outer_address,"endpoint_kind":endpoint_kind,"stage":"canary","error":error,"carrier":carrier_output,"engine_signals":engine_output.signals(),"engine_warning_lines":engine_output.warning_lines,"engine_output_truncated":engine_output.truncated,"front_selection":"NOT_PERFORMED","owned_worker_stop":"PASS","physical_capture":"NOT_RUN"})
                );
                return Err(io::Error::other(error));
            }
            let canary = result
                .flatten()
                .ok_or_else(|| io::Error::other("tunnel_check_incomplete"))?;
            println!(
                "{}",
                serde_json::json!({"relay":hostname,"transport":mode,"outer_port":outer_port,"outer_address":outer_address,"endpoint_kind":endpoint_kind,"ip":canary.ip,"dns":canary.dns,"https":canary.https,"probes":outcomes,"carrier":carrier_output,"engine_signals":engine_output.signals(),"engine_warning_lines":engine_output.warning_lines,"engine_output_truncated":engine_output.truncated,"front_selection":"NOT_PERFORMED","physical_capture":"NOT_RUN","physical_socket":if carried {"PASS_SOCKET_SUBMISSION_AND_RX_PKTINFO"} else {"NOT_RUN"},"owned_worker_stop":"PASS"})
            );
            return if canary.ip && canary.dns && canary.https {
                Ok(())
            } else {
                Err(io::Error::other("tunnel_canary_not_ready"))
            };
        }
        if cleanup_deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(io::Error::other("cleanup_uncertain"));
        }
        thread::sleep(Duration::from_millis(20));
    }
}
struct ProbeWorker(Worker);
impl Resource for ProbeWorker {
    fn check(&mut self) -> Result<(), Failure> {
        if self.0.is_running() {
            Ok(())
        } else {
            Err(Failure::Worker)
        }
    }
    fn stop(&mut self) -> Result<(), Failure> {
        self.0.stop_confirmed()
    }
}
