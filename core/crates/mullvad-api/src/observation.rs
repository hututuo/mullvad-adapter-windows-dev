//! Closed, credential-free control-plane evidence. Timings describe observed
//! request/header/body boundaries, not invented DNS/TCP/TLS substage durations.
use super::*;
use std::sync::Arc;

#[derive(Clone, Debug, Serialize)]
pub struct ApiObservation {
    pub route: ApiAccessRoute,
    pub endpoint: &'static str,
    pub phase: &'static str,
    pub outcome: &'static str,
    pub elapsed_ms: u64,
    pub headers_ms: Option<u64>,
    pub body_ms: Option<u64>,
    pub http_status: Option<u16>,
    pub error_code: Option<&'static str>,
    pub configured_endpoint: Option<SocketAddr>,
}
pub type ApiObserver = Arc<dyn Fn(ApiObservation) + Send + Sync>;
pub const API_TRANSACTION_BUDGET: Duration = Duration::from_secs(60);
pub const API_DISCOVERY_BUDGET: Duration = Duration::from_secs(24);
pub const API_ATTEMPT_BUDGET: Duration = Duration::from_secs(8);
pub const API_ROUTE_REUSE: Duration = Duration::from_secs(15 * 60);

pub(crate) fn endpoint_label(method: Method, path: &str) -> &'static str {
    match (method, path) {
        (_, "app/v1/api-addrs") => "address_discovery",
        (_, "auth/v1/token") => "authentication",
        (_, "accounts/v1/accounts/me") => "account_info",
        (Method::Get, "accounts/v1/devices") => "device_list",
        (Method::Post, "accounts/v1/devices") => "device_create",
        (Method::Delete, p) if p.starts_with("accounts/v1/devices/") => "device_remove",
        (_, "app/v1/relays") => "catalogue",
        (_, "app/v1/submit-voucher") => "voucher",
        _ => "account_operation",
    }
}
pub(crate) fn millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}
pub(crate) fn transport_phase(error: &ureq::Error) -> &'static str {
    match error {
        ureq::Error::Timeout(ureq::Timeout::Resolve) | ureq::Error::HostNotFound => "dns",
        ureq::Error::Timeout(ureq::Timeout::Connect) => "connection_setup",
        ureq::Error::ConnectProxyFailed(_) => "proxy_connect",
        ureq::Error::Rustls(_) | ureq::Error::Tls(_) => "tls",
        ureq::Error::Timeout(ureq::Timeout::RecvResponse) => "response_headers",
        _ => "transport_unknown",
    }
}
impl MullvadClient {
    pub fn with_observer(mut self, observer: ApiObserver) -> Self {
        self.transport.observer = Some(observer);
        self
    }
    /// This deadline clamps ALL requests including authentication and writes.
    /// Cloning/reusing a selected client must bind a new transaction deadline.
    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.transport.operation_deadline = Some(deadline);
        self
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ApiRouteKey {
    pub network_epoch: u64,
    pub independent: Option<BootstrapProxy>,
    pub healthy_tunnel: Option<BootstrapProxy>,
    pub healthy_instance: u64,
}
#[derive(Default)]
pub struct ApiRouteReuse {
    selected: Option<(ApiRouteKey, Instant, ApiBootstrap)>,
}
impl ApiRouteReuse {
    pub fn get(&mut self, key: ApiRouteKey) -> Option<ApiBootstrap> {
        self.get_at(key, Instant::now())
    }
    fn get_at(&mut self, key: ApiRouteKey, now: Instant) -> Option<ApiBootstrap> {
        if self.selected.as_ref().is_some_and(|(old, at, _)| {
            *old == key && now.saturating_duration_since(*at) < API_ROUTE_REUSE
        }) {
            self.selected.as_ref().map(|(_, _, access)| access.clone())
        } else {
            self.invalidate();
            None
        }
    }
    pub fn remember(&mut self, key: ApiRouteKey, access: &ApiBootstrap) {
        let mut selected = access.clone();
        // Per-operation log context and deadlines must not survive reuse.
        selected.client.transport.observer = None;
        selected.client.transport.operation_deadline = None;
        self.selected = Some((key, Instant::now(), selected));
    }
    pub fn invalidate(&mut self) {
        self.selected = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::TcpListener,
        sync::{Arc, Mutex},
    };

    fn proxy(port: u16) -> BootstrapProxy {
        BootstrapProxy::new(SocketAddr::from(([127, 0, 0, 1], port))).unwrap()
    }

    fn key() -> ApiRouteKey {
        ApiRouteKey {
            network_epoch: 7,
            independent: Some(proxy(17_891)),
            healthy_tunnel: Some(proxy(17_892)),
            healthy_instance: 42,
        }
    }

    fn bootstrap() -> ApiBootstrap {
        ApiBootstrap {
            client: MullvadClient::new(proxy(17_891)).unwrap(),
            cache: ApiAddressCache::default(),
            route: ApiAccessRoute::IndependentProxy,
        }
    }

    #[test]
    fn route_reuse_expires_after_its_ttl() {
        let key = key();
        let mut reuse = ApiRouteReuse::default();
        let remembered_at = Instant::now();
        reuse.remember(key, &bootstrap());

        assert!(reuse
            .get_at(
                key,
                remembered_at + API_ROUTE_REUSE - Duration::from_secs(1)
            )
            .is_some());
        assert!(reuse
            .get_at(
                key,
                remembered_at + API_ROUTE_REUSE + Duration::from_secs(1)
            )
            .is_none());
        assert!(reuse.selected.is_none());
    }

    #[test]
    fn route_reuse_invalidates_on_network_or_any_selected_path_change() {
        let original = key();
        let mut changed_network = original;
        changed_network.network_epoch += 1;
        let mut changed_independent_proxy = original;
        changed_independent_proxy.independent = Some(proxy(17_893));
        let mut changed_healthy_tunnel = original;
        changed_healthy_tunnel.healthy_tunnel = Some(proxy(17_894));
        let mut changed_healthy_instance = original;
        changed_healthy_instance.healthy_instance += 1;

        for changed in [
            changed_network,
            changed_independent_proxy,
            changed_healthy_tunnel,
            changed_healthy_instance,
        ] {
            let mut reuse = ApiRouteReuse::default();
            reuse.remember(original, &bootstrap());
            assert!(reuse.get_at(changed, Instant::now()).is_none());
            assert!(reuse.selected.is_none());
        }
    }

    #[test]
    fn route_reuse_clears_observer_and_operation_deadline_from_cached_client() {
        let key = key();
        let mut selected = bootstrap();
        selected.client = selected
            .client
            .with_observer(Arc::new(|_| {}))
            .with_deadline(Instant::now() + Duration::from_secs(30));
        assert!(selected.client.transport.observer.is_some());
        assert!(selected.client.transport.operation_deadline.is_some());

        let mut reuse = ApiRouteReuse::default();
        reuse.remember(key, &selected);
        let cached = reuse.get_at(key, Instant::now()).unwrap();

        assert!(cached.client.transport.observer.is_none());
        assert!(cached.client.transport.operation_deadline.is_none());
        assert!(reuse.selected.as_ref().is_some_and(|(_, _, access)| access
            .client
            .transport
            .observer
            .is_none()
            && access.client.transport.operation_deadline.is_none()));
    }

    #[test]
    fn expired_operation_deadline_emits_evidence_without_opening_proxy_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let local_proxy = BootstrapProxy::new(listener.local_addr().unwrap()).unwrap();
        let observations = Arc::new(Mutex::new(Vec::new()));
        let observed = observations.clone();
        let client = MullvadClient::new(local_proxy)
            .unwrap()
            .with_observer(Arc::new(move |value| observed.lock().unwrap().push(value)))
            .with_deadline(Instant::now() - Duration::from_secs(1));

        let result = client.authenticate(AccountNumber::new("0000000000000000".into()).unwrap());

        assert!(matches!(result, Err(Error::DeadlineExceeded)));
        let observations = observations.lock().unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].endpoint, "authentication");
        assert_eq!(observations[0].phase, "deadline");
        assert_eq!(observations[0].outcome, "failed");
        assert_eq!(observations[0].error_code, Some("api_deadline_exceeded"));
        drop(observations);
        match listener.accept() {
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock),
            Ok((_stream, _address)) => panic!("expired request opened the proxy socket"),
        }
    }

    #[test]
    fn endpoint_labels_are_closed_and_never_include_dynamic_device_ids() {
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let cases = [
            (Method::Get, "accounts/v1/devices", "device_list"),
            (Method::Post, "accounts/v1/devices", "device_create"),
            (
                Method::Delete,
                "accounts/v1/devices/01234567-89ab-cdef-0123-456789abcdef",
                "device_remove",
            ),
            (
                Method::Put,
                "accounts/v1/devices/01234567-89ab-cdef-0123-456789abcdef/pubkey",
                "account_operation",
            ),
            (
                Method::Get,
                "accounts/v1/private-account-sentinel",
                "account_operation",
            ),
        ];

        for (method, path, expected) in cases {
            let label = endpoint_label(method, path);
            assert_eq!(label, expected);
            assert!(!label.contains(id));
            assert!(matches!(
                label,
                "device_list" | "device_create" | "device_remove" | "account_operation"
            ));
        }
    }

    #[test]
    fn only_typed_ureq_failures_receive_specific_phases() {
        let explicit = [
            (ureq::Error::Timeout(ureq::Timeout::Resolve), "dns"),
            (ureq::Error::HostNotFound, "dns"),
            (
                ureq::Error::Timeout(ureq::Timeout::Connect),
                "connection_setup",
            ),
            (
                ureq::Error::ConnectProxyFailed("synthetic detail".into()),
                "proxy_connect",
            ),
            (ureq::Error::Tls("synthetic detail"), "tls"),
            (
                ureq::Error::Timeout(ureq::Timeout::RecvResponse),
                "response_headers",
            ),
        ];
        for (error, expected) in explicit {
            assert_eq!(transport_phase(&error), expected);
        }

        for error in [
            ureq::Error::Timeout(ureq::Timeout::Global),
            ureq::Error::Timeout(ureq::Timeout::SendRequest),
            ureq::Error::Timeout(ureq::Timeout::SendBody),
            ureq::Error::Timeout(ureq::Timeout::RecvBody),
            ureq::Error::Io(std::io::Error::other("synthetic detail")),
        ] {
            assert_eq!(transport_phase(&error), "transport_unknown");
        }
    }
}
