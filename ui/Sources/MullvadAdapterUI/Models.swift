import Foundation

enum TransportPreference: String, CaseIterable, Identifiable, Hashable {
    case auto
    case ss
    case ipv6
    case ipv4

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .auto: return "自动（优先近期可用链路）"
        case .ss: return "SS 混淆"
        case .ipv6: return "IPv6 直连"
        case .ipv4: return "IPv4 直连"
        }
    }

    var shortDisplayName: String {
        switch self {
        case .auto: return "自动"
        case .ss: return "SS"
        case .ipv6: return "IPv6"
        case .ipv4: return "IPv4"
        }
    }

    static func displayName(for rawValue: String?) -> String {
        guard let rawValue, !rawValue.isEmpty else { return "—" }
        return TransportPreference(rawValue: rawValue.lowercased())?.displayName ?? rawValue
    }

    static func shortDisplayName(for rawValue: String?) -> String {
        guard let rawValue, !rawValue.isEmpty else { return "—" }
        return TransportPreference(rawValue: rawValue.lowercased())?.shortDisplayName ?? rawValue
    }
}

struct AdapterStatus: Decodable {
    let status: String?
    let buildID: String?
    let operation: AdapterOperation?
    let diagnosis: NetworkDiagnosis?
    let generation: Int?
    let activeSlot: String?
    let activeRelay: String?
    let activeTransport: String?
    let activeTransportMode: String?
    let transportPreference: String?
    let relayLiveness: String?
    let serviceReadiness: String?
    let controlPlane: ControlPlaneStatus?
    let metadata: MetadataStatus?
    let health: HealthStatus?
    let localNetwork: LocalNetworkStatus?
    let dnsBreaker: DNSBreakerStatus?
    let innerDNSBreaker: DNSBreakerStatus?
    let commonInnerDNSBreaker: DNSBreakerStatus?
    let front: FrontStatus?
    let api: APIStatus?
    let persistence: PersistenceStatus?
    let routingPolicy: RoutingPolicyStatus?
    let workers: [String: WorkerStatus]?
    let dns: DNSLayers?
    let lastCanary: CanaryResult?
    let lastError: String?
    let updatedAt: String?
    let switchedAt: String?
    let switchReason: String?

    enum CodingKeys: String, CodingKey {
        case status
        case buildID = "build_id"
        case operation, diagnosis
        case generation
        case activeSlot = "active_slot"
        case activeRelay = "active_relay"
        case activeTransport = "active_transport"
        case activeTransportMode = "active_transport_mode"
        case transportPreference = "transport_preference"
        case relayLiveness = "relay_liveness"
        case serviceReadiness = "service_readiness"
        case controlPlane = "control_plane"
        case metadata
        case health
        case localNetwork = "local_network"
        case dnsBreaker = "dns_breaker"
        case innerDNSBreaker = "inner_dns_breaker"
        case commonInnerDNSBreaker = "common_inner_dns_breaker"
        case front
        case api
        case persistence
        case routingPolicy = "routing_policy"
        case workers
        case dns
        case lastCanary = "last_canary"
        case lastError = "last_error"
        case updatedAt = "updated_at"
        case switchedAt = "switched_at"
        case switchReason = "switch_reason"
    }

    var effectiveMetadata: MetadataStatus? {
        metadata ?? controlPlane?.effectiveMetadata
    }

    var effectiveDNSBreaker: DNSBreakerStatus? {
        dns?.innerBreaker
            ?? commonInnerDNSBreaker
            ?? innerDNSBreaker
            ?? dnsBreaker
            ?? dns?.commonInnerBreaker
            ?? dns?.breaker
    }

    var activeWorker: WorkerEntry? {
        if let activeSlot, let worker = workers?[activeSlot] {
            return WorkerEntry(slot: activeSlot, worker: worker)
        }
        return workers?.first(where: { $0.value.state == "active" }).map {
            WorkerEntry(slot: $0.key, worker: $0.value)
        }
    }

    var drainingWorker: WorkerEntry? {
        workers?.first(where: { $0.value.state == "draining" }).map {
            WorkerEntry(slot: $0.key, worker: $0.value)
        }
    }

    var activeConnections: Int {
        activeWorker?.worker.frontConnectionCount ?? 0
    }

    var drainingConnections: Int {
        drainingWorker?.worker.frontConnectionCount ?? 0
    }

    var totalVisibleConnections: Int {
        activeConnections + drainingConnections
    }
}

struct LocalNetworkStatus: Decodable {
    let status: String?
    let paused: Bool?
    let recoveryPending: Bool?
    let recoveryStage: String?
    let detail: String?
    let checkedAt: String?
    let offlineAt: String?
    let linkRestoredAt: String?
    let outcome: String?

    enum CodingKeys: String, CodingKey {
        case status, paused, detail, outcome
        case recoveryPending = "recovery_pending"
        case recoveryStage = "recovery_stage"
        case checkedAt = "checked_at"
        case offlineAt = "offline_at"
        case linkRestoredAt = "link_restored_at"
    }

    var message: String? {
        if paused == true {
            return recoveryStage == "settling" ? "本机网络已连接，等待链路稳定；暂不切换节点" : "本机网络已断开，等待恢复；节点切换已暂停"
        }
        guard recoveryPending == true else { return nil }
        switch recoveryStage {
        case "rebuild-original": return "本机网络已恢复，正在重建原节点的原路径"
        case "same-city-fallback": return "原路径重建未通过，正在验证同城备用节点"
        case "local-repair": return "本机网络已恢复，等待本地组件或连接槽位恢复；暂不换节点"
        default: return "本机网络已恢复，正在验证原通道"
        }
    }
}

struct WorkerEntry {
    let slot: String
    let worker: WorkerStatus
}

struct ControlPlaneStatus: Decodable {
    let metadata: MetadataStatus?
    let live: Bool?
    let cache: Bool?
    let source: String?
    let age: Double?
    let ageSeconds: Double?
    let error: String?
    let fetchedAt: String?

    enum CodingKeys: String, CodingKey {
        case metadata
        case live
        case cache
        case source
        case age
        case ageSeconds = "age_seconds"
        case error
        case fetchedAt = "fetched_at"
    }

    var effectiveMetadata: MetadataStatus? {
        if let metadata { return metadata }
        guard live != nil || cache != nil || source != nil || age != nil || ageSeconds != nil || error != nil || fetchedAt != nil else {
            return nil
        }
        return MetadataStatus(live: live, cache: cache, source: source, age: age, ageSeconds: ageSeconds, error: error, fetchedAt: fetchedAt, validationWarnings: nil)
    }
}

struct MetadataStatus: Decodable {
    let live: Bool?
    let cache: Bool?
    let source: String?
    let age: Double?
    let ageSeconds: Double?
    let error: String?
    let fetchedAt: String?
    let validationWarnings: [String]?

    enum CodingKeys: String, CodingKey {
        case live
        case cache
        case source
        case age
        case ageSeconds = "age_seconds"
        case error
        case fetchedAt = "fetched_at"
        case validationWarnings = "validation_warnings"
    }

    init(live: Bool?, cache: Bool?, source: String?, age: Double?, ageSeconds: Double?, error: String?, fetchedAt: String?, validationWarnings: [String]? = nil) {
        self.live = live
        self.cache = cache
        self.source = source
        self.age = age
        self.ageSeconds = ageSeconds
        self.error = error
        self.fetchedAt = fetchedAt
        self.validationWarnings = validationWarnings
    }

    var effectiveAge: Double? { ageSeconds ?? age }
}

struct HealthStatus: Decodable {
    let intervalSeconds: Int?
    let failThreshold: Int?
    let consecutiveWGFailures: Int?
    let consecutiveDNSFailures: Int?
    let lastCheckAt: String?
    let lastRecoveryAt: String?

    enum CodingKeys: String, CodingKey {
        case intervalSeconds = "interval_seconds"
        case failThreshold = "fail_threshold"
        case consecutiveWGFailures = "consecutive_wg_failures"
        case consecutiveDNSFailures = "consecutive_dns_failures"
        case lastCheckAt = "last_check_at"
        case lastRecoveryAt = "last_recovery_at"
    }
}

struct DNSBreakerStatus: Decodable {
    let status: String?
    let state: String?
    let tripped: Bool?
    let active: Bool?
    let reason: String?
    let detail: String?
    let failures: Int?
    let observations: Int?
    let sampleCount: Int?
    let threshold: Int?
    let observedRelays: [String]?
    let until: String?
    let since: String?
    let lastTripAt: String?

    enum CodingKeys: String, CodingKey {
        case status
        case state
        case tripped
        case active
        case reason
        case detail
        case failures
        case observations
        case sampleCount = "sample_count"
        case threshold
        case observedRelays = "observed_relays"
        case until
        case since
        case lastTripAt = "last_trip_at"
    }

    var displayState: String {
        if let state, !state.isEmpty { return state }
        if let status, !status.isEmpty { return status }
        if tripped == true || active == true { return "tripped" }
        if tripped == false || active == false { return "clear" }
        return "unknown"
    }
}

struct FrontStatus: Decodable {
    let mixedPort: Int?
    let controllerPort: Int?
    let ready: Bool?
    let pid: Int?
    let restartedAt: String?
    let probeFailures: Int?
    let dataPath: FrontDataPathStatus?
    let controllerDegraded: Bool?

    enum CodingKeys: String, CodingKey {
        case mixedPort = "mixed_port"
        case controllerPort = "controller_port"
        case ready
        case pid
        case restartedAt = "restarted_at"
        case probeFailures = "probe_failures"
        case dataPath = "data_path"
        case controllerDegraded = "controller_degraded"
    }
}

struct FrontDataPathStatus: Decodable {
    let status: String?
    let detail: String?
    let checkedAt: String?

    enum CodingKeys: String, CodingKey {
        case status
        case detail
        case checkedAt = "checked_at"
    }
}

struct APIStatus: Decodable {
    let host: String?
    let port: Int?
}

struct PersistenceStatus: Decodable {
    let status: String?
    let lastError: String?
    let lastErrorAt: String?

    enum CodingKeys: String, CodingKey {
        case status
        case lastError = "last_error"
        case lastErrorAt = "last_error_at"
    }
}

struct RoutingPolicyStatus: Decodable {
    let owner: String?
    let ingressOwner: String?
    let ingressTarget: String?
    let newConnections: String?
    let establishedConnections: String?
    let failedPathConnections: String?
    let repeatSwitch: String?
    let maxDrainingWorkers: Int?
    let lastEvent: String?
    let lastEventAt: String?
    let lastEventRelay: String?
    let lastEventReason: String?
    let lastEventDetail: String?
    let lastPreemptedConnections: Int?
    let pendingAction: PendingRoutingAction?
    let quarantinedRelays: [QuarantinedRelayStatus]?

    enum CodingKeys: String, CodingKey {
        case owner
        case ingressOwner = "ingress_owner"
        case ingressTarget = "ingress_target"
        case newConnections = "new_connections"
        case establishedConnections = "established_connections"
        case failedPathConnections = "failed_path_connections"
        case repeatSwitch = "repeat_switch"
        case maxDrainingWorkers = "max_draining_workers"
        case lastEvent = "last_event"
        case lastEventAt = "last_event_at"
        case lastEventRelay = "last_event_relay"
        case lastEventReason = "last_event_reason"
        case lastEventDetail = "last_event_detail"
        case lastPreemptedConnections = "last_preempted_connections"
        case pendingAction = "pending_action"
        case quarantinedRelays = "quarantined_relays"
    }
}

struct PendingRoutingAction: Decodable {
    let relay: String?
    let reason: String?
    let transportPreference: String?
    let acceptedAt: String?

    enum CodingKeys: String, CodingKey {
        case relay
        case reason
        case transportPreference = "transport_preference"
        case acceptedAt = "accepted_at"
    }
}

struct QuarantinedRelayStatus: Decodable, Identifiable {
    let relay: String
    let reason: String?
    let remainingSeconds: Int?

    var id: String { relay }

    enum CodingKeys: String, CodingKey {
        case relay
        case reason
        case remainingSeconds = "remaining_seconds"
    }
}

struct WorkerStatus: Decodable {
    let relay: String?
    let transport: String?
    let endpoint: String?
    let endpointPort: Int?
    let endpointKind: String?
    let interface: String?
    let mixedPort: Int?
    let startedAt: String?
    let frontConnectionCount: Int?
    let state: String?
    let drainStartedAt: String?
    let drainDeadlineAt: String?
    let drainTimeoutSeconds: Int?
    let drainRemainingSeconds: Int?
    let stoppedAt: String?

    enum CodingKeys: String, CodingKey {
        case relay
        case transport
        case endpoint
        case endpointPort = "endpoint_port"
        case endpointKind = "endpoint_kind"
        case interface
        case mixedPort = "mixed_port"
        case startedAt = "started_at"
        case frontConnectionCount = "front_connection_count"
        case state
        case drainStartedAt = "drain_started_at"
        case drainDeadlineAt = "drain_deadline_at"
        case drainTimeoutSeconds = "drain_timeout_seconds"
        case drainRemainingSeconds = "drain_remaining_seconds"
        case stoppedAt = "stopped_at"
    }

    var drainStartedDate: Date? {
        guard let drainStartedAt else { return nil }
        return ISO8601DateFormatter().date(from: drainStartedAt)
    }

    var drainDeadlineDate: Date? {
        guard let drainDeadlineAt else { return nil }
        return ISO8601DateFormatter().date(from: drainDeadlineAt)
    }

    func remainingDrainSeconds(at date: Date = Date()) -> Int? {
        if let deadline = drainDeadlineDate {
            return max(Int(ceil(deadline.timeIntervalSince(date))), 0)
        }
        return drainRemainingSeconds
    }
}

struct DNSLayers: Decodable {
    let bootstrap: DNSLayerStatus?
    let inner: DNSLayerStatus?
    let clashGlobal: DNSLayerStatus?
    let breaker: DNSBreakerStatus?
    let innerBreaker: DNSBreakerStatus?
    let commonInnerBreaker: DNSBreakerStatus?

    enum CodingKeys: String, CodingKey {
        case bootstrap
        case inner
        case clashGlobal = "clash_global"
        case breaker
        case innerBreaker = "inner_breaker"
        case commonInnerBreaker = "common_inner_breaker"
    }
}

struct DNSLayerStatus: Decodable {
    let status: String?
    let detail: String?
    let at: String?
    let delayMs: Int?
    let resolver: String?
    let qname: String?
    let answers: Int?

    enum CodingKeys: String, CodingKey {
        case status
        case detail
        case at
        case delayMs = "delay_ms"
        case resolver
        case qname
        case answers
    }
}

struct CanaryResult: Decodable {
    let at: String?
    let pingData: CanaryCheck?
    let controllerProbe: CanaryCheck?
    let ipData: CanaryCheck?
    let innerDNS: CanaryCheck?
    let httpsData: CanaryCheck?

    enum CodingKeys: String, CodingKey {
        case at
        case pingData = "ping_data"
        case controllerProbe = "controller_probe"
        case ipData = "ip_data"
        case innerDNS = "inner_dns"
        case httpsData = "https_data"
    }
}

struct CanaryCheck: Decodable {
    let status: String?
    let delayMs: Int?
    let target: String?
    let detail: String?
    let httpCode: Int?
    let dependency: String?
    let resolver: String?
    let qname: String?
    let answers: Int?

    enum CodingKeys: String, CodingKey {
        case status
        case delayMs = "delay_ms"
        case target
        case detail
        case httpCode = "http_code"
        case dependency
        case resolver
        case qname
        case answers
    }
}

struct AdapterMetrics: Decodable {
    let startedAt: String?
    let metadataRefreshes: Int?
    let metadataRefreshFailures: Int?
    let workerStarts: Int?
    let workerStartFailures: Int?
    let switches: Int?
    let failedSwitches: Int?
    let drainCompletions: Int?
    let drainForced: Int?
    let sameRelayReconnects: Int?
    let frontConnectionsTotal: Int?
    let activeConnections: Int?
    let drainingConnections: Int?
    let healthChecks: Int?
    let healthWGFailures: Int?
    let healthDNSFailures: Int?
    let autoRecoveryAttempts: Int?
    let autoRecoveryFailures: Int?
    let innerDNSBreakerTrips: Int?
    let innerDNSBreakerSuppressed: Int?
    let frontRestarts: Int?
    let frontSelectorRepairs: Int?
    let frontDataProbeFailures: Int?
    let workerCrashes: Int?
    let workerCrashRecoveries: Int?
    let drainPreemptions: Int?
    let failedPathRetirements: Int?
    let persistenceFailures: Int?

    enum CodingKeys: String, CodingKey {
        case startedAt = "started_at"
        case metadataRefreshes = "metadata_refreshes"
        case metadataRefreshFailures = "metadata_refresh_failures"
        case workerStarts = "worker_starts"
        case workerStartFailures = "worker_start_failures"
        case switches
        case failedSwitches = "failed_switches"
        case drainCompletions = "drain_completions"
        case drainForced = "drain_forced"
        case sameRelayReconnects = "same_relay_reconnects"
        case frontConnectionsTotal = "front_connections_total"
        case activeConnections = "active_connections"
        case drainingConnections = "draining_connections"
        case healthChecks = "health_checks"
        case healthWGFailures = "health_wg_failures"
        case healthDNSFailures = "health_dns_failures"
        case autoRecoveryAttempts = "auto_recovery_attempts"
        case autoRecoveryFailures = "auto_recovery_failures"
        case innerDNSBreakerTrips = "inner_dns_breaker_trips"
        case innerDNSBreakerSuppressed = "inner_dns_breaker_suppressed"
        case frontRestarts = "front_restarts"
        case frontSelectorRepairs = "front_selector_repairs"
        case frontDataProbeFailures = "front_data_probe_failures"
        case workerCrashes = "worker_crashes"
        case workerCrashRecoveries = "worker_crash_recoveries"
        case drainPreemptions = "drain_preemptions"
        case failedPathRetirements = "failed_path_retirements"
        case persistenceFailures = "persistence_failures"
    }
}


struct RelayPingTarget: Decodable, Hashable, Sendable {
    let target: String?
    let kind: String?
}

struct RelayPingTargets: Decodable, Hashable, Sendable {
    let ss: RelayPingTarget?
    let ipv4: RelayPingTarget?
    let ipv6: RelayPingTarget?

    func target(for transport: String) -> RelayPingTarget? {
        switch transport.lowercased() {
        case "ipv6": return ipv6
        case "ipv4": return ipv4
        case "ss": return ss ?? ipv4
        default: return ss ?? ipv6 ?? ipv4
        }
    }
}

struct RelayInfo: Decodable, Identifiable, Hashable {
    let hostname: String
    let location: String?
    let provider: String?
    let owned: Bool?
    let extraSSIPv4: Int?
    let country: String?
    let city: String?
    let countryCode: String?
    let cityCode: String?
    let transports: [String]?
    let quickPing: RelayPingTargets?

    enum CodingKeys: String, CodingKey {
        case hostname
        case location
        case provider
        case owned
        case extraSSIPv4 = "extra_ss_ipv4"
        case country
        case city
        case countryCode = "country_code"
        case cityCode = "city_code"
        case transports
        case quickPing = "quick_ping"
    }

    var id: String { hostname }

    var effectiveCountryCode: String? {
        if let countryCode, !countryCode.isEmpty {
            return countryCode.uppercased()
        }
        if let prefix = location?.split(separator: "-", maxSplits: 1).first, !prefix.isEmpty {
            return String(prefix).uppercased()
        }
        if let prefix = hostname.split(separator: "-", maxSplits: 1).first, !prefix.isEmpty {
            return String(prefix).uppercased()
        }
        return nil
    }

    var countryDisplayName: String {
        if let code = effectiveCountryCode,
           let localized = Locale(identifier: "zh_CN").localizedString(forRegionCode: code),
           !localized.isEmpty {
            return localized
        }
        if let country, !country.isEmpty { return country }
        return effectiveCountryCode ?? "未知国家或地区"
    }

    var cityDisplayName: String {
        if let city, !city.isEmpty { return city }
        if let cityCode, !cityCode.isEmpty { return cityCode.uppercased() }
        if let location,
           let suffix = location.split(separator: "-", maxSplits: 1).dropFirst().first,
           !suffix.isEmpty {
            return String(suffix).uppercased()
        }
        let parts = hostname.split(separator: "-")
        if parts.count > 1 { return String(parts[1]).uppercased() }
        return "未知城市"
    }

    var ownershipDisplayName: String {
        switch owned {
        case .some(true): return "自有"
        case .some(false): return "租用"
        case .none: return "未知"
        }
    }

    var normalizedTransports: [String] {
        let values = transports ?? []
        let knownOrder = ["ss", "ipv6", "ipv4"]
        let normalized = Set(values.map { $0.lowercased() })
        let known = knownOrder.filter { normalized.contains($0) }
        let unknown = normalized.subtracting(knownOrder).sorted()
        return known + unknown
    }

    var countryKey: String {
        effectiveCountryCode ?? countryDisplayName
    }

    var cityKey: String {
        let cityIdentity = cityCode?.isEmpty == false ? cityCode!.lowercased() : cityDisplayName
        return countryKey + "|" + cityIdentity
    }

    var searchableText: String {
        [
            hostname,
            provider ?? "",
            countryDisplayName,
            effectiveCountryCode ?? "",
            cityDisplayName,
            cityCode ?? "",
            normalizedTransports.joined(separator: " ")
        ]
        .joined(separator: " ")
        .lowercased()
    }

    func matchesSearch(_ query: String) -> Bool {
        let terms = query
            .lowercased()
            .split(whereSeparator: { $0.isWhitespace })
        guard !terms.isEmpty else { return true }
        return terms.allSatisfy { searchableText.contains($0) }
    }
}

enum RelaySpeedPhase: String {
    case idle
    case queued
    case testing
    case success
    case failed
    case unsupported
}

struct RelaySpeedTestResult: Decodable {
    let relay: String
    let testedAt: String?
    let source: String?
    let durationMs: Int?
    let transportMode: String?
    let relayLiveness: String?
    let serviceReadiness: String?
    let pingData: CanaryCheck?
    let controllerProbe: CanaryCheck?
    let ipData: CanaryCheck?
    let innerDNS: CanaryCheck?
    let httpsData: CanaryCheck?

    enum CodingKeys: String, CodingKey {
        case relay
        case testedAt = "tested_at"
        case source
        case durationMs = "duration_ms"
        case transportMode = "transport_mode"
        case relayLiveness = "relay_liveness"
        case serviceReadiness = "service_readiness"
        case pingData = "ping_data"
        case controllerProbe = "controller_probe"
        case ipData = "ip_data"
        case innerDNS = "inner_dns"
        case httpsData = "https_data"
    }

    var primaryDelayMs: Int? {
        pingData?.delayMs
    }

    var isUsable: Bool {
        relayLiveness == "pass" && serviceReadiness == "ready"
    }
}

struct RelaySpeedTestResponse: Decodable {
    let ok: Bool?
    let result: RelaySpeedTestResult?
    let requestedTransport: String?

    enum CodingKeys: String, CodingKey {
        case ok
        case result
        case requestedTransport = "requested_transport"
    }
}

struct RelayHistorySummary: Decodable, Identifiable {
    let relay: String
    let transportMode: String
    let samples: Int
    let relayPassSamples: Int
    let readySamples: Int
    let failedSamples: Int
    let consecutiveFailures: Int
    let latencySamples: Int
    let latencyEwmaMs: Double?
    let bestDelayMs: Int?
    let worstDelayMs: Int?
    let lastDelayMs: Int?
    let firstTestedAt: String?
    let lastTestedAt: String?
    let lastSuccessAt: String?
    let lastFailureAt: String?
    let sourceCounts: [String: Int]?
    let readinessRate: Double?

    enum CodingKeys: String, CodingKey {
        case relay
        case transportMode = "transport_mode"
        case samples
        case relayPassSamples = "relay_pass_samples"
        case readySamples = "ready_samples"
        case failedSamples = "failed_samples"
        case consecutiveFailures = "consecutive_failures"
        case latencySamples = "latency_samples"
        case latencyEwmaMs = "latency_ewma_ms"
        case bestDelayMs = "best_delay_ms"
        case worstDelayMs = "worst_delay_ms"
        case lastDelayMs = "last_delay_ms"
        case firstTestedAt = "first_tested_at"
        case lastTestedAt = "last_tested_at"
        case lastSuccessAt = "last_success_at"
        case lastFailureAt = "last_failure_at"
        case sourceCounts = "source_counts"
        case readinessRate = "readiness_rate"
    }

    var id: String { "\(relay)|\(transportMode)" }

    var effectiveReadinessRate: Double {
        if let readinessRate { return readinessRate }
        guard samples > 0 else { return 0 }
        return Double(readySamples) / Double(samples)
    }

    /// Wilson lower bound keeps a one-off 1/1 result from outranking a node
    /// that has stayed healthy across many observations.
    var stabilityConfidenceScore: Double {
        guard samples > 0 else { return -1 }
        let n = Double(samples)
        let p = Double(readySamples) / n
        let z = 1.96
        let z2 = z * z
        let numerator = p + z2 / (2 * n) - z * sqrt((p * (1 - p) + z2 / (4 * n)) / n)
        let denominator = 1 + z2 / n
        let failurePenalty = min(Double(consecutiveFailures), 3) * 0.04
        return numerator / denominator - failurePenalty
    }
}

struct RelaySpeedKey: Hashable {
    let relay: String
    let transport: TransportPreference
}

struct BatchSpeedProgress {
    let label: String
    let transport: TransportPreference
    let total: Int
    let completed: Int
    let currentHostname: String?
    let intervalSeconds: Double

    var isSlow: Bool { intervalSeconds >= 3 }

    var intervalDescription: String {
        if intervalSeconds <= 0 { return "无额外等待" }
        if intervalSeconds == floor(intervalSeconds) {
            return "额外等待 \(Int(intervalSeconds)) 秒"
        }
        return String(format: "额外等待 %.1f 秒", intervalSeconds)
    }
}

struct RelaySpeedState {
    let phase: RelaySpeedPhase
    let result: RelaySpeedTestResult?
    let updatedAt: Date?
    let message: String?

    static let idle = RelaySpeedState(phase: .idle, result: nil, updatedAt: nil, message: nil)
    static let queued = RelaySpeedState(phase: .queued, result: nil, updatedAt: nil, message: nil)
    static let testing = RelaySpeedState(phase: .testing, result: nil, updatedAt: nil, message: nil)

    static func success(_ result: RelaySpeedTestResult, updatedAt: Date = Date()) -> RelaySpeedState {
        RelaySpeedState(phase: .success, result: result, updatedAt: updatedAt, message: nil)
    }

    static func failed(_ message: String, updatedAt: Date = Date()) -> RelaySpeedState {
        RelaySpeedState(phase: .failed, result: nil, updatedAt: updatedAt, message: message)
    }

    static func unsupported(_ message: String) -> RelaySpeedState {
        RelaySpeedState(phase: .unsupported, result: nil, updatedAt: Date(), message: message)
    }
}
