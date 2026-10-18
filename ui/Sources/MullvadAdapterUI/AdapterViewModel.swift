import Combine
import Foundation
import AppKit
@preconcurrency import UserNotifications

@MainActor
final class AdapterViewModel: ObservableObject {
    @Published var protection: ProtectionSnapshot?
    @Published var protectionError: String?
    @Published var status: AdapterStatus?
    @Published var metrics: AdapterMetrics?
    @Published var cityWorkspace: CityWorkspace?
    @Published var cityErrorMessage: String?
    @Published var selectingCityID: String?
    @Published var isSavingCities = false
    @Published var relays: [RelayInfo] = []
    @Published var speedStates: [RelaySpeedKey: RelaySpeedState] = [:]
    @Published var relayHistory: [RelaySpeedKey: RelayHistorySummary] = [:]
    @Published var recentRelayHostnames: [String]
    @Published var pinnedCountryKeys: Set<String>
    @Published var pinnedCityKeys: Set<String>
    @Published var pinnedRelayHostnames: Set<String>

    @Published var isLoading = false
    @Published var isLoadingRelays = false
    @Published var isActionRunning = false
    @Published var selectingRelayHostname: String?
    @Published var actionMessage: String?
    @Published var errorMessage: String?
    @Published var relayErrorMessage: String?
    @Published var speedMessage: String?
    @Published var quickPingResults: [String: QuickPingResult] = [:]
    @Published var lastQuickPingBatchID: String?
    @Published var lastQuickPingBatchLabel: String?
    @Published var isQuickTesting = false
    private var quickCompleted = 0
    @Published var speedTestingRelay: String?
    @Published var isSequentialSpeedTesting = false
    @Published var batchSpeedProgress: BatchSpeedProgress?
    @Published var selectedTransport: TransportPreference = .auto
    @Published var transportSelectionDirty = false
    @Published var notificationsEnabled: Bool
    @Published private(set) var notificationPermissionText: String?
    @Published var lastUpdated: Date?
    @Published var connectionError: String?
    @Published var isExportingReport = false
    @Published var reportMessage: String?
    @Published var isCancellingSpeedTest = false
    @Published private var dismissedOperationID: String?

    private let client: AdapterClient
    var accountClient: AdapterClient { client }
    let isPreview: Bool
    private let defaults: UserDefaults
    private let recentRelaysKey = "MullvadAdapterUI.recentRelayHostnames"
    private let pinnedCountriesKey = "MullvadAdapterUI.pinnedCountryKeys"
    private let pinnedCitiesKey = "MullvadAdapterUI.pinnedCityKeys"
    private let pinnedRelaysKey = "MullvadAdapterUI.pinnedRelayHostnames"
    private let notificationsEnabledKey = "MullvadAdapterUI.notificationsEnabled"
    private var quickSpeedTask: Task<Void, Never>?
    private var batchSpeedTask: Task<Void, Never>?
    private var singleSpeedTask: Task<Void, Never>?
    private var statusPollingTask: Task<Void, Never>?
    private var notificationBaselineEstablished = false
    private var lastNotifiedDegradedState: String?

    init(client: AdapterClient = AdapterClient(), defaults: UserDefaults = .standard, preview: Bool = false) {
        self.client = preview ? CityPreview.client() : client
        self.isPreview = preview
        self.defaults = defaults
        if let data = defaults.data(forKey: "MullvadAdapterUI.quickPingResults"),
           let saved = try? JSONDecoder().decode([String: QuickPingResult].self, from: data) {
            quickPingResults = saved
        }
        lastQuickPingBatchID = defaults.string(forKey: "MullvadAdapterUI.lastQuickPingBatchID")
        lastQuickPingBatchLabel = defaults.string(forKey: "MullvadAdapterUI.lastQuickPingBatchLabel")
        self.recentRelayHostnames = defaults.stringArray(forKey: recentRelaysKey) ?? []
        self.pinnedCountryKeys = Set(defaults.stringArray(forKey: pinnedCountriesKey) ?? [])
        self.pinnedCityKeys = Set(defaults.stringArray(forKey: pinnedCitiesKey) ?? [])
        self.pinnedRelayHostnames = Set(defaults.stringArray(forKey: pinnedRelaysKey) ?? [])
        if defaults.object(forKey: notificationsEnabledKey) == nil {
            self.notificationsEnabled = true
        } else {
            self.notificationsEnabled = defaults.bool(forKey: notificationsEnabledKey)
        }
        if preview { loadCityPreview() }
    }

    var isBusy: Bool { isActionRunning || status?.operation?.isRunning == true }

    var displayedStatus: String? {
        if connectionError != nil { return "unreachable" }
        if status?.front?.dataPath?.status == "fail", status?.status == "ready" { return "front_fail" }
        return status?.status ?? status?.serviceReadiness
    }

    var operationMessage: String? {
        status?.operation?.isRunning == true ? status?.operation?.message : actionMessage
    }

    var isSpeedTesting: Bool {
        isQuickTesting || singleSpeedTask != nil || speedTestingRelay != nil || isSequentialSpeedTesting
    }

    var canCancelSpeedTest: Bool {
        isSpeedTesting || (status?.operation?.kind == "speedtest" && status?.operation?.isRunning == true)
    }

    var feedbackSummary: String {
        if let connectionError { return connectionError }
        if let networkMessage = status?.localNetwork?.message { return networkMessage }
        if isCancellingSpeedTest { return "正在停止测速…" }
        if (isSequentialSpeedTesting || isQuickTesting), let speedMessage { return speedMessage }
        if isSpeedTesting { return "正在测速 \(speedTestingRelay ?? "节点")…" }
        if isBusy { return operationMessage ?? "正在处理连接…" }
        if let error = errorMessage ?? relayErrorMessage { return error }
        if let reportMessage { return reportMessage }
        if let speedMessage { return speedMessage }
        if let operation = status?.operation, operation.id != dismissedOperationID {
            return operation.message ?? "操作已结束"
        }
        return "就绪 · 操作进度会显示在这里"
    }

    var feedbackDetails: [String] {
        var messages = [connectionError, errorMessage, relayErrorMessage, operationMessage, speedMessage, reportMessage].compactMap { $0 }
        if let network = status?.localNetwork {
            messages.insert("本机链路：\(network.message ?? network.detail ?? network.status ?? "未知")\n最近检查：\(network.checkedAt ?? "未记录")\n断开：\(network.offlineAt ?? "未记录") · 恢复：\(network.linkRestoredAt ?? "未记录")\n恢复阶段：\(network.recoveryStage ?? "无") · 结果：\(network.outcome ?? "待验证")", at: 0)
        }
        if let operation = status?.operation, operation.id != dismissedOperationID {
            messages.append("最近操作：\(operation.message ?? operation.state)\n\(operation.finishedAt ?? operation.acceptedAt ?? "")")
            if let error = operation.error { messages.append(error) }
        }
        if !quickPingResults.isEmpty {
            let batch = quickPingResults.filter { $0.value.batchID == lastQuickPingBatchID }
            let rows = (batch.isEmpty ? quickPingResults : batch).sorted { $0.value.testedAt > $1.value.testedAt }
            messages.append("快速 Ping 逐节点明细 · \(lastQuickPingBatchLabel ?? "历史结果") · \(rows.count) 条")
            for (key, result) in rows {
                let hostname = key.split(separator: "|", maxSplits: 1).first.map(String.init) ?? key
                let outcome = result.milliseconds.map { "ICMP 回复 \(Int($0.rounded())) ms" }
                    ?? "没有收到 ICMP 回复；这不代表节点连接不可用"
                let interface = result.interface.map { "绑定接口：\($0)" } ?? "旧版快测：未记录绑定接口"
                let targetKind = result.targetKind.map { "目标类型：\($0)" } ?? "目标类型未记录"
                let elapsed = result.durationMilliseconds.map { String(format: "总耗时：%.0f ms", $0) } ?? "总耗时未记录"
                let exit = result.exitCode.map { "Ping 退出码：\($0)" } ?? "Ping 退出码未记录"
                messages.append("\(hostname) · 目标 \(result.target)\n\(outcome) · \(targetKind) · \(interface) · \(elapsed) · \(exit)\n时间：\(result.testedAt.formatted(date: .numeric, time: .standard))\n\(result.detail)")
            }
        }
        return messages.isEmpty ? ["暂无操作提示"] : messages
    }

    func clearFeedback() {
        errorMessage = nil
        relayErrorMessage = nil
        if !isSpeedTesting { speedMessage = nil }
        if !isExportingReport { reportMessage = nil }
        if status?.operation?.isRunning != true { dismissedOperationID = status?.operation?.id }
    }

    var transportSelectionNeedsApply: Bool {
        guard status?.activeRelay != nil else { return false }
        let currentPreference = TransportPreference(rawValue: status?.transportPreference?.lowercased() ?? "") ?? .auto
        return selectedTransport != currentPreference
    }

    func startStatusPolling() {
        guard !isPreview, statusPollingTask == nil else { return }
        prepareNotificationsIfNeeded()
        statusPollingTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.refreshStatusBestEffort()
                do {
                    try await Task.sleep(nanoseconds: (self.isBusy || self.isSpeedTesting) ? 1_000_000_000 : 5_000_000_000)
                } catch {
                    return
                }
            }
        }
    }

    func setNotificationsEnabled(_ enabled: Bool) {
        notificationsEnabled = enabled
        defaults.set(enabled, forKey: notificationsEnabledKey)
        if enabled {
            prepareNotificationsIfNeeded()
        } else {
            notificationPermissionText = "已关闭"
        }
    }

    func refresh() {
        Task { await loadSnapshot() }
    }

    /// Writes a bounded, redacted local report and puts only its absolute path
    /// on the clipboard so it can be handed to a local Agent without sending
    /// the contents anywhere.
    func copyDiagnosticReport() {
        guard !isPreview else { reportMessage = "隔离预览不读取本机日志或写入剪贴板"; return }
        guard !isExportingReport else { return }
        isExportingReport = true
        reportMessage = "正在生成诊断资料…"
        Task { [weak self] in
            guard let self else { return }
            defer { isExportingReport = false }

            let reportClient = client
            @Sendable func section(_ path: String) async -> (Data?, String?) {
                do { return (try await reportClient.reportData(path), nil) }
                catch { return (nil, "读取 \(path) 失败：\(error.localizedDescription)") }
            }
            async let statusSection = section("status")
            async let metricsSection = section("metrics")
            async let citySection = section("cities")
            let (statusResult, metricsResult, cityResult) = await (statusSection, metricsSection, citySection)
            let errors = [statusResult.1, metricsResult.1, cityResult.1].compactMap { $0 }

            let quickEvidence = quickPingResults.sorted { $0.key < $1.key }.map { name, value in
                "\(name) | \(value.target) | \(value.targetKind ?? "未知目标类型") | \(value.milliseconds.map { String($0) + " ms" } ?? "无回复") | \(value.testedAt.formatted(.iso8601)) | \(value.detail)"
            }.joined(separator: "\n")
            let summary = cachedReportSummary() + "\n\n快速 Ping 历史快照（不是实时可用性）：\n" + quickEvidence
            do {
                let url = try await DiagnosticReportExporter.create(
                    status: statusResult.0,
                    metrics: metricsResult.0,
                    cities: cityResult.0,
                    cachedSummary: summary,
                    errors: errors
                )
                NSPasteboard.general.clearContents()
                if NSPasteboard.general.setString(url.path, forType: .string) {
                    reportMessage = "已复制诊断文件路径：\(url.path)"
                } else {
                    reportMessage = "诊断文件已生成，剪贴板写入失败；请手动复制：\(url.path)"
                }
            } catch {
                reportMessage = "生成诊断资料失败：\(error.localizedDescription)"
            }
        }
    }

    func loadProtection() async {
        do { protection = try await client.fetchProtection(); protectionError = nil }
        catch { protectionError = "无法读取连接保护状态。此页面需要配套新版后台；当前连接保持原样。" }
    }

    func applyProtection(_ profile: ProtectionProfile) {
        guard !isBusy, !isSpeedTesting, !isPreview else { return }
        clearFeedback()
        isActionRunning = true
        actionMessage = "正在验证新的连接保护路径…"
        Task {
            defer { isActionRunning = false; actionMessage = nil }
            do {
                let receipt = try await client.applyProtection(profile)
                try await waitForOperation(receipt.id)
            } catch { errorMessage = error.localizedDescription }
            await loadProtection()
            await refreshStatusBestEffort()
        }
    }

    func reconnect() {
        startReconnect(transport: nil, applyingPreference: false)
    }

    func applySelectedTransportToCurrentRelay() {
        startReconnect(transport: selectedTransport, applyingPreference: true)
    }

    private func cachedReportSummary() -> String {
        var lines = [
            "界面最后更新时间：\(lastUpdated?.ISO8601Format() ?? "未知")",
            "界面显示状态：\(localizedAdapterStatus(displayedStatus))",
            "活动节点：\(status?.activeRelay ?? "未知")",
            "服务状态：\(localizedAdapterStatus(status?.serviceReadiness ?? status?.status))",
            "前端数据路径：\(localizedAdapterStatus(status?.front?.dataPath?.status))",
            "前端控制接口：\(status?.front?.controllerDegraded == true ? "异常" : "正常或未检查")",
            "最近错误：\(status?.lastError ?? "无")"
        ]
        if let diagnosis = status?.diagnosis {
            lines.append("最近网络判断：\(diagnosis.summary)")
        }
        return lines.joined(separator: "\n")
    }

    func setSelectedTransport(_ transport: TransportPreference) {
        selectedTransport = transport
        let currentPreference = TransportPreference(rawValue: status?.transportPreference?.lowercased() ?? "") ?? .auto
        transportSelectionDirty = transport != currentPreference
    }

    private func startReconnect(transport: TransportPreference?, applyingPreference: Bool) {
        guard !isBusy, !isSpeedTesting, let activeRelay = status?.activeRelay else { return }

        let effectiveTransport = transport
            ?? TransportPreference(rawValue: status?.transportPreference?.lowercased() ?? "")
            ?? .auto
        clearFeedback()
        isActionRunning = true
        actionMessage = applyingPreference
            ? "正在以\(effectiveTransport.displayName)重建当前节点 \(activeRelay)…"
            : "正在重连 \(activeRelay)…"
        errorMessage = nil

        Task {
            defer {
                isActionRunning = false
                actionMessage = nil
            }

            do {
                let receipt = try await client.reconnect(transport: transport?.rawValue)
                try await waitForOperation(receipt.id)
                if applyingPreference {
                    selectedTransport = TransportPreference(rawValue: status?.transportPreference ?? "") ?? effectiveTransport
                    transportSelectionDirty = false
                }
                await refreshMetricsBestEffort()
            } catch {
                errorMessage = error.localizedDescription
                await refreshStatusBestEffort()
            }
        }
    }

    func selectRelay(hostname: String, transport: TransportPreference? = nil) {
        guard !hostname.isEmpty, !isBusy, !isSpeedTesting else { return }

        let requestedTransport = transport ?? selectedTransport
        clearFeedback()
        isActionRunning = true
        selectingRelayHostname = hostname
        actionMessage = "正在以\(requestedTransport.displayName)切换到 \(hostname)…"
        errorMessage = nil

        Task {
            defer {
                isActionRunning = false
                selectingRelayHostname = nil
                actionMessage = nil
            }

            do {
                let receipt = try await client.select(relay: hostname, transport: requestedTransport.rawValue)
                try await waitForOperation(receipt.id)
                selectedTransport = requestedTransport
                transportSelectionDirty = false
                recordRecentRelay(hostname)
                await refreshMetricsBestEffort()
            } catch {
                errorMessage = error.localizedDescription
                await refreshStatusBestEffort()
            }
        }
    }

    func loadRelays(force: Bool = false) async {
        guard !isPreview else { return }
        if !force, !relays.isEmpty { return }
        guard !isLoadingRelays else { return }
        isLoadingRelays = true
        relayErrorMessage = nil
        defer { isLoadingRelays = false }

        do {
            relays = try await client.fetchRelays()
                .filter { !$0.hostname.isEmpty }
                .sorted {
                    ($0.countryDisplayName, $0.cityDisplayName, $0.hostname) <
                    ($1.countryDisplayName, $1.cityDisplayName, $1.hostname)
                }
        } catch {
            relayErrorMessage = error.localizedDescription
        }
    }

    func reloadRelays() {
        Task {
            async let relayLoad: Void = loadRelays(force: true)
            async let historyLoad: Void = loadRelayHistory()
            _ = await (relayLoad, historyLoad)
        }
    }

    func loadSpeedTests() async {
        do {
            let results = try await client.fetchSpeedTests()
            for result in results {
                guard let transport = speedResultTransport(result) else { continue }
                let key = RelaySpeedKey(relay: result.relay, transport: transport)
                let updatedAt = parsedDate(result.testedAt) ?? Date()
                if let existing = speedStates[key],
                   let existingUpdatedAt = existing.updatedAt,
                   existingUpdatedAt > updatedAt {
                    continue
                }
                speedStates[key] = .success(result, updatedAt: updatedAt)
            }
        } catch let error as AdapterClientError {
            if case .http(let status, _, _) = error, status == 404 {
                return
            }
            speedMessage = "读取测速历史失败：\(error.localizedDescription)"
        } catch {
            speedMessage = "读取测速历史失败：\(error.localizedDescription)"
        }
    }

    func loadRelayHistory() async {
        do {
            let entries = try await client.fetchRelayHistory()
            var updated: [RelaySpeedKey: RelayHistorySummary] = [:]
            for entry in entries {
                guard let transport = TransportPreference(rawValue: entry.transportMode.lowercased()) else { continue }
                updated[RelaySpeedKey(relay: entry.relay, transport: transport)] = entry
            }
            relayHistory = updated
        } catch let error as AdapterClientError {
            if case .http(let status, _, _) = error, status == 404 {
                return
            }
            speedMessage = "读取节点历史统计失败：\(error.localizedDescription)"
        } catch {
            speedMessage = "读取节点历史统计失败：\(error.localizedDescription)"
        }
    }

    func loadSnapshot() async {
        guard !isLoading else { return }
        isLoading = true
        errorMessage = nil
        defer { isLoading = false }

        // Metrics are supplementary; their failure must not discard a fresh
        // connection snapshot or make a healthy service appear unreachable.
        async let statusRequest: Void = refreshStatusBestEffort()
        async let metricsRequest: Void = refreshMetricsBestEffort()
        _ = await (statusRequest, metricsRequest)
    }

    func speedState(for hostname: String, transport: TransportPreference? = nil) -> RelaySpeedState {
        let requestedTransport = transport ?? selectedTransport
        return speedStates[RelaySpeedKey(relay: hostname, transport: requestedTransport)] ?? .idle
    }

    func historySummary(for hostname: String, transport: TransportPreference? = nil) -> RelayHistorySummary? {
        let requested = transport ?? selectedTransport
        if requested != .auto {
            return relayHistory[RelaySpeedKey(relay: hostname, transport: requested)]
        }

        let entries = [TransportPreference.ss, .ipv6, .ipv4].compactMap {
            relayHistory[RelaySpeedKey(relay: hostname, transport: $0)]
        }
        let cutoff = ISO8601DateFormatter().string(from: Date().addingTimeInterval(-600))
        let ready = entries.filter { $0.consecutiveFailures == 0 && ($0.lastTestedAt ?? "") > cutoff }
        return (ready.isEmpty ? entries : ready).max { ($0.lastTestedAt ?? "") < ($1.lastTestedAt ?? "") }
    }

    func concreteSpeedStates(for hostname: String) -> [(transport: TransportPreference, state: RelaySpeedState)] {
        [.ss, .ipv6, .ipv4].map { transport in
            (transport, speedState(for: hostname, transport: transport))
        }
    }

    func relayInfo(for hostname: String?) -> RelayInfo? {
        guard let hostname else { return nil }
        return relays.first { $0.hostname == hostname }
    }

    func isCountryPinned(_ key: String) -> Bool {
        pinnedCountryKeys.contains(key)
    }

    func toggleCountryPinned(_ key: String) {
        var updated = pinnedCountryKeys
        if updated.contains(key) { updated.remove(key) } else { updated.insert(key) }
        pinnedCountryKeys = updated
        defaults.set(updated.sorted(), forKey: pinnedCountriesKey)
    }

    func isCityPinned(_ key: String) -> Bool {
        pinnedCityKeys.contains(key)
    }

    func toggleCityPinned(_ key: String) {
        var updated = pinnedCityKeys
        if updated.contains(key) { updated.remove(key) } else { updated.insert(key) }
        pinnedCityKeys = updated
        defaults.set(updated.sorted(), forKey: pinnedCitiesKey)
    }

    func isRelayPinned(_ hostname: String) -> Bool {
        pinnedRelayHostnames.contains(hostname)
    }

    func toggleRelayPinned(_ hostname: String) {
        var updated = pinnedRelayHostnames
        if updated.contains(hostname) { updated.remove(hostname) } else { updated.insert(hostname) }
        pinnedRelayHostnames = updated
        defaults.set(updated.sorted(), forKey: pinnedRelaysKey)
    }

    func startQuickTest(relays: [RelayInfo], label: String, cityConcurrency: Bool) {
        guard !isPreview else { return }
        guard !relays.isEmpty, !isBusy, !isSpeedTesting else { return }
        // Enforce scope here as well as in the menu: mixed-city lists are serial.
        let locations = Set(relays.map { $0.location ?? $0.hostname })
        let concurrent = cityConcurrency && locations.count == 1
        isQuickTesting = true
        isCancellingSpeedTest = false
        errorMessage = nil
        reportMessage = nil
        speedMessage = "快速测速 · \(label)：0 / \(relays.count)"
        let transport = selectedTransport.rawValue
        let batchID = UUID().uuidString
        lastQuickPingBatchID = batchID
        lastQuickPingBatchLabel = label
        let activeWorker = status?.activeSlot.flatMap { status?.workers?[$0] }
        let interface = activeWorker?.interface
        // A raw system-route ping may enter Clash TUN instead of the VPN's outer path.
        guard let interface, !interface.isEmpty, !interface.hasPrefix("utun") else {
            isQuickTesting = false
            errorMessage = "未能确定 VPN 使用的物理接口，请连接后再快速测速。"
            return
        }
        quickSpeedTask = Task {
            defer {
                isQuickTesting = false
                isCancellingSpeedTest = false
                quickSpeedTask = nil
                if let data = try? JSONEncoder().encode(quickPingResults) {
                    defaults.set(data, forKey: "MullvadAdapterUI.quickPingResults")
                    if let lastQuickPingBatchID { defaults.set(lastQuickPingBatchID, forKey: "MullvadAdapterUI.lastQuickPingBatchID") }
                    if let lastQuickPingBatchLabel { defaults.set(lastQuickPingBatchLabel, forKey: "MullvadAdapterUI.lastQuickPingBatchLabel") }
                }
            }
            var targets = QuickPing.targets(transport: transport, relays: relays)
            let activeMode = status?.activeTransportMode ?? status?.activeTransport
            if (transport == "auto" || transport == activeMode),
               let relay = activeWorker?.relay, let endpoint = activeWorker?.endpoint {
                targets[relay] = RelayPingTarget(target: endpoint, kind: "active-worker-endpoint")
            }
            let pingTargets = targets
            quickCompleted = 0
                await QuickPing.run(hostnames: relays.map(\.hostname), targets: pingTargets, cityConcurrency: concurrent,
                                    probe: { await QuickPing.probe($0, interface: interface) }) { [weak self] name, result in
                    guard let self else { return }
                    let recorded = QuickPingResult(target: result.target, milliseconds: result.milliseconds,
                        testedAt: result.testedAt, detail: result.detail, interface: result.interface,
                        exitCode: result.exitCode, durationMilliseconds: result.durationMilliseconds,
                        batchID: batchID, batchLabel: label, transport: transport,
                        targetKind: pingTargets[name]?.kind)
                    self.quickPingResults["\(name)|\(transport)"] = recorded
                    self.quickCompleted += 1
                    self.speedMessage = "快速测速 · \(label)：\(self.quickCompleted) / \(relays.count) · \(concurrent ? "城市内最多 4 路" : "逐节点串行")"
                }
                speedMessage = "快速测速\(Task.isCancelled ? "已停止" : "完成") · \(label)：\(quickCompleted) / \(relays.count)；切换时验证可用性。"
        }
    }

    func testRelaySpeed(hostname: String, transport: TransportPreference? = nil) {
        guard !hostname.isEmpty, !isBusy, !isSpeedTesting else { return }
        speedMessage = nil
        errorMessage = nil
        reportMessage = nil
        isCancellingSpeedTest = false
        let requestedTransport = transport ?? selectedTransport
        // Set the task synchronously, before yielding to prevent double clicks
        // from queuing two requests in the same main-actor turn.
        singleSpeedTask = Task {
            defer { singleSpeedTask = nil; isCancellingSpeedTest = false }
            _ = await performSpeedTest(hostname: hostname, transport: requestedTransport)
        }
    }

    func testCurrentRelaySpeed() {
        guard
            !isBusy,
            !isSpeedTesting,
            let activeRelay = status?.activeRelay,
            !activeRelay.isEmpty
        else { return }

        speedMessage = nil
        let actualMode = TransportPreference(
            rawValue: status?.activeTransportMode?.lowercased()
                ?? status?.activeTransport?.lowercased()
                ?? ""
        )
        testRelaySpeed(hostname: activeRelay, transport: actualMode)
    }

    func startBatchSpeedTest(
        relays: [RelayInfo],
        label: String,
        transport: TransportPreference,
        intervalSeconds: Double
    ) {
        guard !relays.isEmpty, !isBusy, !isSpeedTesting else { return }

        isCancellingSpeedTest = false
        errorMessage = nil
        reportMessage = nil

        let ordered = relays.sorted { $0.hostname < $1.hostname }
        isSequentialSpeedTesting = true
        speedMessage = "\(label)：0 / \(ordered.count) · \(transport.displayName)"
        batchSpeedProgress = BatchSpeedProgress(
            label: label,
            transport: transport,
            total: ordered.count,
            completed: 0,
            currentHostname: nil,
            intervalSeconds: intervalSeconds
        )
        for relay in ordered {
            speedStates[RelaySpeedKey(relay: relay.hostname, transport: transport)] = .queued
        }

        batchSpeedTask = Task {
            var completed = 0
            var stoppedEarly = false
            var cancelled = false

            defer {
                for relay in ordered {
                    let key = RelaySpeedKey(relay: relay.hostname, transport: transport)
                    if speedStates[key]?.phase == .queued {
                        speedStates[key] = .idle
                    }
                }
                isSequentialSpeedTesting = false
                isCancellingSpeedTest = false
                speedTestingRelay = nil
                batchSpeedTask = nil
                batchSpeedProgress = nil
            }

            for (index, relay) in ordered.enumerated() {
                if Task.isCancelled {
                    cancelled = true
                    break
                }

                batchSpeedProgress = BatchSpeedProgress(
                    label: label,
                    transport: transport,
                    total: ordered.count,
                    completed: completed,
                    currentHostname: relay.hostname,
                    intervalSeconds: intervalSeconds
                )
                speedMessage = "\(label)：\(index + 1) / \(ordered.count) · \(relay.hostname) · \(transport.displayName)"

                let shouldContinue = await performSpeedTest(
                    hostname: relay.hostname,
                    transport: transport
                )
                completed += 1
                batchSpeedProgress = BatchSpeedProgress(
                    label: label,
                    transport: transport,
                    total: ordered.count,
                    completed: completed,
                    currentHostname: nil,
                    intervalSeconds: intervalSeconds
                )

                if !shouldContinue {
                    stoppedEarly = true
                    break
                }

                if index + 1 < ordered.count {
                    do {
                        try await Task.sleep(nanoseconds: UInt64(intervalSeconds * 1_000_000_000))
                    } catch {
                        cancelled = true
                        break
                    }
                }
            }

            if cancelled {
                speedMessage = "已取消 \(label)，完成 \(completed) / \(ordered.count)。"
            } else if stoppedEarly {
                speedMessage = "\(label)已停止，完成 \(completed) / \(ordered.count)。请先处理上方提示后再继续。"
            } else {
                speedMessage = "\(label)完成：\(completed) / \(ordered.count)。"
            }
            await refreshRelayHistoryBestEffort()
        }
    }

    func cancelBatchSpeedTest() {
        cancelSpeedTest()
    }

    private func performSpeedTest(hostname: String, transport: TransportPreference?) async -> Bool {
        let stateTransport = transport ?? .auto
        let key = RelaySpeedKey(relay: hostname, transport: stateTransport)
        speedTestingRelay = hostname
        speedStates[key] = .testing
        defer {
            if speedTestingRelay == hostname {
                speedTestingRelay = nil
            }
        }

        do {
            let result = try await client.speedTest(relay: hostname, transport: transport?.rawValue)
            speedStates[key] = .success(result, updatedAt: parsedDate(result.testedAt) ?? Date())
            if !isSequentialSpeedTesting {
                speedMessage = "\(hostname) 测速完成：\(localizedAdapterStatus(result.serviceReadiness))"
                await refreshRelayHistoryBestEffort()
            }
            return true
        } catch {
            if case AdapterClientError.cancellationUnconfirmed = error {
                speedStates[key] = .failed(error.localizedDescription)
                errorMessage = error.localizedDescription
                speedMessage = error.localizedDescription
                return false
            }
            if Task.isCancelled || error is CancellationError {
                speedStates[key] = .idle
                speedMessage = "测速已停止，当前连接保持原样。"
                return false
            }
            let message = friendlySpeedError(error)
            speedMessage = message
            if case AdapterClientError.http(let status, _, _) = error, status == 404 {
                speedStates[key] = .unsupported(message)
                speedMessage = message
                return false
            }

            speedStates[key] = .failed(message)
            if let code = speedErrorCode(error) {
                if code == "active_transport_change_required" {
                    speedMessage = message
                    return true
                }
                if [
                    "speedtest_busy",
                    "adapter_busy",
                    "slot_draining",
                    "active_worker_inconsistent",
                    "worker_lifecycle_busy"
                ].contains(code) {
                    speedMessage = message
                    return false
                }
            }
            return true
        }
    }

    func checkConnection(repair: Bool) {
        guard !isBusy, !isSpeedTesting else { return }
        isActionRunning = true
        clearFeedback()
        actionMessage = repair ? "正在检查并恢复连接…" : "正在定位网络问题…"
        Task {
            defer { isActionRunning = false; actionMessage = nil }
            do {
                let receipt = try await client.startOperation(repair ? "repair" : "diagnose")
                try await waitForOperation(receipt.id)
            } catch {
                errorMessage = error.localizedDescription
            }
            await refreshStatusBestEffort()
            await refreshMetricsBestEffort()
        }
    }

    func cancelSpeedTest() {
        guard canCancelSpeedTest, !isCancellingSpeedTest else { return }
        isCancellingSpeedTest = true
        if quickSpeedTask != nil {
            quickSpeedTask?.cancel()
            return
        }
        if singleSpeedTask != nil {
            singleSpeedTask?.cancel()
            return
        }
        if batchSpeedTask != nil {
            batchSpeedTask?.cancel()
            return
        }
        guard let operation = status?.operation, operation.kind == "speedtest", operation.isRunning else { return }
        Task {
            await client.cancelOperation(operation.id)
            await refreshStatusBestEffort()
            isCancellingSpeedTest = false
        }
    }

    private func waitForOperation(_ id: String) async throws {
        let deadline = Date().addingTimeInterval(240)
        var readFailures = 0
        while Date() < deadline {
            try Task.checkCancellation()
            let operation: AdapterOperation
            do {
                operation = try await client.fetchOperation(id)
                readFailures = 0
            } catch {
                readFailures += 1
                guard readFailures <= 3, case AdapterClientError.transport = error else { throw error }
                try await Task.sleep(nanoseconds: 500_000_000)
                continue
            }
            actionMessage = operation.message
            await refreshStatusBestEffort()
            if !operation.isRunning {
                if operation.state == "succeeded" || operation.state == "recovered" { return }
                // A specific operation result cannot be confused with an
                // unrelated background health error or a previous generation.
                throw AdapterActionError.rejected(operation.message ?? "操作未完成")
            }
            try await Task.sleep(nanoseconds: 500_000_000)
        }
        throw AdapterActionError.timeout("后台操作仍未结束，请查看当前进度；没有再次发起重连。")
    }

    private func localizedActionError(_ message: String) -> String {
        let lower = message.lowercased()
        if lower.contains("still draining") || lower.contains("deferred") {
            return "切换暂缓：另一条通道还有旧连接在用，读不到确切数量。请稍后再试。\n\(message)"
        }
        if lower.contains("candidate not preferred") {
            return "候选节点健康检查未达到切换条件，已保留原连接。\n\(message)"
        }
        if lower.contains("rollback") {
            return "重连未成功，适配器已尝试恢复原路径。\n\(message)"
        }
        return message
    }

    private func friendlySpeedError(_ error: Error) -> String {
        guard case AdapterClientError.http(_, let code, let message) = error else {
            return error.localizedDescription
        }

        switch code {
        case "speedtest_busy":
            return "已有节点正在测速，请等当前测速结束。"
        case "adapter_busy":
            return "适配器正在切换或重连，完成后才能测速。"
        case "slot_draining":
            return "另一条通道还在收尾旧连接，稍等几秒再试一次。"
        case "active_worker_inconsistent":
            return "当前节点状态和实际的连接进程对不上，暂时不能测速。请刷新一下状态，或等它自动恢复。"
        case "worker_lifecycle_busy":
            return "上一次的连接进程还没清理干净，暂时不能测速。稍等几秒再试。"
        case "active_transport_change_required":
            return "当前节点正在使用不同的连接方式。需要先显式切换连接方式；测速不会为了测试而打断当前连接。"
        default:
            return message
        }
    }

    private func speedErrorCode(_ error: Error) -> String? {
        guard case AdapterClientError.http(_, let code, _) = error else { return nil }
        return code
    }

    private func recordRecentRelay(_ hostname: String) {
        recentRelayHostnames.removeAll { $0 == hostname }
        recentRelayHostnames.insert(hostname, at: 0)
        if recentRelayHostnames.count > 12 {
            recentRelayHostnames = Array(recentRelayHostnames.prefix(12))
        }
        defaults.set(recentRelayHostnames, forKey: recentRelaysKey)
    }

    private func refreshMetricsBestEffort() async {
        if let newMetrics = try? await client.fetchMetrics() {
            metrics = newMetrics
        }
    }

    private func refreshStatusBestEffort() async {
        guard !isPreview else { return }
        do {
            let newStatus = try await client.fetchStatus()
            applyStatusSnapshot(newStatus)
            lastUpdated = Date()
        } catch {
            connectionError = "本地适配器没有响应。正在自动重试；下方是上次读取的状态。"
        }
        await loadCities()
    }

    func loadCities() async {
        guard !isPreview else { return }
        do {
            let workspace = try await client.fetchCities()
            if let generation = workspace.generation, let statusGeneration = status?.generation,
               generation != statusGeneration {
                let latest = try await client.fetchStatus()
                applyStatusSnapshot(latest)
                if let latestGeneration = latest.generation, generation < latestGeneration {
                    cityErrorMessage = "正在同步最新城市状态…"
                    return
                }
            }
            cityWorkspace = workspace
            cityErrorMessage = nil
        } catch {
            cityErrorMessage = "城市状态暂不可用。若后台版本较旧，请先安装配套版本。"
        }
    }

    func saveCities(_ cities: [String]) async -> Bool {
        guard !isBusy, !isSpeedTesting, !isSavingCities else { return false }
        guard (1...3).contains(cities.count), Set(cities).count == cities.count else {
            cityErrorMessage = "请选择 1–3 个不重复城市。"
            return false
        }
        isSavingCities = true
        defer { isSavingCities = false }
        if isPreview {
            loadCityPreview(selected: cityWorkspace?.selectedCity ?? cities[0], favorites: cities)
            return true
        }
        do {
            cityWorkspace = try await client.saveFavoriteCities(cities)
            cityErrorMessage = nil
            return true
        } catch {
            cityErrorMessage = error.localizedDescription
            return false
        }
    }

    func selectCity(_ city: String) {
        guard !isBusy, !isSpeedTesting, !isSavingCities else { return }
        if isPreview {
            loadCityPreview(selected: city, favorites: cityWorkspace?.favoriteCities ?? [city])
            return
        }
        clearFeedback()
        isActionRunning = true
        selectingCityID = city
        actionMessage = "正在验证同城节点，连接通过后切换…"
        Task {
            defer { isActionRunning = false; selectingCityID = nil; actionMessage = nil }
            do {
                let receipt = try await client.selectCity(city)
                try await waitForOperation(receipt.id)
                selectedTransport = .auto
                transportSelectionDirty = false
                await loadCities()
            } catch {
                errorMessage = error.localizedDescription
                await refreshStatusBestEffort()
            }
        }
    }

    func refreshStatusOnly() async {
        await refreshStatusBestEffort()
    }

    private func refreshRelayHistoryBestEffort() async {
        if let entries = try? await client.fetchRelayHistory() {
            var updated: [RelaySpeedKey: RelayHistorySummary] = [:]
            for entry in entries {
                guard let transport = TransportPreference(rawValue: entry.transportMode.lowercased()) else { continue }
                updated[RelaySpeedKey(relay: entry.relay, transport: transport)] = entry
            }
            relayHistory = updated
        }
    }

    private func syncSelectedTransportFromStatus(_ snapshot: AdapterStatus) {
        guard !transportSelectionDirty else { return }
        selectedTransport = TransportPreference(rawValue: snapshot.transportPreference?.lowercased() ?? "") ?? .auto
    }

    private func applyStatusSnapshot(_ snapshot: AdapterStatus) {
        let previous = status
        status = snapshot
        connectionError = nil
        syncSelectedTransportFromStatus(snapshot)

        guard notificationBaselineEstablished, let previous else {
            notificationBaselineEstablished = true
            return
        }
        evaluateNotifications(previous: previous, current: snapshot)
    }

    private func prepareNotificationsIfNeeded() {
        guard notificationsEnabled else { return }
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { [weak self] settings in
            Task { @MainActor in
                guard let self else { return }
                switch settings.authorizationStatus {
                case .authorized, .provisional:
                    self.notificationPermissionText = "已允许"
                case .denied:
                    self.notificationPermissionText = "系统已拒绝"
                case .notDetermined:
                    do {
                        let granted = try await center.requestAuthorization(options: [.alert, .sound])
                        self.notificationPermissionText = granted ? "已允许" : "系统已拒绝"
                    } catch {
                        self.notificationPermissionText = "授权失败"
                    }
                @unknown default:
                    self.notificationPermissionText = "未知"
                }
            }
        }
    }

    private func evaluateNotifications(previous: AdapterStatus, current: AdapterStatus) {
        guard notificationsEnabled else { return }

        let reason = current.switchReason?.lowercased() ?? ""
        let previousRelay = previous.activeRelay
        let currentRelay = current.activeRelay
        var recoveryNotificationSent = false

        if (reason == "ss-endpoint-recovery" || reason == "ss-endpoint-recovery-break-before-make"),
           previousRelay == currentRelay,
           let relay = currentRelay,
           previous.activeWorker?.worker.endpoint != current.activeWorker?.worker.endpoint,
           let endpoint = current.activeWorker?.worker.endpoint {
            postNotification(
                title: "SS 入口已自动切换",
                body: "\(relay) 已切到备用入口 \(endpoint)"
            )
            recoveryNotificationSent = true
        } else if reason == "worker-crash-recovery", previous.generation != current.generation,
                  let relay = currentRelay {
            postNotification(
                title: "Mullvad 连接进程已自动恢复",
                body: "\(relay) 的本地连接进程异常退出后已自动重建"
            )
            recoveryNotificationSent = true
        } else if reason == "health-recovery",
                  let relay = currentRelay,
                  previousRelay != currentRelay {
            let old = previousRelay ?? "原节点"
            postNotification(
                title: "Mullvad 已自动恢复",
                body: "\(old) → \(relay) · \(TransportPreference.shortDisplayName(for: current.activeTransportMode ?? current.activeTransport))"
            )
            recoveryNotificationSent = true
        } else if reason == "dns-recovery-probe",
                  let relay = currentRelay,
                  previousRelay != currentRelay {
            let old = previousRelay ?? "原节点"
            postNotification(
                title: "DNS 已恢复（网络通，DNS 也通了）",
                body: "\(old) → \(relay) · 新节点 DNS 正常"
            )
            recoveryNotificationSent = true
        }

        let previousRoutingEvent = previous.routingPolicy?.lastEvent
        let currentRoutingEvent = current.routingPolicy?.lastEvent
        if currentRoutingEvent != previousRoutingEvent || current.routingPolicy?.lastEventAt != previous.routingPolicy?.lastEventAt {
            switch currentRoutingEvent {
            case "front-restarted", "front-hung-restart", "front-restarted-during-switch", "front-data-path-restarted":
                postNotification(
                    title: "Mullvad 本地前端已自动恢复",
                    body: "本地 17890 转发入口异常后已自动重启，并恢复到当前节点。"
                )
            case "common-dns-failure-detected":
                postNotification(
                    title: "检测到 Mullvad 公共 DNS 故障",
                    body: "多个 Relay 的数据通道正常但内层 DNS 同时失败，已暂停继续换节点，避免无效抖动。"
                )
            case "previous-drain-preempted":
                if let count = current.routingPolicy?.lastPreemptedConnections, count > 0 {
                    postNotification(
                        title: "连续切换已完成",
                        body: "为腾出位置，已结束上一代还留在旧节点上的 \(count) 条连接；新连接继续走当前节点。"
                    )
                }
            default:
                break
            }
        }

        let previousReadiness = (previous.serviceReadiness ?? previous.status ?? "").lowercased()
        let currentReadiness = (current.serviceReadiness ?? current.status ?? "").lowercased()
        let badStates: Set<String> = ["degraded", "degraded_dns", "degraded_service", "data_fail", "fail", "failed", "error"]

        if badStates.contains(currentReadiness), currentReadiness != previousReadiness {
            if lastNotifiedDegradedState != currentReadiness {
                lastNotifiedDegradedState = currentReadiness
                let detail = current.lastError.map { "\n\($0)" } ?? ""
                postNotification(
                    title: "Mullvad 连接异常",
                    body: "\(localizedAdapterStatus(currentReadiness))\(detail)"
                )
            }
        } else if currentReadiness == "ready", badStates.contains(previousReadiness), !recoveryNotificationSent {
            lastNotifiedDegradedState = nil
            postNotification(
                title: "Mullvad 连接已恢复",
                body: "\(currentRelay ?? "当前节点") 已恢复就绪"
            )
        }
    }

    private func postNotification(title: String, body: String) {
        guard notificationsEnabled else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        let request = UNNotificationRequest(
            identifier: "mullvad-adapter-\(UUID().uuidString)",
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request)
    }

    private func parsedDate(_ value: String?) -> Date? {
        guard let value else { return nil }
        return ISO8601DateFormatter().date(from: value)
    }

    private func speedResultTransport(_ result: RelaySpeedTestResult) -> TransportPreference? {
        guard let raw = result.transportMode?.lowercased(), !raw.isEmpty else { return nil }
        return TransportPreference(rawValue: raw)
    }
}

enum AdapterActionError: LocalizedError {
    case rejected(String)
    case timeout(String)

    var errorDescription: String? {
        switch self {
        case .rejected(let message), .timeout(let message):
            return message
        }
    }
}
