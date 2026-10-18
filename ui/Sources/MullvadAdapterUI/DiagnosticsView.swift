import SwiftUI

struct DiagnosticsView: View {
    @ObservedObject var model: AdapterViewModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header

                if let status = model.status {
                    if let diagnosis = status.diagnosis {
                        NetworkDiagnosisCard(diagnosis: diagnosis)
                    }
                    adapterInternalCard(status)
                    routingPolicyCard(status)
                    workerCard(status)
                    metadataCard(status)
                    healthCard(status)
                    dnsDetailCard(status)
                    canaryCard(status)
                    metricsCard(model.metrics)
                    if let error = status.lastError, !error.isEmpty {
                        AppCard("最近一次适配器错误") {
                            Text(error)
                                .font(.callout.monospaced())
                                .foregroundStyle(.red)
                                .textSelection(.enabled)
                        }
                    }
                } else {
                    AppCard("诊断状态") {
                        Text("尚未加载适配器状态。")
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .padding(18)
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .task(id: model.status?.drainingWorker?.worker.drainStartedAt) {
            await monitorDrainStatus()
        }
    }

    private func routingPolicyCard(_ status: AdapterStatus) -> some View {
        AppCard("切换控制权与连接语义") {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .top, spacing: 18) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("谁决定走哪个节点")
                            .font(.subheadline.weight(.semibold))
                        Text("主 Clash 只负责把命中规则的流量送进 Mullvad 本地适配器；具体 Relay、SS 入口和传输方式由 Adapter 决定。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    VStack(alignment: .leading, spacing: 6) {
                        Text("切换时")
                            .font(.subheadline.weight(.semibold))
                        Text("新连接立即走新节点；正常手动切换时，已经打开的旧连接会留在旧节点上自然走完。故障切换时旧路径不会继续占着 30 分钟，替代路径一就绪就立刻退役。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    VStack(alignment: .leading, spacing: 6) {
                        Text("连续再次切换")
                            .font(.subheadline.weight(.semibold))
                        Text("只有两个工作槽位。若备用槽还被上一代旧连接占着，会先结束最老那一批旧连接再执行新切换；当前正在用的连接不受影响。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }

                if let policy = status.routingPolicy {
                    Divider()
                    HStack(spacing: 18) {
                        KeyValueRow(label: "策略所有者", value: policy.owner == "adapter" ? "Mullvad Adapter" : (policy.owner ?? "—"))
                        if let pending = policy.pendingAction {
                            KeyValueRow(label: "正在执行", value: "\(pending.relay ?? "—") · \(localizedSwitchReason(pending.reason))", monospaced: true)
                        }
                        if let event = policy.lastEvent {
                            KeyValueRow(label: "最近路由事件", value: localizedRoutingEvent(event))
                        }
                        Spacer(minLength: 0)
                    }
                    .font(.callout)

                    if let quarantined = policy.quarantinedRelays, !quarantined.isEmpty {
                        Text(
                            "自动恢复暂避：" + quarantined.map {
                                "\($0.relay)（\(($0.remainingSeconds ?? 0) / 60) 分）"
                            }.joined(separator: "、")
                        )
                        .font(.caption)
                        .foregroundStyle(.orange)
                    }
                }
            }
        }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                Text("网络诊断")
                    .font(.title2.weight(.semibold))
                Text("先比较适配器与 Clash 的实际访问结果，再查看技术细节。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                model.checkConnection(repair: false)
            } label: {
                Label("检查网络", systemImage: "stethoscope")
            }
            .disabled(model.isLoading || model.isBusy)

            Button {
                model.copyDiagnosticReport()
            } label: {
                Label(model.isExportingReport ? "生成中…" : "复制排查资料", systemImage: "doc.on.clipboard")
            }
            .disabled(model.isExportingReport)
        }
    }

    private func adapterInternalCard(_ status: AdapterStatus) -> some View {
        AppCard("适配器内部状态") {
            HStack(alignment: .top, spacing: 24) {
                VStack(alignment: .leading, spacing: 7) {
                    HStack(spacing: 8) {
                        Text("状态")
                            .foregroundStyle(.secondary)
                        AdapterStatusBadge(rawStatus: status.status)
                    }
                    KeyValueRow(label: "代次", value: status.generation.map(String.init) ?? "—")
                    KeyValueRow(label: "活动槽位", value: status.activeSlot?.uppercased() ?? "—")
                    KeyValueRow(label: "当前 Relay", value: status.activeRelay ?? "—", monospaced: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                VStack(alignment: .leading, spacing: 7) {
                    KeyValueRow(label: "传输方式", value: status.activeTransport ?? "—")
                    KeyValueRow(label: "切换原因", value: localizedSwitchReason(status.switchReason))
                    KeyValueRow(label: "切换时间", value: status.switchedAt ?? "—", monospaced: true)
                    KeyValueRow(label: "状态更新时间", value: status.updatedAt ?? "—", monospaced: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                VStack(alignment: .leading, spacing: 7) {
                    KeyValueRow(label: "本地前端", value: frontSummary(status.front), monospaced: true)
                    KeyValueRow(label: "前端数据路径", value: localizedAdapterStatus(status.front?.dataPath?.status))
                    KeyValueRow(label: "前端控制接口", value: status.front?.controllerDegraded == true ? "暂时异常，数据仍通" : "正常 / 待检查")
                    KeyValueRow(label: "服务版本", value: status.buildID ?? "旧版", monospaced: true)
                    KeyValueRow(label: "控制 API", value: apiSummary(status.api), monospaced: true)
                    KeyValueRow(label: "Relay 存活", value: localizedAdapterStatus(status.relayLiveness))
                    KeyValueRow(label: "网络", value: factSummary(status, id: "network"))
                    KeyValueRow(label: "DNS", value: factSummary(status, id: "dns"))
                    KeyValueRow(label: "综合状态", value: localizedAdapterStatus(status.serviceReadiness))
                    KeyValueRow(label: "状态持久化", value: localizedAdapterStatus(status.persistence?.status))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private func workerCard(_ status: AdapterStatus) -> some View {
        AppCard("工作进程与旧连接收尾") {
            HStack(alignment: .top, spacing: 14) {
                workerDetail("活动 Worker", status.activeWorker)
                workerDetail("正在收尾的旧节点", status.drainingWorker)

                VStack(alignment: .leading, spacing: 7) {
                    Text("连接计数")
                        .font(.subheadline.weight(.semibold))
                    metricLine("活动连接", status.activeConnections)
                    metricLine("旧连接数", status.drainingConnections)
                    metricLine("当前可见总数", status.totalVisibleConnections)
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
            }
        }
    }

    private func workerDetail(_ title: String, _ entry: WorkerEntry?) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title)
                .font(.subheadline.weight(.semibold))
            if let entry {
                KeyValueRow(label: "槽位", value: entry.slot.uppercased())
                KeyValueRow(label: "状态", value: localizedAdapterStatus(entry.worker.state))
                KeyValueRow(label: "Relay", value: entry.worker.relay ?? "—", monospaced: true)
                KeyValueRow(label: "传输", value: entry.worker.transport ?? "—")
                KeyValueRow(label: "接口", value: entry.worker.interface ?? "—", monospaced: true)
                KeyValueRow(label: "端点", value: endpointSummary(entry.worker), monospaced: true)
                KeyValueRow(label: "连接数", value: String(entry.worker.frontConnectionCount ?? 0))
                if let startedAt = entry.worker.startedAt {
                    KeyValueRow(label: "启动时间", value: startedAt, monospaced: true)
                }
                if let drainStartedAt = entry.worker.drainStartedAt {
                    KeyValueRow(label: "收尾开始", value: drainStartedAt, monospaced: true)
                }
                if let drainDeadlineAt = entry.worker.drainDeadlineAt {
                    KeyValueRow(label: "最晚收尾", value: drainDeadlineAt, monospaced: true)
                }
                if entry.worker.state == "draining" {
                    Divider()
                    DrainCountdownView(entry: entry, compact: true)
                }
            } else {
                Text("无")
                    .foregroundStyle(.secondary)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
    }

    @ViewBuilder
    private func metadataCard(_ status: AdapterStatus) -> some View {
        if let metadata = status.effectiveMetadata {
            AppCard("控制面元数据") {
                HStack(alignment: .top, spacing: 24) {
                    VStack(alignment: .leading, spacing: 7) {
                        if let live = metadata.live {
                            KeyValueRow(label: "实时获取", value: live ? "是" : "否")
                        }
                        if let cache = metadata.cache {
                            KeyValueRow(label: "已验证缓存", value: cache ? "可用" : "不可用")
                        }
                        KeyValueRow(label: "来源", value: metadata.source ?? "—", monospaced: true)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    VStack(alignment: .leading, spacing: 7) {
                        if let age = metadata.effectiveAge {
                            KeyValueRow(label: "缓存年龄", value: formatAdapterSeconds(age))
                        }
                        KeyValueRow(label: "获取时间", value: metadata.fetchedAt ?? "—", monospaced: true)
                        if let error = metadata.error, !error.isEmpty {
                            Text(error)
                                .font(.caption.monospaced())
                                .foregroundStyle(.red)
                                .textSelection(.enabled)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
    }

    private func healthCard(_ status: AdapterStatus) -> some View {
        AppCard("健康检查与自动恢复") {
            HStack(alignment: .top, spacing: 20) {
                VStack(alignment: .leading, spacing: 7) {
                    Text("活动 Relay 健康")
                        .font(.subheadline.weight(.semibold))
                    KeyValueRow(
                        label: "检查间隔",
                        value: status.health?.intervalSeconds.map { "\($0) s" } ?? "—"
                    )
                    KeyValueRow(
                        label: "WG 失败阈值",
                        value: status.health?.failThreshold.map(String.init) ?? "—"
                    )
                    KeyValueRow(
                        label: "连续 WG 失败",
                        value: status.health?.consecutiveWGFailures.map(String.init) ?? "—"
                    )
                    KeyValueRow(
                        label: "连续 DNS 失败",
                        value: status.health?.consecutiveDNSFailures.map(String.init) ?? "—"
                    )
                    KeyValueRow(label: "最近检查", value: status.health?.lastCheckAt ?? "—", monospaced: true)
                    KeyValueRow(label: "最近恢复", value: status.health?.lastRecoveryAt ?? "无", monospaced: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                if let breaker = status.effectiveDNSBreaker {
                    VStack(alignment: .leading, spacing: 7) {
                        Text("公共内层 DNS 熔断器")
                            .font(.subheadline.weight(.semibold))
                        AdapterStatusBadge(rawStatus: breaker.displayState)
                        if let relays = breaker.observedRelays {
                            KeyValueRow(label: "已观察 Relay", value: relays.isEmpty ? "无" : relays.joined(separator: ", "), monospaced: true)
                        }
                        KeyValueRow(label: "触发阈值", value: breaker.threshold.map(String.init) ?? "—")
                        KeyValueRow(label: "抑制到", value: breaker.until ?? "—", monospaced: true)
                        if let detail = breaker.detail, !detail.isEmpty {
                            Text(detail)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
    }

    private func dnsDetailCard(_ status: AdapterStatus) -> some View {
        AppCard("DNS 分层详情") {
            HStack(alignment: .top, spacing: 12) {
                dnsDetail("引导 / 控制面 DNS", status.dns?.bootstrap)
                dnsDetail("Mullvad 内层 DNS", status.dns?.inner)
                dnsDetail("Clash 全局 DNS", status.dns?.clashGlobal)
            }
        }
    }

    private func dnsDetail(_ title: String, _ layer: DNSLayerStatus?) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.subheadline.weight(.semibold))
            AdapterStatusBadge(rawStatus: layer?.status)
            if let delay = layer?.delayMs {
                KeyValueRow(label: "延迟", value: "\(delay) ms")
            }
            if let resolver = layer?.resolver {
                KeyValueRow(label: "解析器", value: resolver, monospaced: true)
            }
            if let qname = layer?.qname {
                KeyValueRow(label: "查询名", value: qname, monospaced: true)
            }
            if let answers = layer?.answers {
                KeyValueRow(label: "应答数", value: String(answers))
            }
            Text(layer?.detail ?? "暂无详情")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
    }

    private func canaryCard(_ status: AdapterStatus) -> some View {
        AppCard("最近一次探针") {
            if let canary = status.lastCanary {
                VStack(alignment: .leading, spacing: 10) {
                    if let at = canary.at {
                        Text(at)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    LazyVGrid(
                        columns: [GridItem(.adaptive(minimum: 210), spacing: 12, alignment: .topLeading)],
                        alignment: .leading,
                        spacing: 12
                    ) {
                        canaryDetail("Worker 控制器探针", canary.controllerProbe)
                        canaryDetail("IP 数据面", canary.ipData)
                        canaryDetail("内层 DNS", canary.innerDNS)
                        canaryDetail("HTTPS 服务", canary.httpsData)
                    }
                }
            } else {
                Text("尚无探针结果。")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func canaryDetail(_ title: String, _ check: CanaryCheck?) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.subheadline.weight(.semibold))
            AdapterStatusBadge(rawStatus: check?.status)
            if let delay = check?.delayMs {
                KeyValueRow(label: "延迟", value: "\(delay) ms")
            }
            if let code = check?.httpCode, code > 0 {
                KeyValueRow(label: "HTTP", value: String(code))
            }
            if let dependency = check?.dependency {
                KeyValueRow(label: "依赖", value: dependency, monospaced: true)
            }
            if let detail = check?.detail, !detail.isEmpty {
                Text(detail)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(4)
                    .help(detail)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
    }

    private func metricsCard(_ metrics: AdapterMetrics?) -> some View {
        AppCard("累计运行指标") {
            if let metrics {
                LazyVGrid(
                    columns: [GridItem(.adaptive(minimum: 220), spacing: 14, alignment: .topLeading)],
                    alignment: .leading,
                    spacing: 12
                ) {
                    metricGroup("切换") {
                        metricLine("切换次数", metrics.switches)
                        metricLine("切换失败", metrics.failedSwitches)
                        metricLine("同 Relay 重连", metrics.sameRelayReconnects)
                        metricLine("Worker 启动", metrics.workerStarts)
                        metricLine("Worker 启动失败", metrics.workerStartFailures)
                    }
                    metricGroup("控制面与旧连接收尾") {
                        metricLine("元数据刷新", metrics.metadataRefreshes)
                        metricLine("元数据刷新失败", metrics.metadataRefreshFailures)
                        metricLine("旧连接自然走完", metrics.drainCompletions)
                        metricLine("到点强制收尾", metrics.drainForced)
                        metricLine("为切换或测速提前收尾", metrics.drainPreemptions)
                        metricLine("故障旧路径立即退役", metrics.failedPathRetirements)
                    }
                    metricGroup("连接") {
                        metricLine("前端总连接", metrics.frontConnectionsTotal)
                        metricLine("活动连接", metrics.activeConnections)
                        metricLine("旧连接数", metrics.drainingConnections)
                    }
                    metricGroup("健康与恢复") {
                        metricLine("健康检查", metrics.healthChecks)
                        metricLine("WG 健康失败", metrics.healthWGFailures)
                        metricLine("内层 DNS 健康失败", metrics.healthDNSFailures)
                        metricLine("自动恢复尝试", metrics.autoRecoveryAttempts)
                        metricLine("自动恢复失败", metrics.autoRecoveryFailures)
                        metricLine("Worker 异常退出", metrics.workerCrashes)
                        metricLine("Worker 崩溃恢复", metrics.workerCrashRecoveries)
                        metricLine("DNS 熔断触发", metrics.innerDNSBreakerTrips)
                        metricLine("被熔断抑制的恢复", metrics.innerDNSBreakerSuppressed)
                    }
                    metricGroup("本地前端") {
                        metricLine("前端自动重启", metrics.frontRestarts)
                        metricLine("选择器自动校正", metrics.frontSelectorRepairs)
                        metricLine("前端数据探针失败", metrics.frontDataProbeFailures)
                        metricLine("状态持久化失败", metrics.persistenceFailures)
                    }
                }
            } else {
                Text("运行指标不可用。")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func metricGroup<Content: View>(_ title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title)
                .font(.subheadline.weight(.semibold))
            content()
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
    }

    private func metricLine(_ label: String, _ value: Int?) -> some View {
        HStack {
            Text(label)
                .foregroundStyle(.secondary)
            Spacer(minLength: 10)
            Text(value.map(String.init) ?? "—")
                .font(.body.monospacedDigit())
        }
        .font(.callout)
    }

    private func metricLine(_ label: String, _ value: Int) -> some View {
        metricLine(label, Optional(value))
    }

    private func frontSummary(_ front: FrontStatus?) -> String {
        guard let front else { return "—" }
        let ready = front.ready == true ? "已就绪" : "未就绪"
        if let port = front.mixedPort {
            return "127.0.0.1:\(port)（\(ready)）"
        }
        return ready
    }

    private func apiSummary(_ api: APIStatus?) -> String {
        guard let api else { return "—" }
        if let host = api.host, let port = api.port {
            return "\(host):\(port)"
        }
        return api.host ?? api.port.map(String.init) ?? "—"
    }

    /// 单条事实（网络 / DNS）的纯文本摘要，给 KeyValueRow 用。
    private func factSummary(_ status: AdapterStatus, id: String) -> String {
        guard let fact = readinessFacts(for: status).first(where: { $0.id == id }) else {
            return "暂无探针数据"
        }
        let extra = fact.extra.map { " · \($0)" } ?? ""
        return "\(fact.detail)\(extra)"
    }

    private func endpointSummary(_ worker: WorkerStatus) -> String {
        guard let endpoint = worker.endpoint else { return "—" }
        if let port = worker.endpointPort {
            return "\(endpoint):\(port)"
        }
        return endpoint
    }

    private func monitorDrainStatus() async {
        while !Task.isCancelled, model.status?.drainingWorker != nil {
            do {
                try await Task.sleep(nanoseconds: 1_000_000_000)
            } catch {
                return
            }
            await model.refreshStatusOnly()
        }
    }
}
