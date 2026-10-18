import SwiftUI

struct OverviewView: View {
    @ObservedObject var model: AdapterViewModel
    @State private var showDetails = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header

                if let status = model.status {
                    nowCard(status)
                    if let diagnosis = status.diagnosis {
                        NetworkDiagnosisCard(diagnosis: diagnosis)
                    }
                    currentNodeCard(status)
                    connectionCard(status)
                    DisclosureGroup("连接详情", isExpanded: $showDetails) {
                        VStack(spacing: 12) {
                            healthCard(status)
                            dnsCard(status)
                            recoveryCard(status)
                        }.padding(.top, 10)
                    }
                } else {
                    AppCard("连接状态") {
                        Text("尚未加载适配器状态。")
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .padding(18)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text("连接概览")
                    .font(.title2.weight(.semibold))
                if let date = model.lastUpdated {
                    Text("更新时间：\(date.formatted(date: .omitted, time: .standard))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Text("查看当前节点、连接健康和 DNS 状态")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            Button {
                model.refresh()
            } label: {
                Label("刷新", systemImage: "arrow.clockwise")
            }
            .disabled(model.isLoading || model.isBusy)

            Button {
                model.copyDiagnosticReport()
            } label: {
                Label(model.isExportingReport ? "生成中…" : "复制排查资料", systemImage: "doc.on.clipboard")
            }
            .disabled(model.isExportingReport)

            Button {
                model.checkConnection(repair: true)
            } label: {
                Label("检查并恢复", systemImage: "stethoscope")
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.isBusy || model.isSpeedTesting)
        }
    }

    /// 一眼看懂"现在什么情况"：先一句结论，再把网络和 DNS 分开列。
    private func nowCard(_ status: AdapterStatus) -> some View {
        let headline = readinessHeadline(model.displayedStatus)
        let facts = readinessFacts(for: status)

        return AppCard("现在什么情况") {
            VStack(alignment: .leading, spacing: 12) {
                Text(headline)
                    .font(.title3.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)

                Text(model.isBusy ? "正在处理，进度会自动更新。" : "后台会检查连接并尝试恢复。遇到问题时点“检查并恢复”，不用先判断该换哪个节点。")
                    .font(.callout).foregroundStyle(.secondary)

                if status.front?.controllerDegraded == true {
                    InlineNotice(text: "网页仍能访问，但本地控制接口暂时异常，正在自动复查。", kind: .info)
                }

                if facts.isEmpty {
                    Text("还没有探针结果，稍等一下。")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                } else {
                    HStack(spacing: 12) {
                        ForEach(facts) { fact in
                            ReadinessFactChip(fact: fact)
                        }
                        Spacer(minLength: 0)
                    }
                }

                if let canary = status.lastCanary, let at = canary.at {
                    Text("这两项来自最近一次探测：\(shortAdapterTime(at))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func currentNodeCard(_ status: AdapterStatus) -> some View {
        let relay = model.relayInfo(for: status.activeRelay)

        return AppCard("当前节点") {
            HStack(alignment: .top, spacing: 26) {
                VStack(alignment: .leading, spacing: 8) {
                    Text(status.activeRelay ?? "—")
                        .font(.title3.monospaced().weight(.semibold))
                        .textSelection(.enabled)
                    if let relay {
                        Text("\(relay.countryDisplayName) · \(relay.cityDisplayName)")
                            .foregroundStyle(.secondary)
                    }
                    AdapterStatusBadge(rawStatus: status.serviceReadiness ?? status.status)
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                VStack(alignment: .leading, spacing: 7) {
                    KeyValueRow(
                        label: "当前实际方式",
                        value: TransportPreference.displayName(for: status.activeTransportMode ?? status.activeTransport)
                    )
                    KeyValueRow(
                        label: "连接偏好",
                        value: TransportPreference.displayName(for: status.transportPreference)
                    )
                    if let relay {
                        KeyValueRow(label: "提供商", value: relay.provider ?? "未知")
                        KeyValueRow(label: "归属", value: relay.ownershipDisplayName)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                VStack(alignment: .leading, spacing: 7) {
                    if let relay {
                        KeyValueRow(label: "额外 SS 入口", value: String(relay.extraSSIPv4 ?? 0))
                    }
                    KeyValueRow(label: "最近切换", value: status.switchedAt ?? "—", monospaced: true)
                    KeyValueRow(label: "切换原因", value: localizedSwitchReason(status.switchReason))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private func healthCard(_ status: AdapterStatus) -> some View {
        let facts = readinessFacts(for: status)
        let networkFact = facts.first { $0.id == "network" }
        let dnsFact = facts.first { $0.id == "dns" }

        return AppCard("全链路健康") {
            HStack(alignment: .top, spacing: 18) {
                healthItem("本地适配器", status.status, detail: "本机连接管理")
                healthItem("隧道", status.relayLiveness, detail: "WireGuard 数据通道")
                factItem("网络", networkFact, fallback: status.serviceReadiness, detail: "能不能连出去")
                factItem("DNS", dnsFact, fallback: status.serviceReadiness, detail: "域名能不能解析")

                VStack(alignment: .leading, spacing: 6) {
                    Text("最近探针")
                        .font(.subheadline.weight(.semibold))
                    if let https = status.lastCanary?.httpsData {
                        AdapterStatusBadge(rawStatus: https.status)
                        if let delay = https.delayMs {
                            Text("HTTPS \(delay) ms")
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(.secondary)
                        }
                    } else {
                        Text("暂无")
                            .foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    /// 网络 / DNS 各自一项。有探针数据就直接说"通 / 不通"，
    /// 没有探针数据时才回落到 daemon 的综合状态。
    @ViewBuilder
    private func factItem(
        _ title: String,
        _ fact: ReadinessFact?,
        fallback: String?,
        detail: String
    ) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.subheadline.weight(.semibold))
            if let fact {
                HStack(spacing: 6) {
                    Image(systemName: fact.isOK ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundStyle(fact.isOK ? Color.green : Color.red)
                    Text(fact.detail)
                        .fontWeight(.semibold)
                        .foregroundStyle(fact.isOK ? Color.primary : Color.red)
                }
                .font(.callout)
            } else {
                AdapterStatusBadge(rawStatus: fallback)
            }
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func healthItem(_ title: String, _ status: String?, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.subheadline.weight(.semibold))
            AdapterStatusBadge(rawStatus: status)
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func dnsCard(_ status: AdapterStatus) -> some View {
        AppCard("解析与控制路径") {
            HStack(alignment: .top, spacing: 12) {
                dnsLayer("节点列表获取", status.dns?.bootstrap)
                dnsLayer("Mullvad 内层 DNS", status.dns?.inner)
                dnsLayer("Clash 控制通路网页", status.dns?.clashGlobal)
            }
        }
    }

    private func dnsLayer(_ title: String, _ layer: DNSLayerStatus?) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.subheadline.weight(.semibold))
            AdapterStatusBadge(rawStatus: layer?.status)
            if let delay = layer?.delayMs {
                Text("\(delay) ms")
                    .font(.body.monospacedDigit().weight(.medium))
            }
            Text(layer?.detail ?? "暂无详情")
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
    }

    private func connectionCard(_ status: AdapterStatus) -> some View {
        AppCard("活动连接") {
            VStack(alignment: .leading, spacing: 12) {
                if status.routingPolicy?.owner == "adapter" {
                    Label(
                        "切换控制权：Mullvad Adapter（主 Clash 只负责把命中规则的流量送进本地适配器）",
                        systemImage: "arrow.triangle.branch"
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }

                HStack(spacing: 28) {
                    countBlock("当前通道", status.activeConnections)
                    countBlock("旧节点上还没走完的连接", status.drainingConnections)
                    countBlock("当前可见总数", status.totalVisibleConnections)
                    Spacer()
                    if status.drainingConnections > 0 {
                        Text("新连接已经走当前节点")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                if let draining = status.drainingWorker {
                    Divider()
                    DrainCountdownView(entry: draining)
                }

                if let count = status.routingPolicy?.lastPreemptedConnections, count > 0 {
                    switch status.routingPolicy?.lastEvent {
                    case "previous-drain-preempted":
                        Text("最近一次连续切换为腾出位置，结束了上一代还留在旧节点上的 \(count) 条连接。")
                            .font(.caption2)
                            .foregroundStyle(.orange)
                    case "speedtest-slot-freed":
                        Text("这次测速前先结束了旧节点上的 \(count) 条残留连接，才能腾出位置跑测速。")
                            .font(.caption2)
                            .foregroundStyle(.orange)
                    default:
                        EmptyView()
                    }
                }
            }
        }
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

    private func countBlock(_ title: String, _ value: Int) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(String(value))
                .font(.title2.monospacedDigit().weight(.semibold))
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func recoveryCard(_ status: AdapterStatus) -> some View {
        AppCard("最近恢复") {
            HStack(alignment: .top, spacing: 28) {
                VStack(alignment: .leading, spacing: 6) {
                    KeyValueRow(label: "最近健康检查", value: status.health?.lastCheckAt ?? "—", monospaced: true)
                    KeyValueRow(label: "最近自动恢复", value: status.health?.lastRecoveryAt ?? "无", monospaced: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                VStack(alignment: .leading, spacing: 6) {
                    KeyValueRow(
                        label: "连续 WG 失败",
                        value: status.health?.consecutiveWGFailures.map(String.init) ?? "—"
                    )
                    KeyValueRow(
                        label: "连续 DNS 失败",
                        value: status.health?.consecutiveDNSFailures.map(String.init) ?? "—"
                    )
                    if let breaker = status.effectiveDNSBreaker {
                        HStack(spacing: 8) {
                            Text("公共内层 DNS 熔断：")
                                .foregroundStyle(.secondary)
                            AdapterStatusBadge(rawStatus: breaker.displayState)
                        }
                        .font(.callout)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
}
