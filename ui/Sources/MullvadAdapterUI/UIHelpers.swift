import SwiftUI

struct AppCard<Content: View>: View {
    let title: String
    let content: Content

    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.headline)
            content
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12))
        .overlay {
            RoundedRectangle(cornerRadius: 12)
                .stroke(Color.secondary.opacity(0.16), lineWidth: 1)
        }
    }
}

struct AdapterStatusBadge: View {
    let rawStatus: String?

    var body: some View {
        Text(localizedAdapterStatus(rawStatus))
            .font(.caption.weight(.semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .foregroundStyle(adapterStatusColor(rawStatus))
            .background(adapterStatusColor(rawStatus).opacity(0.12), in: Capsule())
    }
}

struct KeyValueRow: View {
    let label: String
    let value: String
    var monospaced = false

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text(label + "：")
                .foregroundStyle(.secondary)
            if monospaced {
                Text(value)
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
            } else {
                Text(value)
                    .textSelection(.enabled)
            }
        }
        .font(.callout)
    }
}

struct InlineNotice: View {
    enum Kind {
        case error
        case warning
        case info
    }

    let text: String
    let kind: Kind

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: symbol)
            Text(text)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .font(.callout)
        .foregroundStyle(color)
        .padding(10)
        .background(color.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
    }

    private var color: Color {
        switch kind {
        case .error: return .red
        case .warning: return .orange
        case .info: return .secondary
        }
    }

    private var symbol: String {
        switch kind {
        case .error: return "exclamationmark.triangle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .info: return "info.circle"
        }
    }
}

struct DrainCountdownView: View {
    let entry: WorkerEntry
    var compact = false

    var body: some View {
        VStack(alignment: .leading, spacing: compact ? 5 : 7) {
            HStack(spacing: 8) {
                Label("旧连接收尾中", systemImage: "arrow.triangle.branch")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.orange)
                Spacer(minLength: 8)
                if let remaining = remainingSeconds {
                    Text(remaining > 0 ? "最长还需 \(formatAdapterCountdown(remaining))" : "已到强制收尾时间")
                        .font(.callout.monospacedDigit().weight(.semibold))
                        .foregroundStyle(remaining > 0 ? Color.primary : Color.orange)
                } else {
                    Text("等待旧连接结束")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }

            if let remaining = remainingSeconds, let total = entry.worker.drainTimeoutSeconds, total > 0 {
                ProgressView(value: Double(max(total - remaining, 0)), total: Double(total))
                    .controlSize(.small)
            }

            HStack(spacing: 7) {
                Text(entry.worker.relay ?? "旧节点")
                    .font(.caption.monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text("·")
                Text("剩余 \(entry.worker.frontConnectionCount ?? 0) 条旧连接")
                if let deadline = entry.worker.drainDeadlineAt {
                    Text("· 最晚 \(shortAdapterTime(deadline))")
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)

            if !compact {
                Text("旧连接全部结束就立刻收尾；倒计时只是最长等待时间。")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var remainingSeconds: Int? {
        entry.worker.remainingDrainSeconds()
    }
}

func localizedAdapterStatus(_ rawStatus: String?) -> String {
    guard let rawStatus, !rawStatus.isEmpty else { return "未知" }
    switch rawStatus.lowercased() {
    case "ready": return "正常"
    case "ok": return "正常"
    case "pass": return "正常"
    case "active": return "活动"
    case "clear": return "正常"
    case "closed": return "已关闭"
    case "switching": return "切换中"
    case "reconnecting": return "重连中"
    case "waiting_network": return "等待本机网络"
    case "network_recovering": return "恢复原连接中"
    case "candidate": return "正在试连"
    case "draining": return "旧连接收尾中"
    case "external": return "外部"
    case "half_open": return "半开"
    case "degraded": return "部分可用"
    case "degraded_dns": return "网络通，DNS 不通"
    case "degraded_service": return "网络通，网页打不开"
    case "data_fail": return "网络不通"
    case "backend_fail": return "网络不通（后端路径不通）"
    case "fail", "failed": return "失败"
    case "error": return "错误"
    case "tripped": return "已触发"
    case "open": return "已打开"
    case "starting": return "启动中"
    case "stopping": return "停止中"
    case "stopped": return "已停止"
    case "skip", "skipped": return "已跳过"
    case "idle": return "空闲"
    case "pending": return "等待中"
    case "unknown": return "未知"
    case "unreachable": return "适配器未响应"
    case "front_fail": return "本地转发探测未通过"
    default: return rawStatus
    }
}

func adapterStatusColor(_ rawStatus: String?) -> Color {
    guard let rawStatus else { return .secondary }
    switch rawStatus.lowercased() {
    case "ready", "pass", "active", "clear", "closed":
        return .green
    case "switching", "reconnecting", "waiting_network", "network_recovering", "candidate", "draining", "external", "half_open":
        return .orange
    // 部分可用（例如网络通但 DNS 不通）是"能连出去、但有一项不通"，
    // 用橙色警告色，不要和"完全上不了网"的红色混为一谈。
    case "degraded", "degraded_dns", "degraded_service":
        return .orange
    case "front_fail", "unreachable", "data_fail", "backend_fail", "fail", "failed", "error", "tripped", "open":
        return .red
    default:
        return .secondary
    }
}

func localizedSwitchReason(_ reason: String?) -> String {
    guard let reason, !reason.isEmpty else { return "—" }
    switch reason.lowercased() {
    case "startup": return "启动"
    case "startup-retry": return "启动重试"
    case "startup-noop": return "启动（当前节点无需切换）"
    case "startup-retry-noop": return "启动重试（当前节点无需切换）"
    case "select", "user-select": return "用户选择节点"
    case "select-noop": return "继续使用当前节点"
    case "reconnect": return "用户重连"
    case "reconnect-break-before-make": return "同节点重连"
    case "network-resume-original": return "本机网络恢复后重建原路径"
    case "network-resume-fallback": return "原路径未通过，已恢复同城备用节点"
    case "ss-endpoint-recovery", "ss-endpoint-recovery-break-before-make": return "网络不通，已自动换入口"
    case "worker-crash-recovery": return "连接进程崩溃后自动恢复"
    case "reconnect-rollback": return "重连回滚"
    case "health-recovery": return "健康检查自动恢复"
    case "dns-recovery-probe": return "DNS 不通，已自动换节点"
    case "auto-recovery": return "自动恢复"
    default: return reason
    }
}

func localizedRoutingEvent(_ event: String?) -> String {
    guard let event, !event.isEmpty else { return "—" }
    switch event.lowercased() {
    case "action-accepted": return "已接受切换请求"
    case "switch-committed": return "新路径已提交"
    case "graceful-drain-started": return "旧连接留在旧节点上继续用"
    case "previous-drain-preempted": return "为再次切换结束了上一代旧连接"
    case "speedtest-slot-freed": return "测速前结束了旧节点上的残留连接"
    case "drain-preemption-deferred": return "读不到旧连接数，为安全起见暂缓连续切换"
    case "failed-path-retired": return "故障旧路径已立即退役"
    case "front-restarted": return "本地前端已重启"
    case "front-hung-restart": return "本地前端无响应后已重启"
    case "front-restarted-during-switch": return "切换过程中本地前端已重建"
    case "front-data-path-restarted": return "前端数据路径已自动重建"
    case "front-selector-repaired": return "前端选择器已自动校正"
    case "active-worker-crashed": return "正在用的连接进程异常退出"
    case "dead-draining-worker-retired": return "收尾中的旧节点进程异常退出，已清理"
    case "stale-recovery-suppressed": return "已抑制过期自动恢复"
    case "common-dns-failure-detected": return "多个节点同时 DNS 不通，已停止换节点"
    case "persistence-warning": return "状态持久化告警"
    default: return event
    }
}

/// 把 daemon 的综合就绪度翻译成一句人话结论。
///
/// 文案规范（用户明确要求）：**网络和 DNS 分开陈述**，
/// 说"网络通、DNS 不通"这种两个事实，不用"降级"这类抽象词。
func readinessHeadline(_ rawStatus: String?) -> String {
    switch (rawStatus ?? "").lowercased() {
    case "ready": return "Mullvad 连接正常"
    case "switching": return "正在切换节点…"
    case "reconnecting": return "正在重连当前节点…"
    case "waiting_network": return "本机网络断开，等待恢复"
    case "network_recovering": return "本机网络恢复，正在验证原连接"
    case "starting": return "正在启动…"
    case "degraded_dns": return "能连出去，但 DNS 不通 —— 网页打不开"
    case "degraded_service": return "网络通、DNS 通，但网页打不开"
    case "degraded": return "能连出去，但有一项不通"
    case "data_fail": return "上不了网"
    case "backend_fail": return "上不了网（后端路径不通）"
    case "fail", "failed", "error": return "连接失败"
    case "idle", "stopped", "": return "已停止"
    default: return localizedAdapterStatus(rawStatus)
    }
}

/// 一条独立事实：网络 / DNS 各自"通"还是"不通"。
struct ReadinessFact: Identifiable {
    let id: String
    let label: String
    let isOK: Bool
    let detail: String
    let extra: String?
}

/// 从最近一次金丝雀探针里拆出"网络"和"DNS"两个独立事实。
///
/// 与 daemon 的 `classify_canary` 保持一致：
/// - 网络通 = `ip_data` 或 `https_data` 有一个 pass
/// - DNS 通 = `inner_dns` pass
/// 没有探针数据时返回空数组，调用方不要显示这一块。
func readinessFacts(for status: AdapterStatus) -> [ReadinessFact] {
    guard status.localNetwork?.paused != true, status.localNetwork?.recoveryPending != true else { return [] }
    guard let canary = status.lastCanary else { return [] }
    return readinessFacts(
        ipData: canary.ipData,
        httpsData: canary.httpsData,
        innerDNS: canary.innerDNS
    )
}

/// 同上，用于单个节点的测速结果。
func readinessFacts(for result: RelaySpeedTestResult) -> [ReadinessFact] {
    readinessFacts(
        ipData: result.ipData,
        httpsData: result.httpsData,
        innerDNS: result.innerDNS
    )
}

func readinessFacts(
    ipData: CanaryCheck?,
    httpsData: CanaryCheck?,
    innerDNS: CanaryCheck?
) -> [ReadinessFact] {
    guard ipData != nil || httpsData != nil || innerDNS != nil else { return [] }

    let ipOK = ipData?.status?.lowercased() == "pass"
    let httpsOK = httpsData?.status?.lowercased() == "pass"
    let dnsOK = innerDNS?.status?.lowercased() == "pass"
    let networkOK = ipOK || httpsOK

    let networkDelay = ipData?.delayMs ?? httpsData?.delayMs
    let dnsDelay = innerDNS?.delayMs

    return [
        ReadinessFact(
            id: "network",
            label: "网络",
            isOK: networkOK,
            detail: networkOK ? "通" : "不通",
            extra: networkOK ? networkDelay.map { "\($0) ms" } : nil
        ),
        ReadinessFact(
            id: "dns",
            label: "DNS",
            isOK: dnsOK,
            detail: dnsOK ? "通" : "不通",
            extra: dnsOK ? dnsDelay.map { "\($0) ms" } : nil
        ),
    ]
}

/// 单个事实的展示胶囊：`网络 ✅ 通 · 142 ms`
struct ReadinessFactChip: View {
    let fact: ReadinessFact

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: fact.isOK ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundStyle(fact.isOK ? Color.green : Color.red)
            Text(fact.label)
                .foregroundStyle(.secondary)
            Text(fact.detail)
                .fontWeight(.semibold)
                .foregroundStyle(fact.isOK ? Color.primary : Color.red)
            if let extra = fact.extra {
                Text(extra)
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
        .font(.callout)
        .padding(.horizontal, 12)
        .padding(.vertical, 7)
        .background(
            (fact.isOK ? Color.green : Color.red).opacity(0.10),
            in: RoundedRectangle(cornerRadius: 9)
        )
    }
}

func formatAdapterSeconds(_ value: Double) -> String {
    if value < 60 {
        return String(format: "%.0f 秒", value)
    }
    if value < 3_600 {
        return String(format: "%.1f 分钟", value / 60)
    }
    return String(format: "%.1f 小时", value / 3_600)
}

func formatAdapterCountdown(_ value: Int) -> String {
    let seconds = max(value, 0)
    let hours = seconds / 3_600
    let minutes = (seconds % 3_600) / 60
    let remainder = seconds % 60
    if hours > 0 {
        return String(format: "%d:%02d:%02d", hours, minutes, remainder)
    }
    return String(format: "%02d:%02d", minutes, remainder)
}

func shortAdapterTime(_ iso8601: String) -> String {
    guard let date = ISO8601DateFormatter().date(from: iso8601) else { return iso8601 }
    return date.formatted(date: .omitted, time: .shortened)
}
