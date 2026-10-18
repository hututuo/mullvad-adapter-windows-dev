import SwiftUI

struct HistoryView: View {
    @ObservedObject var model: AdapterViewModel

    @State private var transport: TransportPreference = .ss
    @State private var searchText = ""
    @State private var sortMode: SortMode = .stability

    private enum SortMode: String, CaseIterable, Identifiable {
        case stability
        case samples
        case latency

        var id: String { rawValue }

        var title: String {
            switch self {
            case .stability: return "稳定性"
            case .samples: return "样本数"
            case .latency: return "典型 Ping"
            }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            if entries.isEmpty {
                Spacer()
                VStack(spacing: 8) {
                    Image(systemName: "chart.line.uptrend.xyaxis")
                        .font(.largeTitle)
                        .foregroundStyle(.secondary)
                    Text("还没有这个连接方式的历史样本")
                        .font(.headline)
                    Text("手动测速、候选健康检查和实际使用中的定期健康检查都会自动累计；重启适配器后仍保留。")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 560)
                }
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(spacing: 8) {
                        summaryStrip
                        tableHeader
                        ForEach(entries) { entry in
                            historyRow(entry)
                        }
                    }
                    .padding(14)
                }
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
        .task {
            await model.loadRelayHistory()
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("历史统计")
                        .font(.title2.weight(.semibold))
                    Text("稳定性按历史样本置信度计算；不会让偶然一次 1/1 成功直接排到长期稳定节点前面。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Button {
                    Task { await model.loadRelayHistory() }
                } label: {
                    Label("刷新历史", systemImage: "arrow.clockwise")
                }
            }

            HStack(spacing: 12) {
                Picker("连接方式", selection: $transport) {
                    Text("SS").tag(TransportPreference.ss)
                    Text("IPv6").tag(TransportPreference.ipv6)
                    Text("IPv4").tag(TransportPreference.ipv4)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 270)

                HStack(spacing: 7) {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)
                    TextField("搜索节点、国家、城市或提供商", text: $searchText)
                        .textFieldStyle(.plain)
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 7)
                .frame(minWidth: 250, maxWidth: 430)
                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))

                Picker("排序", selection: $sortMode) {
                    ForEach(SortMode.allCases) { mode in
                        Text(mode.title).tag(mode)
                    }
                }
                .frame(width: 150)

                Spacer(minLength: 0)
            }
        }
        .padding(14)
    }

    private var summaryStrip: some View {
        AppCard("\(transport.shortDisplayName) 历史概览") {
            HStack(spacing: 34) {
                summaryValue("有历史节点", "\(entries.count)")
                summaryValue("累计样本", "\(entries.reduce(0) { $0 + $1.samples })")
                summaryValue("完整就绪", "\(entries.reduce(0) { $0 + $1.readySamples })")
                if let best = topStableEntry {
                    summaryValue("当前稳定性靠前", best.relay)
                }
                Spacer(minLength: 0)
            }
        }
    }

    private func summaryValue(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(value)
                .font(.title3.monospacedDigit().weight(.semibold))
                .lineLimit(1)
                .truncationMode(.middle)
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var tableHeader: some View {
        HStack(spacing: 12) {
            columnHeader("节点", width: 185, alignment: .leading)
            columnHeader("位置", width: 175, alignment: .leading)
            columnHeader("样本", width: 60, alignment: .trailing)
            columnHeader("就绪率", width: 76, alignment: .trailing)
            columnHeader("典型 Ping", width: 92, alignment: .trailing)
            columnHeader("连续失败", width: 76, alignment: .trailing)
            columnHeader("最近观测", width: 135, alignment: .leading)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12)
        .font(.caption.weight(.semibold))
        .foregroundStyle(.secondary)
    }

    private func columnHeader(_ text: String, width: CGFloat, alignment: Alignment) -> some View {
        Text(text)
            .frame(width: width, alignment: alignment)
    }

    private func historyRow(_ entry: RelayHistorySummary) -> some View {
        let relay = model.relayInfo(for: entry.relay)
        let readyPercent = Int((entry.effectiveReadinessRate * 100).rounded())

        return HStack(spacing: 12) {
            HStack(spacing: 6) {
                Text(entry.relay)
                    .font(.callout.monospaced().weight(.medium))
                    .lineLimit(1)
                    .truncationMode(.middle)
                if model.isRelayPinned(entry.relay) {
                    Image(systemName: "pin.fill")
                        .font(.caption2)
                        .foregroundStyle(Color.accentColor)
                }
            }
            .frame(width: 185, alignment: .leading)

            Text(locationText(relay))
                .lineLimit(1)
                .frame(width: 175, alignment: .leading)

            Text("\(entry.samples)")
                .monospacedDigit()
                .frame(width: 60, alignment: .trailing)

            Text("\(readyPercent)%")
                .monospacedDigit()
                .foregroundStyle(readinessColor(entry))
                .frame(width: 76, alignment: .trailing)

            Text(entry.latencyEwmaMs.map { "\(Int($0.rounded())) ms" } ?? "—")
                .monospacedDigit()
                .frame(width: 92, alignment: .trailing)

            Text("\(entry.consecutiveFailures)")
                .monospacedDigit()
                .foregroundStyle(entry.consecutiveFailures > 0 ? Color.orange : Color.secondary)
                .frame(width: 76, alignment: .trailing)

            Text(entry.lastTestedAt.map(shortAdapterTime) ?? "—")
                .frame(width: 135, alignment: .leading)

            Spacer(minLength: 0)
        }
        .font(.callout)
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 9))
        .overlay {
            RoundedRectangle(cornerRadius: 9)
                .stroke(Color.secondary.opacity(0.12), lineWidth: 1)
        }
        .help(historyHelp(entry))
    }

    private var entries: [RelayHistorySummary] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let values = model.relayHistory.values.filter { summary in
            guard summary.transportMode.lowercased() == transport.rawValue else { return false }
            guard !query.isEmpty else { return true }
            if summary.relay.lowercased().contains(query) { return true }
            return model.relayInfo(for: summary.relay)?.searchableText.contains(query) == true
        }

        return values.sorted { lhs, rhs in
            let lhsPinned = model.isRelayPinned(lhs.relay)
            let rhsPinned = model.isRelayPinned(rhs.relay)
            if lhsPinned != rhsPinned { return lhsPinned }

            switch sortMode {
            case .stability:
                if lhs.stabilityConfidenceScore != rhs.stabilityConfidenceScore {
                    return lhs.stabilityConfidenceScore > rhs.stabilityConfidenceScore
                }
                if lhs.samples != rhs.samples { return lhs.samples > rhs.samples }
            case .samples:
                if lhs.samples != rhs.samples { return lhs.samples > rhs.samples }
                if lhs.stabilityConfidenceScore != rhs.stabilityConfidenceScore {
                    return lhs.stabilityConfidenceScore > rhs.stabilityConfidenceScore
                }
            case .latency:
                let lhsLatency = lhs.latencyEwmaMs ?? .greatestFiniteMagnitude
                let rhsLatency = rhs.latencyEwmaMs ?? .greatestFiniteMagnitude
                if lhsLatency != rhsLatency { return lhsLatency < rhsLatency }
            }
            return lhs.relay.localizedStandardCompare(rhs.relay) == .orderedAscending
        }
    }

    private var topStableEntry: RelayHistorySummary? {
        model.relayHistory.values
            .filter { $0.transportMode.lowercased() == transport.rawValue && $0.samples >= 3 }
            .max { lhs, rhs in
                if lhs.stabilityConfidenceScore != rhs.stabilityConfidenceScore {
                    return lhs.stabilityConfidenceScore < rhs.stabilityConfidenceScore
                }
                if lhs.samples != rhs.samples { return lhs.samples < rhs.samples }
                let lhsLatency = lhs.latencyEwmaMs ?? .greatestFiniteMagnitude
                let rhsLatency = rhs.latencyEwmaMs ?? .greatestFiniteMagnitude
                return lhsLatency > rhsLatency
            }
    }

    private func locationText(_ relay: RelayInfo?) -> String {
        guard let relay else { return "—" }
        return "\(relay.countryDisplayName) · \(relay.cityDisplayName)"
    }

    private func readinessColor(_ entry: RelayHistorySummary) -> Color {
        if entry.consecutiveFailures > 0 { return .orange }
        if entry.effectiveReadinessRate >= 0.9 { return .green }
        if entry.effectiveReadinessRate < 0.5 { return .red }
        return .primary
    }

    private func historyHelp(_ entry: RelayHistorySummary) -> String {
        [
            "\(entry.relay) · \(TransportPreference.displayName(for: entry.transportMode))",
            "样本：\(entry.samples)，Relay 存活：\(entry.relayPassSamples)，完整就绪：\(entry.readySamples)，失败：\(entry.failedSamples)",
            "连续失败：\(entry.consecutiveFailures)",
            entry.latencyEwmaMs.map { "典型延迟（EWMA）：\(Int($0.rounded())) ms" },
            entry.bestDelayMs.map { "最好：\($0) ms" },
            entry.worstDelayMs.map { "最慢：\($0) ms" },
            entry.lastSuccessAt.map { "最近成功：\($0)" },
            entry.lastFailureAt.map { "最近失败：\($0)" }
        ]
        .compactMap { $0 }
        .joined(separator: "\n")
    }
}
