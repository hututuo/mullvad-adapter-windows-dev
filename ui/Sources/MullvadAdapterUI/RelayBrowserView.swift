import SwiftUI

struct RelayBrowserView: View {
    @ObservedObject var model: AdapterViewModel

    @State private var searchText = ""
    @State private var selectedCountryKey: String?
    @State private var selectedCityKey: String?
    @State private var didAutoLocate = false
    @State private var cachedCountries: [CountryGroup] = []
    @State private var cachedDisplayCountries: [CountryGroup] = []
    @AppStorage("MullvadAdapterUI.relaySortMode") private var relaySortModeRaw = RelaySortMode.stability.rawValue

    private enum RelaySortMode: String, CaseIterable, Identifiable {
        case stability
        case latency
        case name

        var id: String { rawValue }

        var displayName: String {
            switch self {
            case .stability: return "稳定优先"
            case .latency: return "延迟优先"
            case .name: return "名称"
            }
        }
    }

    private struct CityGroup: Identifiable {
        let id: String
        let name: String
        let relays: [RelayInfo]
    }

    private struct CountryGroup: Identifiable {
        let id: String
        let name: String
        let relays: [RelayInfo]
        let cities: [CityGroup]

        var relayCount: Int { relays.count }
    }

    var body: some View {
        VStack(spacing: 0) {
            topBar
            Divider()

            if model.isLoadingRelays && model.relays.isEmpty {
                Spacer()
                ProgressView("正在加载节点…")
                Spacer()
            } else if model.relays.isEmpty {
                Spacer()
                emptyRelays
                Spacer()
            } else {
                HSplitView {
                    countryColumn
                        .frame(minWidth: 138, idealWidth: 154, maxWidth: 176)
                    cityColumn
                        .frame(minWidth: 142, idealWidth: 158, maxWidth: 180)
                    nodeColumn
                        .frame(minWidth: 430, maxWidth: .infinity)
                }
            }
        }
        .task {
            await model.loadRelays()
            rebuildCountryCache()
            await model.loadSpeedTests()
            await model.loadRelayHistory()
            autoLocateCurrentRelay(force: false)
        }
        .onChange(of: model.relays) { _ in
            rebuildCountryCache()
            autoLocateCurrentRelay(force: false)
        }
        .onChange(of: model.status?.activeRelay) { _ in
            autoLocateCurrentRelay(force: true)
        }
        .onChange(of: searchText) { _ in
            cachedDisplayCountries = searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                ? cachedCountries : buildCountries(from: filteredRelays)
            ensureSelectionVisible()
        }
    }

    private var topBar: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("全部节点")
                        .font(.title2.weight(.semibold))
                    if let current = model.status?.activeRelay {
                        Text("当前：\(current) · 实际方式：\(TransportPreference.shortDisplayName(for: model.status?.activeTransportMode ?? model.status?.activeTransport))")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    } else {
                        Text("尚无活动节点")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                Spacer(minLength: 12)

                Menu {
                    if pinnedRelayInfos.isEmpty {
                        Text("尚未置顶节点")
                    } else {
                        ForEach(pinnedRelayInfos) { relay in
                            Button { locateRelay(relay) } label: {
                                Text("\(relay.hostname) · \(relay.countryDisplayName) / \(relay.cityDisplayName)")
                            }
                        }
                    }
                } label: {
                    Label("常用节点", systemImage: pinnedRelayInfos.isEmpty ? "pin" : "pin.fill")
                }
                .help(pinnedRelayInfos.isEmpty ? "暂无置顶节点" : "快速定位到已置顶节点")

                Button {
                    model.reloadRelays()
                } label: {
                    Label("刷新节点", systemImage: "arrow.clockwise")
                }
                .disabled(model.isLoadingRelays || model.isBusy || model.isSpeedTesting)
            }

            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("搜索国家、城市、hostname 或提供商", text: $searchText)
                    .textFieldStyle(.plain)
                if !searchText.isEmpty {
                    Button {
                        searchText = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .help("清空搜索")
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .frame(minWidth: 260, idealWidth: 380, maxWidth: 520)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            .overlay {
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color.secondary.opacity(0.16), lineWidth: 1)
            }

            HStack(alignment: .center, spacing: 12) {
                Text("连接方式")
                    .font(.subheadline.weight(.semibold))

                Picker(
                    "连接方式",
                    selection: Binding(
                        get: { model.selectedTransport },
                        set: { model.setSelectedTransport($0) }
                    )
                ) {
                    ForEach(TransportPreference.allCases) { transport in
                        Text(transport.displayName).tag(transport)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(maxWidth: 520)
                .disabled(model.isBusy || model.isSpeedTesting)

                Spacer(minLength: 0)
            }

            HStack(alignment: .center, spacing: 10) {

                Button {
                    model.testCurrentRelaySpeed()
                } label: {
                    Label("完整测速当前节点", systemImage: "gauge.with.dots.needle.67percent")
                        .padding(.horizontal, 10).padding(.vertical, 6).contentShape(Rectangle())
                }
                .disabled(model.status?.activeRelay == nil || model.isBusy || model.isSpeedTesting)

                if model.transportSelectionNeedsApply {
                    Button {
                        model.applySelectedTransportToCurrentRelay()
                    } label: {
                        Label("应用到当前节点", systemImage: "arrow.triangle.2.circlepath")
                            .padding(.horizontal, 10).padding(.vertical, 6).contentShape(Rectangle())
                    }
                    .disabled(model.isBusy || model.isSpeedTesting)
                }

                Spacer(minLength: 0)
            }

            Text(model.transportSelectionNeedsApply
                 ? "应用连接方式会短暂中断当前节点；确认后点击“应用到当前节点”。"
                 : model.selectedTransport == .auto
                    ? "自动优先近期验证可用的链路；无记录时从 SS 开始。测速不会自动切换当前节点。"
                    : "测速只检查连接；需要使用其他节点时点击“切换”。")
                .font(.caption)
                .foregroundStyle(model.transportSelectionNeedsApply ? Color.orange : Color.secondary)
                .lineLimit(2)
                .frame(maxWidth: .infinity, alignment: .leading)
                .frame(height: 32, alignment: .topLeading)

        }
        .padding(14)
    }

    private var countryColumn: some View {
        VStack(spacing: 0) {
            columnHeader("国家与地区", detail: "\(displayCountries.count) 个")
            Divider()

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 4) {
                    if searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        if !pinnedCountries.isEmpty {
                            sectionLabel("置顶地区")
                            ForEach(pinnedCountries) { country in
                                countryRow(country, kind: .pinned)
                            }
                        }

                        if !quickCountries.isEmpty {
                            sectionLabel("快捷")
                            ForEach(quickCountries) { country in
                                countryRow(country, kind: .quick)
                            }
                        }

                        if !recentCountries.isEmpty {
                            sectionLabel("最近使用")
                            ForEach(recentCountries) { country in
                                countryRow(country, kind: .recent)
                            }
                        }

                        if !remainingCountries.isEmpty {
                            sectionLabel("全部国家与地区")
                            ForEach(remainingCountries) { country in
                                countryRow(country, kind: .normal)
                            }
                        }
                    } else if displayCountries.isEmpty {
                        Text("没有匹配的国家或地区")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .padding(12)
                    } else {
                        sectionLabel("搜索结果")
                        ForEach(displayCountries) { country in
                            countryRow(country, kind: .normal)
                        }
                    }
                }
                .padding(8)
            }
        }
        .background(Color(nsColor: .controlBackgroundColor))
    }

    private var cityColumn: some View {
        VStack(spacing: 0) {
            columnHeader("城市", detail: selectedCountry.map { "\($0.cities.count) 个" } ?? "—")
            Divider()

            if let country = selectedCountry {
                ScrollView {
                    LazyVStack(spacing: 5) {
                        ForEach(orderedCities(country.cities)) { city in
                            cityRow(city)
                        }
                    }
                    .padding(8)
                }
            } else {
                placeholderColumn("选择一个国家或地区")
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var nodeColumn: some View {
        VStack(spacing: 0) {
            if let city = selectedCity {
                nodeHeader(city)
                Divider()
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(orderedRelays(city.relays)) { relay in
                            nodeRow(relay)
                        }
                    }
                    .padding(12)
                }
            } else {
                placeholderColumn("选择一个城市查看节点")
            }
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private enum CountryRowKind: Equatable {
        case pinned
        case quick
        case recent
        case normal
    }

    private func countryRow(_ country: CountryGroup, kind: CountryRowKind) -> some View {
        let isSelected = country.id == selectedCountryKey
        let isCurrent = country.id == currentRelay?.countryKey
        let isPinned = model.isCountryPinned(country.id)

        return HStack(spacing: 3) {
            Button {
                selectCountry(country.id)
            } label: {
                HStack(spacing: 8) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(country.name)
                            .lineLimit(1)
                        HStack(spacing: 5) {
                            Text("\(country.relayCount) 个节点")
                            if isCurrent {
                                Text("当前").foregroundStyle(.green)
                            } else if kind == .pinned {
                                Text("置顶").foregroundStyle(Color.accentColor)
                            } else if kind == .recent {
                                Text("最近")
                            } else if country.id == "US" && kind == .quick {
                                Text("美国快捷")
                            }
                        }
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 2)
                    if isSelected {
                        Image(systemName: "chevron.right")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(Color.accentColor)
                    }
                }
                .padding(.leading, 8)
                .padding(.vertical, 7)
                .frame(maxWidth: .infinity, alignment: .leading)
                .frame(minHeight: 48, alignment: .leading)
                .background(isSelected ? Color.accentColor.opacity(0.12) : Color.clear, in: RoundedRectangle(cornerRadius: 7))
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            pinButton(isPinned: isPinned, itemName: "地区") {
                model.toggleCountryPinned(country.id)
            }
        }
    }

    private func cityRow(_ city: CityGroup) -> some View {
        let isSelected = city.id == selectedCityKey
        let isCurrent = city.id == currentRelay?.cityKey
        let isPinned = model.isCityPinned(city.id)

        return HStack(spacing: 3) {
            Button {
                selectedCityKey = city.id
            } label: {
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(city.name).lineLimit(1)
                        Spacer(minLength: 2)
                        Text("\(city.relays.count)")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    HStack(spacing: 6) {
                        Text(citySpeedSummary(city.relays))
                        if isCurrent {
                            Text("当前城市").foregroundStyle(.green)
                        } else if isPinned {
                            Text("置顶").foregroundStyle(Color.accentColor)
                        }
                    }
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                }
                .padding(.leading, 8)
                .padding(.vertical, 7)
                .frame(maxWidth: .infinity, alignment: .leading)
                .frame(minHeight: 56, alignment: .leading)
                .background(isSelected ? Color.accentColor.opacity(0.12) : Color.clear, in: RoundedRectangle(cornerRadius: 7))
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            pinButton(isPinned: isPinned, itemName: "城市") {
                model.toggleCityPinned(city.id)
            }
        }
    }

    private func nodeHeader(_ city: CityGroup) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            VStack(alignment: .leading, spacing: 3) {
                Text(city.name)
                    .font(.title3.weight(.semibold))
                Text("\(city.relays.count) 个节点 · \(citySpeedSummary(city.relays)) · 测速方式：\(model.selectedTransport.displayName)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            HStack(alignment: .center, spacing: 10) {
                Menu {
                    ForEach(RelaySortMode.allCases) { mode in
                        Button {
                            relaySortModeRaw = mode.rawValue
                        } label: {
                            if mode == relaySortMode {
                                Label(mode.displayName, systemImage: "checkmark")
                            } else {
                                Text(mode.displayName)
                            }
                        }
                    }
                } label: {
                    Label("排序：\(relaySortMode.displayName)", systemImage: "arrow.up.arrow.down")
                }
                .help("手动置顶和当前节点始终在最前；其余节点按这里的方式排序")

                Spacer(minLength: 0)

                if model.isSequentialSpeedTesting {
                    Button(role: .cancel) {
                        model.cancelBatchSpeedTest()
                    } label: {
                        Label("取消批量测速", systemImage: "xmark.circle")
                    }
                } else {
                    Button {
                        model.startQuickTest(relays: city.relays, label: city.name, cityConcurrency: true)
                    } label: {
                        Label("快速检查本市", systemImage: "bolt.horizontal.circle")
                    }
                    .help("只做入口 ICMP 检查；本市最多并发 4 路，不会切换节点")

                    Menu {
                        if let country = selectedCountry {
                            Button("快速检查整个国家（逐节点）") {
                                model.startQuickTest(relays: country.relays, label: country.name, cityConcurrency: false)
                            }
                        }

                        Divider()

                        Button {
                            model.startBatchSpeedTest(
                                relays: city.relays,
                                label: "完整验证本市",
                                transport: model.selectedTransport,
                                intervalSeconds: 0
                            )
                        } label: {
                            Text("完整验证本市（\(city.relays.count) 个节点）")
                        }

                        if let country = selectedCountry {
                            Button {
                                model.startBatchSpeedTest(
                                    relays: country.relays,
                                    label: "完整验证国家 · \(country.name)",
                                    transport: model.selectedTransport,
                                    intervalSeconds: 3
                                )
                            } label: {
                                Text("完整验证国家（\(country.relayCount) 个节点，逐个）")
                            }
                        }

                        Divider()

                        Button {
                            model.startBatchSpeedTest(
                                relays: city.relays,
                                label: "完整验证本市（慢速）",
                                transport: model.selectedTransport,
                                intervalSeconds: 3
                            )
                        } label: {
                            Text("高级：本市慢速验证（每节点额外等待 3 秒）")
                        }
                    } label: {
                        Label("更多测速", systemImage: "ellipsis.circle")
                    }
                    .disabled(model.isBusy || model.isSpeedTesting)
                }
            }

            VStack(alignment: .leading, spacing: 4) {
                if let progress = model.batchSpeedProgress {
                    ProgressView(value: Double(progress.completed), total: Double(max(progress.total, 1)))
                    Text("\(progress.completed) / \(progress.total) · \(progress.currentHostname ?? "等待下一节点") · \(progress.intervalDescription)")
                        .monospacedDigit()
                } else {
                    Text(model.isQuickTesting ? (model.speedMessage ?? "正在快速测速…") : "快速：仅入口 Ping；完整：隧道、DNS、HTTPS。切换前会验证。")
                }
            }
            .font(.caption2)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            .frame(maxWidth: .infinity, alignment: .leading)
            .frame(height: 36, alignment: .center)

        }
        .padding(12)
    }

    private func nodeRow(_ relay: RelayInfo) -> some View {
        let isCurrent = relay.hostname == model.status?.activeRelay
        let isSelecting = relay.hostname == model.selectingRelayHostname
        let speed = model.speedState(for: relay.hostname)
        let history = model.historySummary(for: relay.hostname)

        return VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .center, spacing: 10) {
                HStack(spacing: 7) {
                    Text(relay.hostname)
                        .font(.headline.monospaced())
                        .lineLimit(1)
                    if isCurrent {
                        Label("当前", systemImage: "checkmark.circle.fill")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.green)
                    }
                    pinButton(isPinned: model.isRelayPinned(relay.hostname), itemName: "节点") {
                        model.toggleRelayPinned(relay.hostname)
                    }
                }
                Spacer(minLength: 8)
            }

            HStack(alignment: .center, spacing: 8) {
                VStack(alignment: .leading, spacing: 2) {
                    if let quick = model.quickPingResults["\(relay.hostname)|\(model.selectedTransport.rawValue)"] {
                        Text(quick.milliseconds.map { "入口 ICMP \(Int($0.rounded())) ms · 未验证隧道" } ?? "入口 ICMP 无回复 · 不代表节点不可用")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .help("\(quick.target) · \(quick.interface ?? "接口未记录") · \(quick.testedAt.formatted()) · \(quick.detail)")
                    }
                    speedStatus(speed, requestedTransport: model.selectedTransport)
                }
                    .frame(minWidth: 180, maxWidth: .infinity, alignment: .leading)
                    .frame(height: 56, alignment: .leading)
                    .clipped()

                Spacer(minLength: 4)

                Menu {
                    Button("快速测速（入口 Ping）") {
                        model.startQuickTest(relays: [relay], label: relay.hostname, cityConcurrency: false)
                    }
                    Button("完整测速（验证可用性）") {
                        model.testRelaySpeed(hostname: relay.hostname, transport: model.selectedTransport)
                    }
                } label: {
                    Text("测速").frame(width: 68, height: 34).contentShape(Rectangle())
                }
                .buttonStyle(.bordered)
                .disabled(model.isBusy || model.isSpeedTesting)

                Button {
                    model.selectRelay(hostname: relay.hostname, transport: model.selectedTransport)
                } label: {
                    if isSelecting {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Text(isCurrent ? "当前" : "切换")
                    }
                }
                .frame(width: 62, height: 34)
                .contentShape(Rectangle())
                .buttonStyle(.borderedProminent)
                .disabled(isCurrent || model.isBusy || model.isSpeedTesting)
            }

            HStack(spacing: 6) {
                relayTag("提供商：\(relay.provider ?? "未知")")
                relayTag(relay.ownershipDisplayName)
                relayTag("SS 入口：自动 · \(relay.extraSSIPv4 ?? 0)")
                Spacer(minLength: 0)
            }

            HStack(spacing: 6) {
                ForEach(relay.normalizedTransports, id: \.self) { transport in
                    relayTag(TransportPreference.shortDisplayName(for: transport))
                }
                if let history {
                    historySummaryTag(history)
                }
                Spacer(minLength: 0)
            }

            if model.selectedTransport == .auto {
                concreteTransportCacheTags(relay.hostname)
            }
        }
        .padding(11)
        .background(
            isCurrent ? Color.accentColor.opacity(0.08) : Color(nsColor: .controlBackgroundColor),
            in: RoundedRectangle(cornerRadius: 10)
        )
        .overlay {
            RoundedRectangle(cornerRadius: 10)
                .stroke(isCurrent ? Color.accentColor.opacity(0.75) : Color.secondary.opacity(0.14), lineWidth: isCurrent ? 1.5 : 1)
        }
    }

    private func historySummaryTag(_ summary: RelayHistorySummary) -> some View {
        let percent = Int((summary.effectiveReadinessRate * 100).rounded())
        let latency = summary.latencyEwmaMs.map { " · 典型 Ping \(Int($0.rounded())) ms" } ?? ""
        let failureSuffix = summary.consecutiveFailures > 0 ? " · 连败 \(summary.consecutiveFailures)" : ""
        let text = "历史 \(summary.samples) 次 · 就绪 \(percent)%\(latency)\(failureSuffix)"
        let help = [
            "Relay：\(summary.relay)",
            "方式：\(TransportPreference.displayName(for: summary.transportMode))",
            "样本：\(summary.samples)",
            "Relay 存活：\(summary.relayPassSamples)",
            "完整就绪：\(summary.readySamples)",
            "失败：\(summary.failedSamples)",
            "连续失败：\(summary.consecutiveFailures)",
            summary.lastSuccessAt.map { "最近成功：\($0)" },
            summary.lastFailureAt.map { "最近失败：\($0)" }
        ]
        .compactMap { $0 }
        .joined(separator: "\n")

        return Label(text, systemImage: "chart.line.uptrend.xyaxis")
            .font(.caption2.monospacedDigit())
            .foregroundStyle(summary.consecutiveFailures > 0 ? .orange : .secondary)
            .lineLimit(1)
            .help(help)
    }

    @ViewBuilder
    private func speedStatus(_ state: RelaySpeedState, requestedTransport: TransportPreference) -> some View {
        switch state.phase {
        case .idle:
            Text("未测速")
                .font(.callout)
                .foregroundStyle(.secondary)
        case .queued:
            Label("等待测速", systemImage: "clock")
                .font(.callout)
                .foregroundStyle(.secondary)
        case .testing:
            HStack(spacing: 6) {
                ProgressView()
                    .controlSize(.small)
                Text("测速中…")
            }
            .font(.callout)
        case .success:
            VStack(alignment: .leading, spacing: 3) {
                if let delay = state.result?.primaryDelayMs {
                    Text("Ping \(delay) ms")
                        .font(.body.monospacedDigit().weight(.semibold))
                } else {
                    Text("Ping —")
                        .font(.callout.weight(.medium))
                }
                HStack(spacing: 6) {
                    if let result = state.result {
                        let facts = readinessFacts(for: result)
                        if facts.isEmpty {
                            AdapterStatusBadge(rawStatus: result.serviceReadiness)
                        } else {
                            ForEach(facts) { fact in
                                HStack(spacing: 3) {
                                    Image(systemName: fact.isOK ? "checkmark.circle.fill" : "xmark.circle.fill")
                                    Text("\(fact.label)\(fact.detail)")
                                }
                                .font(.caption2.weight(.semibold))
                                .lineLimit(1)
                                .foregroundStyle(fact.isOK ? Color.green : Color.red)
                            }
                        }
                    }
                    if let transport = state.result?.transportMode {
                        Text(
                            requestedTransport == .auto
                                ? "自动→\(TransportPreference.shortDisplayName(for: transport))"
                                : "· \(TransportPreference.shortDisplayName(for: transport))"
                        )
                            .font(.caption2.weight(.medium))
                            .foregroundStyle(.secondary)
                    }
                    if let updatedAt = state.updatedAt {
                        Text(updatedAt.formatted(date: Calendar.current.isDateInToday(updatedAt) ? .omitted : .numeric, time: .shortened))
                            .lineLimit(1)
                            .help("上次测速：\(updatedAt.formatted())；不是实时连接状态")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        case .failed, .unsupported:
            VStack(alignment: .leading, spacing: 2) {
                Text(state.phase == .unsupported ? "测速不可用" : "测速失败")
                    .font(.callout.weight(.medium))
                    .foregroundStyle(.red)
                if let message = state.message {
                    Text(message)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .help(message)
                }
            }
        }
    }

    private func concreteTransportCacheTags(_ hostname: String) -> some View {
        HStack(spacing: 5) {
            Text("具体缓存")
                .font(.caption2)
                .foregroundStyle(.secondary)
            ForEach([TransportPreference.ss, .ipv6, .ipv4], id: \.self) { transport in
                let state = model.speedState(for: hostname, transport: transport)
                cacheTag(transport, state: state)
            }
        }
    }

    private func cacheTag(_ transport: TransportPreference, state: RelaySpeedState) -> some View {
        let text: String
        switch state.phase {
        case .idle:
            text = "\(transport.shortDisplayName) —"
        case .queued:
            text = "\(transport.shortDisplayName) 等待"
        case .testing:
            text = "\(transport.shortDisplayName) 测速中"
        case .success:
            if let delay = state.result?.primaryDelayMs {
                text = "\(transport.shortDisplayName) \(delay) ms"
            } else {
                text = "\(transport.shortDisplayName) 已测"
            }
        case .failed:
            text = "\(transport.shortDisplayName) 失败"
        case .unsupported:
            text = "\(transport.shortDisplayName) 不可用"
        }

        return Text(text)
            .font(.caption2.monospacedDigit())
            .foregroundStyle(.secondary)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Color.secondary.opacity(0.07), in: Capsule())
            .help(cacheHelpText(transport, state: state))
    }

    private func cacheHelpText(_ transport: TransportPreference, state: RelaySpeedState) -> String {
        var parts = ["\(transport.displayName) 最近测速缓存"]
        if let actual = state.result?.transportMode {
            parts.append("实际方式：\(TransportPreference.displayName(for: actual))")
        }
        if let updatedAt = state.updatedAt {
            parts.append("时间：\(updatedAt.formatted(date: .abbreviated, time: .standard))")
        }
        if let message = state.message, !message.isEmpty {
            parts.append(message)
        }
        return parts.joined(separator: "\n")
    }

    private var emptyRelays: some View {
        VStack(spacing: 8) {
            Image(systemName: "network.slash")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            Text("没有可用节点")
                .font(.headline)
            Text("请确认适配器元数据可用，然后刷新节点。")
                .foregroundStyle(.secondary)
        }
    }

    private func placeholderColumn(_ text: String) -> some View {
        VStack {
            Spacer()
            Text(text)
                .foregroundStyle(.secondary)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func columnHeader(_ title: String, detail: String) -> some View {
        HStack {
            Text(title)
                .font(.subheadline.weight(.semibold))
            Spacer()
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 9)
    }

    private func sectionLabel(_ text: String) -> some View {
        Text(text)
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 8)
            .padding(.top, 9)
            .padding(.bottom, 3)
    }

    private func relayTag(_ text: String) -> some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            .fixedSize(horizontal: true, vertical: false)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(Color.secondary.opacity(0.08), in: Capsule())
    }

    private func pinButton(isPinned: Bool, itemName: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: isPinned ? "pin.fill" : "pin")
                .font(.caption.weight(.semibold))
                .foregroundStyle(isPinned ? Color.accentColor : Color.secondary)
                .frame(width: 24, height: 24)
                .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .help(isPinned ? "取消置顶\(itemName)" : "置顶\(itemName)")
    }

    private var currentRelay: RelayInfo? {
        model.relayInfo(for: model.status?.activeRelay)
    }

    private var filteredRelays: [RelayInfo] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return model.relays }
        return model.relays.filter { $0.matchesSearch(query) }
    }

    private var allCountries: [CountryGroup] {
        cachedCountries
    }

    private var displayCountries: [CountryGroup] {
        cachedDisplayCountries
    }

    private func rebuildCountryCache() {
        cachedCountries = buildCountries(from: model.relays)
        cachedDisplayCountries = searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? cachedCountries : buildCountries(from: filteredRelays)
    }

    private var selectedCountry: CountryGroup? {
        guard let selectedCountryKey else { return nil }
        return displayCountries.first { $0.id == selectedCountryKey }
    }

    private var selectedCity: CityGroup? {
        guard let selectedCityKey else { return nil }
        return selectedCountry?.cities.first { $0.id == selectedCityKey }
    }

    private var pinnedCountries: [CountryGroup] {
        guard searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return [] }
        return allCountries
            .filter { model.isCountryPinned($0.id) }
            .sorted { lhs, rhs in
                if lhs.id == currentRelay?.countryKey { return true }
                if rhs.id == currentRelay?.countryKey { return false }
                return lhs.name.localizedStandardCompare(rhs.name) == .orderedAscending
            }
    }

    private var quickCountries: [CountryGroup] {
        guard searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return [] }
        let map = Dictionary(uniqueKeysWithValues: allCountries.map { ($0.id, $0) })
        let pinnedIDs = Set(pinnedCountries.map(\.id))
        var keys: [String] = []
        if let current = currentRelay?.countryKey { keys.append(current) }
        if !keys.contains("US") { keys.append("US") }
        return keys.compactMap { map[$0] }.filter { !pinnedIDs.contains($0.id) }
    }

    private var recentCountries: [CountryGroup] {
        guard searchText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return [] }
        let map = Dictionary(uniqueKeysWithValues: allCountries.map { ($0.id, $0) })
        let excludedIDs = Set((pinnedCountries + quickCountries).map(\.id))
        var seen = Set<String>()
        var output: [CountryGroup] = []
        for hostname in model.recentRelayHostnames {
            guard let relay = model.relayInfo(for: hostname) else { continue }
            let key = relay.countryKey
            guard !excludedIDs.contains(key), seen.insert(key).inserted, let country = map[key] else { continue }
            output.append(country)
        }
        return output
    }

    private var remainingCountries: [CountryGroup] {
        let excluded = Set((pinnedCountries + quickCountries + recentCountries).map(\.id))
        return allCountries.filter { !excluded.contains($0.id) }
    }

    private func buildCountries(from relays: [RelayInfo]) -> [CountryGroup] {
        Dictionary(grouping: relays, by: \.countryKey)
            .compactMap { key, countryRelays in
                guard let first = countryRelays.first else { return nil }
                let cities = Dictionary(grouping: countryRelays, by: \.cityKey)
                    .compactMap { cityKey, cityRelays -> CityGroup? in
                        guard let cityFirst = cityRelays.first else { return nil }
                        return CityGroup(
                            id: cityKey,
                            name: cityFirst.cityDisplayName,
                            relays: cityRelays.sorted { $0.hostname < $1.hostname }
                        )
                    }
                    .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }

                return CountryGroup(
                    id: key,
                    name: first.countryDisplayName,
                    relays: countryRelays,
                    cities: cities
                )
            }
            .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    private func orderedCities(_ cities: [CityGroup]) -> [CityGroup] {
        cities.sorted { lhs, rhs in
            let lhsPinned = model.isCityPinned(lhs.id)
            let rhsPinned = model.isCityPinned(rhs.id)
            if lhsPinned != rhsPinned { return lhsPinned }
            if lhs.id == currentRelay?.cityKey { return true }
            if rhs.id == currentRelay?.cityKey { return false }
            return lhs.name.localizedStandardCompare(rhs.name) == .orderedAscending
        }
    }

    private var relaySortMode: RelaySortMode {
        RelaySortMode(rawValue: relaySortModeRaw) ?? .stability
    }

    private func orderedRelays(_ relays: [RelayInfo]) -> [RelayInfo] {
        relays.sorted { lhs, rhs in
            let lhsPinned = model.isRelayPinned(lhs.hostname)
            let rhsPinned = model.isRelayPinned(rhs.hostname)
            if lhsPinned != rhsPinned { return lhsPinned }
            if lhs.hostname == model.status?.activeRelay { return true }
            if rhs.hostname == model.status?.activeRelay { return false }

            switch relaySortMode {
            case .stability:
                let lhsHistory = model.historySummary(for: lhs.hostname)
                let rhsHistory = model.historySummary(for: rhs.hostname)
                if (lhsHistory != nil) != (rhsHistory != nil) {
                    return lhsHistory != nil
                }
                if let lhsHistory, let rhsHistory {
                    let scoreDelta = lhsHistory.stabilityConfidenceScore - rhsHistory.stabilityConfidenceScore
                    if abs(scoreDelta) > 0.000_1 {
                        return scoreDelta > 0
                    }
                    if lhsHistory.samples != rhsHistory.samples {
                        return lhsHistory.samples > rhsHistory.samples
                    }
                    let lhsDelay = lhsHistory.latencyEwmaMs ?? .greatestFiniteMagnitude
                    let rhsDelay = rhsHistory.latencyEwmaMs ?? .greatestFiniteMagnitude
                    if lhsDelay != rhsDelay {
                        return lhsDelay < rhsDelay
                    }
                }
            case .latency:
                let lhsDelay = sortingDelay(lhs.hostname)
                let rhsDelay = sortingDelay(rhs.hostname)
                if lhsDelay != rhsDelay {
                    return lhsDelay < rhsDelay
                }
            case .name:
                break
            }

            return lhs.hostname.localizedStandardCompare(rhs.hostname) == .orderedAscending
        }
    }

    private func sortingDelay(_ hostname: String) -> Double {
        if let delay = model.speedState(for: hostname).result?.primaryDelayMs {
            return Double(delay)
        }
        return model.historySummary(for: hostname)?.latencyEwmaMs ?? .greatestFiniteMagnitude
    }

    private var pinnedRelayInfos: [RelayInfo] {
        model.relays
            .filter { model.isRelayPinned($0.hostname) }
            .sorted { lhs, rhs in
                let left = "\(lhs.countryDisplayName)|\(lhs.cityDisplayName)|\(lhs.hostname)"
                let right = "\(rhs.countryDisplayName)|\(rhs.cityDisplayName)|\(rhs.hostname)"
                return left.localizedStandardCompare(right) == .orderedAscending
            }
    }

    private func locateRelay(_ relay: RelayInfo) {
        searchText = ""
        selectedCountryKey = relay.countryKey
        selectedCityKey = relay.cityKey
        didAutoLocate = true
    }

    private func citySpeedSummary(_ relays: [RelayInfo]) -> String {
        if let batchID = model.lastQuickPingBatchID {
            let quick = relays.compactMap { model.quickPingResults["\($0.hostname)|\(model.selectedTransport.rawValue)"] }
                .filter { $0.batchID == batchID }
            if !quick.isEmpty {
                let replies = quick.filter { $0.milliseconds != nil }.count
                return "快速 Ping 收到回复 \(replies)/\(quick.count)"
            }
        }
        let states = relays.map { model.speedState(for: $0.hostname) }
        if states.contains(where: { $0.phase == .testing }) {
            return "测速中"
        }

        let successful = states.filter { $0.phase == .success }
        guard !successful.isEmpty else {
            let failures = states.filter { $0.phase == .failed }.count
            return failures > 0 ? "暂无成功结果 · \(failures) 失败" : "未测速"
        }

        let delays = successful.compactMap { $0.result?.primaryDelayMs }
        if let best = delays.min() {
            return "已测 \(successful.count)/\(relays.count) · 最低 Ping \(best) ms"
        }
        return "已测 \(successful.count)/\(relays.count)"
    }

    private func autoLocateCurrentRelay(force: Bool) {
        guard force || !didAutoLocate else { return }
        guard !model.relays.isEmpty else { return }

        if let relay = currentRelay {
            selectedCountryKey = relay.countryKey
            selectedCityKey = relay.cityKey
        } else if selectedCountryKey == nil, let first = quickCountries.first ?? allCountries.first {
            selectedCountryKey = first.id
            selectedCityKey = first.cities.first?.id
        }
        didAutoLocate = true
        ensureSelectionVisible()
    }

    private func ensureSelectionVisible() {
        let countries = displayCountries
        guard !countries.isEmpty else {
            selectedCountryKey = nil
            selectedCityKey = nil
            return
        }

        if let selectedCountryKey,
           let country = countries.first(where: { $0.id == selectedCountryKey }) {
            if let selectedCityKey, country.cities.contains(where: { $0.id == selectedCityKey }) {
                return
            }
            if country.id == currentRelay?.countryKey,
               let currentCity = currentRelay?.cityKey,
               country.cities.contains(where: { $0.id == currentCity }) {
                self.selectedCityKey = currentCity
            } else {
                self.selectedCityKey = country.cities.first?.id
            }
            return
        }

        let preferred = countries.first(where: { $0.id == currentRelay?.countryKey }) ?? countries.first!
        selectedCountryKey = preferred.id
        if preferred.id == currentRelay?.countryKey,
           let currentCity = currentRelay?.cityKey,
           preferred.cities.contains(where: { $0.id == currentCity }) {
            selectedCityKey = currentCity
        } else {
            selectedCityKey = preferred.cities.first?.id
        }
    }

    private func selectCountry(_ key: String) {
        selectedCountryKey = key
        guard let country = displayCountries.first(where: { $0.id == key }) else {
            selectedCityKey = nil
            return
        }

        if key == currentRelay?.countryKey,
           let currentCity = currentRelay?.cityKey,
           country.cities.contains(where: { $0.id == currentCity }) {
            selectedCityKey = currentCity
        } else {
            selectedCityKey = country.cities.first?.id
        }
    }
}
