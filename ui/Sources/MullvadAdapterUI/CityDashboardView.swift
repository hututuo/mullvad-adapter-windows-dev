import SwiftUI

struct CityDashboardView: View {
    @ObservedObject var model: AdapterViewModel
    @State private var managingCities = false
    private let columns = Array(repeating: GridItem(.flexible(), spacing: 14), count: 3)

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 5) {
                        Text("常用城市").font(.largeTitle.weight(.semibold))
                        if model.isPreview { Text("设计预览 · 示例数据").font(.caption).foregroundStyle(.orange) }
                        Text("选一个城市，后台在同城维护和恢复连接。")
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button { managingCities = true } label: {
                        Label("管理城市", systemImage: "slider.horizontal.3").padding(.vertical, 3)
                    }
                    .disabled(model.isBusy || model.isSpeedTesting || model.isSavingCities)
                    Button { Task { await model.loadSnapshot() } } label: {
                        Image(systemName: "arrow.clockwise").padding(3)
                    }.help("刷新城市和连接状态")
                }

                LazyVGrid(columns: columns, spacing: 14) {
                    ForEach(0..<3, id: \.self) { index in
                        if let city = city(at: index) {
                            cityButton(city)
                        } else {
                            Button { managingCities = true } label: {
                                VStack(spacing: 10) {
                                    Image(systemName: "plus.circle").font(.title)
                                    Text("添加常用城市").font(.headline)
                                    Text("最多 3 个").font(.caption).foregroundStyle(.secondary)
                                }
                                .frame(maxWidth: .infinity).frame(height: 144)
                                .background(Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 16))
                                .contentShape(Rectangle())
                            }.buttonStyle(.plain)
                                .disabled(model.isBusy || model.isSpeedTesting)
                        }
                    }
                }

                HStack(alignment: .top, spacing: 14) {
                    primaryCard.frame(maxWidth: .infinity).frame(height: 206, alignment: .top)
                    AppCard("自动恢复") {
                        policyRow("1", "本机断网先等待", "暂停重试和节点切换")
                        policyRow("2", "恢复后先验证原连接", "原路径确实不通，才换同城节点")
                        policyRow("3", "城市由你决定", "自动恢复不会跳到其他城市")
                    }.frame(maxWidth: .infinity).frame(height: 206, alignment: .top)
                }

                AppCard("同城备用候选") {
                    ForEach(0..<2, id: \.self) { index in
                        if index > 0 { Divider() }
                        backupRow(index < (model.cityWorkspace?.selected?.backups.count ?? 0)
                                  ? model.cityWorkspace?.selected?.backups[index] : nil, index: index)
                    }
                }
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: "info.circle")
                    Text(model.status?.localNetwork?.message ?? model.cityErrorMessage ?? "当前城市每 30 秒维护备用候选，其他常用城市每 3 分钟维护。本机断网时暂停维护；切换前才验证完整连接。备用候选不是已连好的备用通道。")
                        .lineLimit(3)
                        .fixedSize(horizontal: false, vertical: true)
                }.font(.caption).foregroundStyle(.secondary).frame(height: 48, alignment: .top)
            }.padding(24).frame(maxWidth: 1160, alignment: .leading)
                .frame(maxWidth: .infinity)
        }
        .sheet(isPresented: $managingCities) { CityManagerView(model: model) }
    }

    private func city(at index: Int) -> CitySummary? {
        guard let workspace = model.cityWorkspace, index < workspace.favoriteCities.count else { return nil }
        return workspace.cities.first { $0.id == workspace.favoriteCities[index] }
    }

    private func cityButton(_ city: CitySummary) -> some View {
        let selected = model.cityWorkspace?.selectedCity == city.id
        return Button { model.selectCity(city.id) } label: {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text(city.countryName).font(.subheadline).foregroundStyle(.secondary)
                    Spacer()
                    Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                        .foregroundStyle(selected ? Color.accentColor : .secondary)
                }
                Text(city.cityName).font(.title2.weight(.semibold)).lineLimit(1).minimumScaleFactor(0.7)
                HStack(spacing: 5) {
                    if model.selectingCityID == city.id { ProgressView().controlSize(.small) }
                    Text(model.selectingCityID == city.id ? "正在验证连接…" : selected ? "当前城市 · \(city.relayCount) 个节点" : "点击连接 · \(city.relayCount) 个节点")
                        .font(.caption).foregroundStyle(selected ? Color.accentColor : .secondary)
                        .lineLimit(1).minimumScaleFactor(0.8)
                }
            }.padding(18).frame(maxWidth: .infinity, alignment: .leading).frame(height: 144)
                .background(selected ? Color.accentColor.opacity(0.09) : Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 16))
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(selected ? Color.accentColor.opacity(0.7) : .secondary.opacity(0.18), lineWidth: selected ? 2 : 1))
                .contentShape(Rectangle())
        }.buttonStyle(.plain).disabled(model.isBusy || model.isSpeedTesting || model.isSavingCities)
            .accessibilityLabel("\(city.countryName) \(city.cityName)，\(selected ? "当前城市" : "连接城市")")
            .help("连接此城市；同城节点验证通过后才切换。")
    }

    private var primaryCard: some View {
        AppCard("当前主节点") {
            HStack {
                Text(model.cityWorkspace?.selected?.cityName ?? "先选择常用城市").font(.title3.weight(.semibold))
                Spacer()
                AdapterStatusBadge(rawStatus: model.displayedStatus)
            }
            Text(model.status?.activeRelay ?? "尚未连接")
                .font(.system(.title3, design: .monospaced)).textSelection(.enabled).lineLimit(1)
            HStack {
                Text(TransportPreference.shortDisplayName(for: model.status?.activeTransportMode))
                    .font(.caption.weight(.semibold)).padding(.horizontal, 9).padding(.vertical, 4)
                    .background(Color.accentColor.opacity(0.1), in: Capsule())
                Spacer()
                Text(model.status?.activeSlot == nil ? "没有活动通道" : "当前活动通道").font(.caption).foregroundStyle(.secondary)
            }
            Text("完整检查：\(shortAdapterTime(model.status?.health?.lastCheckAt ?? model.status?.lastCanary?.at ?? ""))")
                .font(.caption).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading).frame(height: 52, alignment: .bottom)
        }
    }

    private func policyRow(_ number: String, _ title: String, _ detail: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Text(number).font(.caption.weight(.semibold)).frame(width: 22, height: 22)
                .background(Color.secondary.opacity(0.1), in: Circle())
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.subheadline.weight(.medium))
                Text(detail).font(.caption).foregroundStyle(.secondary)
            }
        }.frame(maxWidth: .infinity, minHeight: 42, alignment: .leading)
    }

    private func backupRow(_ node: CityNodeEvidence?, index: Int) -> some View {
        HStack(spacing: 14) {
            Text("\(index + 1)").font(.headline).foregroundStyle(.secondary)
                .frame(width: 32, height: 32).background(Color.secondary.opacity(0.08), in: Circle())
            VStack(alignment: .leading, spacing: 5) {
                Text(node?.relay ?? "暂无同城候选").font(.system(.body, design: .monospaced)).textSelection(.enabled)
                Text(node == nil ? "节点列表更新后会自动补充" : "\(node!.evidenceLabel) · \(TransportPreference.shortDisplayName(for: node?.transport)) · \(shortAdapterTime(node?.checkedAt ?? ""))")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 5) {
                Text(node?.evidence == "recent_ready" ? "近期可用" : "切换前验证")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(node?.evidence == "recent_ready" ? Color.green : .secondary)
                Text(outerDescription(node?.outerProbe)).font(.caption).foregroundStyle(.secondary)
            }
        }.frame(height: 64)
    }

    private func outerDescription(_ probe: CityOuterProbe?) -> String {
        guard let probe else { return "等待外层探测" }
        let mode = probe.transport.map { TransportPreference.shortDisplayName(for: $0) + " " } ?? ""
        let result = probe.status == "pass" ? "外层 \(mode)\(probe.delayMS.map { "\($0) ms" } ?? "可达")" : "\(mode)ICMP 未回应"
        return "\(result) · \(shortAdapterTime(probe.checkedAt ?? ""))"
    }
}

private struct CityManagerView: View {
    private struct Choice: Identifiable {
        let id: String
        let country: String
        let city: String
        let unavailable: Bool
    }
    @ObservedObject var model: AdapterViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var selected: [String] = []
    @State private var search = ""

    private var choices: [Choice] {
        let grouped = Dictionary(grouping: model.relays.filter { $0.location != nil }, by: { $0.location! })
        var values = grouped.values.compactMap(\.first).map {
            Choice(id: $0.location!, country: $0.countryDisplayName, city: $0.cityDisplayName, unavailable: false)
        }
        for city in model.cityWorkspace?.cities ?? [] where !values.contains(where: { $0.id == city.id }) {
            values.append(Choice(id: city.id, country: city.countryName, city: city.cityName, unavailable: true))
        }
        return values.filter {
            search.isEmpty || "\($0.country) \($0.city) \($0.id)".localizedCaseInsensitiveContains(search)
        }.sorted { ($0.country, $0.city) < ($1.country, $1.city) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("管理常用城市").font(.title2.weight(.semibold))
            Text("保存 1–3 个城市。当前城市需要先切换，才能移除。")
                .font(.subheadline).foregroundStyle(.secondary)
            TextField("搜索国家或城市", text: $search).textFieldStyle(.roundedBorder)
            List(choices) { choice in
                let id = choice.id
                let checked = selected.contains(id)
                Button {
                    if checked { selected.removeAll { $0 == id } }
                    else if selected.count < 3 { selected.append(id) }
                } label: {
                    HStack(spacing: 10) {
                        Image(systemName: checked ? "checkmark.circle.fill" : "circle")
                            .foregroundStyle(checked ? Color.accentColor : .secondary)
                        Text(choice.country).foregroundStyle(.secondary)
                        Text(choice.city)
                        Spacer()
                        if choice.unavailable { Text("暂无节点").font(.caption).foregroundStyle(.secondary) }
                        if id == model.cityWorkspace?.selectedCity { Text("当前城市").font(.caption).foregroundStyle(.secondary) }
                    }.padding(.vertical, 8).frame(maxWidth: .infinity).contentShape(Rectangle())
                }.buttonStyle(.plain).disabled(id == model.cityWorkspace?.selectedCity || (!checked && selected.count >= 3) || model.isSavingCities)
            }.frame(height: 370)
                .overlay {
                    if choices.isEmpty {
                        Text(model.isLoadingRelays ? "正在读取城市…" : model.relayErrorMessage ?? "没有匹配的城市")
                            .font(.subheadline).foregroundStyle(.secondary).allowsHitTesting(false)
                    }
                }
            Text(model.cityErrorMessage ?? "已选择 \(selected.count)/3 个城市；其他城市仍可在全部节点页查看。")
                .font(.caption).foregroundStyle(.secondary).frame(height: 32, alignment: .top)
            HStack {
                Spacer()
                Button("取消") { dismiss() }.keyboardShortcut(.cancelAction)
                Button(model.isSavingCities ? "保存中…" : "保存城市") {
                    Task { if await model.saveCities(selected) { dismiss() } }
                }.keyboardShortcut(.defaultAction).disabled(selected.isEmpty || model.isSavingCities)
            }
        }.padding(24).frame(width: 570)
            .onAppear { selected = model.cityWorkspace?.favoriteCities ?? [] }
            .task { await model.loadRelays() }
    }
}
