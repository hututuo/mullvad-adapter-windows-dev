import SwiftUI

struct ProtectionProfile: Codable, Equatable {
    var multihop: Bool
    var entryCity: String?
    var postQuantum: Bool = false
    enum CodingKeys: String, CodingKey { case multihop; case postQuantum = "post_quantum"; case entryCity = "entry_city" }
    init(multihop: Bool, entryCity: String?, postQuantum: Bool = false) {
        self.multihop = multihop; self.entryCity = entryCity; self.postQuantum = postQuantum
    }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        multihop = try c.decode(Bool.self, forKey: .multihop)
        entryCity = try c.decodeIfPresent(String.self, forKey: .entryCity)
        postQuantum = try c.decodeIfPresent(Bool.self, forKey: .postQuantum) ?? false
    }

}

struct ProtectionSnapshot: Decodable {
    let profile: ProtectionProfile
    let configError: String?
    let effective: ProtectionPath?
    let checkedAt: String?
    let capabilities: [String: String]
    enum CodingKeys: String, CodingKey { case profile, effective, capabilities; case configError = "config_error"; case checkedAt = "checked_at" }
}

struct ProtectionPath: Decodable {
    let relay: String
    let entryRelay: String?
    let entryCity: String?
    let multihop: Bool
    let transportMode: String
    let postQuantum: Bool
    let daita: Bool
    enum CodingKeys: String, CodingKey {
        case relay, multihop, daita
        case entryRelay = "entry_relay", entryCity = "entry_city"
        case transportMode = "transport_mode", postQuantum = "post_quantum"
    }
}

struct ProtectionView: View {
    @ObservedObject var model: AdapterViewModel
    @State private var multihop = false
    @State private var entryCity = ""
    @State private var postQuantum = false
    @State private var confirming = false

    init(model: AdapterViewModel) {
        self.model = model
        _multihop = State(initialValue: model.protection?.profile.multihop ?? false)
        _entryCity = State(initialValue: model.protection?.profile.entryCity ?? "")
        _postQuantum = State(initialValue: model.protection?.profile.postQuantum ?? false)
    }

    private var cities: [(id: String, name: String)] {
        Dictionary(grouping: model.relays, by: { $0.location ?? "" }).compactMap { id, nodes in
            guard !id.isEmpty, let node = nodes.first else { return nil }
            return (id, "\(node.country ?? id) · \(node.city ?? id)")
        }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }
    private var draft: ProtectionProfile {
        ProtectionProfile(multihop: multihop, entryCity: multihop ? entryCity : nil, postQuantum: postQuantum)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 5) {
                    Text("连接保护").font(.largeTitle.bold())
                    Text("入口、出口与实际隧道能力").foregroundStyle(.secondary)
                }
                Spacer()
                Button("刷新状态", systemImage: "arrow.clockwise") { Task { await model.loadProtection() } }
            }
            HStack {
                Image(systemName: model.protectionError == nil ? "info.circle" : "exclamationmark.triangle")
                Text(model.protectionError ?? model.protection?.configError ?? "出口仍由常用城市决定。变更通过验证后才保存；多跳失败不会自动降回单跳。")
                    .font(.callout).lineLimit(3)
                Spacer(minLength: 0)
            }
            .padding(12).frame(maxWidth: .infinity, minHeight: 64, maxHeight: 64, alignment: .leading)
            .background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 10))
            ScrollView {
                VStack(spacing: 16) {
                    AppCard("实际路径 · 最近读取") {
                        Text(model.protection?.checkedAt ?? (model.isPreview ? "示例数据" : "尚未读取"))
                            .font(.caption).foregroundStyle(.secondary)
                        if let path = model.protection?.effective {
                            HStack(spacing: 18) {
                                routeItem("本机", "Clash → 本地适配器", "desktopcomputer")
                                Image(systemName: "arrow.right").foregroundStyle(.secondary)
                                if let entry = path.entryRelay {
                                    routeItem("入口", entry, "point.topleft.down.to.point.bottomright.curvepath")
                                    Image(systemName: "arrow.right").foregroundStyle(.secondary)
                                }
                                routeItem("出口", path.relay, "globe")
                            }.frame(maxWidth: .infinity, alignment: .leading)
                            Divider()
                            Text("\(path.multihop ? "双层 WireGuard 多跳" : "单跳 WireGuard") · \(TransportPreference.displayName(for: path.transportMode))")
                            Text("抗量子：\(path.postQuantum ? "已协商" : "未启用") · DAITA：\(path.daita ? "已启用" : "未启用")")
                                .font(.caption).foregroundStyle(.secondary)
                        } else {
                            Text("尚未确认活动隧道；保存的设置不代表连接已经生效。").foregroundStyle(.secondary)
                        }
                    }
                    AppCard("隧道设置") {
                        Toggle("经另一个入口节点连接出口", isOn: $multihop)
                        Text("出口 IP 保持在你选择的城市。入口可独立选择城市，后台在该城市尝试少量节点和入口，不做全量测速。")
                            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true).frame(maxWidth: 700, alignment: .leading)
                        if multihop {
                            Picker("入口城市", selection: $entryCity) {
                                Text("请选择入口城市").tag("")
                                ForEach(cities, id: \.id) { city in Text(city.name).tag(city.id) }
                            }.frame(maxWidth: 540, alignment: .leading)
                            Text("入口与出口使用不同节点；已有实例占用的入口不会重复建立。多跳会增加延迟与流量开销。")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Divider()
                        Toggle("抗量子密钥协商", isOn: $postQuantum)
                            .disabled(model.protection?.capabilities["post_quantum"] != "single-hop-supported" && !postQuantum)
                        if model.protection?.capabilities["post_quantum"] != "single-hop-supported" {
                            Text("此后台尚未包含抗量子组件，升级完整后台后可启用。")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Text("每次重建时，通过官方 ML-KEM / HQC 协商新的临时身份和预共享密钥。当前已验证单跳；多跳组合尚在验证，暂不能同时开启。缺少组件或协商失败时不会降低保护要求。")
                            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true).frame(maxWidth: 700, alignment: .leading)
                        if multihop && postQuantum {
                            Text("请先关闭其中一项；多跳＋抗量子组合尚未通过验收。")
                                .font(.callout).foregroundStyle(.orange)
                        }
                        Button { confirming = true } label: {
                            Label("验证并应用到当前出口", systemImage: "checkmark.shield")
                                .padding(.vertical, 3).frame(minWidth: 220).contentShape(Rectangle())
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(model.isBusy || model.isSpeedTesting || model.isPreview || model.protection == nil ||
                                  model.status?.activeRelay == nil || (multihop && entryCity.isEmpty) || (multihop && postQuantum) ||
                                  (draft == model.protection?.profile && model.protection?.configError == nil))
                    }
                    AppCard("官方其他保护能力") {
                        capability("SS 传输混淆", "当前后台已支持。是否正在使用以顶部实际路径为准；可在连接概览选择 SS 或自动。", "network")
                        Divider()
                        capability("抗量子隧道", "已接入官方协商器，当前支持单跳。顶部显示活动隧道是否实际完成协商；仅保存设置不代表生效。", "key.fill")
                        Divider()
                        capability("DAITA 流量分析防护", "需要兼容的隧道引擎执行官方填充机器；不是只更改账号设置。当前核心不支持，尚未接入。", "waveform.path")
                        Divider()
                        capability("QUIC、UDP-over-TCP、LWO", "是其他传输混淆方式。需要对应的传输组件和核心支持，目前只有 SS 可用。", "point.3.connected.trianglepath.dotted")
                        Link("查看 Mullvad 官方开源实现", destination: URL(string: "https://github.com/mullvad/mullvadvpn-app")!)
                    }
                }.padding(.bottom, 16)
            }
        }
        .padding(22)
        .task { await reload() }
        .onChange(of: model.status?.generation) { _ in Task { await model.loadProtection() } }
        .alert("重建当前出口连接？", isPresented: $confirming) {
            Button("取消", role: .cancel) {}
            Button("验证并应用") { model.applyProtection(draft) }
        } message: {
            Text("使用同一出口身份需要先关闭旧隧道，期间连接可能短暂中断。新路径未通过会重建原路径；如果回退也失败，保留原保护要求并继续同城恢复。")
        }
    }

    private func reload() async {
        await model.loadProtection()
        if let profile = model.protection?.profile { multihop = profile.multihop; entryCity = profile.entryCity ?? ""; postQuantum = profile.postQuantum }
    }
    private func routeItem(_ title: String, _ value: String, _ icon: String) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Label(title, systemImage: icon).font(.headline)
            Text(value).font(.caption.monospaced()).textSelection(.enabled)
        }
    }
    private func capability(_ title: String, _ detail: String, _ icon: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon).frame(width: 24)
            VStack(alignment: .leading, spacing: 5) {
                Text(title).font(.headline)
                Text(detail).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true).frame(maxWidth: 700, alignment: .leading)
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
}
