import SwiftUI
import AppKit

struct AccountView: View {
    @ObservedObject var model: AdapterViewModel
    @ObservedObject private var account: AccountViewModel
    @State private var number = ""
    @State private var voucher = ""
    @State private var removing: AccountDevice?
    @State private var confirmingLogout = false
    @State private var confirmingKey = false
    @State private var confirmingVoucher = false
    @State private var confirmingCreate = false
    @State private var confirmingDraftKey = false
    @State private var confirmingInstall = false
    @State private var confirmingAbandonInstall = false
    @State private var switchingIdentity: SavedLocalIdentity?

    init(model: AdapterViewModel) {
        self.model = model
        account = model.accountManagement
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 5) {
                    Text("账号与设备").font(.largeTitle.bold())
                    Text("Mullvad 账号 · 本机身份 · 设备管理").foregroundStyle(.secondary)
                }
                Spacer()
                if account.busy { ProgressView().controlSize(.small) }
                Button("刷新官方状态", systemImage: "arrow.clockwise") { Task { await account.refresh() } }
                    .disabled(account.busy || account.snapshot?.signedIn != true || model.isPreview)
            }
            HStack(alignment: .center, spacing: 10) {
                Image(systemName: account.hasError ? "exclamationmark.triangle" : "info.circle")
                Text(account.message).font(.callout).lineLimit(3).textSelection(.enabled)
                Spacer(minLength: 0)
            }
            .foregroundStyle(account.hasError ? Color.red : .secondary)
            .padding(12).frame(maxWidth: .infinity, minHeight: 64, maxHeight: 64, alignment: .leading)
            .background(Color.secondary.opacity(0.07), in: RoundedRectangle(cornerRadius: 10))

            ScrollView {
                VStack(spacing: 16) {
                    loginCard
                    connectionCard
                    savedIdentitiesCard
                    identityCard
                    deviceCard
                    accountActions
                }.padding(.bottom, 16)
            }
        }
        .padding(22)
        .task {
            await account.load()
            while !Task.isCancelled {
                do { try await Task.sleep(nanoseconds: 5_000_000_000) } catch { break }
                await account.readLocalSnapshot()
            }
        }
        .onDisappear { account.hideKey(); number = ""; voucher = "" }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in account.hideKey() }
        .alert("切换本机隧道身份？", isPresented: Binding(get: { switchingIdentity != nil }, set: { if !$0 { switchingIdentity = nil } })) {
            Button("取消", role: .cancel) { switchingIdentity = nil }
            Button("切换并连接") {
                if let identity = switchingIdentity {
                    Task { await account.switchIdentity(identity); await model.refreshStatusOnly() }
                }
                switchingIdentity = nil
            }
        } message: {
            Text("切换到账号尾号 \(switchingIdentity?.accountSuffix ?? "—") · \(switchingIdentity?.title ?? "")。会短暂中断当前通道，再用所选身份重连原节点；失败时可切回。不会创建或撤销官方设备。")
        }
        .alert("撤销设备？", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } })) {
            Button("取消", role: .cancel) { removing = nil }
            Button("撤销", role: .destructive) {
                if let device = removing { Task { await account.remove(device, allowCurrentIfStopped: device.current && model.connectionsStopped) } }
                removing = nil
            }
        } message: { Text("\(removing?.name ?? "此设备") 将无法再使用这个账号连接。此操作会修改 Mullvad 官方设备列表。") }
        .alert("退出账号管理？", isPresented: $confirmingLogout) {
            Button("取消", role: .cancel) {}
            Button("清除本地登录", role: .destructive) { Task { await account.logout() } }
        } message: { Text("清除本地保存的账号与访问令牌。原 WireGuard 密钥和当前隧道保留；这不是断开网络或撤销设备。") }
        .alert("在本机显示私钥？", isPresented: $confirmingKey) {
            Button("取消", role: .cancel) {}
            Button("显示私钥") { Task { await account.revealKey() } }
        } message: { Text("私钥能用于本机设备身份。请勿发给别人或放进诊断报告；离开页面或切到其他应用时自动隐藏。") }
        .alert("创建本机设备？", isPresented: $confirmingCreate) {
            Button("取消", role: .cancel) {}
            Button("创建设备") { Task { await account.createDevice() } }
        } message: { Text("会在当前账号下新增设备，占用一个设备名额。密钥先保存在本机钥匙串，只向官方发送公钥。这不会安装或更换隧道身份。") }
        .alert("启用此设备作为本机身份？", isPresented: $confirmingInstall) {
            Button("取消", role: .cancel) {}
            Button("安装本机身份") {
                Task { await account.installDraft(); await model.refreshStatusOnly() }
            }
        } message: {
            Text("将本机钥匙串中的密钥与官方分配的地址安装到适配器。仅适用于尚未配置身份的本机，不会替换已有身份。完成后再到城市页选择城市并连接。")
        }
        .alert("放弃未完成的本机安装？", isPresented: $confirmingAbandonInstall) {
            Button("取消", role: .cancel) {}
            Button("保留密钥并放弃安装", role: .destructive) {
                Task { await account.abandonPendingInstallation(); await model.refreshStatusOnly() }
            }
        } message: {
            Text("只释放本机未完成安装的占位，原安装资料和密钥会保留。不会撤销官方设备、释放设备名额或更换当前身份。完成后可明确创建或安装另一设备。")
        }
        .alert("显示新设备私钥？", isPresented: $confirmingDraftKey) {
            Button("取消", role: .cancel) {}
            Button("显示新设备私钥") { account.revealDraftKey() }
        } message: { Text("此操作显示钥匙串中的本机新设备密钥，不会安装或更换隧道身份。请勿发给别人或写入诊断报告。") }
        .alert("兑换到当前账号？", isPresented: $confirmingVoucher) {
            Button("取消", role: .cancel) {}
            Button("确认兑换") { let code = voucher; voucher = ""; Task { await account.voucher(code) } }
        } message: { Text("兑换码将使用到账号尾号 \(account.snapshot?.accountSuffix ?? "未知")。提交超时后先刷新有效期，避免重复兑换。") }
    }

    @ViewBuilder private var savedIdentitiesCard: some View {
        if let identities = account.snapshot?.savedIdentities, !identities.isEmpty {
            AppCard("已保存账号与本机身份") {
                Text("“管理设备”只刷新和管理所选账号，不切换网络；“启用身份”才会重新连接。")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(identities) { identity in
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: identity.current ? "checkmark.circle.fill" : "person.crop.circle")
                            .foregroundStyle(identity.current ? Color.green : .secondary)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(identity.title).font(.headline)
                            Text("账号尾号 \(identity.accountSuffix)\(identity.current ? " · 当前隧道身份" : "")")
                            Text(identity.publicKey).font(.caption.monospaced()).textSelection(.enabled)
                            if identity.nameSource == "not_verified" {
                                Text("账号关联与设备名称待核实；密钥已保留。").font(.caption).foregroundStyle(.orange)
                            }
                            if identity.registrationStatus == "unmatched" {
                                Text("最近的官方列表未找到此公钥；可能已撤销或账号不匹配。密钥仍保留供核对。")
                                    .font(.caption).foregroundStyle(.orange)
                            } else if identity.registrationStatus == "matched" {
                                Text("最近刷新时官方登记匹配；不等于隧道已连通。").font(.caption).foregroundStyle(.secondary)
                            }
                        }.frame(maxWidth: .infinity, alignment: .leading)
                        Button(identity.managing == true ? "刷新设备" : "管理设备") { Task { await account.manageIdentity(identity) } }
                            .buttonStyle(.bordered).disabled(account.busy || model.isPreview)
                            .help("从官方刷新这个保存账号的设备列表，不切换隧道身份")
                        Button(identity.current ? "当前身份" : "启用身份…") { switchingIdentity = identity }
                            .buttonStyle(.bordered).contentShape(Rectangle())
                            .disabled(identity.current || account.busy || model.isBusy || model.isPreview || account.snapshot?.identitySwitchSupported != true)
                    }.padding(10).frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
                }
            }
        }
    }

    private var loginCard: some View {
        AppCard("账号登录与设备管理") {
            Text("可直接输入任一 Mullvad 账号管理设备。账号已满、原设备被撤销或隧道断开，都不需要先切换本机身份。")
                .font(.callout).foregroundStyle(.secondary)
            HStack {
                SecureField("16 位账号，可粘贴空格分组", text: $number)
                    .textFieldStyle(.roundedBorder).onSubmit { loginEnteredAccount() }
                Button("验证并登录管理") { loginEnteredAccount() }
                    .buttonStyle(.borderedProminent).disabled(number.isEmpty || account.busy || model.isPreview)
            }
            if let data = account.snapshot, data.signedIn {
                Text("正在管理：账号尾号 \(data.accountSuffix ?? "—") · 不等于正在用此账号联网")
                    .font(.headline)
                Text(data.freshness?.summary ?? (data.verified ? "上次读取成功，请刷新查看最新设备" : "已保存账号，尚未核实最新设备"))
                    .foregroundStyle(account.hasError ? Color.orange : .secondary)
                Text(data.checkedAt.map { "上次成功核实：\($0)" } ?? "尚无成功核实时间")
                    .font(.caption).foregroundStyle(.secondary)
                Text(data.freshness?.routeDescription ?? "账号服务出口待核实").font(.caption).foregroundStyle(.secondary)
                if let result = data.freshness?.apiLastResult {
                    Text(result.summary).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
                }
                if let expiry = data.expiryDate { Text("账号有效期至 \(expiry.formatted(date: .abbreviated, time: .shortened))").font(.caption) }
            }
            if let warning = account.snapshot?.profileWarning ?? account.snapshot?.identityStoreError {
                InlineNotice(text: warning, kind: .warning)
            }
        }
    }

    private func loginEnteredAccount() {
        guard !number.isEmpty, !account.busy, !model.isPreview else { return }
        let value = number
        Task { await account.login(value); if !account.hasError { number = "" } }
    }

    private var connectionCard: some View {
        AppCard("本机连接 · 与账号管理分开") {
            HStack {
                AdapterStatusBadge(rawStatus: model.displayedStatus)
                Text(model.status?.activeRelay ?? "尚无活动节点").font(.callout.monospaced())
                Spacer()
                Button(model.isStoppingConnections ? "正在停止…" : "停止全部连接", systemImage: "stop.fill") { model.stopConnections() }
                    .buttonStyle(.bordered).disabled(model.isStoppingConnections || model.isPreview)
                Button("重连当前节点", systemImage: "bolt.horizontal.circle") { model.reconnect() }
                    .disabled(model.isBusy || model.status?.activeRelay == nil || model.isPreview)
            }
            Text("停止会关闭本机隧道、转发入口和自动恢复；账号登录、刷新与设备管理继续可用。国内和其他节点的流量仍按 Clash 规则。")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private var identityCard: some View {
        AppCard("本机设备与密钥") {
            if let data = account.snapshot {
                KeyValueRow(label: "Mullvad 设备名称", value: data.currentDevice?.name ?? "尚未匹配")
                if !data.hasLocalIdentity {
                    Text("尚未安装本机 WireGuard 身份，列表中的设备均不标记为当前隧道设备。")
                        .font(.callout).foregroundStyle(.secondary)
                } else if data.deviceMatch == "unmatched" {
                    InlineNotice(text: "账号已验证，但此账号中没有当前公钥。当前隧道仍使用原身份；请确认账号是否正确。这里不会自动注册或更换密钥。", kind: .warning)
                } else if data.deviceMatch == "unknown" {
                    Text("登录并刷新后，将按当前公钥匹配官方设备名称。").foregroundStyle(.secondary)
                }
                KeyValueRow(label: "WireGuard 公钥", value: data.publicKey.isEmpty ? "尚未配置" : data.publicKey, monospaced: true)
                HStack {
                    Button("复制公钥", systemImage: "doc.on.doc") { copyPublicKey(data.publicKey) }
                        .disabled(!data.hasLocalIdentity)
                    Button(account.privateKey == nil || account.privateKeyIsDraft ? "查看本机私钥…" : "隐藏私钥", systemImage: "key") {
                        if account.privateKey == nil || account.privateKeyIsDraft { confirmingKey = true } else { account.hideKey() }
                    }.disabled(account.busy || model.isPreview || !data.hasLocalIdentity)
                }
                if let key = account.privateKey, !account.privateKeyIsDraft { KeyValueRow(label: "本机私钥", value: key, monospaced: true) }
            } else {
                Text("连接配套后台后可读取本机身份。").foregroundStyle(.secondary)
            }
        }
    }

    private var deviceCard: some View {
        AppCard("官方设备列表 · \(account.snapshot?.devices.count ?? 0) 台") {
            if account.snapshot?.verified != true {
                Text("以下可能是上次成功读取的列表；刷新失败不会把旧资料当成最新状态。可重新输入账号，或对保存账号点“管理设备”。").foregroundStyle(.secondary)
            }
            if let pending = account.snapshot?.pendingIdentityInstallation,
               account.snapshot?.hasLocalIdentity == false, !pending.cancellationComplete {
                VStack(alignment: .leading, spacing: 8) {
                    Text(pending.cancellationPending ? "正在恢复本机安装取消记录" : "有一份未完成的本机身份安装").font(.headline)
                    Text("若已不再使用这次安装，可保留资料并释放本机占位，再继续安装其他设备。官方设备和名额保持不变。")
                        .font(.callout).foregroundStyle(.secondary)
                    DisclosureGroup("查看未完成安装的公钥") {
                        KeyValueRow(label: "公钥", value: pending.publicKey, monospaced: true)
                        KeyValueRow(label: "设备 ID", value: pending.deviceID, monospaced: true)
                        Text(pending.accountFingerprint == account.snapshot?.accountFingerprint ? "属于当前管理账号" : "属于之前登录的另一账号")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Button(pending.cancellationPending ? "继续完成本机取消…" : "保留密钥并放弃安装…") { confirmingAbandonInstall = true }
                        .disabled(account.busy || model.isPreview || account.snapshot?.signedIn != true || account.snapshot?.identityAbandonmentSupported != true)
                }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
            }
            if account.snapshot?.devicesFull == true {
                InlineNotice(text: "设备名额已满（\(account.snapshot?.devices.count ?? 0)/\(account.snapshot?.devicesLimit ?? 5)）。仍可登录和管理；先明确选择一台不再使用的设备撤销，再创建。", kind: .warning)
            }
            HStack {
                Button("为本机创建新设备…") { confirmingCreate = true }
                    .disabled(account.busy || account.snapshot?.verified != true || model.isPreview || !canCreateDraft || account.snapshot?.devicesFull == true || account.snapshot?.accountFingerprint == nil)
                Text("官方只提供公钥，其他电脑的私钥不能从服务端取回。").font(.caption).foregroundStyle(.secondary)
            }
            if let draft = account.deviceDraft {
                VStack(alignment: .leading, spacing: 8) {
                    Text(draft.deviceName ?? "待核实的新设备").font(.headline)
                    KeyValueRow(label: "新设备公钥", value: draft.publicKey, monospaced: true)
                    Text(draftStatus(draft))
                        .font(.caption).foregroundStyle(.secondary)
                    if !draft.registrationConfirmed {
                        Button("核对官方登记结果", systemImage: "checkmark.shield") { Task { await account.reconcileDraft() } }
                            .disabled(account.busy || model.isPreview)
                    }
                    if draft.stage == .created {
                        if account.snapshot?.hasLocalIdentity == false {
                            Button("安装为本机身份…", systemImage: "checkmark.shield") { confirmingInstall = true }
                                .disabled(account.busy || account.snapshot?.verified != true || model.isPreview || account.snapshot?.pendingIdentityInstallation?.cancellationPending == true)
                        } else {
                            Text("本机已有隧道身份。新设备密钥已保留，此处不会覆盖现有身份。")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    if draft.stage == .created, account.snapshot?.hasLocalIdentity == true {
                        Button("保存为可选本机身份") { Task { await account.saveDraft() } }
                            .disabled(account.busy || model.isPreview || account.snapshot?.identitySaveSupported != true)
                        if let saved = account.snapshot?.savedIdentities?.first(where: { $0.publicKey == draft.publicKey && $0.accountFingerprint == draft.accountFingerprint }) {
                            Button("启用这个新身份…") { switchingIdentity = saved }
                                .disabled(account.busy || model.isBusy || model.isPreview || saved.current)
                        }
                    }
                    Button(account.privateKeyIsDraft ? "隐藏新设备私钥" : "查看新设备私钥…") {
                        if account.privateKeyIsDraft { account.hideKey() } else { confirmingDraftKey = true }
                    }.disabled(account.busy || model.isPreview)
                    if let key = account.privateKey, account.privateKeyIsDraft { KeyValueRow(label: "新设备私钥 · 本机临时显示", value: key, monospaced: true) }
                }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                  .background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
            }
            ForEach(account.snapshot?.devices ?? []) { device in
                HStack(alignment: .top, spacing: 14) {
                    Image(systemName: device.current ? "desktopcomputer" : "laptopcomputer").font(.title2)
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text(device.name).font(.headline)
                            if device.current { Text(model.connectionsStopped ? "本机已配置 · 已停止" : "本机连接身份").font(.caption).foregroundStyle(.green) }
                        }
                        Text(device.created.map { "注册时间：\($0)" } ?? "注册时间未提供").font(.caption).foregroundStyle(.secondary)
                        DisclosureGroup("查看公钥与设备 ID") {
                            KeyValueRow(label: "公钥", value: device.pubkey, monospaced: true)
                            KeyValueRow(label: "设备 ID", value: device.id, monospaced: true)
                        }.font(.caption)
                    }
                    Spacer(minLength: 0)
                    if !device.current || model.connectionsStopped {
                        Button(device.current ? "撤销本机设备…" : "撤销设备…", role: .destructive) { removing = device }
                            .disabled(account.busy || model.isPreview)
                    }
                }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
            }
            Text("名称由 Mullvad 分配。正在使用的设备受保护；如要撤销本机设备，请先停止全部连接，再明确确认。撤销不会删除本机保留的旧密钥。").font(.caption).foregroundStyle(.secondary)
        }
    }

    private var accountActions: some View {
        AppCard("账号管理") {
            HStack {
                Link("打开官方账号 / 购买时间", destination: URL(string: "https://mullvad.net/account")!)
                Spacer()
                Button("退出账号管理…") { confirmingLogout = true }
                    .disabled(account.snapshot?.signedIn != true || account.busy || model.isPreview)
            }
            HStack {
                SecureField("Mullvad 兑换码", text: $voucher).textFieldStyle(.roundedBorder)
                Button("兑换时间…") { confirmingVoucher = true }
                    .disabled(voucher.isEmpty || account.snapshot?.signedIn != true || account.busy || model.isPreview)
            }
            Text("此页面接入官方账号接口。系统流量入口、DNS 与隧道仍由 Clash 和本适配器管理。").font(.caption).foregroundStyle(.secondary)
        }
    }

    private var canCreateDraft: Bool {
        if let pending = account.snapshot?.pendingIdentityInstallation, !pending.cancellationComplete { return false }
        guard let draft = account.deviceDraft else { return true }
        return draft.stage == .prepared || draft.stage == .activated || draft.stage == .abandoned
    }

    private func draftStatus(_ draft: AccountDeviceDraft) -> String {
        switch draft.stage {
        case .prepared:
            return "本机密钥已保存，尚未确认登记。确认创建时会继续使用此密钥。"
        case .submitted:
            return "注册结果待核实，密钥已保留；请核对官方登记结果，避免重复创建。"
        case .registered:
            return "官方已确认登记，私钥已保留；缺少官方分配的隧道地址，暂不能安装。"
        case .created:
            return "注册成功，官方已分配隧道地址。密钥保存在本机钥匙串，等待安装。"
        case .activated:
            return "已安装为本机身份。可到城市页连接；安装成功不代表隧道已连通。"
        case .abandoned:
            return "已放弃这次本机安装，旧密钥与资料已保留；官方设备仍在。可明确创建下一设备，原设备仍占用名额。"
        }
    }

    private func copyPublicKey(_ key: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key, forType: .string)
    }
}
