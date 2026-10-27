import SwiftUI
import AppKit

struct AccountView: View {
    @ObservedObject var model: AdapterViewModel
    @StateObject private var account: AccountViewModel
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
        _account = StateObject(wrappedValue: AccountViewModel(client: model.accountClient))
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
                    connectionCard
                    savedIdentitiesCard
                    identityCard
                    deviceCard
                    accountActions
                }.padding(.bottom, 16)
            }
        }
        .padding(22)
        .task { await account.load() }
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
                if let device = removing { Task { await account.remove(device) } }
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
            AppCard("保存的本机身份") {
                Text("只启用一条身份。设备名称来自已保存的官方响应；当前登记情况需刷新官方状态核实。")
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
                        Button(identity.current ? "使用中" : "切换…") { switchingIdentity = identity }
                            .buttonStyle(.bordered).contentShape(Rectangle())
                            .disabled(identity.current || account.busy || model.isBusy || model.isPreview || account.snapshot?.identitySwitchSupported != true)
                    }.padding(10).frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 8))
                }
            }
        }
    }

    private var connectionCard: some View {
        AppCard("连接与账号") {
            HStack(alignment: .top, spacing: 28) {
                VStack(alignment: .leading, spacing: 10) {
                    Text("当前隧道").foregroundStyle(.secondary)
                    AdapterStatusBadge(rawStatus: model.displayedStatus)
                    Text(model.status?.activeRelay ?? "尚无活动节点").font(.callout.monospaced())
                    Text("隧道状态独立于账号 API 是否可达。").font(.caption).foregroundStyle(.secondary)
                    if account.snapshot?.hasLocalIdentity == false {
                        InlineNotice(text: "隧道尚未初始化。请登录账号、创建设备并安装本机身份，然后到城市页连接。", kind: .warning)
                    }
                    Button("重连当前节点", systemImage: "bolt.horizontal.circle") { model.reconnect() }
                        .disabled(model.isBusy || model.status?.activeRelay == nil || model.isPreview)
                }.frame(maxWidth: .infinity, alignment: .leading)
                Divider()
                VStack(alignment: .leading, spacing: 10) {
                    if let data = account.snapshot, data.signedIn {
                        Text("账号尾号 \(data.accountSuffix ?? "—")").font(.headline)
                        Text(data.verified ? "账号已验证" : "已保存登录 · 待刷新验证")
                        if let expiry = data.expiryDate {
                            Text("有效期至 \(expiry.formatted(date: .abbreviated, time: .shortened))")
                                .foregroundStyle(expiry < Date() ? Color.red : .primary)
                        }
                        Text(data.checkedAt.map { "官方核实：\($0)" } ?? "尚未核实官方状态")
                            .font(.caption).foregroundStyle(.secondary)
                        if data.deviceSource == "official_api" {
                            Text("设备名称与公钥：官方账号 API").font(.caption).foregroundStyle(.secondary)
                        }
                    } else {
                        Text("登录 Mullvad 账号").font(.headline)
                        SecureField("16 位账号，可粘贴空格分组", text: $number).textFieldStyle(.roundedBorder)
                        Button("验证并保存账号") {
                            let value = number
                            Task { await account.login(value); if account.snapshot?.signedIn == true && !account.hasError { number = "" } }
                        }.disabled(number.isEmpty || account.busy || model.isPreview)
                    }
                    if let data = account.snapshot, let route = data.apiRoute {
                        Text(route == "system_https" ? "账号接口：系统路由 HTTPS" : (data.apiRouteSource == "legacy_local_default" ? "账号接口：沿用旧版本机引导代理" : "账号接口：已配置的本机引导代理"))
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
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
                Text("登录或刷新后显示真实设备列表。").foregroundStyle(.secondary)
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
            HStack {
                Button("为本机创建新设备…") { confirmingCreate = true }
                    .disabled(account.busy || account.snapshot?.verified != true || model.isPreview || !canCreateDraft || account.snapshot?.accountFingerprint == nil)
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
                            if device.current { Text("本适配器正在使用").font(.caption).foregroundStyle(.green) }
                        }
                        Text(device.created.map { "注册时间：\($0)" } ?? "注册时间未提供").font(.caption).foregroundStyle(.secondary)
                        DisclosureGroup("查看公钥与设备 ID") {
                            KeyValueRow(label: "公钥", value: device.pubkey, monospaced: true)
                            KeyValueRow(label: "设备 ID", value: device.id, monospaced: true)
                        }.font(.caption)
                    }
                    Spacer(minLength: 0)
                    if !device.current {
                        Button("撤销设备…", role: .destructive) { removing = device }
                            .disabled(account.busy || model.isPreview)
                    }
                }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.secondary.opacity(0.05), in: RoundedRectangle(cornerRadius: 10))
            }
            Text("名称由 Mullvad 分配。当前设备受保护；其他设备撤销后会失去账号连接权限。").font(.caption).foregroundStyle(.secondary)
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
