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
        } message: { Text("会在当前账号下新增设备，占用一个设备名额。密钥先保存在本机钥匙串，只向官方发送公钥；当前连接保留原身份。") }
        .alert("显示新设备私钥？", isPresented: $confirmingDraftKey) {
            Button("取消", role: .cancel) {}
            Button("显示新设备私钥") { account.revealDraftKey() }
        } message: { Text("这是本机生成的新设备密钥，当前隧道仍使用原身份。请勿发给别人或写入诊断报告。") }
        .alert("兑换到当前账号？", isPresented: $confirmingVoucher) {
            Button("取消", role: .cancel) {}
            Button("确认兑换") { let code = voucher; voucher = ""; Task { await account.voucher(code) } }
        } message: { Text("兑换码将使用到账号尾号 \(account.snapshot?.accountSuffix ?? "未知")。提交超时后先刷新有效期，避免重复兑换。") }
    }

    private var connectionCard: some View {
        AppCard("连接与账号") {
            HStack(alignment: .top, spacing: 28) {
                VStack(alignment: .leading, spacing: 10) {
                    Text("当前隧道").foregroundStyle(.secondary)
                    AdapterStatusBadge(rawStatus: model.displayedStatus)
                    Text(model.status?.activeRelay ?? "尚无活动节点").font(.callout.monospaced())
                    Text("隧道状态独立于账号 API 是否可达。").font(.caption).foregroundStyle(.secondary)
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
                    } else {
                        Text("登录 Mullvad 账号").font(.headline)
                        SecureField("16 位账号，可粘贴空格分组", text: $number).textFieldStyle(.roundedBorder)
                        Button("验证并保存账号") {
                            let value = number
                            Task { await account.login(value); if account.snapshot?.signedIn == true && !account.hasError { number = "" } }
                        }.disabled(number.isEmpty || account.busy || model.isPreview)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private var identityCard: some View {
        AppCard("本机设备与密钥") {
            if let data = account.snapshot {
                KeyValueRow(label: "Mullvad 设备名称", value: data.currentDevice?.name ?? "尚未匹配")
                if data.deviceMatch == "unmatched" {
                    InlineNotice(text: "账号已验证，但此账号中没有当前公钥。当前隧道仍使用原身份；请确认账号是否正确。这里不会自动注册或更换密钥。", kind: .warning)
                } else if data.deviceMatch == "unknown" {
                    Text("登录并刷新后，将按当前公钥匹配官方设备名称。").foregroundStyle(.secondary)
                }
                KeyValueRow(label: "WireGuard 公钥", value: data.publicKey, monospaced: true)
                HStack {
                    Button("复制公钥", systemImage: "doc.on.doc") { copyPublicKey(data.publicKey) }
                    Button(account.privateKey == nil ? "查看本机私钥…" : "隐藏私钥", systemImage: "key") {
                        if account.privateKey == nil { confirmingKey = true } else { account.hideKey() }
                    }.disabled(account.busy || model.isPreview)
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
            HStack {
                Button("为本机创建新设备…") { confirmingCreate = true }
                    .disabled(account.busy || account.snapshot?.verified != true || model.isPreview || (account.deviceDraft != nil && account.deviceDraft?.stage != .prepared) || account.snapshot?.accountFingerprint == nil)
                Text("官方只提供公钥，其他电脑的私钥不能从服务端取回。").font(.caption).foregroundStyle(.secondary)
            }
            if let draft = account.deviceDraft {
                VStack(alignment: .leading, spacing: 8) {
                    Text(draft.device?.name ?? "待核实的新设备").font(.headline)
                    KeyValueRow(label: "新设备公钥", value: draft.publicKey, monospaced: true)
                    Text(draft.stage == .created ? "注册成功，私钥已存入本机钥匙串。当前隧道保留原身份。" : "注册结果待核实，密钥已保留；请刷新设备列表核对，不要重复创建。")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("查看新设备私钥…") { confirmingDraftKey = true }.disabled(account.busy || model.isPreview)
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

    private func copyPublicKey(_ key: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(key, forType: .string)
    }
}
