import Foundation
import Combine

struct PendingIdentityInstallation: Decodable {
    let accountFingerprint: String
    let deviceID: String
    let publicKey: String
    let metadataSHA256: String
    let hasPendingTemplate: Bool
    let cancellationPending: Bool
    let cancellationComplete: Bool
    enum CodingKeys: String, CodingKey {
        case accountFingerprint = "account_fingerprint", deviceID = "device_id", publicKey = "public_key", metadataSHA256 = "metadata_sha256"
        case hasPendingTemplate = "has_pending_template", cancellationPending = "cancellation_pending", cancellationComplete = "cancellation_complete"
    }
}
struct AbandonedIdentityReceipt: Codable, Equatable {
    let accountFingerprint: String
    let deviceID: String
    let publicKey: String
    let metadataSHA256: String
    let receiptSHA256: String
    func matches(account: String, publicKey: String, deviceID: String?) -> Bool {
        accountFingerprint == account && self.publicKey == publicKey && self.deviceID == deviceID && UUID(uuidString: self.deviceID) != nil &&
            [accountFingerprint, metadataSHA256, receiptSHA256].allSatisfy { $0.count == 64 && $0.allSatisfy(\.isHexDigit) }
    }
    enum CodingKeys: String, CodingKey {
        case accountFingerprint = "account_fingerprint", deviceID = "device_id", publicKey = "public_key", metadataSHA256 = "metadata_sha256", receiptSHA256 = "receipt_sha256"
    }
}
struct AbandonmentStatus: Decodable { let receipt: AbandonedIdentityReceipt? }

struct AccountSnapshot: Decodable {
    var savedIdentities: [SavedLocalIdentity]? = nil
    var activeIdentityID: String? = nil
    var identitySwitchSupported: Bool? = nil
    let signedIn: Bool
    let verified: Bool
    let accountSuffix: String?
    let expiry: String?
    let checkedAt: String?
    let publicKey: String
    let deviceMatch: String
    let devices: [AccountDevice]
    let accountFingerprint: String?
    let identityConfigured: Bool?
    let apiRoute: String?
    let apiRouteSource: String?
    let deviceSource: String?
    let activatedDraftPublicKey: String?
    let activatedDraftDeviceID: String?
    let identityAbandonmentSupported: Bool?
    let pendingIdentityInstallation: PendingIdentityInstallation?
    var hasLocalIdentity: Bool { identityConfigured ?? !publicKey.isEmpty }
    var currentDevice: AccountDevice? { devices.first { $0.current } }
    var expiryDate: Date? {
        guard let expiry else { return nil }
        let formatter = ISO8601DateFormatter()
        if let date = formatter.date(from: expiry) { return date }
        formatter.formatOptions.insert(.withFractionalSeconds)
        return formatter.date(from: expiry)
    }
    enum CodingKeys: String, CodingKey {
        case savedIdentities = "saved_identities", activeIdentityID = "active_identity_id", identitySwitchSupported = "identity_switch_supported"
        case signedIn = "signed_in", verified, accountSuffix = "account_suffix", expiry
        case checkedAt = "checked_at", publicKey = "public_key", deviceMatch = "device_match", devices
        case accountFingerprint = "account_fingerprint"
        case identityConfigured = "identity_configured", apiRoute = "api_route", apiRouteSource = "api_route_source", deviceSource = "device_source"
        case activatedDraftPublicKey = "activated_draft_public_key", activatedDraftDeviceID = "activated_draft_device_id"
        case identityAbandonmentSupported = "identity_abandonment_supported", pendingIdentityInstallation = "pending_identity_installation"
    }
}

struct SavedLocalIdentity: Decodable, Identifiable, Equatable {
    let id: String
    let accountSuffix: String
    let deviceName: String?
    let nameSource: String?
    let publicKey: String
    let current: Bool
    let registrationStatus: String?
    var title: String { deviceName ?? "旧身份 · 设备名待核实" }
    enum CodingKeys: String, CodingKey {
        case id, current, accountSuffix = "account_suffix", deviceName = "device_name", nameSource = "name_source"
        case publicKey = "public_key", registrationStatus = "registration_status"
    }
}

struct AccountDevice: Codable, Identifiable, Equatable {
    let id: String
    let name: String
    let pubkey: String
    let created: String?
    let current: Bool
    var registration: CreatedAccountDevice? = nil
}

struct LocalKey: Decodable {
    let privateKey: String
    enum CodingKeys: String, CodingKey { case privateKey = "private_key" }
}

@MainActor
final class AccountViewModel: ObservableObject {
    @Published private(set) var snapshot: AccountSnapshot?
    @Published private(set) var busy = false
    @Published private(set) var message = "输入账号后验证；不会更换当前密钥或节点。"
    @Published private(set) var hasError = false
    @Published private(set) var privateKey: String?
    @Published private(set) var privateKeyIsDraft = false
    @Published private(set) var deviceDraft: AccountDeviceDraft?
    private let client: AdapterClient
    private let draftStore: any AccountDraftPersisting
    private var keyRevealGeneration = 0
    init(client: AdapterClient, draftStore: any AccountDraftPersisting = AccountDraftStore()) { self.client = client; self.draftStore = draftStore }

    func load() async {
        await perform { try await self.client.account() }
        if !hasError, snapshot?.signedIn == true, snapshot?.verified == false { await refresh() }
    }
    func login(_ number: String) async {
        await perform(success: "账号已验证；本机身份以公钥匹配结果为准。") {
            try await self.client.account("login", payload: ["account_number": number])
        }
    }
    func createDevice() async {
        guard !busy, snapshot?.verified == true, let binding = snapshot?.accountFingerprint else { message = "请先登录配套后台并验证账号。"; hasError = true; return }
        guard snapshot?.pendingIdentityInstallation?.cancellationPending != true else { message = "请先完成未收尾的本机取消事务；旧密钥已保留。"; hasError = true; return }
        hideKey(); busy = true; hasError = false
        defer { busy = false }
        do {
            let store = draftStore
            var draft = try store.load(account: binding) ?? AccountDeviceDraft.generate(account: binding)
            if draft.stage == .activated {
                guard let snapshot, snapshot.verified, snapshot.activatedDraftPublicKey == draft.publicKey,
                      snapshot.activatedDraftDeviceID == draft.device?.id, snapshot.currentDevice?.pubkey == draft.publicKey,
                      snapshot.currentDevice?.id == draft.device?.id else { throw DraftError.corrupt }
                draft = try store.prepareNextDraft(from: draft)
            } else if draft.stage == .abandoned {
                guard let receipt = draft.abandonmentReceipt,
                      receipt.matches(account: binding, publicKey: draft.publicKey, deviceID: draft.device?.id),
                      try await client.abandonmentReceipt(accountFingerprint: binding, publicKey: draft.publicKey, deviceID: receipt.deviceID) == receipt else { throw DraftError.unknown }
                draft = try store.prepareNextDraft(from: draft)
            }
            if draft.registrationConfirmed { deviceDraft = draft; message = "已保留这个新设备，未重复注册。"; return }
            guard draft.stage == .prepared else { throw DraftError.unknown }
            try store.save(draft) // Durable local key before any mutation request.
            draft.stage = .submitted; try store.save(draft); deviceDraft = draft
            let device = try await client.createDevice(publicKey: draft.publicKey, accountFingerprint: binding)
            guard device.pubkey == draft.publicKey else { throw DraftError.unknown }
            draft.device = device; draft.stage = .created; try store.save(draft); deviceDraft = draft
            message = "新设备已注册，私钥保留在本机钥匙串；尚未安装或更换隧道身份。"
            try accept(try await client.account("refresh"))
        } catch {
            // A definite rejection allows a later explicit retry with the same
            // saved key. Timeouts/malformed success never reopen registration.
            if case AdapterClientError.http(_, let code?, _) = error,
               ["http_400", "http_401", "http_403", "http_404", "http_409", "http_429", "invalid_account", "invalid_key", "confirmation_required",
                "account_changed", "account_busy", "not_signed_in"].contains(code),
               var draft = deviceDraft, draft.stage == .submitted {
                draft.stage = .prepared
                do { try draftStore.save(draft); deviceDraft = draft } catch { message = error.localizedDescription; hasError = true; return }
            }
            message = error.localizedDescription; hasError = true
        }
    }
    func abandonPendingInstallation() async {
        guard !busy, let snapshot, !snapshot.hasLocalIdentity, let binding = snapshot.accountFingerprint,
              let pending = snapshot.pendingIdentityInstallation else { message = "仅能放弃无已提交模板的本机未完成安装。"; hasError = true; return }
        hideKey(); busy = true; hasError = false
        defer { busy = false }
        do {
            try accept(try await client.abandonIdentity(accountFingerprint: binding, pending: pending))
            try await restoreAbandonedDraftIfConfirmed()
            message = "本机未完成安装已放弃，旧密钥已保留；官方设备和名额保持不变。"
        } catch {
            let failure = error.localizedDescription
            // GET and local receipt checks only. A lost reply never replays
            // cancellation, device creation, revocation or installation.
            if let fresh = try? await client.account() {
                try? accept(fresh)
                try? await restoreAbandonedDraftIfConfirmed()
            }
            let receipt = try? await client.abandonmentReceipt(accountFingerprint: binding, publicKey: pending.publicKey, deviceID: pending.deviceID,
                installationAccountFingerprint: pending.accountFingerprint, metadataSHA256: pending.metadataSHA256)
            let confirmed = receipt?.matches(account: pending.accountFingerprint, publicKey: pending.publicKey, deviceID: pending.deviceID) == true && receipt?.metadataSHA256 == pending.metadataSHA256
            hasError = !confirmed || self.snapshot?.pendingIdentityInstallation != nil
            message = confirmed ? (hasError ? "旧记录已安全归档，取消事务尚待收尾；请再次确认完成。" : "后台已确认本机安装占位已释放；旧密钥与官方设备均保留。") : failure
        }
    }
    func installDraft() async {
        guard !busy, let snapshot, snapshot.verified, !snapshot.hasLocalIdentity,
              let binding = snapshot.accountFingerprint, let draft = deviceDraft,
              draft.accountFingerprint == binding, draft.stage == .created, let device = draft.device,
              device.hasValidAssignedAddresses else { message = "仅能首次安装已确认官方地址的本机设备；现有身份保持不变。"; hasError = true; return }
        hideKey(); busy = true; hasError = false
        defer { busy = false }
        do {
            try draft.validate(account: binding)
            try accept(try await client.installIdentity(draft: draft))
            guard deviceDraft?.stage == .activated else { throw DraftError.storage }
            message = "本机身份已安装；尚未验证网络连接。请选择城市连接。"
        } catch {
            // Local commit may have completed before a lost reply. Only read
            // back; neither installation nor device registration is replayed.
            let failure = error.localizedDescription
            if let fresh = try? await client.account("refresh") { try? accept(fresh) }
            message = deviceDraft?.stage == .activated ? "已读回本机身份安装结果；尚未验证网络连接。" : failure
            hasError = deviceDraft?.stage != .activated
        }
    }
    func reconcileDraft() async {
        guard !busy, let binding = snapshot?.accountFingerprint, var draft = deviceDraft,
              draft.accountFingerprint == binding else { return }
        hideKey(); busy = true; hasError = false
        defer { busy = false }
        do {
            let official = try await client.reconcileDevice(publicKey: draft.publicKey, accountFingerprint: binding)
            try draft.reconcile(official)
            try draftStore.save(draft)
            deviceDraft = draft
            try accept(try await client.account("refresh"))
            message = "官方已确认本机公钥的登记，私钥已保留；尚未安装或更换隧道身份。"
        } catch { message = error.localizedDescription; hasError = true }
    }
    func revealDraftKey() {
        guard !busy, let draft = deviceDraft, draft.accountFingerprint == snapshot?.accountFingerprint else { return }
        hideKey(); privateKeyIsDraft = true
        privateKey = draft.privateKey.base64EncodedString()
        expireKey(after: keyRevealGeneration)
    }
    private func expireKey(after generation: Int) {
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: 20_000_000_000)
            guard let self, self.keyRevealGeneration == generation else { return }
            self.hideKey()
        }
    }
    func refresh() async {
        await perform(success: "已从 Mullvad 刷新账号与设备列表。") { try await self.client.account("refresh") }
    }
    func switchIdentity(_ identity: SavedLocalIdentity) async {
        guard !busy, !identity.current, snapshot?.identitySwitchSupported == true else { return }
        hideKey(); busy = true; hasError = false
        defer { busy = false }
        do {
            let receipt = try await client.switchIdentity(identity.id, expectedActiveID: snapshot?.activeIdentityID)
            message = "已收到切换请求，正在结束旧通道…"
            let deadline = Date().addingTimeInterval(150)
            while Date() < deadline {
                try await Task.sleep(nanoseconds: 750_000_000)
                let operation = try await client.fetchOperation(receipt.id)
                message = operation.message ?? "正在切换身份并验证连接…"
                if !operation.isRunning {
                    try accept(try await client.account())
                    hasError = operation.state != "succeeded"
                    if hasError {
                        message = snapshot?.activeIdentityID == identity.id
                            ? "已切换到 \(identity.title)，但联网验证未通过。可在主页重试，或切回原身份。"
                            : (operation.error ?? operation.message ?? "身份切换未完成，请刷新后核对。")
                    }
                    return
                }
            }
            throw AdapterClientError.invalidResponse("切换尚未确认完成，请刷新状态核对；不会重复提交。")
        } catch {
            // Read back after an ambiguous response; never replay the switch.
            if let fresh = try? await client.account() { try? accept(fresh) }
            hasError = true; message = error.localizedDescription
        }
    }
    func logout() async {
        hideKey()
        await perform(success: "已清除本地账号登录；当前适配器隧道继续使用原密钥。") {
            try await self.client.account("logout", payload: ["account_fingerprint": self.snapshot?.accountFingerprint ?? ""])
        }
    }
    func remove(_ device: AccountDevice) async {
        guard !device.current else { return }
        await perform(success: "设备已撤销，已刷新官方列表。") {
            try await self.client.account("devices/remove", payload: ["device_id": device.id, "confirm": true, "account_fingerprint": self.snapshot?.accountFingerprint ?? ""])
        }
    }
    func voucher(_ code: String) async {
        await perform(success: "兑换已完成，已刷新有效期。") {
            try await self.client.account("voucher", payload: ["voucher_code": code, "account_fingerprint": self.snapshot?.accountFingerprint ?? ""])
        }
    }
    func revealKey() async {
        guard !busy else { return }
        busy = true
        let generation = keyRevealGeneration
        defer { busy = false }
        do {
            let key = try await client.revealPrivateKey()
            if generation == keyRevealGeneration { privateKeyIsDraft = false; privateKey = key; expireKey(after: generation) }
        }
        catch { message = error.localizedDescription; hasError = true }
    }
    func hideKey() { keyRevealGeneration += 1; privateKey = nil; privateKeyIsDraft = false }
    private func accept(_ value: AccountSnapshot) throws {
        snapshot = value
        deviceDraft = nil
        if let binding = value.accountFingerprint, var draft = try draftStore.load(account: binding) {
            if draft.stage == .created, value.verified, value.hasLocalIdentity,
               value.activatedDraftPublicKey == draft.publicKey, value.activatedDraftDeviceID == draft.device?.id,
               value.currentDevice?.pubkey == draft.publicKey, value.currentDevice?.id == draft.device?.id {
                draft.stage = .activated
                try draftStore.save(draft)
            }
            deviceDraft = draft
        }
    }
    private func restoreAbandonedDraftIfConfirmed() async throws {
        guard snapshot?.identityAbandonmentSupported == true, let binding = snapshot?.accountFingerprint,
              var draft = deviceDraft, draft.stage == .created || draft.stage == .activated,
              snapshot?.publicKey != draft.publicKey, let device = draft.device else { return }
        if let receipt = try await client.abandonmentReceipt(accountFingerprint: binding, publicKey: draft.publicKey, deviceID: device.id) {
            guard receipt.matches(account: binding, publicKey: draft.publicKey, deviceID: device.id) else { throw DraftError.corrupt }
            draft.abandonmentReceipt = receipt
            draft.stage = .abandoned
            try draftStore.save(draft)
            deviceDraft = draft
        }
    }
    private func perform(success: String? = nil, _ operation: () async throws -> AccountSnapshot) async {
        guard !busy else { return }
        hideKey()
        busy = true
        message = "正在核实账号状态…"
        hasError = false
        defer { busy = false }
        do {
            try accept(try await operation())
            try await restoreAbandonedDraftIfConfirmed()
            message = success ?? (snapshot?.signedIn == true ? "已读取本地登录；可刷新官方状态。" : "请输入 Mullvad 的 16 位账号。")
        } catch { message = error.localizedDescription; hasError = true }
    }
}
