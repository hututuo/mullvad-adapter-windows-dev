import Foundation
import Combine

struct AccountSnapshot: Decodable {
    let signedIn: Bool
    let verified: Bool
    let accountSuffix: String?
    let expiry: String?
    let checkedAt: String?
    let publicKey: String
    let deviceMatch: String
    let devices: [AccountDevice]
    let accountFingerprint: String?
    var currentDevice: AccountDevice? { devices.first { $0.current } }
    var expiryDate: Date? {
        guard let expiry else { return nil }
        let formatter = ISO8601DateFormatter()
        if let date = formatter.date(from: expiry) { return date }
        formatter.formatOptions.insert(.withFractionalSeconds)
        return formatter.date(from: expiry)
    }
    enum CodingKeys: String, CodingKey {
        case signedIn = "signed_in", verified, accountSuffix = "account_suffix", expiry
        case checkedAt = "checked_at", publicKey = "public_key", deviceMatch = "device_match", devices
        case accountFingerprint = "account_fingerprint"
    }
}

struct AccountDevice: Decodable, Identifiable {
    let id: String
    let name: String
    let pubkey: String
    let created: String?
    let current: Bool
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
    private var keyRevealGeneration = 0
    init(client: AdapterClient) { self.client = client }

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
        guard !busy, let binding = snapshot?.accountFingerprint else { message = "请先登录配套后台并验证账号。"; hasError = true; return }
        hideKey(); busy = true; hasError = false
        defer { busy = false }
        do {
            let store = AccountDraftStore()
            var draft = try store.load(account: binding) ?? AccountDeviceDraft.generate(account: binding)
            if draft.stage == .created { deviceDraft = draft; message = "已保留这个新设备，未重复注册。"; return }
            guard draft.stage == .prepared else { throw DraftError.unknown }
            try store.save(draft) // Durable local key before any mutation request.
            draft.stage = .submitted; try store.save(draft); deviceDraft = draft
            let device = try await client.createDevice(publicKey: draft.publicKey)
            guard device.pubkey == draft.publicKey else { throw DraftError.unknown }
            draft.device = device; draft.stage = .created; try store.save(draft); deviceDraft = draft
            message = "新设备已注册，私钥保留在本机钥匙串；当前隧道继续使用原身份。"
            snapshot = try await client.account("refresh")
        } catch {
            // A definite rejection allows a later explicit retry with the same
            // saved key. Timeouts/malformed success never reopen registration.
            if case AdapterClientError.http(_, let code?, _) = error,
               ["http_400", "http_401", "http_403", "http_404", "http_409", "http_429", "invalid_account", "invalid_key", "confirmation_required"].contains(code),
               var draft = deviceDraft, draft.stage == .submitted {
                draft.stage = .prepared
                do { try AccountDraftStore().save(draft); deviceDraft = draft } catch { message = error.localizedDescription; hasError = true; return }
            }
            message = error.localizedDescription; hasError = true
        }
    }
    func revealDraftKey() {
        guard let draft = deviceDraft else { return }
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
    func logout() async {
        hideKey()
        await perform(success: "已清除本地账号登录；当前适配器隧道继续使用原密钥。") {
            try await self.client.account("logout")
        }
    }
    func remove(_ device: AccountDevice) async {
        guard !device.current else { return }
        await perform(success: "设备已撤销，已刷新官方列表。") {
            try await self.client.account("devices/remove", payload: ["device_id": device.id, "confirm": true])
        }
    }
    func voucher(_ code: String) async {
        await perform(success: "兑换已完成，已刷新有效期。") {
            try await self.client.account("voucher", payload: ["voucher_code": code])
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
    private func perform(success: String? = nil, _ operation: () async throws -> AccountSnapshot) async {
        guard !busy else { return }
        hideKey()
        busy = true
        message = "正在核实账号状态…"
        hasError = false
        defer { busy = false }
        do {
            snapshot = try await operation()
            if let binding = snapshot?.accountFingerprint { deviceDraft = try AccountDraftStore().load(account: binding) }
            else { deviceDraft = nil }
            message = success ?? (snapshot?.signedIn == true ? "已读取本地登录；可刷新官方状态。" : "请输入 Mullvad 的 16 位账号。")
        } catch { message = error.localizedDescription; hasError = true }
    }
}
