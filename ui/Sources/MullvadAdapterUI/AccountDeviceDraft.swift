import Foundation
import CryptoKit
import Security

struct CreatedAccountDevice: Codable {
    let id: String
    let name: String
    let pubkey: String
    let created: String?
    let ipv4Address: String
    let ipv6Address: String
    enum CodingKeys: String, CodingKey { case id, name, pubkey, created; case ipv4Address = "ipv4_address", ipv6Address = "ipv6_address" }
}
struct AccountDeviceDraft: Codable {
    enum Stage: String, Codable { case prepared, submitted, created }
    let accountFingerprint: String
    let privateKey: Data
    let publicKey: String
    var stage: Stage
    var device: CreatedAccountDevice?
    static func generate(account: String) throws -> Self {
        guard account.count == 64, account.allSatisfy({ $0.isHexDigit }) else { throw DraftError.invalidAccount }
        let key = Curve25519.KeyAgreement.PrivateKey()
        return Self(accountFingerprint: account, privateKey: key.rawRepresentation,
            publicKey: key.publicKey.rawRepresentation.base64EncodedString(), stage: .prepared)
    }
    func validate(account: String) throws {
        guard accountFingerprint == account,
              try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation.base64EncodedString() == publicKey,
              stage != .created || (device?.pubkey == publicKey && UUID(uuidString: device?.id ?? "") != nil) else { throw DraftError.corrupt }
    }
}
enum DraftError: LocalizedError {
    case invalidAccount, corrupt, storage, unknown
    var errorDescription: String? {
        switch self {
        case .invalidAccount: return "请先登录并验证账号。配套后台需要提供完整账号的本机匹配标识。"
        case .corrupt: return "本机待注册设备记录无效，已保留原资料；未创建新设备。"
        case .storage: return "无法确认钥匙串保存成功；未继续注册设备。"
        case .unknown: return "之前的注册结果尚未确认，私钥已保留在钥匙串。请刷新官方设备列表核对，不要重复注册。"
        }
    }
}
struct AccountDraftStore {
    private func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "local.mullvad.adapter.device-drafts",
         kSecAttrAccount as String: account,
         kSecAttrSynchronizable as String: false]
    }
    func load(account: String) throws -> AccountDeviceDraft? {
        var request = query(account)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var output: CFTypeRef?
        let result = SecItemCopyMatching(request as CFDictionary, &output)
        if result == errSecItemNotFound { return nil }
        guard result == errSecSuccess, let data = output as? Data, data.count <= 16_384 else { throw DraftError.storage }
        let draft = try JSONDecoder().decode(AccountDeviceDraft.self, from: data)
        try draft.validate(account: account)
        return draft
    }
    func save(_ draft: AccountDeviceDraft) throws {
        try draft.validate(account: draft.accountFingerprint)
        if let old = try load(account: draft.accountFingerprint), old.publicKey != draft.publicKey { throw DraftError.corrupt }
        let data = try JSONEncoder().encode(draft)
        guard data.count <= 16_384 else { throw DraftError.storage }
        var request = query(draft.accountFingerprint)
        request[kSecValueData as String] = data
        request[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let added = SecItemAdd(request as CFDictionary, nil)
        if added == errSecDuplicateItem {
            guard SecItemUpdate(query(draft.accountFingerprint) as CFDictionary, [kSecValueData as String: data] as CFDictionary) == errSecSuccess else { throw DraftError.storage }
        } else if added != errSecSuccess { throw DraftError.storage }
        guard let verified = try load(account: draft.accountFingerprint), verified.publicKey == draft.publicKey,
              verified.privateKey == draft.privateKey, verified.stage == draft.stage, verified.device?.id == draft.device?.id else { throw DraftError.storage }
    }
}
