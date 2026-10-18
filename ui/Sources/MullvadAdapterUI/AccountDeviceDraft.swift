import Foundation
import CryptoKit
import Security
import Darwin

struct CreatedAccountDevice: Codable, Equatable {
    let id: String
    let name: String
    let pubkey: String
    let created: String?
    let ipv4Address: String
    let ipv6Address: String
    enum CodingKeys: String, CodingKey { case id, name, pubkey, created; case ipv4Address = "ipv4_address", ipv6Address = "ipv6_address" }
    var hasValidAssignedAddresses: Bool {
        var ipv4 = in_addr(), ipv6 = in6_addr()
        return ipv4Address.hasSuffix("/32") && ipv6Address.hasSuffix("/128") &&
            inet_pton(AF_INET, String(ipv4Address.dropLast(3)), &ipv4) == 1 &&
            inet_pton(AF_INET6, String(ipv6Address.dropLast(4)), &ipv6) == 1
    }
}
struct AccountDeviceDraft: Codable, Equatable {
    enum Stage: String, Codable { case prepared, submitted, registered, created, activated, abandoned }
    let accountFingerprint: String
    let privateKey: Data
    let publicKey: String
    var stage: Stage
    var device: CreatedAccountDevice?
    var registeredDevice: AccountDevice? = nil
    var abandonmentReceipt: AbandonedIdentityReceipt? = nil
    var deviceName: String? { device?.name ?? registeredDevice?.name }
    var registrationConfirmed: Bool { stage == .created || stage == .registered || stage == .activated || stage == .abandoned }
    static func generate(account: String) throws -> Self {
        guard account.count == 64, account.allSatisfy({ $0.isHexDigit }) else { throw DraftError.invalidAccount }
        let key = Curve25519.KeyAgreement.PrivateKey()
        return Self(accountFingerprint: account, privateKey: key.rawRepresentation,
            publicKey: key.publicKey.rawRepresentation.base64EncodedString(), stage: .prepared)
    }
    func validate(account: String) throws {
        guard accountFingerprint == account,
              try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation.base64EncodedString() == publicKey,
              (stage != .created && stage != .activated && stage != .abandoned) || (device?.pubkey == publicKey && UUID(uuidString: device?.id ?? "") != nil && device?.hasValidAssignedAddresses == true),
              stage != .abandoned || abandonmentReceipt?.matches(account: account, publicKey: publicKey, deviceID: device?.id) == true,
              stage != .registered || (registeredDevice?.pubkey == publicKey && UUID(uuidString: registeredDevice?.id ?? "") != nil) else { throw DraftError.corrupt }
    }

    mutating func reconcile(_ official: AccountDevice) throws {
        guard stage != .abandoned else { throw DraftError.corrupt }
        guard official.pubkey == publicKey, UUID(uuidString: official.id) != nil else { throw DraftError.corrupt }
        // A list response confirms registration, not addresses or activation.
        registeredDevice = official
        if let receipt = official.registration {
            guard receipt.pubkey == publicKey, receipt.id == official.id, receipt.hasValidAssignedAddresses else { throw DraftError.corrupt }
            device = receipt
            if stage != .activated { stage = .created }
        } else if stage != .created && stage != .activated { stage = .registered }
        try validate(account: accountFingerprint)
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
protocol AccountDraftPersisting {
    func load(account: String) throws -> AccountDeviceDraft?
    func save(_ draft: AccountDeviceDraft) throws
    func prepareNextDraft(from completed: AccountDeviceDraft) throws -> AccountDeviceDraft
}
protocol AccountKeychainAccess {
    func read(_ query: [String: Any]) -> (OSStatus, Data?)
    func add(_ attributes: [String: Any]) -> OSStatus
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus
}
struct LocalAccountKeychain: AccountKeychainAccess {
    func read(_ query: [String: Any]) -> (OSStatus, Data?) {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return (status, result as? Data)
    }
    func add(_ attributes: [String: Any]) -> OSStatus { SecItemAdd(attributes as CFDictionary, nil) }
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus { SecItemUpdate(query as CFDictionary, attributes as CFDictionary) }
}
struct AccountDraftStore: AccountDraftPersisting {
    private let keychain: any AccountKeychainAccess
    private let stateDirectory: URL
    init(keychain: any AccountKeychainAccess = LocalAccountKeychain(), stateDirectory: URL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/MullvadLocalAdapter")) {
        self.keychain = keychain
        self.stateDirectory = stateDirectory
    }
    private func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "local.mullvad.adapter.device-drafts",
         kSecAttrAccount as String: account,
         kSecAttrSynchronizable as String: false]
    }
    func load(account: String) throws -> AccountDeviceDraft? {
        guard let data = try rawData(query(account)) else { return nil }
        let draft = try JSONDecoder().decode(AccountDeviceDraft.self, from: data)
        try draft.validate(account: account)
        return draft
    }
    func save(_ draft: AccountDeviceDraft) throws {
        try withWriterLock { try saveLocked(draft) }
    }
    private func saveLocked(_ draft: AccountDeviceDraft) throws {
        try draft.validate(account: draft.accountFingerprint)
        if let old = try load(account: draft.accountFingerprint) {
            guard old.publicKey == draft.publicKey,
                  old.stage != .activated || draft.stage == .activated || draft.stage == .abandoned,
                  old.stage != .abandoned || draft.stage == .abandoned else { throw DraftError.corrupt }
        }
        let data = try JSONEncoder().encode(draft)
        guard data.count <= 16_384 else { throw DraftError.storage }
        var request = query(draft.accountFingerprint)
        request[kSecValueData as String] = data
        request[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let added = keychain.add(request)
        if added == errSecDuplicateItem {
            guard keychain.update(query(draft.accountFingerprint), attributes: [kSecValueData as String: data]) == errSecSuccess else { throw DraftError.storage }
        } else if added != errSecSuccess { throw DraftError.storage }
        guard let verified = try load(account: draft.accountFingerprint), verified == draft else { throw DraftError.storage }
    }

    // Archive exact original bytes before generating or saving another key.
    // An immutable archive conflict or readback failure preserves the old slot.
    func prepareNextDraft(from completed: AccountDeviceDraft) throws -> AccountDeviceDraft {
        try withWriterLock {
            guard completed.stage == .activated || completed.stage == .abandoned,
                  let original = try rawData(query(completed.accountFingerprint)),
                  try JSONDecoder().decode(AccountDeviceDraft.self, from: original) == completed else { throw DraftError.corrupt }
            try completed.validate(account: completed.accountFingerprint)
            var archive = query(completed.accountFingerprint + ":" + SHA256.hash(data: Data(completed.publicKey.utf8)).map { String(format: "%02x", $0) }.joined())
            archive[kSecAttrService as String] = "local.mullvad.adapter.device-draft-archives"
            var addition = archive
            addition[kSecValueData as String] = original
            addition[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let result = keychain.add(addition)
            guard result == errSecSuccess || result == errSecDuplicateItem,
                  try rawData(archive) == original,
                  try rawData(query(completed.accountFingerprint)) == original else { throw DraftError.storage }
            let next = try AccountDeviceDraft.generate(account: completed.accountFingerprint)
            let data = try JSONEncoder().encode(next)
            guard keychain.update(query(completed.accountFingerprint), attributes: [kSecValueData as String: data]) == errSecSuccess,
                  try rawData(query(completed.accountFingerprint)) == data,
                  try load(account: completed.accountFingerprint) == next else { throw DraftError.storage }
            return next
        }
    }

    private func rawData(_ query: [String: Any]) throws -> Data? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        let (result, data) = keychain.read(request)
        if result == errSecItemNotFound { return nil }
        guard result == errSecSuccess, let data, data.count <= 16_384 else { throw DraftError.storage }
        return data
    }

    private func withWriterLock<T>(_ operation: () throws -> T) throws -> T {
        let directory = stateDirectory
        var directoryStat = stat()
        if lstat(directory.path, &directoryStat) != 0 {
            guard errno == ENOENT else { throw DraftError.storage }
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        guard lstat(directory.path, &directoryStat) == 0, (directoryStat.st_mode & S_IFMT) == S_IFDIR,
              directoryStat.st_uid == getuid(), directoryStat.st_mode & 0o077 == 0 else { throw DraftError.storage }
        let descriptor = open(directory.appendingPathComponent(".account-drafts.lock").path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw DraftError.storage }
        defer { _ = close(descriptor) }
        var fileStat = stat()
        guard fstat(descriptor, &fileStat) == 0, (fileStat.st_mode & S_IFMT) == S_IFREG,
              fileStat.st_uid == getuid(), fileStat.st_nlink == 1, fileStat.st_mode & 0o077 == 0,
              flock(descriptor, LOCK_EX | LOCK_NB) == 0 else { throw DraftError.storage }
        defer { _ = flock(descriptor, LOCK_UN) }
        return try operation()
    }
}
