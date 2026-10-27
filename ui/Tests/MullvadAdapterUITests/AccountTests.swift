import XCTest
import AppKit
import SwiftUI
import CryptoKit
import Security
@testable import MullvadAdapterUI

private final class AccountProtocol: URLProtocol {
    static var handler: ((URLRequest) -> (Int, Data))!
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let (code, data) = Self.handler(request)
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: code, httpVersion: nil, headerFields: nil)!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

private final class MemoryAccountDraftStore: AccountDraftPersisting {
    var draft: AccountDeviceDraft?
    var rejectWrites = false
    var writes = 0
    var rejectWriteNumber: Int?
    var archives: [AccountDeviceDraft] = []
    var rejectArchive = false
    func load(account: String) throws -> AccountDeviceDraft? {
        guard let draft else { return nil }
        try draft.validate(account: account)
        return draft
    }
    func save(_ draft: AccountDeviceDraft) throws {
        writes += 1
        if rejectWrites || rejectWriteNumber == writes { throw DraftError.storage }
        try draft.validate(account: draft.accountFingerprint)
        self.draft = draft
    }
    func prepareNextDraft(from completed: AccountDeviceDraft) throws -> AccountDeviceDraft {
        guard !rejectArchive, completed.stage == .activated || completed.stage == .abandoned, draft == completed else { throw DraftError.storage }
        archives.append(completed)
        let next = try AccountDeviceDraft.generate(account: completed.accountFingerprint)
        try save(next)
        return next
    }
}

private final class MockAccountKeychain: AccountKeychainAccess {
    var records: [String: Data] = [:]
    var trace: [String] = []
    var failArchiveRead = false
    var failActiveUpdate = false
    var ambiguousActiveUpdate = false
    private func key(_ query: [String: Any]) -> String {
        "\(query[kSecAttrService as String] as! String)|\(query[kSecAttrAccount as String] as! String)"
    }
    private func isArchive(_ query: [String: Any]) -> Bool { (query[kSecAttrService as String] as! String).hasSuffix("archives") }
    func read(_ query: [String: Any]) -> (OSStatus, Data?) {
        trace.append(isArchive(query) ? "read_archive" : "read_active")
        if isArchive(query), failArchiveRead { return (errSecNotAvailable, nil) }
        guard let value = records[key(query)] else { return (errSecItemNotFound, nil) }
        return (errSecSuccess, value)
    }
    func add(_ attributes: [String: Any]) -> OSStatus {
        trace.append(isArchive(attributes) ? "add_archive" : "add_active")
        XCTAssertEqual(attributes[kSecAttrSynchronizable as String] as? Bool, false)
        XCTAssertEqual(attributes[kSecAttrAccessible as String] as? String, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
        let record = key(attributes)
        if records[record] != nil { return errSecDuplicateItem }
        records[record] = attributes[kSecValueData as String] as? Data
        return errSecSuccess
    }
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus {
        trace.append("update_active")
        if failActiveUpdate { return errSecNotAvailable }
        records[key(query)] = attributes[kSecValueData as String] as? Data
        return ambiguousActiveUpdate ? errSecNotAvailable : errSecSuccess
    }
}

final class AccountTests: XCTestCase {
    func testPreviewBundleNeverFallsBackToProductionAfterRelaunchWithoutArguments() {
        XCTAssertTrue(CityPreview.isEnabled(arguments: [], bundleIdentifier: "local.mullvad.adapter.account.preview"))
        XCTAssertTrue(CityPreview.isEnabled(arguments: [], bundleIdentifier: "local.mullvad.adapter.city-preview"))
        XCTAssertTrue(CityPreview.isEnabled(arguments: ["--preview-cities"], bundleIdentifier: nil))
        XCTAssertFalse(CityPreview.isEnabled(arguments: [], bundleIdentifier: "local.mullvad.adapter.ui"))
    }
    private func client() -> AdapterClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [AccountProtocol.self]
        return AdapterClient(session: URLSession(configuration: config), accountCapability: { "test-capability" })
    }
    private func snapshotData(binding: String, key: String? = nil) -> Data {
        var object = try! JSONSerialization.jsonObject(with: CityPreview.data("account")) as! [String: Any]
        object["account_fingerprint"] = binding
        if let key { object["devices"] = [["id": "33333333-3333-3333-3333-333333333333", "name": "Recovered Bird", "pubkey": key, "current": false]] }
        return try! JSONSerialization.data(withJSONObject: object)
    }
    private func createdDraft(binding: String, stage: AccountDeviceDraft.Stage = .created) throws -> AccountDeviceDraft {
        var draft = try AccountDeviceDraft.generate(account: binding)
        draft.stage = stage
        draft.device = CreatedAccountDevice(id: "33333333-3333-3333-3333-333333333333", name: "Test Bird", pubkey: draft.publicKey, created: nil, ipv4Address: "10.64.0.2/32", ipv6Address: "fc00::2/128")
        return draft
    }
    private func identitySnapshot(_ draft: AccountDeviceDraft, installed: Bool) -> Data {
        var object = try! JSONSerialization.jsonObject(with: snapshotData(binding: draft.accountFingerprint, key: draft.publicKey)) as! [String: Any]
        object["identity_configured"] = installed
        object["public_key"] = installed ? draft.publicKey : ""
        object["devices"] = [["id": draft.device!.id, "name": "Test Bird", "pubkey": draft.publicKey, "current": installed]]
        if installed { object["activated_draft_public_key"] = draft.publicKey; object["activated_draft_device_id"] = draft.device!.id }
        return try! JSONSerialization.data(withJSONObject: object)
    }
    private func abandonmentProof(_ draft: AccountDeviceDraft) -> AbandonedIdentityReceipt {
        AbandonedIdentityReceipt(accountFingerprint: draft.accountFingerprint, deviceID: draft.device!.id, publicKey: draft.publicKey,
            metadataSHA256: String(repeating: "c", count: 64), receiptSHA256: String(repeating: "d", count: 64))
    }
    private func abandonmentSnapshot(_ draft: AccountDeviceDraft, pending: AccountDeviceDraft? = nil, cancellationPending: Bool = false) -> Data {
        var object = try! JSONSerialization.jsonObject(with: identitySnapshot(draft, installed: false)) as! [String: Any]
        object["identity_abandonment_supported"] = true
        object["devices"] = [] // A revoked original need not remain in the official list.
        if let pending {
            object["pending_identity_installation"] = ["account_fingerprint": pending.accountFingerprint, "device_id": pending.device!.id,
                "public_key": pending.publicKey, "metadata_sha256": String(repeating: "c", count: 64), "has_pending_template": true,
                "cancellation_pending": cancellationPending, "cancellation_complete": false]
        }
        return try! JSONSerialization.data(withJSONObject: object)
    }
    private func requestObject(_ request: URLRequest) -> [String: Any] {
        var data = request.httpBody ?? Data()
        if data.isEmpty, let stream = request.httpBodyStream {
            stream.open(); defer { stream.close() }
            var buffer = [UInt8](repeating: 0, count: 1024)
            while true { let size = stream.read(&buffer, maxLength: buffer.count); if size <= 0 { break }; data.append(buffer, count: size) }
        }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
    }
    private func receiptData(_ receipt: AbandonedIdentityReceipt?) -> Data {
        try! JSONEncoder().encode(AbandonmentStatusForTest(receipt: receipt))
    }
    private struct AbandonmentStatusForTest: Encodable { let receipt: AbandonedIdentityReceipt? }

    func testSnapshotUsesOfficialMatchAndFractionalExpiry() throws {
        let data = CityPreview.data("account")
        let snapshot = try JSONDecoder().decode(AccountSnapshot.self, from: data)
        XCTAssertEqual(snapshot.currentDevice?.name, "Example Bird")
        XCTAssertNotNil(snapshot.expiryDate)
        var object = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        object["expiry"] = "2027-01-01T00:00:00.123456Z"
        let fractional = try JSONDecoder().decode(AccountSnapshot.self, from: JSONSerialization.data(withJSONObject: object))
        XCTAssertNotNil(fractional.expiryDate)
    }

    func testClientUsesLocalAuthorizationAndNoURLCredential() async throws {
        AccountProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer test-capability")
            XCTAssertEqual(request.url?.path, "/account/login")
            XCTAssertNil(request.url?.query)
            XCTAssertEqual(request.httpMethod, "POST")
            return (200, CityPreview.data("account"))
        }
        _ = try await client().account("login", payload: ["account_number": "1234567890123456"])
    }

    func testSavedIdentityListDecodesWithoutInventingAnUnknownDeviceName() throws {
        var object = try JSONSerialization.jsonObject(with: CityPreview.data("account")) as! [String: Any]
        object["identity_switch_supported"] = true
        object["active_identity_id"] = "old"
        object["saved_identities"] = [
            ["id": "old", "account_suffix": "3456", "public_key": "fixture-old", "current": true, "name_source": "not_verified"],
            ["id": "new", "account_suffix": "3478", "public_key": "fixture-new", "current": false, "device_name": "Example Bird", "name_source": "saved_official_response"]]
        let snapshot = try JSONDecoder().decode(AccountSnapshot.self, from: JSONSerialization.data(withJSONObject: object))
        XCTAssertEqual(snapshot.savedIdentities?.count, 2)
        XCTAssertNil(snapshot.savedIdentities?.first?.deviceName)
        XCTAssertEqual(snapshot.savedIdentities?.last?.title, "Example Bird")
        XCTAssertEqual(snapshot.activeIdentityID, "old")
    }

    func testIdentitySwitchSendsOnlySelectionAndNeverReplaysAfterAmbiguousResponse() async throws {
        var calls = 0
        AccountProtocol.handler = { request in
            calls += 1
            XCTAssertEqual(request.url?.path, "/account/identities/switch")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer test-capability")
            let payload = self.requestObject(request)
            XCTAssertEqual(payload["id"] as? String, "new")
            XCTAssertEqual(payload["expected_active_id"] as? String, "old")
            XCTAssertEqual(payload["confirm"] as? Bool, true)
            XCTAssertNil(payload["private_key"])
            XCTAssertNil(payload["account_number"])
            return (500, Data("{\"error\":\"fixture failure\"}".utf8))
        }
        do { _ = try await client().switchIdentity("new", expectedActiveID: "old"); XCTFail("expected a definite client error") }
        catch { }
        XCTAssertEqual(calls, 1)
    }

    @MainActor
    func testFailedRefreshRetainsKnownSnapshotWithVisibleError() async {
        var requests = 0
        AccountProtocol.handler = { _ in
            requests += 1
            return requests == 1 ? (200, CityPreview.data("account")) : (422, Data(#"{"code":"api_unreachable","error":"API unavailable"}"#.utf8))
        }
        let model = AccountViewModel(client: client())
        await model.load()
        await model.refresh()
        XCTAssertEqual(model.snapshot?.currentDevice?.name, "Example Bird")
        XCTAssertTrue(model.hasError)
        XCTAssertTrue(model.message.contains("API unavailable"))
        XCTAssertFalse(model.busy)
    }

    @MainActor
    func testHidingDuringKeyRequestDiscardsLatePrivateKey() async {
        let started = expectation(description: "key request started")
        AccountProtocol.handler = { _ in
            started.fulfill()
            Thread.sleep(forTimeInterval: 0.15)
            return (200, Data(#"{"private_key":"public-test-vector-only"}"#.utf8))
        }
        let model = AccountViewModel(client: client())
        let task = Task { await model.revealKey() }
        await fulfillment(of: [started], timeout: 2)
        model.hideKey()
        await task.value
        XCTAssertNil(model.privateKey)
    }

    @MainActor
    func testImmediateDoubleClickDoesNotRepeatLogin() async {
        var requests = 0
        AccountProtocol.handler = { _ in
            requests += 1
            Thread.sleep(forTimeInterval: 0.05)
            return (200, CityPreview.data("account"))
        }
        let model = AccountViewModel(client: client())
        async let first: Void = model.login("1234567890123456")
        async let second: Void = model.login("1234567890123456")
        _ = await (first, second)
        XCTAssertEqual(requests, 1)
    }

    func testSubmittedDeviceDraftKeepsItsKeyAndExactAccountBinding() throws {
        let account = String(repeating: "a", count: 64)
        var draft = try AccountDeviceDraft.generate(account: account)
        draft.stage = .submitted
        let restored = try JSONDecoder().decode(AccountDeviceDraft.self, from: JSONEncoder().encode(draft))
        try restored.validate(account: account)
        XCTAssertEqual(restored.privateKey, draft.privateKey)
        XCTAssertEqual(restored.stage, .submitted)
        XCTAssertThrowsError(try restored.validate(account: String(repeating: "b", count: 64)))
    }

    func testDeviceCreationClientSendsPublicHalfOnly() async throws {
        let draft = try AccountDeviceDraft.generate(account: String(repeating: "a", count: 64))
        AccountProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/account/devices/create")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer test-capability")
            var data = request.httpBody ?? Data()
            if data.isEmpty, let stream = request.httpBodyStream {
                stream.open(); defer { stream.close() }
                var buffer = [UInt8](repeating: 0, count: 1024)
                while true { let count = stream.read(&buffer, maxLength: buffer.count); if count <= 0 { break }; data.append(buffer, count: count) }
            }
            guard let body = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
                XCTFail("missing public-key request payload")
                return (422, Data("{}".utf8))
            }
            XCTAssertEqual(body["public_key"] as? String, draft.publicKey)
            XCTAssertEqual(body["confirm"] as? Bool, true)
            XCTAssertEqual(body["account_fingerprint"] as? String, draft.accountFingerprint)
            XCTAssertNil(body["private_key"])
            return (200, try! JSONSerialization.data(withJSONObject: ["id":"33333333-3333-3333-3333-333333333333", "name":"test bird", "pubkey":draft.publicKey, "ipv4_address":"10.1.2.3/32", "ipv6_address":"fc00::3/128"]))
        }
        let created = try await client().createDevice(publicKey: draft.publicKey, accountFingerprint: draft.accountFingerprint)
        XCTAssertEqual(created.pubkey, draft.publicKey)
    }

    func testOfficialReconciliationPreservesPrivateKeyWithoutInventingAssignedAddresses() throws {
        let binding = String(repeating: "a", count: 64)
        var draft = try AccountDeviceDraft.generate(account: binding)
        draft.stage = .submitted
        let originalKey = draft.privateKey
        let official = AccountDevice(id: "33333333-3333-3333-3333-333333333333", name: "Recovered Bird", pubkey: draft.publicKey, created: nil, current: false)
        try draft.reconcile(official)
        XCTAssertEqual(draft.stage, .registered)
        XCTAssertEqual(draft.privateKey, originalKey)
        XCTAssertNil(draft.device)
        let restored = try JSONDecoder().decode(AccountDeviceDraft.self, from: JSONEncoder().encode(draft))
        try restored.validate(account: binding)
        XCTAssertEqual(restored.registeredDevice?.name, "Recovered Bird")
        XCTAssertThrowsError(try draft.reconcile(AccountDevice(id: official.id, name: official.name, pubkey: "different-key", created: nil, current: false)))
    }

    @MainActor
    func testRestartedSubmittedDraftReconcilesWithoutAnotherCreate() async throws {
        let binding = String(repeating: "a", count: 64)
        let store = MemoryAccountDraftStore()
        var draft = try AccountDeviceDraft.generate(account: binding)
        draft.stage = .submitted
        store.draft = try JSONDecoder().decode(AccountDeviceDraft.self, from: JSONEncoder().encode(draft))
        let snapshot = snapshotData(binding: binding, key: draft.publicKey)
        var paths: [String] = []
        AccountProtocol.handler = { request in
            let path = request.url!.path
            paths.append(path)
            if path == "/account/devices/reconcile" {
                return (200, try! JSONEncoder().encode(AccountDevice(id: "33333333-3333-3333-3333-333333333333", name: "Recovered Bird", pubkey: draft.publicKey, created: nil, current: false)))
            }
            return (200, snapshot)
        }
        let model = AccountViewModel(client: client(), draftStore: store)
        await model.load()
        await model.createDevice() // Submitted records cannot be replayed.
        XCTAssertTrue(model.hasError)
        await model.reconcileDraft()
        XCTAssertFalse(model.hasError)
        XCTAssertEqual(model.deviceDraft?.stage, .registered)
        XCTAssertEqual(store.draft?.privateKey, draft.privateKey)
        XCTAssertFalse(paths.contains("/account/devices/create"))
        XCTAssertEqual(paths.filter { $0 == "/account/devices/reconcile" }.count, 1)
    }

    @MainActor
    func testMissingOfficialDraftKeepsSubmittedStageAndLocalKey() async throws {
        let binding = String(repeating: "a", count: 64)
        let store = MemoryAccountDraftStore()
        var draft = try AccountDeviceDraft.generate(account: binding)
        draft.stage = .submitted; store.draft = draft
        let snapshot = snapshotData(binding: binding)
        AccountProtocol.handler = { request in
            request.url!.path == "/account/devices/reconcile" ? (422, Data(#"{"code":"draft_not_found","error":"not found; key retained"}"#.utf8)) : (200, snapshot)
        }
        let model = AccountViewModel(client: client(), draftStore: store)
        await model.load(); await model.reconcileDraft()
        XCTAssertTrue(model.hasError)
        XCTAssertEqual(store.draft?.stage, .submitted)
        XCTAssertEqual(store.draft?.privateKey, draft.privateKey)
    }

    @MainActor
    func testAccountChangeNeverReusesAnotherAccountsDraft() async throws {
        let binding = String(repeating: "a", count: 64)
        let store = MemoryAccountDraftStore()
        store.draft = try AccountDeviceDraft.generate(account: binding)
        let other = snapshotData(binding: String(repeating: "b", count: 64))
        var requests = 0
        AccountProtocol.handler = { _ in requests += 1; return (200, other) }
        let model = AccountViewModel(client: client(), draftStore: store)
        await model.load()
        XCTAssertTrue(model.hasError)
        XCTAssertNil(model.deviceDraft)
        await model.reconcileDraft()
        XCTAssertEqual(requests, 1)
        XCTAssertEqual(store.draft?.accountFingerprint, binding)
    }

    func testAccountOnlySnapshotHasNoConfiguredIdentity() throws {
        let data = Data(#"{"signed_in":false,"verified":false,"public_key":"","device_match":"unconfigured","devices":[],"identity_configured":false,"api_route":"system_https","api_route_source":"system_default","device_source":"not_verified"}"#.utf8)
        let snapshot = try JSONDecoder().decode(AccountSnapshot.self, from: data)
        XCTAssertFalse(snapshot.hasLocalIdentity)
        XCTAssertNil(snapshot.currentDevice)
        XCTAssertEqual(snapshot.apiRoute, "system_https")
    }

    @MainActor
    func testTimeoutRetainsSubmittedKeyAndNeverAutomaticallyResendsCreate() async throws {
        let binding = String(repeating: "a", count: 64)
        let store = MemoryAccountDraftStore()
        let snapshot = snapshotData(binding: binding)
        var creates = 0
        AccountProtocol.handler = { request in
            if request.url!.path == "/account/devices/create" {
                creates += 1
                return (422, Data(#"{"code":"mutation_outcome_unknown","error":"timeout; verify official list"}"#.utf8))
            }
            return (200, snapshot)
        }
        let model = AccountViewModel(client: client(), draftStore: store)
        await model.load(); await model.createDevice()
        let savedKey = try XCTUnwrap(store.draft?.privateKey)
        XCTAssertEqual(store.draft?.stage, .submitted)
        XCTAssertTrue(model.hasError)
        await model.refresh(); await model.createDevice()
        XCTAssertEqual(creates, 1)
        XCTAssertEqual(store.draft?.privateKey, savedKey)
        XCTAssertEqual(store.draft?.stage, .submitted)
    }

    @MainActor
    func testSubmittedPersistenceFailureStopsBeforeOfficialCreate() async {
        let binding = String(repeating: "a", count: 64)
        let store = MemoryAccountDraftStore()
        store.rejectWriteNumber = 2
        let snapshot = snapshotData(binding: binding)
        var paths: [String] = []
        AccountProtocol.handler = { request in paths.append(request.url!.path); return (200, snapshot) }
        let model = AccountViewModel(client: client(), draftStore: store)
        await model.load(); await model.createDevice()
        XCTAssertTrue(model.hasError)
        XCTAssertEqual(store.draft?.stage, .prepared)
        XCTAssertFalse(paths.contains("/account/devices/create"))
        XCTAssertEqual(store.writes, 2)
    }

    @MainActor
    func testDefiniteLocalCreateGatesKeepSamePreparedKeyUntilAnotherExplicitCreate() async throws {
        let binding = String(repeating: "a", count: 64)
        for code in ["account_changed", "account_busy", "not_signed_in"] {
            let store = MemoryAccountDraftStore()
            let snapshot = snapshotData(binding: binding)
            var creates = 0
            AccountProtocol.handler = { request in
                if request.url!.path == "/account/devices/create" {
                    creates += 1
                    let responseCode = creates == 1 ? code : "mutation_outcome_unknown"
                    return (code == "account_busy" ? 409 : 422, try! JSONSerialization.data(withJSONObject: ["code": responseCode, "error": "synthetic local rejection"]))
                }
                return (200, snapshot)
            }
            let model = AccountViewModel(client: client(), draftStore: store)
            await model.load(); await model.createDevice()
            let savedKey = try XCTUnwrap(store.draft?.privateKey)
            XCTAssertEqual(store.draft?.stage, .prepared, code)
            XCTAssertEqual(creates, 1, code)
            await model.refresh()
            XCTAssertEqual(creates, 1, code)
            await model.createDevice()
            XCTAssertEqual(creates, 2, code)
            XCTAssertEqual(store.draft?.privateKey, savedKey, code)
            XCTAssertEqual(store.draft?.stage, .submitted, code)
        }
    }

    @MainActor
    func testAmbiguousCreateFailuresStaySubmittedAndNeverBecomeRetryableLocalGates() async throws {
        let binding = String(repeating: "a", count: 64)
        for code in ["mutation_outcome_unknown", "account_operation_failed", "api_unreachable", "invalid_response", "http_500"] {
            let store = MemoryAccountDraftStore()
            let snapshot = snapshotData(binding: binding)
            var creates = 0
            AccountProtocol.handler = { request in
                if request.url!.path == "/account/devices/create" {
                    creates += 1
                    return (500, try! JSONSerialization.data(withJSONObject: ["code": code, "error": "synthetic unknown outcome"]))
                }
                return (200, snapshot)
            }
            let model = AccountViewModel(client: client(), draftStore: store)
            await model.load(); await model.createDevice()
            let savedKey = try XCTUnwrap(store.draft?.privateKey)
            await model.refresh(); await model.createDevice()
            XCTAssertEqual(creates, 1, code)
            XCTAssertEqual(store.draft?.stage, .submitted, code)
            XCTAssertEqual(store.draft?.privateKey, savedKey, code)
        }
    }

    func testCreatedDraftRejectsCorruptAssignedAddresses() throws {
        let binding = String(repeating: "a", count: 64)
        var draft = try AccountDeviceDraft.generate(account: binding)
        draft.stage = .created
        draft.device = CreatedAccountDevice(id: "33333333-3333-3333-3333-333333333333", name: "Test Bird", pubkey: draft.publicKey, created: nil, ipv4Address: "invalid/32", ipv6Address: "fc00::3/128")
        XCTAssertThrowsError(try draft.validate(account: binding))
    }

    @MainActor
    func testFirstInstallMarksActivatedOnlyAfterBoundBackendProofAndKeepsKey() async throws {
        let draft = try createdDraft(binding: String(repeating: "a", count: 64))
        let store = MemoryAccountDraftStore(); store.draft = draft
        let before = identitySnapshot(draft, installed: false), after = identitySnapshot(draft, installed: true)
        var installs = 0
        AccountProtocol.handler = { request in
            if request.url!.path == "/account/identity/install" { installs += 1; return (200, after) }
            return (200, before)
        }
        let model = AccountViewModel(client: client(), draftStore: store)
        await model.load(); await model.installDraft()
        XCTAssertEqual(installs, 1)
        XCTAssertEqual(model.deviceDraft?.stage, .activated)
        XCTAssertEqual(store.draft?.privateKey, draft.privateKey)
        XCTAssertTrue(model.snapshot?.hasLocalIdentity == true)
        XCTAssertFalse(model.hasError)
    }

    @MainActor
    func testLostInstallReplyUsesReadbackWithoutReplayingInstall() async throws {
        let draft = try createdDraft(binding: String(repeating: "a", count: 64))
        let store = MemoryAccountDraftStore(); store.draft = draft
        let before = identitySnapshot(draft, installed: false), after = identitySnapshot(draft, installed: true)
        var installs = 0
        AccountProtocol.handler = { request in
            if request.url!.path == "/account/identity/install" { installs += 1; return (422, Data(#"{"code":"identity_install_unknown","error":"lost reply"}"#.utf8)) }
            return (200, installs == 0 ? before : after)
        }
        let model = AccountViewModel(client: client(), draftStore: store)
        await model.load(); await model.installDraft(); await model.installDraft()
        XCTAssertEqual(installs, 1)
        XCTAssertEqual(store.draft?.stage, .activated)
        XCTAssertEqual(store.draft?.privateKey, draft.privateKey)
    }

    @MainActor
    func testRegisteredWithoutAddressesCannotInstallOrArchive() async throws {
        var draft = try createdDraft(binding: String(repeating: "a", count: 64))
        draft.registeredDevice = AccountDevice(id: draft.device!.id, name: "Test Bird", pubkey: draft.publicKey, created: nil, current: false)
        draft.device = nil; draft.stage = .registered
        let store = MemoryAccountDraftStore(); store.draft = draft
        let snapshot = snapshotData(binding: draft.accountFingerprint)
        var requests = 0
        AccountProtocol.handler = { _ in requests += 1; return (200, snapshot) }
        let model = AccountViewModel(client: client(), draftStore: store)
        await model.load(); await model.installDraft(); await model.createDevice()
        XCTAssertEqual(requests, 1)
        XCTAssertEqual(store.draft?.stage, .registered)
        XCTAssertTrue(store.archives.isEmpty)
    }

    @MainActor
    func testActivatedDraftArchivesBeforeAnotherExplicitCreateAndFailureStopsRegistration() async throws {
        let draft = try createdDraft(binding: String(repeating: "a", count: 64), stage: .activated)
        let store = MemoryAccountDraftStore(); store.draft = draft; store.rejectArchive = true
        let snapshot = identitySnapshot(draft, installed: true)
        var creates = 0
        AccountProtocol.handler = { request in
            if request.url!.path == "/account/devices/create" { creates += 1; return (422, Data(#"{"code":"mutation_outcome_unknown","error":"synthetic timeout"}"#.utf8)) }
            return (200, snapshot)
        }
        let model = AccountViewModel(client: client(), draftStore: store)
        await model.load(); await model.createDevice()
        XCTAssertEqual(creates, 0)
        XCTAssertEqual(store.draft, draft)
        store.rejectArchive = false
        await model.createDevice()
        XCTAssertEqual(creates, 1)
        XCTAssertEqual(store.archives, [draft])
        XCTAssertNotEqual(store.draft?.publicKey, draft.publicKey)
        XCTAssertEqual(store.draft?.stage, .submitted)
    }

    func testKeychainArchivePreservesExactBytesBeforeReplacingActivatedSlot() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let keychain = MockAccountKeychain()
        let store = AccountDraftStore(keychain: keychain, stateDirectory: directory)
        let draft = try createdDraft(binding: String(repeating: "a", count: 64), stage: .activated)
        try store.save(draft)
        let original = keychain.records.values.first!
        keychain.trace.removeAll()
        let next = try store.prepareNextDraft(from: draft)
        XCTAssertEqual(next.stage, .prepared)
        XCTAssertNotEqual(next.publicKey, draft.publicKey)
        XCTAssertEqual(try store.load(account: draft.accountFingerprint), next)
        XCTAssertTrue(keychain.records.contains { $0.key.contains("archives|") && $0.value == original })
        XCTAssertLessThan(keychain.trace.firstIndex(of: "read_archive")!, keychain.trace.firstIndex(of: "update_active")!)
    }

    func testKeychainArchiveReadbackAndAmbiguousReplacementNeverLosePreviousKey() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let keychain = MockAccountKeychain()
        let store = AccountDraftStore(keychain: keychain, stateDirectory: directory)
        let draft = try createdDraft(binding: String(repeating: "a", count: 64), stage: .activated)
        try store.save(draft)
        let original = keychain.records.values.first!
        keychain.failArchiveRead = true
        XCTAssertThrowsError(try store.prepareNextDraft(from: draft))
        XCTAssertEqual(try store.load(account: draft.accountFingerprint), draft)
        keychain.failArchiveRead = false; keychain.ambiguousActiveUpdate = true
        XCTAssertThrowsError(try store.prepareNextDraft(from: draft))
        XCTAssertTrue(keychain.records.contains { $0.key.contains("archives|") && $0.value == original })
        XCTAssertEqual(try store.load(account: draft.accountFingerprint)?.stage, .prepared)
    }

    @MainActor
    func testConfirmedAbandonmentKeepsOldKeyUntilExplicitCreateArchivesIt() async throws {
        let draft = try createdDraft(binding: String(repeating: "a", count: 64))
        let proof = abandonmentProof(draft)
        let store = MemoryAccountDraftStore(); store.draft = draft
        let before = abandonmentSnapshot(draft, pending: draft), after = abandonmentSnapshot(draft)
        var cancelled = false, cancels = 0, creates = 0, paths: [String] = []
        AccountProtocol.handler = { request in
            let path = request.url!.path; paths.append(path)
            if path == "/account/identity/abandon" {
                let body = self.requestObject(request)
                XCTAssertEqual(body["account_fingerprint"] as? String, draft.accountFingerprint)
                XCTAssertEqual(body["expected_installation_account_fingerprint"] as? String, draft.accountFingerprint)
                XCTAssertEqual(body["expected_metadata_sha256"] as? String, proof.metadataSHA256)
                XCTAssertNil(body["private_key"])
                cancels += 1; cancelled = true; return (200, after)
            }
            if path == "/account/identity/abandonment-status" { return (200, self.receiptData(cancelled ? proof : nil)) }
            if path == "/account/devices/create" {
                creates += 1
                XCTAssertEqual(store.archives.first?.privateKey, draft.privateKey)
                XCTAssertEqual(store.archives.first?.stage, .abandoned)
                return (422, Data(#"{"code":"mutation_outcome_unknown","error":"synthetic timeout"}"#.utf8))
            }
            return (200, cancelled ? after : before)
        }
        let model = AccountViewModel(client: client(), draftStore: store)
        await model.load(); await model.abandonPendingInstallation()
        XCTAssertEqual(cancels, 1)
        XCTAssertEqual(creates, 0)
        XCTAssertEqual(store.draft?.stage, .abandoned)
        XCTAssertEqual(store.draft?.privateKey, draft.privateKey)
        XCTAssertTrue(store.archives.isEmpty)
        XCTAssertFalse(paths.contains("/account/refresh"))
        await model.createDevice()
        XCTAssertEqual(creates, 1)
        XCTAssertEqual(store.archives.count, 1)
        XCTAssertNotEqual(store.draft?.publicKey, draft.publicKey)
    }

    @MainActor
    func testLostCancelReplyReadsCrossAccountProofWithoutTouchingOtherDraft() async throws {
        let old = try createdDraft(binding: String(repeating: "a", count: 64))
        let current = try createdDraft(binding: String(repeating: "b", count: 64))
        let proof = abandonmentProof(old)
        let store = MemoryAccountDraftStore(); store.draft = current
        let before = abandonmentSnapshot(current, pending: old), after = abandonmentSnapshot(current)
        var cancelled = false, cancels = 0, paths: [String] = []
        AccountProtocol.handler = { request in
            let path = request.url!.path; paths.append(path)
            if path == "/account/identity/abandon" {
                let body = self.requestObject(request)
                XCTAssertEqual(body["account_fingerprint"] as? String, current.accountFingerprint)
                XCTAssertEqual(body["expected_installation_account_fingerprint"] as? String, old.accountFingerprint)
                cancels += 1; cancelled = true
                return (500, Data(#"{"code":"identity_abandonment_unknown","error":"lost reply"}"#.utf8))
            }
            if path == "/account/identity/abandonment-status" {
                let body = self.requestObject(request)
                return (200, self.receiptData(cancelled && body["installation_account_fingerprint"] as? String == old.accountFingerprint ? proof : nil))
            }
            return (200, cancelled ? after : before)
        }
        let model = AccountViewModel(client: client(), draftStore: store)
        await model.load(); await model.abandonPendingInstallation()
        XCTAssertEqual(cancels, 1)
        XCTAssertEqual(store.draft, current)
        XCTAssertTrue(store.archives.isEmpty)
        XCTAssertFalse(model.hasError)
        XCTAssertFalse(paths.contains("/account/refresh"))
        XCTAssertFalse(paths.contains("/account/devices/create"))
    }

    @MainActor
    func testLaterLoginRestoresAbandonedStateOnlyFromVerifiedBackendReceipt() async throws {
        let draft = try createdDraft(binding: String(repeating: "a", count: 64))
        let store = MemoryAccountDraftStore(); store.draft = draft
        let snapshot = abandonmentSnapshot(draft), proof = abandonmentProof(draft)
        var creates = 0
        AccountProtocol.handler = { request in
            if request.url!.path == "/account/identity/abandonment-status" { return (200, self.receiptData(proof)) }
            if request.url!.path == "/account/devices/create" { creates += 1 }
            return (200, snapshot)
        }
        let model = AccountViewModel(client: client(), draftStore: store)
        await model.load()
        XCTAssertEqual(model.deviceDraft?.stage, .abandoned)
        XCTAssertEqual(store.draft?.privateKey, draft.privateKey)
        XCTAssertEqual(creates, 0)
    }

    @MainActor
    func testUiForgedRetiredStageCannotGenerateAnotherKeyWithoutBackendProof() async throws {
        var draft = try createdDraft(binding: String(repeating: "a", count: 64))
        draft.stage = .abandoned; draft.abandonmentReceipt = abandonmentProof(draft)
        let store = MemoryAccountDraftStore(); store.draft = draft
        let snapshot = abandonmentSnapshot(draft)
        var creates = 0
        AccountProtocol.handler = { request in
            if request.url!.path == "/account/identity/abandonment-status" { return (200, self.receiptData(nil)) }
            if request.url!.path == "/account/devices/create" { creates += 1 }
            return (200, snapshot)
        }
        let model = AccountViewModel(client: client(), draftStore: store)
        await model.load(); await model.createDevice()
        XCTAssertTrue(model.hasError)
        XCTAssertEqual(store.draft, draft)
        XCTAssertTrue(store.archives.isEmpty)
        XCTAssertEqual(creates, 0)
    }

    @MainActor
    func testUnfinishedCancellationBlocksCreateEvenWithACompletedArchiveProof() async throws {
        var draft = try createdDraft(binding: String(repeating: "a", count: 64))
        draft.stage = .abandoned; draft.abandonmentReceipt = abandonmentProof(draft)
        let store = MemoryAccountDraftStore(); store.draft = draft
        let snapshot = abandonmentSnapshot(draft, pending: draft, cancellationPending: true)
        var requests = 0
        AccountProtocol.handler = { _ in requests += 1; return (200, snapshot) }
        let model = AccountViewModel(client: client(), draftStore: store)
        await model.load(); await model.createDevice()
        XCTAssertEqual(requests, 1)
        XCTAssertEqual(store.draft, draft)
        XCTAssertTrue(store.archives.isEmpty)
    }

    func testAbandonedDraftKeychainArchiveKeepsOriginalProofAndKeyBytes() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let keychain = MockAccountKeychain()
        let store = AccountDraftStore(keychain: keychain, stateDirectory: directory)
        var draft = try createdDraft(binding: String(repeating: "a", count: 64))
        draft.stage = .abandoned; draft.abandonmentReceipt = abandonmentProof(draft)
        try store.save(draft)
        let raw = keychain.records.values.first!
        let next = try store.prepareNextDraft(from: draft)
        XCTAssertEqual(next.stage, .prepared)
        XCTAssertNotEqual(next.publicKey, draft.publicKey)
        XCTAssertTrue(keychain.records.contains { $0.key.contains("archives|") && $0.value == raw })
        XCTAssertEqual(try JSONDecoder().decode(AccountDeviceDraft.self, from: raw).abandonmentReceipt, draft.abandonmentReceipt)
    }

    @MainActor
    func testAccountPageRendersWithinMinimumWindow() {
        let model = AdapterViewModel(preview: true)
        let view = NSHostingView(rootView: AccountView(model: model))
        view.frame = NSRect(x: 0, y: 0, width: 820, height: 650)
        view.layoutSubtreeIfNeeded()
        XCTAssertLessThanOrEqual(view.fittingSize.width, 820)
    }
}
