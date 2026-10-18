import XCTest
import AppKit
import SwiftUI
import CryptoKit
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
            XCTAssertNil(body["private_key"])
            return (200, try! JSONSerialization.data(withJSONObject: ["id":"33333333-3333-3333-3333-333333333333", "name":"test bird", "pubkey":draft.publicKey, "ipv4_address":"10.1.2.3/32", "ipv6_address":"fc00::3/128"]))
        }
        let created = try await client().createDevice(publicKey: draft.publicKey)
        XCTAssertEqual(created.pubkey, draft.publicKey)
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
