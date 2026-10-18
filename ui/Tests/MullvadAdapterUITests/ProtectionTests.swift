import XCTest
import AppKit
import SwiftUI
@testable import MullvadAdapterUI

private final class ProtectionProtocol: URLProtocol {
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

final class ProtectionTests: XCTestCase {
    private func client() -> AdapterClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [ProtectionProtocol.self]
        return AdapterClient(session: URLSession(configuration: config), accountCapability: { "test-capability" })
    }

    func testSnapshotKeepsRequestedAndEffectiveCapabilitiesSeparate() throws {
        let snapshot = try JSONDecoder().decode(ProtectionSnapshot.self, from: CityPreview.data("protection"))
        XCTAssertTrue(snapshot.profile.multihop)
        XCTAssertEqual(snapshot.effective?.entryCity, "jp-osa")
        XCTAssertFalse(snapshot.effective!.postQuantum)
        XCTAssertFalse(snapshot.effective!.daita)
        let disconnected = try JSONDecoder().decode(ProtectionSnapshot.self, from: Data(#"{"profile":{"multihop":true,"entry_city":"jp-tyo"},"effective":null,"capabilities":{}}"#.utf8))
        XCTAssertNil(disconnected.effective)
        XCTAssertTrue(disconnected.profile.multihop)
    }

    func testProtectionChangeUsesLocalCapabilityAndReceiptInsteadOfRepeatingPost() async throws {
        ProtectionProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer test-capability")
            XCTAssertEqual(request.url?.path, "/protection")
            XCTAssertEqual(request.httpMethod, "POST")
            let value = try! JSONDecoder().decode(ProtectionProfile.self, from: request.httpBody ?? request.httpBodyStream!.readAll())
            XCTAssertEqual(value, ProtectionProfile(multihop: true, entryCity: "jp-tyo"))
            return (202, Data(#"{"id":"protection-test","state":"queued"}"#.utf8))
        }
        let receipt = try await client().applyProtection(ProtectionProfile(multihop: true, entryCity: "jp-tyo"))
        XCTAssertEqual(receipt.id, "protection-test")
    }

    func testPQPolicyUsesExplicitJSONFieldAndLegacyDefaultsOff() throws {
        let old = try JSONDecoder().decode(ProtectionProfile.self, from: Data(#"{"multihop":false}"#.utf8))
        XCTAssertFalse(old.postQuantum)
        let enabled = ProtectionProfile(multihop: false, entryCity: nil, postQuantum: true)
        let json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(enabled)) as! [String: Any]
        XCTAssertEqual(json["post_quantum"] as? Bool, true)
    }

    @MainActor
    func testProtectionPageFitsMinimumDetailWidth() throws {
        let model = AdapterViewModel(preview: true)
        model.protection = try JSONDecoder().decode(ProtectionSnapshot.self, from: CityPreview.data("protection"))
        let view = NSHostingView(rootView: ProtectionView(model: model))
        view.frame = NSRect(x: 0, y: 0, width: 820, height: 650)
        view.layoutSubtreeIfNeeded()
        XCTAssertLessThanOrEqual(view.fittingSize.width, 820)
        if let path = ProcessInfo.processInfo.environment["PROTECTION_PREVIEW_PATH"],
           let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) {
            view.cacheDisplay(in: view.bounds, to: bitmap)
            try bitmap.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: path))
        }
    }
}

private extension InputStream {
    func readAll() -> Data {
        open(); defer { close() }
        var result = Data(); var buffer = [UInt8](repeating: 0, count: 2048)
        while true {
            let count = read(&buffer, maxLength: buffer.count)
            if count <= 0 { return result }
            result.append(buffer, count: count)
        }
    }
}
