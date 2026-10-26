import XCTest
import Foundation
@testable import MullvadAdapterUI

private final class CatalogueFixtureState: @unchecked Sendable {
    private let lock = NSLock()
    private var requests: [(String, String, String?)] = []
    func reset() { lock.lock(); defer { lock.unlock() }; requests = [] }
    func record(_ request: URLRequest) {
        lock.lock(); defer { lock.unlock() }
        requests.append((request.httpMethod ?? "GET", request.url!.path, request.value(forHTTPHeaderField: "Authorization")))
    }
    var all: [(String, String, String?)] { lock.lock(); defer { lock.unlock() }; return requests }
}

private final class CatalogueFixtureProtocol: URLProtocol {
    static let state = CatalogueFixtureState()
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.state.record(request)
        let path = request.url!.path
        let data: Data
        let status: Int
        switch path {
        case "/metadata/refresh":
            status = 202
            data = Data(#"{"accepted":true,"refreshing":true}"#.utf8)
        case "/metadata":
            status = 200
            data = Data(#"{"live":true,"cache":true,"refreshing":false,"fetched_at":"2026-01-01T12:00:00Z","relay_count":5}"#.utf8)
        case "/relays", "/relay-history":
            status = 200
            data = Data("[]".utf8)
        default:
            status = 200
            data = CityPreview.data(request.url!.lastPathComponent)
        }
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

final class CatalogueRefreshTests: XCTestCase {
    private func client() -> AdapterClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [CatalogueFixtureProtocol.self]
        return AdapterClient(baseURL: URL(string: "http://catalogue-fixture.invalid")!, session: URLSession(configuration: config), accountCapability: { "fixture-capability" })
    }

    func testRefreshUsesAuthorizedPostAndSeparateLiveProgressRead() async throws {
        CatalogueFixtureProtocol.state.reset()
        let client = client()
        let receipt = try await client.refreshCatalogue()
        XCTAssertTrue(receipt.accepted)
        let progress = try await client.fetchCatalogueStatus()
        XCTAssertEqual(progress.refreshing, false)
        XCTAssertEqual(progress.relayCount, 5)
        let requests = CatalogueFixtureProtocol.state.all
        XCTAssertEqual(requests.map { $0.1 }, ["/metadata/refresh", "/metadata"])
        XCTAssertEqual(requests.first?.0, "POST")
        XCTAssertEqual(requests.first?.2, "Bearer fixture-capability")
    }

    @MainActor
    func testManualRefreshIsCoalescedAndDoesNotClaimAConnectionOperation() async throws {
        CatalogueFixtureProtocol.state.reset()
        let defaults = UserDefaults(suiteName: "catalogue-fixture-\(UUID().uuidString)")!
        let model = AdapterViewModel(client: client(), defaults: defaults)
        model.refreshOfficialCatalogue()
        model.refreshOfficialCatalogue()
        XCTAssertTrue(model.isRefreshingCatalogue)
        XCTAssertFalse(model.isActionRunning)
        for _ in 0..<200 {
            if !model.isRefreshingCatalogue { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertFalse(model.isRefreshingCatalogue)
        XCTAssertEqual(model.catalogueMessage, "官方目录已更新")
        let requests = CatalogueFixtureProtocol.state.all
        XCTAssertEqual(requests.filter { $0.1 == "/metadata/refresh" }.count, 1)
        XCTAssertTrue(requests.contains { $0.1 == "/relays" })
        XCTAssertFalse(requests.contains { ["/reconnect", "/select", "/repair"].contains($0.1) })
    }
}
