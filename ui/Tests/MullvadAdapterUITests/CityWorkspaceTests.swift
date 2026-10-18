import XCTest
import SwiftUI
@testable import MullvadAdapterUI

final class CityWorkspaceTests: XCTestCase {
    func testPreviewDecodesPrimaryAndDistinctBackupEvidence() throws {
        let workspace = try JSONDecoder().decode(CityWorkspace.self, from: CityPreview.data("cities"))
        XCTAssertEqual(workspace.favoriteCities.count, 3)
        XCTAssertFalse(workspace.autoCrossCity)
        XCTAssertEqual(workspace.selected?.primary?.relay, "us-sjc-wg-506")
        XCTAssertEqual(workspace.selected?.backups.map(\.evidence), ["recent_ready", "expired_or_failed"])
        XCTAssertEqual(workspace.selected?.backups.last?.evidenceLabel, "需要重新验证")
    }

    @MainActor
    func testCityFailureDoesNotDiscardWorkingConnectionOrPriorWorkspace() async throws {
        let model = AdapterViewModel(client: client(), defaults: isolatedDefaults())
        model.cityWorkspace = try JSONDecoder().decode(CityWorkspace.self, from: CityPreview.data("cities"))
        CityTestProtocol.handler = { request in
            (request.url!.path == "/cities" ? 404 : 200, request.url!.path == "/cities" ? Data("{}".utf8) : CityPreview.data("status"))
        }
        await model.refreshStatusOnly()
        XCTAssertEqual(model.status?.serviceReadiness, "ready")
        XCTAssertEqual(model.cityWorkspace?.selectedCity, "us-sjc")
        XCTAssertNotNil(model.cityErrorMessage)
        XCTAssertNil(model.connectionError)
    }

    @MainActor
    func testCityDoubleClickPostsOnceAndRefreshesSelectedCity() async throws {
        var posts = 0
        CityTestProtocol.handler = { request in
            if request.url!.path == "/cities/select" {
                XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer test-capability")
                posts += 1
                return (202, Data(#"{"id":"city-test"}"#.utf8))
            }
            if request.url!.path.hasPrefix("/operations/") { return (200, Data(#"{"id":"city-test","state":"succeeded"}"#.utf8)) }
            return (200, CityPreview.data(request.url!.lastPathComponent, selected: "us-sea"))
        }
        let model = AdapterViewModel(client: client(), defaults: isolatedDefaults())
        model.selectCity("us-sea")
        model.selectCity("de-ber")
        for _ in 0..<100 where model.isActionRunning { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(posts, 1)
        XCTAssertFalse(model.isActionRunning)
        XCTAssertEqual(model.cityWorkspace?.selectedCity, "us-sea")
        XCTAssertEqual(model.status?.activeRelay, "us-sea-wg-506")
    }

    @MainActor
    func testPreviewCitySelectionUsesNoProvidedAPIClient() {
        CityTestProtocol.handler = { _ in XCTFail("preview must not use the injected production client"); return (500, Data()) }
        let model = AdapterViewModel(client: client(), defaults: isolatedDefaults(), preview: true)
        model.selectCity("de-ber")
        XCTAssertEqual(model.cityWorkspace?.selectedCity, "de-ber")
        XCTAssertEqual(model.status?.activeRelay, "de-ber-wg-506")
        XCTAssertFalse(model.isActionRunning)
    }

    @MainActor
    func testCityDashboardRendersAtMinimumWindowWidth() {
        let model = AdapterViewModel(defaults: isolatedDefaults(), preview: true)
        let host = NSHostingView(rootView: CityDashboardView(model: model))
        host.frame = NSRect(x: 0, y: 0, width: 820, height: 656)
        host.layoutSubtreeIfNeeded()
        XCTAssertEqual(host.frame.width, 820)
        XCTAssertNotNil(host.bitmapImageRepForCachingDisplay(in: host.bounds))
    }

    private func client() -> AdapterClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [CityTestProtocol.self]
        return AdapterClient(baseURL: URL(string: "http://city-tests.invalid")!, session: URLSession(configuration: config), accountCapability: { "test-capability" })
    }

    private func isolatedDefaults() -> UserDefaults { UserDefaults(suiteName: "city-tests-\(UUID().uuidString)")! }
}

private final class CityTestProtocol: URLProtocol {
    static var handler: ((URLRequest) -> (Int, Data))?
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let (code, data) = Self.handler?(request) ?? (500, Data())
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: code, httpVersion: nil, headerFields: nil)!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
