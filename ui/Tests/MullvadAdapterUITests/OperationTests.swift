import XCTest
import SwiftUI
import AppKit
@testable import MullvadAdapterUI

private final class StubProtocol: URLProtocol {
    static var handler: ((URLRequest) -> (Int, String))!
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let (code, body) = Self.handler(request)
        if code == -1 {
            client?.urlProtocol(self, didFailWithError: URLError(.networkConnectionLost))
            return
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: code, httpVersion: nil, headerFields: nil)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

final class OperationTests: XCTestCase {
    func testAllOrdinaryControlPostsCarryLocalCapability() async throws {
        var paths: [String] = []
        StubProtocol.handler = { request in
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer test-capability")
            paths.append(request.url!.path)
            return (202, #"{"id":"authorized-operation","state":"queued"}"#)
        }
        for path in ["select", "reconnect", "cities/select", "speedtest/start", "repair", "diagnose"] {
            _ = try await client().startOperation(path)
        }
        await client().cancelOperation("authorized-operation")
        XCTAssertEqual(paths.count, 7)
    }

    @MainActor
    func testMetricsFailureDoesNotDiscardCurrentConnectionStatus() async {
        StubProtocol.handler = { request in
            if request.url!.path == "/metrics" { return (500, #"{"error":"metrics unavailable"}"#) }
            return (200, #"{"status":"ready","active_relay":"current-relay"}"#)
        }
        let model = AdapterViewModel(client: client())
        await model.loadSnapshot()
        XCTAssertEqual(model.status?.activeRelay, "current-relay")
        XCTAssertEqual(model.status?.status, "ready")
        XCTAssertNil(model.connectionError)
    }

    @MainActor
    func testStatusBarKeepsSameHeightForIdleLongErrorAndProgress() {
        let model = AdapterViewModel(client: client())
        let view = NSHostingView(rootView: OperationStatusBar(model: model))
        view.frame = NSRect(x: 0, y: 0, width: 800, height: 64)
        view.layoutSubtreeIfNeeded()
        XCTAssertEqual(view.fittingSize.height, 64, accuracy: 1)
        model.errorMessage = String(repeating: "很长的错误和文件路径，", count: 100)
        view.layoutSubtreeIfNeeded()
        XCTAssertEqual(view.fittingSize.height, 64, accuracy: 1)
        model.isActionRunning = true
        model.actionMessage = "正在处理"
        view.layoutSubtreeIfNeeded()
        XCTAssertEqual(view.fittingSize.height, 64, accuracy: 1)
    }

    func testTemporaryReadFailureDoesNotResubmitSpeedTest() async throws {
        var posts = 0
        var reads = 0
        StubProtocol.handler = { request in
            if request.url!.path == "/speedtest/start" {
                posts += 1
                return (202, #"{"id":"retry"}"#)
            }
            reads += 1
            if reads == 1 { return (-1, "") }
            return (200, #"{"id":"retry","state":"succeeded","result":{"relay":"test-relay","transport_mode":"ss","service_readiness":"ready"}}"#)
        }
        let result = try await client().speedTest(relay: "test-relay")
        XCTAssertEqual(result.relay, "test-relay")
        XCTAssertEqual(posts, 1)
        XCTAssertEqual(reads, 2)
    }

    func testCancelBeforeReceiptStillCancelsAcceptedOperation() async {
        let started = expectation(description: "POST sent")
        let cancelled = expectation(description: "cancel sent")
        cancelled.assertForOverFulfill = false
        StubProtocol.handler = { request in
            if request.url!.path == "/speedtest/start" {
                started.fulfill()
                Thread.sleep(forTimeInterval: 0.1)
                return (202, #"{"id":"cancel-before-receipt"}"#)
            }
            if request.url!.path == "/cancel" {
                var body = request.httpBody ?? Data()
                if let stream = request.httpBodyStream {
                    stream.open()
                    defer { stream.close() }
                    var buffer = [UInt8](repeating: 0, count: 1024)
                    while stream.hasBytesAvailable {
                        let count = stream.read(&buffer, maxLength: buffer.count)
                        if count <= 0 { break }
                        body.append(contentsOf: buffer.prefix(count))
                    }
                }
                let payload = try? JSONSerialization.jsonObject(with: body) as? [String: String]
                XCTAssertEqual(payload?["id"], "cancel-before-receipt")
                cancelled.fulfill()
                return (202, #"{"ok":true}"#)
            }
            return (200, #"{"id":"cancel-before-receipt","state":"cancelled"}"#)
        }
        let api = client()
        let task = Task { try await api.speedTest(relay: "test-relay") }
        await fulfillment(of: [started], timeout: 2)
        task.cancel()
        do { _ = try await task.value; XCTFail("Expected cancellation") }
        catch { XCTAssertTrue(error is CancellationError) }
        await fulfillment(of: [cancelled], timeout: 2)
    }

    @MainActor
    func testImmediateDoubleClickCreatesOneOperation() async throws {
        var posts = 0
        StubProtocol.handler = { request in
            if request.url!.path == "/speedtest/start" {
                posts += 1
                return (202, #"{"id":"single"}"#)
            }
            if request.url!.path == "/relay-history" { return (200, "[]") }
            return (200, #"{"id":"single","state":"succeeded","result":{"relay":"test-relay","transport_mode":"ss","service_readiness":"ready"}}"#)
        }
        let model = AdapterViewModel(client: client())
        model.testRelaySpeed(hostname: "test-relay")
        XCTAssertTrue(model.isSpeedTesting)
        model.testRelaySpeed(hostname: "test-relay")
        for _ in 0..<100 where model.isSpeedTesting { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertFalse(model.isSpeedTesting)
        XCTAssertEqual(posts, 1)
        XCTAssertTrue(model.feedbackSummary.contains("测速完成"))
    }

    private func client() -> AdapterClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [StubProtocol.self]
        return AdapterClient(session: URLSession(configuration: config), accountCapability: { "test-capability" })
    }

    func testAsyncSpeedTestUsesReceiptResult() async throws {
        var paths: [String] = []
        StubProtocol.handler = { request in
            let path = request.url!.path
            paths.append(path)
            if path == "/speedtest/start" { return (202, #"{"id":"test-operation"}"#) }
            return (200, #"{"id":"test-operation","state":"succeeded","result":{"relay":"test-relay","transport_mode":"ss","service_readiness":"ready"}}"#)
        }
        let result = try await client().speedTest(relay: "test-relay", transport: "ss")
        XCTAssertEqual(result.relay, "test-relay")
        XCTAssertEqual(paths, ["/speedtest/start", "/operations/test-operation"])
    }

    func testFailedSpeedTestDoesNotMasqueradeAsSuccessfulResult() async {
        StubProtocol.handler = { request in
            if request.url!.path == "/speedtest/start" { return (202, #"{"id":"test-operation"}"#) }
            return (200, #"{"id":"test-operation","state":"failed","message":"测速未完成，当前连接保持原样"}"#)
        }
        do {
            _ = try await client().speedTest(relay: "test-relay")
            XCTFail("Expected a terminal failure")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("当前连接保持原样"))
        }
    }

    func testNewStatusFieldsRemainOptionalForOlderDaemon() throws {
        let status = try JSONDecoder().decode(AdapterStatus.self, from: Data(#"{"status":"ready","generation":1}"#.utf8))
        XCTAssertNil(status.operation)
        XCTAssertNil(status.diagnosis)
        XCTAssertEqual(status.status, "ready")
    }

    func testControlFailureAndDataSuccessCanBeShownTogether() throws {
        let status = try JSONDecoder().decode(AdapterStatus.self, from: Data(#"{"front":{"ready":true,"controller_degraded":true,"data_path":{"status":"pass"}},"operation":{"id":"x","state":"running","message":"正在检查"}}"#.utf8))
        XCTAssertEqual(status.front?.controllerDegraded, true)
        XCTAssertEqual(status.front?.dataPath?.status, "pass")
        XCTAssertEqual(status.operation?.isRunning, true)
    }
}
