import XCTest
import Foundation
import Darwin
@testable import MullvadAdapterUI

private final class ReadFixtureState: @unchecked Sendable {
    private let lock = NSLock()
    private var mode = "healthy"
    private var held: ReadFixtureProtocol?
    private var counts: [String: Int] = [:]
    func count(_ path: String) -> Int { lock.lock(); defer { lock.unlock() }; return counts[path, default: 0] }
    func saw(_ path: String) { lock.lock(); defer { lock.unlock() }; counts[path, default: 0] += 1 }
    func set(_ value: String) { lock.lock(); defer { lock.unlock() }; mode = value }
    func current() -> String { lock.lock(); defer { lock.unlock() }; return mode }
    func hold(_ value: ReadFixtureProtocol) { lock.lock(); defer { lock.unlock() }; held = value }
    func take() -> ReadFixtureProtocol? { lock.lock(); defer { lock.unlock() }; defer { held = nil }; return held }
}

private final class ReadFixtureProtocol: URLProtocol {
    static let state = ReadFixtureState()
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let mode = Self.state.current()
        Self.state.saw(request.url!.path)
        if (mode == "hold-cities" && request.url!.path == "/cities") || (mode == "hold-account" && request.url!.path == "/account") {
            Self.state.hold(self); return
        }
        if request.url!.path == "/status" {
            if mode == "timed" || mode == "wrong-request" || mode == "bad-dispatch" {
                respond(200, CityPreview.data("status"), headers: [
                    "X-Adapter-Request-Id": mode == "wrong-request" ? UUID().uuidString : request.value(forHTTPHeaderField: "X-Adapter-Request-Id")!,
                    "X-Adapter-Dispatch-Ms": mode == "bad-dispatch" ? "-1" : "12",
                    "X-Adapter-Request-Read-Ms": "3"])
                return
            }
            if mode == "stale" { respond(503, Data(#"{"code":"status_snapshot_stale"}"#.utf8)); return }
            if mode == "aged" { respond(200, CityPreview.data("status"), headers: ["X-Adapter-Status-Age-Ms": "2300", "X-Adapter-Status-Capture-Ms": "51"]); return }
            if mode == "expired" { respond(200, CityPreview.data("status"), headers: ["X-Adapter-Status-Age-Ms": "3001"]); return }
            if mode == "bad-age" { respond(200, CityPreview.data("status"), headers: ["X-Adapter-Status-Age-Ms": "-1"]); return }
            if mode == "hold" { Self.state.hold(self); return }
            if mode == "cancel" { fail(URLError(.cancelled)); return }
            if mode == "timeout" { fail(URLError(.timedOut)); return }
            if mode == "http" { respond(500, Data(#"{"error":"Bearer secret-response"}"#.utf8)); return }
            if mode == "invalid" { respond(200, Data("private_key=not-json-secret".utf8)); return }
        }
        respond(200, CityPreview.data(request.url!.lastPathComponent))
    }
    func fail(_ error: Error) { client?.urlProtocol(self, didFailWithError: error) }
    func respond(_ code: Int, _ data: Data, headers: [String: String]? = nil) {
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: code, httpVersion: nil, headerFields: headers)!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

private final class ReadEvents: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [StatusReadEvent] = []
    func append(_ event: StatusReadEvent) { lock.lock(); defer { lock.unlock() }; events.append(event) }
    var all: [StatusReadEvent] { lock.lock(); defer { lock.unlock() }; return events }
}

final class StatusReadTests: XCTestCase {
    private func finishNew(_ health: inout StatusReadHealth, failure: StatusReadFailure?, at time: TimeInterval) -> Bool {
        let id = health.begin()
        return health.finish(id, failure: failure, at: time)
    }

    func testSustainedTransportFailureNeedsCountAndTimeAndSuccessResets() {
        var h = StatusReadHealth()
        let timeout = StatusReadFailure.classify(URLError(.timedOut))
        XCTAssertTrue(finishNew(&h, failure: nil, at: 0))
        for time in [1.0, 2, 3] { XCTAssertTrue(finishNew(&h, failure: timeout, at: time)) }
        XCTAssertEqual(h.displayStatus(at: 3), "status_pending")
        XCTAssertTrue(finishNew(&h, failure: timeout, at: 11))
        XCTAssertEqual(h.displayStatus(at: 11), "status_unavailable")
        XCTAssertTrue(finishNew(&h, failure: nil, at: 12))
        XCTAssertNil(h.displayStatus(at: 12))
        XCTAssertEqual(h.failureCount, 0)
        XCTAssertEqual(h.lastSuccessAt, 12)
    }

    func testRespondedErrorsCannotCountAsUnreachableOrContributeTransportStrikes() {
        var h = StatusReadHealth()
        let http = StatusReadFailure.classify(AdapterClientError.http(status: 500, code: nil, message: "secret"))
        for time in [0.0, 15, 30] { XCTAssertTrue(finishNew(&h, failure: http, at: time)) }
        XCTAssertEqual(h.displayStatus(at: 30), "status_error")
        XCTAssertTrue(finishNew(&h, failure: .classify(URLError(.timedOut)), at: 40))
        XCTAssertEqual(h.displayStatus(at: 40), "status_pending")
        XCTAssertTrue(finishNew(&h, failure: .classify(AdapterClientError.invalidResponse("secret")), at: 50))
        XCTAssertEqual(h.displayStatus(at: 50), "status_invalid")
    }

    func testOldSuccessAndOldFailureCannotReplaceNewerObservation() {
        var h = StatusReadHealth()
        let old = h.begin(), new = h.begin()
        XCTAssertTrue(h.finish(new, failure: nil, at: 1))
        XCTAssertFalse(h.finish(old, failure: .classify(URLError(.timedOut)), at: 2))
        XCTAssertNil(h.lastFailure)
        let older = h.begin(), newer = h.begin()
        XCTAssertTrue(h.finish(newer, failure: .classify(URLError(.timedOut)), at: 3))
        XCTAssertFalse(h.finish(older, failure: nil, at: 4))
        XCTAssertEqual(h.lastSuccessAt, 1)
    }

    func testCancellationDoesNotAdvanceFenceOrAlterFailureHistory() {
        var h = StatusReadHealth()
        let old = h.begin(), cancelled = h.begin()
        XCTAssertFalse(h.finish(cancelled, failure: .classify(URLError(.cancelled)), at: 3))
        XCTAssertTrue(h.finish(old, failure: nil, at: 4))
        XCTAssertEqual(h.failureCount, 0)
        XCTAssertNil(h.lastFailure)
    }

    @MainActor private func model(_ events: ReadEvents,
                                  clock: @escaping @Sendable () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }) -> AdapterViewModel {
        ReadFixtureProtocol.state.set("healthy")
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [ReadFixtureProtocol.self]
        let defaults = UserDefaults(suiteName: "status-read-tests-\(UUID().uuidString)")!
        defaults.set(false, forKey: "MullvadAdapterUI.notificationsEnabled")
        return AdapterViewModel(client: AdapterClient(baseURL: URL(string: "http://status-fixtures.invalid")!, session: URLSession(configuration: config)), defaults: defaults,
                                statusEventSink: { events.append($0) }, statusClock: clock)
    }

    @MainActor func testCancelledReadPreservesReadyAndProducesCancellationEvidence() async throws {
        let events = ReadEvents()
        let subject = model(events)
        await subject.refreshStatusOnly()
        ReadFixtureProtocol.state.set("cancel")
        await subject.refreshStatusOnly()
        XCTAssertEqual(subject.displayedStatus, "ready")
        XCTAssertNil(subject.connectionError)
        XCTAssertEqual(events.all.last?.event, "status-read-cancelled")
        XCTAssertEqual(events.all.last?.consecutiveFailures, 0)
    }

    @MainActor func testHTTPAndDecodeFailuresRetainSnapshotButDoNotClaimCurrentReady() async throws {
        let events = ReadEvents(), m = model(events)
        await m.refreshStatusOnly()
        for (mode, state) in [("http", "status_error"), ("invalid", "status_invalid"), ("timeout", "status_pending")] {
            ReadFixtureProtocol.state.set(mode)
            await m.refreshStatusOnly()
            XCTAssertEqual(m.displayedStatus, state)
            XCTAssertEqual(m.status?.serviceReadiness, "ready")
            XCTAssertNotNil(m.connectionError)
            XCTAssertNotNil(m.lastUpdated)
        }
        let text = String(decoding: try JSONEncoder().encode(events.all), as: UTF8.self)
        XCTAssertFalse(text.contains("secret"))
        XCTAssertFalse(text.contains("private_key"))
        XCTAssertFalse(text.contains("status-fixtures"))
        XCTAssertTrue(text.contains("-1001"))
        ReadFixtureProtocol.state.set("healthy")
        await m.refreshStatusOnly()
        XCTAssertNil(m.connectionError)
        XCTAssertEqual(events.all.last?.event, "status-read-recovered")
    }

    @MainActor func testLateFailureDoesNotCoverNewSuccessInRealViewModel() async throws {
        let events = ReadEvents(), m = model(events)
        await m.refreshStatusOnly()
        ReadFixtureProtocol.state.set("hold")
        let old = Task { await m.refreshStatusOnly() }
        var held: ReadFixtureProtocol?
        for _ in 0..<1000 {
            held = ReadFixtureProtocol.state.take()
            if held != nil { break }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        let pending = try XCTUnwrap(held)
        ReadFixtureProtocol.state.set("healthy")
        await m.refreshStatusOnly()
        pending.fail(URLError(.timedOut))
        await old.value
        XCTAssertEqual(m.displayedStatus, "ready")
        XCTAssertNil(m.connectionError)
        XCTAssertTrue(events.all.contains { $0.event == "status-read-discarded" && $0.failureKind == "timeout" })
    }


    private func fixtureSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [ReadFixtureProtocol.self]
        return URLSession(configuration: config)
    }

    private func heldRequest() async throws -> ReadFixtureProtocol {
        for _ in 0..<1000 {
            if let held = ReadFixtureProtocol.state.take() { return held }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        throw XCTUnwrapError.missingHeldRequest
    }

    private enum XCTUnwrapError: Error { case missingHeldRequest }

    func testProductionStatusSessionHasIndependentUncachedLocalPool() {
        let subject = AdapterClient()
        XCTAssertFalse(subject.session === subject.statusSession)
        let config = subject.statusSession.configuration
        XCTAssertNotNil(config.connectionProxyDictionary)
        XCTAssertTrue(config.connectionProxyDictionary!.isEmpty)
        XCTAssertNil(config.urlCache)
        XCTAssertNil(config.httpCookieStorage)
        XCTAssertNil(config.urlCredentialStorage)
        XCTAssertEqual(config.timeoutIntervalForResource, 5)
        let injected = fixtureSession()
        XCTAssertTrue(AdapterClient(session: injected).statusSession === injected)
        injected.invalidateAndCancel()
    }

    func testAccountCanRemainPendingWhileStatusUsesIndependentSession() async throws {
        let ordinary = fixtureSession(), status = fixtureSession()
        defer { ordinary.invalidateAndCancel(); status.invalidateAndCancel() }
        let subject = AdapterClient(baseURL: URL(string: "http://status-fixtures.invalid")!, session: ordinary,
                                    statusSession: status, accountCapability: { "fixture-capability" })
        ReadFixtureProtocol.state.set("hold-account")
        let account = Task { try await subject.account() }
        let pending = try await heldRequest()
        XCTAssertEqual(pending.request.value(forHTTPHeaderField: "Authorization"), "Bearer fixture-capability")
        let observed = try await subject.fetchStatus()
        XCTAssertEqual(observed.serviceReadiness, "ready")
        pending.fail(URLError(.cancelled))
        _ = await account.result
    }

    @MainActor func testPublicationDelayIsNotAnUnreachableServiceAndOldReadyIsNotFresh() async throws {
        let events = ReadEvents(), m = model(events)
        await m.refreshStatusOnly()
        let oldUpdate = m.lastUpdated
        ReadFixtureProtocol.state.set("stale")
        await m.refreshStatusOnly()
        XCTAssertEqual(m.displayedStatus, "status_stale")
        XCTAssertEqual(m.status?.serviceReadiness, "ready")
        XCTAssertEqual(m.lastUpdated, oldUpdate)
        XCTAssertEqual(events.all.last?.failureKind, "snapshot_stale")
        XCTAssertTrue(m.connectionError?.contains("本机服务能响应") == true)
        ReadFixtureProtocol.state.set("aged")
        await m.refreshStatusOnly()
        XCTAssertEqual(m.displayedStatus, "ready")
        XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(try XCTUnwrap(m.lastUpdated)), 2.3)
        XCTAssertEqual(events.all.last?.publicationAgeMs, 2300)
        XCTAssertEqual(events.all.last?.publicationCaptureMs, 51)
    }

    func testHeadersRejectExpiredOrMalformedAgeAndLegacyServerStillWorks() async throws {
        let session = fixtureSession()
        defer { session.invalidateAndCancel() }
        let subject = AdapterClient(baseURL: URL(string: "http://status-fixtures.invalid")!, session: session)
        ReadFixtureProtocol.state.set("healthy")
        let legacy = try await subject.fetchStatusObservation()
        XCTAssertNil(legacy.ageMilliseconds)
        XCTAssertEqual(legacy.snapshot.serviceReadiness, "ready")
        for mode in ["expired", "bad-age", "wrong-request", "bad-dispatch"] {
            ReadFixtureProtocol.state.set(mode)
            do { _ = try await subject.fetchStatusObservation(); XCTFail("must reject \(mode)") }
            catch {
                let failure = StatusReadFailure.classify(error)
                XCTAssertFalse(failure.connectivity)
                XCTAssertEqual(failure.kind, mode == "expired" ? "snapshot_stale" : "invalid_response")
            }
        }
    }

    @MainActor func testStatusCorrelationAndServerTimingSurviveIntoSafeEvents() async throws {
        let events = ReadEvents(), m = model(events)
        ReadFixtureProtocol.state.set("timed")
        await m.refreshStatusOnly()
        let event = try XCTUnwrap(events.all.last)
        XCTAssertNotNil(UUID(uuidString: try XCTUnwrap(event.correlationID)))
        XCTAssertEqual(event.serverDispatchMs, 12)
        XCTAssertEqual(event.serverRequestReadMs, 3)
        ReadFixtureProtocol.state.set("timeout")
        await m.refreshStatusOnly()
        let timeout = try XCTUnwrap(events.all.last)
        XCTAssertNotNil(UUID(uuidString: try XCTUnwrap(timeout.correlationID)))
        XCTAssertNotEqual(timeout.correlationID, event.correlationID)
        XCTAssertNil(timeout.serverDispatchMs)
    }

    @MainActor func testPollingContinuesWhileCityReadRemainsBlocked() async throws {
        let events = ReadEvents(), m = model(events)
        ReadFixtureProtocol.state.set("hold-cities")
        let before = ReadFixtureProtocol.state.count("/status")
        m.startStatusPolling()
        let city = try await heldRequest()
        defer { m.stopStatusPolling(); city.fail(URLError(.cancelled)) }
        // One full normal five-second interval, without live API/window/network work.
        for _ in 0..<650 {
            if ReadFixtureProtocol.state.count("/status") >= before + 2 { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertGreaterThanOrEqual(ReadFixtureProtocol.state.count("/status"), before + 2)
        XCTAssertEqual(m.displayedStatus, "ready")
    }

    private final class DelayedClock: @unchecked Sendable {
        private let lock = NSLock()
        private var calls = 0
        func now() -> TimeInterval {
            lock.lock(); defer { lock.unlock() }
            calls += 1
            return calls == 1 ? 0 : 1
        }
    }

    @MainActor func testRequestDelayCannotMakeOldPublicationFresh() async {
        let clock = DelayedClock(), events = ReadEvents()
        let m = model(events, clock: { clock.now() })
        ReadFixtureProtocol.state.set("aged")
        await m.refreshStatusOnly()
        XCTAssertEqual(m.displayedStatus, "status_stale")
        XCTAssertNil(m.status)
        XCTAssertNil(m.lastUpdated)
        XCTAssertEqual(events.all.last?.failureKind, "snapshot_stale")
    }

    func testPublicationAgeIsPreservedInHealthClock() {
        var health = StatusReadHealth()
        let id = health.begin()
        XCTAssertTrue(health.finish(id, failure: nil, at: 10, observationAge: 2.5))
        XCTAssertEqual(health.lastSuccessAt, 7.5)
    }

    func testLogRotationPermissionsAndMachineReadableAllowlist() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let logger = StatusReadLogger(directory: directory, limit: 1100)
        for id in 0..<20 {
            logger.record(.init(event: "status-read-failed", requestID: id, durationMs: 5001, failureKind: "timeout", errorCode: -1001, consecutiveFailures: id, snapshotAgeSeconds: id * 5, displayState: "status_pending"))
        }
        logger.flush()
        let files = ["ui-status.jsonl", "ui-status.jsonl.1"].map { directory.appendingPathComponent($0) }
        for file in files {
            let attrs = try FileManager.default.attributesOfItem(atPath: file.path)
            XCTAssertLessThanOrEqual((attrs[.size] as! NSNumber).intValue, 1100)
            XCTAssertEqual((attrs[.posixPermissions] as! NSNumber).intValue & 0o777, 0o600)
            for line in try String(contentsOf: file, encoding: .utf8).split(separator: "\n") {
                let row = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
                XCTAssertEqual(row["error_code"] as? Int, -1001)
                XCTAssertNotNil(row["at"])
                XCTAssertNotNil(row["session_id"])
                XCTAssertNil(row["url"])
                XCTAssertNil(row["message"])
            }
        }
        XCTAssertTrue(try String(contentsOf: files[0], encoding: .utf8).contains("\"request_id\":19"))
        let urls = DiagnosticReportExporter.diagnosticLogURLs(home: directory).map(\.lastPathComponent)
        XCTAssertTrue(urls.contains("ui-status.jsonl"))
        XCTAssertTrue(urls.contains("ui-status.jsonl.1"))
    }

    func testLoggerRefusesSymlinkWithoutWritingTarget() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("unrelated")
        try Data("unchanged".utf8).write(to: target)
        try FileManager.default.createSymbolicLink(at: directory.appendingPathComponent("ui-status.jsonl"), withDestinationURL: target)
        let logger = StatusReadLogger(directory: directory)
        logger.record(.init(event: "status-read-ready", requestID: 1, durationMs: 1, failureKind: nil, errorCode: nil, consecutiveFailures: 0, snapshotAgeSeconds: 0, displayState: nil))
        logger.flush()
        XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), "unchanged")
    }

    func testExportSkipsSymlinksAndFIFOsWithoutReadingOrWaiting() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("unrelated")
        try Data("must-not-export".utf8).write(to: target)
        let link = directory.appendingPathComponent("linked-log")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        XCTAssertFalse(DiagnosticReportExporter.readTail(link).contains("must-not-export"))
        let hard = directory.appendingPathComponent("hardlinked-log")
        try FileManager.default.linkItem(at: target, to: hard)
        XCTAssertFalse(DiagnosticReportExporter.readTail(hard).contains("must-not-export"))
        let fifo = directory.appendingPathComponent("fifo-log")
        XCTAssertEqual(mkfifo(fifo.path, 0o600), 0)
        let start = ProcessInfo.processInfo.systemUptime
        XCTAssertTrue(DiagnosticReportExporter.readTail(fifo).contains("非普通"))
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - start, 1)
    }

    func testExistingBroadPermissionsAreTightenedBeforeRotation() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("ui-status.jsonl")
        try Data(String(repeating: "x", count: 490).utf8).write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path.path)
        let logger = StatusReadLogger(directory: directory, limit: 500)
        logger.record(.init(event: "status-read-ready", requestID: 1, durationMs: 1, failureKind: nil, errorCode: nil, consecutiveFailures: 0, snapshotAgeSeconds: 0, displayState: nil))
        XCTAssertTrue(logger.flush())
        for file in [path, directory.appendingPathComponent("ui-status.jsonl.1")] {
            let attrs = try FileManager.default.attributesOfItem(atPath: file.path)
            XCTAssertEqual((attrs[.posixPermissions] as! NSNumber).intValue & 0o777, 0o600)
        }
        let attrs = try FileManager.default.attributesOfItem(atPath: directory.path)
        XCTAssertEqual((attrs[.posixPermissions] as! NSNumber).intValue & 0o777, 0o700)
    }

    func testLoggerRefusesLinkedDirectory() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("target")
        try FileManager.default.createDirectory(at: target, withIntermediateDirectories: true)
        let link = directory.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        let logger = StatusReadLogger(directory: link)
        logger.record(.init(event: "status-read-ready", requestID: 1, durationMs: 1, failureKind: nil, errorCode: nil, consecutiveFailures: 0, snapshotAgeSeconds: 0, displayState: nil))
        XCTAssertTrue(logger.flush())
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.appendingPathComponent("ui-status.jsonl").path))
    }
}
