import XCTest
@testable import MullvadAdapterUI

final class DiagnosticReportTests: XCTestCase {
    func testReportSurvivesUnavailableDaemonAndRedactsAllSections() {
        let report = DiagnosticReportExporter.render(
            status: nil, metrics: Data(#"{"password":"metrics-secret"}"#.utf8),
            cachedSummary: "private_key=cache-secret", errors: ["Bearer error-secret"],
            logs: [("/tmp/events.jsonl", "account: 1234567890123456\nhttps://user:pass@example.test\nhttps://example.test/?token=abc")])
        XCTAssertTrue(report.contains("FAIL（服务未响应"))
        XCTAssertTrue(report.contains("/tmp/events.jsonl"))
        for secret in ["metrics-secret", "cache-secret", "error-secret", "1234567890123456", "user:pass", "token=abc"] {
            XCTAssertFalse(report.contains(secret), secret)
        }
    }

    func testTailIsBoundedAndPreservesRecentEvidence() throws {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: path) }
        try Data((String(repeating: "old log line\n", count: 100) + "recent failure\n").utf8).write(to: path)
        let tail = DiagnosticReportExporter.readTail(path, byteLimit: 100)
        XCTAssertLessThanOrEqual(tail.utf8.count, 100)
        XCTAssertTrue(tail.hasSuffix("recent failure\n"))
    }

    func testReportIncludesCityBoundaryAndRedactsCityCredentials() {
        let report = DiagnosticReportExporter.render(status: nil, metrics: nil,
            cities: Data(#"{"selected_city":"us-sjc","auto_cross_city":false,"token":"city-secret"}"#.utf8),
            cachedSummary: "", errors: [], logs: [])
        XCTAssertTrue(report.contains("城市维护与备用候选"))
        XCTAssertTrue(report.contains("us-sjc"))
        XCTAssertTrue(report.contains("auto_cross_city"))
        XCTAssertFalse(report.contains("city-secret"))
    }

    func testRedactedStatusRemainsMachineReadableJSON() throws {
        let input = Data(#"{"instance_token":"secret-value","nested":{"pre_shared_key":"another-secret"},"status":"ready"}"#.utf8)
        let report = DiagnosticReportExporter.render(status: input, metrics: nil, cachedSummary: "", errors: [], logs: [])
        let block = try XCTUnwrap(report.components(separatedBy: "```json\n").dropFirst().first?.components(separatedBy: "\n```").first)
        let result = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(block.utf8)) as? [String: Any])
        XCTAssertEqual(result["status"] as? String, "ready")
        XCTAssertEqual(result["instance_token"] as? String, "[REDACTED]")
        XCTAssertFalse(report.contains("another-secret"))
    }
}
