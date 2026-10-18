import XCTest
@testable import MullvadAdapterUI

final class HistoryContractTests: XCTestCase {
    private struct Fixture: Decodable {
        let cases: [Case]
    }
    private struct Case: Decodable {
        let name: String
        let id: String
        let summary: RelayHistorySummary
        let expectedRate: Double?
        let expectedEffectiveRate: Double
        let expectedScore: Double
        enum CodingKeys: String, CodingKey {
            case name, id, summary
            case expectedRate = "expected_rate"
            case expectedEffectiveRate = "expected_effective_rate"
            case expectedScore = "expected_score"
        }
    }
    private func fixtureData() throws -> Data {
        // Resolve from this checked-in test source, not the current working directory.
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        return try Data(contentsOf: root.appendingPathComponent("core/crates/history/fixtures/summary-contract.json"))
    }
    private func cases() throws -> [Case] {
        try JSONDecoder().decode(Fixture.self, from: fixtureData()).cases
    }

    func testActualModelDecodesSharedFieldsRatesAndWilsonScores() throws {
        for item in try cases() {
            let row = item.summary
            XCTAssertEqual(row.id, item.id, item.name)
            XCTAssertEqual(row.effectiveReadinessRate, item.expectedEffectiveRate, accuracy: 1e-12, item.name)
            XCTAssertEqual(row.stabilityConfidenceScore, item.expectedScore, accuracy: 1e-12, item.name)
            XCTAssertEqual(row.failedSamples, row.samples - row.readySamples, item.name)
            if row.samples == 0 {
                XCTAssertNil(row.readinessRate)
                XCTAssertNil(item.expectedRate)
                XCTAssertNil(row.latencyEwmaMs)
                XCTAssertNil(row.lastTestedAt)
            }
        }
    }

    func testMissingRateAndOptionalFieldsDoNotInventMeasurements() throws {
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: fixtureData()) as? [String: Any])
        let items = try XCTUnwrap(root["cases"] as? [[String: Any]])
        for item in items {
            var summary = try XCTUnwrap(item["summary"] as? [String: Any])
            for key in ["readiness_rate", "latency_ewma_ms", "best_delay_ms", "worst_delay_ms", "last_delay_ms",
                        "first_tested_at", "last_tested_at", "last_success_at", "last_failure_at", "source_counts"] {
                summary.removeValue(forKey: key)
            }
            let row = try JSONDecoder().decode(RelayHistorySummary.self, from: JSONSerialization.data(withJSONObject: summary))
            let expected = try XCTUnwrap(item["expected_effective_rate"] as? Double)
            XCTAssertEqual(row.effectiveReadinessRate, expected, accuracy: 1e-12)
            XCTAssertNil(row.latencyEwmaMs)
            XCTAssertNil(row.lastTestedAt)
            XCTAssertNil(row.sourceCounts)
        }
    }

    func testActualModelKeepsEveryOptionalMeasurementAndLabel() throws {
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: fixtureData()) as? [String: Any])
        let items = try XCTUnwrap(root["cases"] as? [[String: Any]])
        for item in items {
            let expected = try XCTUnwrap(item["summary"] as? [String: Any])
            let row = try JSONDecoder().decode(RelayHistorySummary.self, from: JSONSerialization.data(withJSONObject: expected))
            XCTAssertEqual(row.relayPassSamples, expected["relay_pass_samples"] as? Int)
            XCTAssertEqual(row.latencySamples, expected["latency_samples"] as? Int)
            XCTAssertEqual(row.latencyEwmaMs, expected["latency_ewma_ms"] as? Double)
            XCTAssertEqual(row.bestDelayMs, expected["best_delay_ms"] as? Int)
            XCTAssertEqual(row.worstDelayMs, expected["worst_delay_ms"] as? Int)
            XCTAssertEqual(row.lastDelayMs, expected["last_delay_ms"] as? Int)
            XCTAssertEqual(row.firstTestedAt, expected["first_tested_at"] as? String)
            XCTAssertEqual(row.lastTestedAt, expected["last_tested_at"] as? String)
            XCTAssertEqual(row.lastSuccessAt, expected["last_success_at"] as? String)
            XCTAssertEqual(row.lastFailureAt, expected["last_failure_at"] as? String)
            XCTAssertEqual(row.sourceCounts, expected["source_counts"] as? [String: Int])
            XCTAssertEqual(row.readinessRate, expected["readiness_rate"] as? Double)
        }
    }

    func testStableEvidencePenaltyCapAndDistinctTransportIdentities() throws {
        let items = try cases()
        let byName = Dictionary(uniqueKeysWithValues: items.map { ($0.name, $0.summary) })
        let stable = try XCTUnwrap(byName["stable_twenty"])
        let once = try XCTUnwrap(byName["one_success"])
        let three = try XCTUnwrap(byName["three_failures"])
        let five = try XCTUnwrap(byName["five_failures"])
        XCTAssertGreaterThan(stable.stabilityConfidenceScore, once.stabilityConfidenceScore)
        XCTAssertEqual(three.stabilityConfidenceScore, five.stabilityConfidenceScore, accuracy: 1e-12)
        let transports = items.map(\.summary).filter { $0.relay == "us-aaa-wg-003" }
        XCTAssertEqual(Set(transports.map(\.id)).count, 3)
        XCTAssertEqual(Set(transports.map(\.transportMode)), Set(["ss", "ipv4", "ipv6"]))
    }
}
