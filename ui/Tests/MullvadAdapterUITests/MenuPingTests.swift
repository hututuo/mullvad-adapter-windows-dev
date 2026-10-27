import XCTest
@testable import MullvadAdapterUI

final class MenuPingTests: XCTestCase {
    private func snapshot(_ overrides: [String: Any] = [:]) throws -> AdapterStatus {
        var data: [String: Any] = ["status": "ready", "service_readiness": "ready", "relay_liveness": "pass", "active_slot": "a",
            "switched_at": "2026-10-27T22:00:00Z", "last_canary": ["at": "2026-10-27T22:01:00Z",
                "ping_data": ["status": "pass", "delay_ms": 100], "ip_data": ["status": "pass"],
                "inner_dns": ["status": "pass"], "https_data": ["status": "pass"]]]
        data.merge(overrides) { _, new in new }
        return try JSONDecoder().decode(AdapterStatus.self, from: JSONSerialization.data(withJSONObject: data))
    }
    private var now: Date { ISO8601DateFormatter().date(from: "2026-10-27T22:01:10Z")! }
    func testHealthyFreshDataAllowsAnOuterPing() throws {
        XCTAssertEqual(try snapshot().validatedMenuPing(now: now), 100)
    }
    func testPingAloneCannotGiveTheMenuAConnectedLatency() throws {
        for value in ["data_fail", "degraded_dns", "degraded_service", "reconnecting"] {
            XCTAssertNil(try snapshot(["service_readiness": value]).validatedMenuPing(now: now))
        }
        let canary: [String: Any] = ["at": "2026-10-27T22:01:00Z", "ping_data": ["status": "pass", "delay_ms": 100],
            "ip_data": ["status": "fail"], "inner_dns": ["status": "fail"], "https_data": ["status": "skip"]]
        XCTAssertNil(try snapshot(["last_canary": canary]).validatedMenuPing(now: now))
    }
    func testOldOrPreviousPathPingCannotBeShownAsCurrent() throws {
        XCTAssertNil(try snapshot().validatedMenuPing(now: now.addingTimeInterval(300)))
        XCTAssertNil(try snapshot(["switched_at": "2026-10-27T22:01:05Z"]).validatedMenuPing(now: now))
        XCTAssertNil(try snapshot(["recovery": ["phase": "original", "running": true]]).validatedMenuPing(now: now))
        XCTAssertNil(try snapshot(["active_slot": NSNull()]).validatedMenuPing(now: now))
    }
}
