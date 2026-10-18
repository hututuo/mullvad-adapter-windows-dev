import XCTest
@testable import MullvadAdapterUI

private actor ProbeRecorder {
    var active = 0
    var peak = 0
    var count = 0
    func probe(_ target: String) async -> QuickPingResult {
        active += 1
        count += 1
        peak = max(peak, active)
        try? await Task.sleep(nanoseconds: 30_000_000)
        active -= 1
        return QuickPingResult(target: target, milliseconds: 12, testedAt: Date(), detail: "test")
    }
    func values() -> (Int, Int) { (peak, count) }
}

final class QuickPingTests: XCTestCase {
    func testCityBoundedConcurrencyAndCountrySerial() async {
        for city in [true, false] {
            let recorder = ProbeRecorder()
            let names = (0..<9).map(String.init)
            await QuickPing.run(hostnames: names, targets: [:], cityConcurrency: city,
                                probe: { await recorder.probe($0) }, receive: { _, _ in })
            let (peak, count) = await recorder.values()
            XCTAssertEqual(count, 9)
            XCTAssertEqual(peak, city ? 4 : 1)
        }
    }

    func testCancelledBatchDoesNotStartNextWave() async {
        let recorder = ProbeRecorder()
        let task = Task {
            await QuickPing.run(hostnames: (0..<100).map(String.init), targets: [:], cityConcurrency: true,
                                probe: { await recorder.probe($0) }, receive: { _, _ in })
        }
        try? await Task.sleep(nanoseconds: 10_000_000)
        task.cancel()
        await task.value
        let (_, count) = await recorder.values()
        XCTAssertLessThanOrEqual(count, 4)
    }

    func testTargetFollowsTransport() throws {
        let data = Data(#"[{"hostname":"node","location":"us-sjc","quick_ping":{"ss":{"target":"192.0.2.2","kind":"shadowsocks-extra-ipv4"},"ipv4":{"target":"192.0.2.1","kind":"wireguard-ipv4"},"ipv6":{"target":"2001:db8::1","kind":"wireguard-ipv6"}}}]"#.utf8)
        let relays = try JSONDecoder().decode([RelayInfo].self, from: data)
        XCTAssertEqual(QuickPing.targets(transport: "ss", relays: relays)["node"]?.target, "192.0.2.2")
        XCTAssertEqual(QuickPing.targets(transport: "auto", relays: relays)["node"]?.target, "192.0.2.2")
        XCTAssertEqual(QuickPing.targets(transport: "ipv4", relays: relays)["node"]?.target, "192.0.2.1")
        XCTAssertEqual(QuickPing.targets(transport: "ipv6", relays: relays)["node"]?.target, "2001:db8::1")
        XCTAssertEqual(QuickPing.targets(transport: "ss", relays: relays)["node"]?.kind, "shadowsocks-extra-ipv4")
    }

    func testRejectsNonIPWithoutLaunchingCommand() async {
        let result = await QuickPing.probe("-f; echo bad")
        XCTAssertNil(result.milliseconds)
        XCTAssertEqual(result.detail, "无有效 IP 入口")
    }

    func testActualLoopbackPingAndCatalog() async throws {
        let result = await QuickPing.probe("127.0.0.1")
        XCTAssertNotNil(result.milliseconds)
        XCTAssertEqual(result.target, "127.0.0.1")
    }
}
