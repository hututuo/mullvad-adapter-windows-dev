import XCTest
@testable import MullvadAdapterUI

final class LocalNetworkTests: XCTestCase {
    func testOldDaemonStatusRemainsCompatible() throws {
        let status = try decode(#"{"status":"ready","service_readiness":"ready"}"#)
        XCTAssertNil(status.localNetwork)
        XCTAssertEqual(status.serviceReadiness, "ready")
    }

    @MainActor
    func testOfflineStateOverridesStaleSuccessAndOperationMessage() throws {
        let model = AdapterViewModel(defaults: UserDefaults(suiteName: "network-test-\(UUID().uuidString)")!, preview: true)
        model.status = try decode(#"{"status":"waiting_network","service_readiness":"waiting_network","local_network":{"status":"unavailable","paused":true,"recovery_pending":true,"recovery_stage":"waiting","checked_at":"2026-10-05T12:00:00+08:00"},"last_canary":{"ip_data":{"status":"pass"},"inner_dns":{"status":"pass"},"https_data":{"status":"pass"}}}"#)
        model.speedMessage = "之前测速完成"
        XCTAssertEqual(model.feedbackSummary, "本机网络已断开，等待恢复；节点切换已暂停")
        XCTAssertTrue(readinessFacts(for: model.status!).isEmpty)
        XCTAssertTrue(model.feedbackDetails.first!.contains("2026-10-05T12:00:00+08:00"))
        XCTAssertEqual(localizedAdapterStatus(model.displayedStatus), "等待本机网络")
    }

    func testResumeStagesExplainWhichPathIsBeingTried() throws {
        for (stage, expected) in [("verify-original", "正在验证原通道"), ("rebuild-original", "正在重建原节点的原路径"), ("same-city-fallback", "正在验证同城备用节点")] {
            let status = try decode("{\"local_network\":{\"paused\":false,\"recovery_pending\":true,\"recovery_stage\":\"\(stage)\"}}")
            XCTAssertTrue(status.localNetwork!.message!.contains(expected))
        }
        XCTAssertEqual(readinessHeadline("network_recovering"), "本机网络恢复，正在验证原连接")
    }

    private func decode(_ json: String) throws -> AdapterStatus {
        try JSONDecoder().decode(AdapterStatus.self, from: Data(json.utf8))
    }
}
