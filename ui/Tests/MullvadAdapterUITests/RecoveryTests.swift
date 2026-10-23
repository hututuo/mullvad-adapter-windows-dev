import XCTest
@testable import MullvadAdapterUI

final class RecoveryTests: XCTestCase {
    func testOlderDaemonDoesNotInventRecoveryProgress() throws {
        let status = try JSONDecoder().decode(AdapterStatus.self, from: Data(#"{"status":"ready"}"#.utf8))
        XCTAssertNil(status.recovery)
    }

    func testProgressDecodesActualTargetAttemptAndBudget() throws {
        let status = try JSONDecoder().decode(AdapterStatus.self, from: Data(#"{"recovery":{"phase":"same_city","running":true,"target_relay":"example","endpoint":"192.0.2.2","endpoint_port":20484,"attempt":7,"inlet_attempt":2,"city_attempt":2,"elapsed_seconds":80,"remaining_seconds":220,"budget_seconds":300,"next_step":"继续下一个同城候选"}}"#.utf8))
        let progress = try XCTUnwrap(status.recovery)
        XCTAssertEqual(progress.title, "3 · 尝试同城备用节点")
        XCTAssertEqual(progress.target, "example · 192.0.2.2:20484")
        XCTAssertEqual(progress.timing, "已尝试 7 次 · 用时 80 秒 / 300 秒预算")
        XCTAssertEqual(progress.cityAttempt, 2)
    }

    func testRetryWaitIsDelayAfterAttemptRatherThanConnectionDeadline() throws {
        let progress = try decode(#"{"phase":"retry_wait","running":true,"attempt":1,"elapsed_seconds":9,"budget_seconds":300,"retry_in_seconds":1}"#)
        XCTAssertTrue(progress.timing.contains("1 秒后重试"))
        XCTAssertTrue(progress.timing.contains("用时 9 秒"))
    }

    func testFinishedAndPendingStopHaveDifferentTitles() throws {
        XCTAssertEqual(try decode(#"{"phase":"stopped","running":true}"#).title, "正在停止恢复")
        XCTAssertEqual(try decode(#"{"phase":"stopped","running":false}"#).title, "自动恢复已停止")
        XCTAssertEqual(try decode(#"{"phase":"exhausted","running":false,"retry_in_seconds":30}"#).timing,
                       "已尝试 0 次 · 用时 0 秒 / 300 秒预算 · 30 秒后再开一轮")
    }

    private func decode(_ text: String) throws -> RecoveryStatus {
        try JSONDecoder().decode(RecoveryStatus.self, from: Data(text.utf8))
    }
}
