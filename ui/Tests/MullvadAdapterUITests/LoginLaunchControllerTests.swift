import Foundation
import XCTest
@testable import MullvadAdapterUI

private final class LoginLaunchFake {
    var loaded = false
    var disabled = false
    var failures: [String: Int32] = [:]
    var calls: [String] = []
    var delay: UInt64 = 0
    var oversizedOverrides = false

    func run(_ arguments: [String]) async throws -> LoginLaunchCommandResult {
        let action = arguments[0]
        calls.append(action)
        if delay > 0 { try await Task.sleep(nanoseconds: delay) }
        if let status = failures[action] { return .init(status: status, output: "injected \(action) failure") }
        switch action {
        case "print": return .init(status: loaded ? 0 : 113, output: "")
        case "print-disabled":
            if oversizedOverrides {
                return .init(status: 0, output: String(repeating: " ", count: LoginLaunchCommand.outputLimit) + "\"local.mullvad.adapter.ui.login\" => true")
            }
            return .init(status: 0, output: "disabled services = {\n\"local.mullvad.adapter.ui.login\" => \(disabled)\n}")
        case "bootout": loaded = false
        case "bootstrap": loaded = true
        case "enable": disabled = false
        default: XCTFail("Unexpected launchctl action: \(action)")
        }
        return .init(status: 0, output: "")
    }
}

final class LoginLaunchControllerTests: XCTestCase {
    private func temporaryPlist() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        return directory.appendingPathComponent("login.plist")
    }

    @MainActor
    private func controller(_ file: URL, _ fake: LoginLaunchFake,
                            removeFile: @escaping (URL) throws -> Void = { try FileManager.default.removeItem(at: $0) }) -> LoginLaunchController {
        LoginLaunchController(launchAgentURL: file, bundleURL: URL(fileURLWithPath: "/Applications/Test.app"),
            userID: 501, command: { try await fake.run($0) }, removeFile: removeFile)
    }

    @MainActor
    func testInitialStateIsUnknownAndAbsentServiceIsDisabled() async throws {
        let model = controller(try temporaryPlist(), LoginLaunchFake())
        XCTAssertEqual(model.state, .unknown)
        XCTAssertFalse(model.isEnabled)
        await model.refresh()
        XCTAssertEqual(model.state, .disabled)
        XCTAssertNil(model.lastError)
    }

    @MainActor
    func testBootstrapFailureNeverMakesPlistAloneEnabledAndCanRetry() async throws {
        let file = try temporaryPlist()
        let fake = LoginLaunchFake()
        fake.failures["bootstrap"] = 5
        let model = controller(file, fake)
        await model.setEnabled(true)
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path))
        XCTAssertEqual(model.state, .needsRepair)
        XCTAssertFalse(model.isEnabled)
        XCTAssertTrue(model.lastError?.contains("bootstrap") == true)
        fake.failures.removeValue(forKey: "bootstrap")
        await model.setEnabled(true)
        XCTAssertEqual(model.state, .enabled)
        XCTAssertNil(model.lastError)
        await model.setEnabled(false)
        XCTAssertEqual(model.state, .disabled)
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    }

    @MainActor
    func testBootoutFailurePreservesConfigurationAndError() async throws {
        let file = try temporaryPlist()
        let fake = LoginLaunchFake()
        let model = controller(file, fake)
        await model.setEnabled(true)
        let original = try Data(contentsOf: file)
        fake.failures["bootout"] = 5
        await model.setEnabled(false)
        XCTAssertEqual(model.state, .enabled)
        XCTAssertEqual(try Data(contentsOf: file), original)
        XCTAssertTrue(model.lastError?.contains("bootout") == true)
        let bootstraps = fake.calls.filter { $0 == "bootstrap" }.count
        await model.setEnabled(true)
        XCTAssertEqual(fake.calls.filter { $0 == "bootstrap" }.count, bootstraps)
        XCTAssertEqual(try Data(contentsOf: file), original)
    }

    @MainActor
    func testRemovalFailureIsReportedAndCanRetry() async throws {
        let file = try temporaryPlist()
        let fake = LoginLaunchFake()
        var failRemoval = true
        let model = controller(file, fake, removeFile: { file in
            if failRemoval { throw NSError(domain: "removal", code: 1) }
            try FileManager.default.removeItem(at: file)
        })
        await model.setEnabled(true)
        await model.setEnabled(false)
        XCTAssertEqual(model.state, .needsRepair)
        XCTAssertNotNil(model.lastError)
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path))
        failRemoval = false
        await model.setEnabled(false)
        XCTAssertEqual(model.state, .disabled)
        XCTAssertNil(model.lastError)
    }

    @MainActor
    func testDisabledOverrideAndMissingPlistAreNotEnabled() async throws {
        let file = try temporaryPlist()
        let fake = LoginLaunchFake()
        let model = controller(file, fake)
        await model.setEnabled(true)
        fake.disabled = true
        await model.refresh()
        XCTAssertEqual(model.state, .needsRepair)
        await model.setEnabled(true)
        XCTAssertEqual(model.state, .enabled)
        try FileManager.default.removeItem(at: file)
        await model.refresh()
        XCTAssertEqual(model.state, .needsRepair)
        XCTAssertFalse(model.isEnabled)
    }

    @MainActor
    func testQueryFailureIsUnknownNotDisabled() async throws {
        let fake = LoginLaunchFake()
        fake.failures["print"] = 5
        let model = controller(try temporaryPlist(), fake)
        await model.refresh()
        XCTAssertEqual(model.state, .unknown)
        XCTAssertNotNil(model.lastError)
        await model.setEnabled(false)
        XCTAssertFalse(fake.calls.contains("bootout"))
        XCTAssertEqual(model.state, .unknown)
    }

    @MainActor
    func testStalePlistDoesNotCountAsEnabled() async throws {
        let file = try temporaryPlist()
        let fake = LoginLaunchFake()
        let model = controller(file, fake)
        await model.setEnabled(true)
        let otherApp = LoginLaunchController(launchAgentURL: file,
            bundleURL: URL(fileURLWithPath: "/Applications/Moved.app"),
            userID: 501, command: { try await fake.run($0) })
        await otherApp.refresh()
        XCTAssertEqual(otherApp.state, .needsRepair)
    }

    @MainActor
    func testOverlappingRequestsDoNotRaceOrBlockMainActor() async throws {
        let fake = LoginLaunchFake()
        fake.delay = 20_000_000
        let model = controller(try temporaryPlist(), fake)
        let operation = Task { await model.setEnabled(true) }
        while !model.isBusy { await Task.yield() }
        await model.setEnabled(false)
        await model.refresh()
        XCTAssertTrue(model.isBusy)
        await operation.value
        XCTAssertEqual(model.state, .enabled)
        XCTAssertFalse(fake.calls.contains("bootout"))
        XCTAssertFalse(model.isBusy)
    }

    func testCommandTimeoutAndLargeOutputDoNotHang() async throws {
        let started = ProcessInfo.processInfo.systemUptime
        do {
            _ = try await LoginLaunchCommand.run(["-c", "exec sleep 5"],
                executable: URL(fileURLWithPath: "/bin/sh"), timeout: 0.05)
            XCTFail("Expected timeout")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("超时"))
        }
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - started, 2)
        do {
            _ = try await LoginLaunchCommand.run(["-c", "i=0; while [ $i -lt 10000 ]; do echo 12345678901234567890; i=$((i+1)); done"],
                executable: URL(fileURLWithPath: "/bin/sh"))
            XCTFail("Oversized output must not be silently truncated")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("上限"))
        }
    }

    func testOutputLimitChecksBytesAndRejectsOneByteOverLimit() throws {
        XCTAssertEqual(try LoginLaunchCommand.decodedOutput(Data(repeating: 65, count: LoginLaunchCommand.outputLimit)).utf8.count, LoginLaunchCommand.outputLimit)
        XCTAssertThrowsError(try LoginLaunchCommand.decodedOutput(Data(repeating: 65, count: LoginLaunchCommand.outputLimit + 1)))
    }

    @MainActor
    func testTruncatedDisabledListNeverReportsEnabled() async throws {
        let fake = LoginLaunchFake()
        let model = controller(try temporaryPlist(), fake)
        await model.setEnabled(true)
        XCTAssertEqual(model.state, .enabled)
        fake.oversizedOverrides = true
        await model.refresh()
        XCTAssertEqual(model.state, .unknown)
        XCTAssertFalse(model.isEnabled)
        XCTAssertTrue(model.lastError?.contains("上限") == true)
    }

}
