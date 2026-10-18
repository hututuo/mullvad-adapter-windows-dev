import Combine
import Darwin
import Foundation

struct LoginLaunchCommandResult: Sendable {
    let status: Int32
    let output: String
}

/// All process waiting happens off the main actor. File output avoids pipe-buffer
/// deadlocks; both the command and forced-termination grace period are bounded.
enum LoginLaunchCommand {
    static let outputLimit = 16_384

    static func decodedOutput(_ data: Data) throws -> String {
        guard data.count <= outputLimit else {
            throw LoginLaunchError.detail("自启命令输出超过安全上限，无法确认完整系统状态。")
        }
        return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func run(_ arguments: [String], executable: URL = URL(fileURLWithPath: "/bin/launchctl"),
                    timeout: TimeInterval = 3) async throws -> LoginLaunchCommandResult {
        try await Task.detached(priority: .utility) {
            try execute(arguments, executable: executable, timeout: timeout)
        }.value
    }

    private static func execute(_ arguments: [String], executable: URL,
                                timeout: TimeInterval) throws -> LoginLaunchCommandResult {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        guard FileManager.default.createFile(atPath: file.path, contents: nil,
                                             attributes: [.posixPermissions: 0o600]) else {
            throw LoginLaunchError.detail("无法创建自启检查的临时输出文件。")
        }
        defer { try? FileManager.default.removeItem(at: file) }
        let output = try FileHandle(forWritingTo: file)
        defer { try? output.close() }
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = output
        try process.run()
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        if process.isRunning {
            process.terminate()
            let grace = ProcessInfo.processInfo.systemUptime + 0.2
            while process.isRunning && ProcessInfo.processInfo.systemUptime < grace {
                Thread.sleep(forTimeInterval: 0.01)
            }
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            throw LoginLaunchError.detail("自启命令 \(arguments.first ?? "") 超时；请刷新状态后重试。")
        }
        let reader = try FileHandle(forReadingFrom: file)
        defer { try? reader.close() }
        let data = try reader.read(upToCount: outputLimit + 1) ?? Data()
        return LoginLaunchCommandResult(status: process.terminationStatus,
            output: try decodedOutput(data))
    }
}

@MainActor
final class LoginLaunchController: ObservableObject {
    enum State: Equatable { case unknown, disabled, enabled, needsRepair }
    @Published private(set) var state: State = .unknown
    @Published private(set) var isBusy = false
    @Published private(set) var lastError: String?
    var isEnabled: Bool { state == .enabled }

    private let label = "local.mullvad.adapter.ui.login"
    private let launchAgentURL: URL
    private let bundleURL: URL
    private let domainTarget: String
    private let command: ([String]) async throws -> LoginLaunchCommandResult
    private let removeFile: (URL) throws -> Void

    init(launchAgentURL: URL = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/local.mullvad.adapter.ui.login.plist"),
         bundleURL: URL = Bundle.main.bundleURL, userID: UInt32 = getuid(),
         command: @escaping ([String]) async throws -> LoginLaunchCommandResult = { try await LoginLaunchCommand.run($0) },
         removeFile: @escaping (URL) throws -> Void = { try FileManager.default.removeItem(at: $0) }) {
        self.launchAgentURL = launchAgentURL
        self.bundleURL = bundleURL
        self.domainTarget = "gui/\(userID)"
        self.command = command
        self.removeFile = removeFile
    }

    func refresh() async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        await reconcile()
    }

    func setEnabled(_ enabled: Bool) async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        var failure: String?
        do {
            if enabled { try await installLaunchAgent() }
            else { try await removeLaunchAgent() }
        } catch {
            failure = error.localizedDescription
        }
        await reconcile(operationError: failure)
    }

    private func reconcile(operationError: String? = nil) async {
        do {
            let loaded = try await isLoaded()
            let exists = FileManager.default.fileExists(atPath: launchAgentURL.path)
            if !loaded && !exists {
                state = .disabled
                lastError = operationError
                return
            }
            let overrides = try await checked(["print-disabled", domainTarget])
            let pattern = "\"" + NSRegularExpression.escapedPattern(for: label) + "\"\\s*=>\\s*true"
            let disabled = overrides.range(of: pattern, options: .regularExpression) != nil
            let data = exists ? try Data(contentsOf: launchAgentURL) : nil
            let plist: [String: Any]?
            if let data {
                plist = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
            } else {
                plist = nil
            }
            let valid = (plist?["Label"] as? String) == label
                && (plist?["ProgramArguments"] as? [String]) == programArguments
                && (plist?["RunAtLoad"] as? Bool) == true
            state = loaded && valid && !disabled ? .enabled : .needsRepair
            lastError = operationError ?? (state == .needsRepair
                ? "自启配置与系统注册状态不一致。可重试启用，或移除自启配置。" : nil)
        } catch {
            state = .unknown
            lastError = [operationError, "无法确认自启状态：\(error.localizedDescription)"].compactMap { $0 }.joined(separator: "\n")
        }
    }

    private var programArguments: [String] {
        ["/usr/bin/open", "-gj", bundleURL.path, "--args", "--background-login"]
    }

    private func installLaunchAgent() async throws {
        guard bundleURL.pathExtension.lowercased() == "app" else { throw LoginLaunchError.notAppBundle }
        // Do not overwrite the persisted configuration until the previous job is
        // unloaded successfully. A failed bootout must be visible and retryable.
        if try await isLoaded() { _ = try await checked(["bootout", serviceTarget]) }
        try FileManager.default.createDirectory(at: launchAgentURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let plist: [String: Any] = ["Label": label, "ProgramArguments": programArguments,
                                    "RunAtLoad": true, "ProcessType": "Interactive"]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try data.write(to: launchAgentURL, options: .atomic)
        _ = try await checked(["enable", serviceTarget])
        // Retain a failed registration's plist for an explicit retry/remove, but
        // never report it as enabled solely because this file exists.
        _ = try await checked(["bootstrap", domainTarget, launchAgentURL.path])
    }

    private func removeLaunchAgent() async throws {
        if try await isLoaded() { _ = try await checked(["bootout", serviceTarget]) }
        if FileManager.default.fileExists(atPath: launchAgentURL.path) { try removeFile(launchAgentURL) }
    }

    private func isLoaded() async throws -> Bool {
        let result = try await command(["print", serviceTarget])
        if result.status == 0 { return true }
        // launchctl's service-not-found code; other failures are unknown, not off.
        if result.status == 113 { return false }
        throw commandError("print", result)
    }

    private func checked(_ arguments: [String]) async throws -> String {
        let result = try await command(arguments)
        // Injected runners must obey the same complete-output contract.
        guard result.output.utf8.count <= LoginLaunchCommand.outputLimit else {
            throw LoginLaunchError.detail("自启命令输出超过安全上限，无法确认完整系统状态。")
        }
        guard result.status == 0 else { throw commandError(arguments[0], result) }
        return result.output
    }

    private func commandError(_ action: String, _ result: LoginLaunchCommandResult) -> LoginLaunchError {
        .detail("自启命令 \(action) 失败（\(result.status)）：\(result.output.isEmpty ? "请刷新状态后重试。" : result.output)")
    }

    private var serviceTarget: String { "\(domainTarget)/\(label)" }
}

private enum LoginLaunchError: LocalizedError {
    case notAppBundle
    case detail(String)
    var errorDescription: String? {
        switch self {
        case .notAppBundle: return "开机自启只能从已安装的 Mullvad Adapter.app 中启用。"
        case .detail(let detail): return detail
        }
    }
}
