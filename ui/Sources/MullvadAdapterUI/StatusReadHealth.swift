import Foundation
import Darwin

// This observes the local control API. It never changes tunnel recovery or routing.
struct StatusReadFailure: Equatable {
    let kind: String
    let code: Int?
    let connectivity: Bool

    static func classify(_ error: Error) -> StatusReadFailure {
        if error is CancellationError { return .init(kind: "cancelled", code: nil, connectivity: false) }
        if let url = error as? URLError { return urlFailure(url.code.rawValue) }
        if let error = error as? AdapterClientError {
            switch error {
            case .urlTransport(let code): return urlFailure(code)
            case .transport: return .init(kind: "transport", code: nil, connectivity: true)
            case .http(let status, _, _): return .init(kind: "http", code: status, connectivity: false)
            case .invalidResponse: return .init(kind: "invalid_response", code: nil, connectivity: false)
            case .cancellationUnconfirmed: break
            }
        }
        return .init(kind: "other", code: nil, connectivity: false)
    }

    private static func urlFailure(_ code: Int) -> StatusReadFailure {
        .init(kind: code == URLError.cancelled.rawValue ? "cancelled" :
                (code == URLError.timedOut.rawValue ? "timeout" : "transport"),
              code: code, connectivity: code != URLError.cancelled.rawValue)
    }
}

struct StatusReadHealth {
    private var issued = 0
    private var latestFinished = 0
    private(set) var failureCount = 0
    private(set) var lastSuccessAt: TimeInterval?
    private(set) var lastFailure: StatusReadFailure?
    private var transportFailures = 0
    private var transportFailureSince: TimeInterval?

    mutating func begin() -> Int { issued += 1; return issued }

    // Completion order matters: an old result cannot overwrite a newer observation.
    // Cancellation is not an observation of the service, and does not advance this fence.
    mutating func finish(_ id: Int, failure: StatusReadFailure?, at now: TimeInterval) -> Bool {
        guard id >= latestFinished, failure?.kind != "cancelled" else { return false }
        latestFinished = id
        lastFailure = failure
        if let failure {
            failureCount += 1
            if failure.connectivity {
                transportFailures += 1
                if transportFailureSince == nil { transportFailureSince = now }
            } else {
                transportFailures = 0
                transportFailureSince = nil
            }
        } else {
            failureCount = 0
            transportFailures = 0
            transportFailureSince = nil
            lastSuccessAt = now
        }
        return true
    }

    func displayStatus(at now: TimeInterval) -> String? {
        guard let failure = lastFailure else { return nil }
        if failure.kind == "invalid_response" { return "status_invalid" }
        if !failure.connectivity { return "status_error" }
        if transportFailures >= 3, let since = transportFailureSince, now - since >= 10 {
            return "status_unavailable"
        }
        return "status_pending"
    }

    func message(at now: TimeInterval) -> String? {
        guard let state = displayStatus(at: now) else { return nil }
        let age = lastSuccessAt.map { "上次状态为 \(max(0, Int(now - $0))) 秒前。" } ?? "尚未成功读取状态。"
        let text: String
        switch state {
        case "status_invalid": text = "已收到本机服务响应，但状态格式无法解析；正在重试。"
        case "status_error": text = "本机服务返回异常，正在重试读取状态。"
        case "status_unavailable": text = "持续无法读取本机服务状态，当前连接情况未知；正在重试。"
        default: text = "状态暂未更新，正在重试；尚不能据此判断网络中断。"
        }
        return text + " " + age
    }
}

// An allowlist, deliberately without URL, response body, arbitrary error text or credentials.
struct StatusReadEvent: Encodable, Sendable {
    let event: String
    let requestID: Int
    let durationMs: Int
    let failureKind: String?
    let errorCode: Int?
    let consecutiveFailures: Int
    let snapshotAgeSeconds: Int?
    let displayState: String?

    enum CodingKeys: String, CodingKey {
        case event, requestID = "request_id", durationMs = "duration_ms"
        case failureKind = "failure_kind", errorCode = "error_code"
        case consecutiveFailures = "consecutive_failures", snapshotAgeSeconds = "snapshot_age_seconds"
        case displayState = "display_state"
    }
}

final class StatusReadLogger: @unchecked Sendable {
    static let shared = StatusReadLogger(directory: FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Logs/MullvadLocalAdapter"))
    private let queue = DispatchQueue(label: "local.mullvad.adapter.ui-status-log")
    private let directory: URL
    private let limit: Int
    private let sessionID = UUID().uuidString
    private var lastWriteWarning: Date?
    private let pendingLock = NSLock()
    private var pending = 0
    private var dropped = 0

    // Two 256-KiB files, independent of daemon logs; slow disk never blocks the UI actor.
    init(directory: URL, limit: Int = 256 * 1024) { self.directory = directory; self.limit = limit }

    func record(_ event: StatusReadEvent) {
        pendingLock.lock()
        guard pending < 64 else { dropped += 1; pendingLock.unlock(); return }
        pending += 1
        pendingLock.unlock()
        queue.async {
            self.write(event)
            self.pendingLock.lock()
            self.pending -= 1
            self.pendingLock.unlock()
        }
    }

    @discardableResult func flush(timeout: TimeInterval = 1) -> Bool {
        let done = DispatchSemaphore(value: 0)
        queue.async { done.signal() }
        return done.wait(timeout: .now() + max(0, timeout)) == .success
    }

    private func secureLog(_ name: String, in directoryFD: Int32, create: Bool = false) throws -> Int32? {
        let fd = openat(directoryFD, name, O_WRONLY | O_APPEND | O_NOFOLLOW | O_NONBLOCK | (create ? O_CREAT : 0), 0o600)
        if fd < 0 {
            if !create, errno == ENOENT { return nil }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == getuid(), info.st_nlink == 1, fchmod(fd, 0o600) == 0 else {
            close(fd)
            throw POSIXError(.EIO)
        }
        return fd
    }

    private func write(_ event: StatusReadEvent) {
        do {
            let fm = FileManager.default
            try fm.createDirectory(at: directory, withIntermediateDirectories: true,
                                   attributes: [.posixPermissions: 0o700])
            let directoryFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK)
            guard directoryFD >= 0 else { throw POSIXError(.ELOOP) }
            defer { close(directoryFD) }
            var directoryInfo = stat()
            guard fstat(directoryFD, &directoryInfo) == 0, directoryInfo.st_uid == getuid(),
                  fchmod(directoryFD, 0o700) == 0 else { throw POSIXError(.EACCES) }
            let name = "ui-status.jsonl", old = "ui-status.jsonl.1"
            // Check and tighten both files before any rename; never follow links.
            if let archiveFD = try secureLog(old, in: directoryFD) { close(archiveFD) }
            let activeFD = try secureLog(name, in: directoryFD)
            var size: Int64 = 0
            if let activeFD {
                var info = stat()
                if fstat(activeFD, &info) == 0 { size = info.st_size }
                close(activeFD)
            }
            var object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(event)) as! [String: Any]
            object["at"] = ISO8601DateFormatter().string(from: Date())
            object["session_id"] = sessionID
            object["ui_version"] = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "test"
            object["ui_build"] = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "test"
            pendingLock.lock()
            object["logger_dropped_events"] = dropped
            pendingLock.unlock()
            var data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
            data.append(10)
            guard data.count <= limit else { throw POSIXError(.EFBIG) }
            if size + Int64(data.count) > Int64(limit) {
                if renameat(directoryFD, name, directoryFD, old) != 0 { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            }
            guard let fd = try secureLog(name, in: directoryFD, create: true) else { throw POSIXError(.EIO) }
            defer { close(fd) }
            try data.withUnsafeBytes { bytes in
                var offset = 0
                while offset < bytes.count {
                    let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                    if count < 0, errno == EINTR { continue }
                    guard count > 0 else { throw POSIXError(.EIO) }
                    offset += count
                }
            }
        } catch {
            // No raw error description: file paths and unrelated user data stay out of logs.
            if lastWriteWarning == nil || Date().timeIntervalSince(lastWriteWarning!) >= 60 {
                lastWriteWarning = Date()
                fputs("Mullvad UI: status diagnostic log write failed; status polling continues.\n", stderr)
            }
        }
    }
}
