import Foundation

enum DiagnosticReportExporter {
    /// Snapshots and a bounded log tail only; configuration / key files are
    /// intentionally excluded. Works when the daemon or external network is down.
    static func create(status: Data?, metrics: Data?, cities: Data? = nil, cachedSummary: String, errors: [String]) async throws -> URL {
        try await Task.detached(priority: .utility) {
            let home = FileManager.default.homeDirectoryForCurrentUser
            let logs = home.appendingPathComponent("Library/Logs/MullvadLocalAdapter")
            let directory = logs.appendingPathComponent("Reports", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.dateFormat = "yyyyMMdd-HHmmss"
            let name = "Mullvad-诊断-\(formatter.string(from: Date()))-\(UUID().uuidString.prefix(6)).md"
            let destination = directory.appendingPathComponent(name)
            let logFiles = [
                logs.appendingPathComponent("events.jsonl.1"),
                logs.appendingPathComponent("events.jsonl"),
                logs.appendingPathComponent("daemon.err.log"),
                home.appendingPathComponent("Library/Logs/MullvadFailOpen/watchdog.log")
            ]
            let tails = logFiles.map { ($0.path, readTail($0)) }
            let document = render(status: status, metrics: metrics, cities: cities, cachedSummary: cachedSummary,
                                  errors: errors, logs: tails)
            try Data(document.utf8).write(to: destination, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
            return destination
        }.value
    }

    static func readTail(_ url: URL, byteLimit: UInt64 = 64 * 1024) -> String {
        do {
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            let length = try handle.seekToEnd()
            let offset = length > byteLimit ? length - byteLimit : 0
            try handle.seek(toOffset: offset)
            let data = try handle.read(upToCount: Int(byteLimit)) ?? Data()
            var text = String(decoding: data, as: UTF8.self)
            if offset > 0, let newline = text.firstIndex(of: "\n") { text = String(text[text.index(after: newline)...]) }
            return text.isEmpty ? "（日志为空）" : redact(text)
        } catch {
            return "（未能读取：\(error.localizedDescription)）"
        }
    }

    static func redact(_ text: String) -> String {
        let patterns: [(String, String)] = [
            (#"(?i)(private[-_ ]?key|pre[-_ ]?shared[-_ ]?key|password|secret|(?:access[-_ ]?|refresh[-_ ]?)?token|authorization|account(?:[-_ ]?number)?|subscription(?:[-_ ]?url)?)\s*[\"']?\s*[:=]\s*[\"']?[^\s,\"'}]+"#, "$1=[REDACTED]"),
            (#"(?i)Bearer\s+[A-Za-z0-9._~+/=-]+"#, "Bearer [REDACTED]"),
            (#"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/])"#, "[KEY REDACTED]"),
            (#"\b\d{16}\b"#, "[ACCOUNT REDACTED]"),
            (#"\b(?:\d{4}[ -]){3}\d{4}\b"#, "[ACCOUNT REDACTED]"),
            (#"https?://[^\s\"<>]*\?[^\s\"<>]*"#, "[URL QUERY REDACTED]"),
            (#"https?://[^/\s:@]+:[^/\s@]+@[^\s\"]+"#, "[CREDENTIAL URL REDACTED]")
        ]
        return patterns.reduce(text) { result, rule in
            result.replacingOccurrences(of: rule.0, with: rule.1, options: .regularExpression)
        }
    }

    static func render(status: Data?, metrics: Data?, cities: Data? = nil, cachedSummary: String, errors: [String], logs: [(String, String)]) -> String {
        func json(_ data: Data?) -> String {
            guard let data, let object = try? JSONSerialization.jsonObject(with: data),
                  let pretty = try? JSONSerialization.data(withJSONObject: redactedJSON(object), options: [.prettyPrinted, .sortedKeys]),
                  let text = String(data: pretty, encoding: .utf8) else { return "NOT_AVAILABLE：本次未取到此项" }
            return text
        }
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "development"
        var report = """
        # Mullvad 本地适配器诊断资料

        - 导出时间：\(ISO8601DateFormatter().string(from: Date()))
        - 系统：\(ProcessInfo.processInfo.operatingSystemVersionString)
        - 界面版本：\(version)
        - 本次服务状态获取：\(status == nil ? "FAIL（服务未响应；不能把缓存当作当前状态）" : "PASS")
        - 采集方式：只读取本地 API 和日志，没有切换节点、重启服务或更改网络。
        - 网页 / DNS 探测以每项的 checked_at、at 或 last_check_at 为准；导出没有额外发起外网测试。
        - 未包含账号、私钥模板、完整 Clash 配置或订阅内容。日志经过常见凭据模式过滤；资料中仍有本机路径、节点地址和访问错误。

        ## 界面最后看到的状态（可能已过期）

        \(redact(cachedSummary))

        ## 本次读取错误

        \(errors.isEmpty ? "无" : redact(errors.joined(separator: "\n")))

        ## 当前服务状态

        ```json
        \(json(status))
        ```

        ## 累计指标

        ```json
        \(json(metrics))
        ```

        ## 城市维护与备用候选

        外层探测和完整验证历史分开记录。候选并非已连接的热备用通道。

        ```json
        \(json(cities))
        ```

        ## 日志摘录

        每个文件最多保留末尾 64 KiB。下列绝对路径可供本地 Agent 继续读取；缺失日志会明确标注。

        """
        for (path, tail) in logs {
            report += "\n### \(path)\n\n```text\n\(redact(tail).replacingOccurrences(of: "```", with: "'''"))\n```\n"
        }
        return report
    }

    private static func redactedJSON(_ value: Any) -> Any {
        if let dictionary = value as? [String: Any] {
            return dictionary.reduce(into: [String: Any]()) { result, entry in
                let sensitive = entry.key.range(of: #"(?i)private.?key|pre.?shared.?key|password|secret|token|authorization|account|subscription"#, options: .regularExpression) != nil
                result[entry.key] = sensitive ? "[REDACTED]" : redactedJSON(entry.value)
            }
        }
        if let array = value as? [Any] { return array.map(redactedJSON) }
        if let string = value as? String { return redact(string) }
        return value
    }
}
