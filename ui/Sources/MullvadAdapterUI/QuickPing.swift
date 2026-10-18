import Foundation
import Darwin

struct QuickPingResult: Codable, Sendable {
    let target: String
    let milliseconds: Double?
    let testedAt: Date
    let detail: String
    let interface: String?
    let exitCode: Int?
    let durationMilliseconds: Double?
    let batchID: String?
    let batchLabel: String?
    let transport: String?
    let targetKind: String?

    init(target: String, milliseconds: Double?, testedAt: Date = Date(), detail: String,
         interface: String? = nil, exitCode: Int? = nil, durationMilliseconds: Double? = nil,
         batchID: String? = nil, batchLabel: String? = nil, transport: String? = nil,
         targetKind: String? = nil) {
        self.target = target
        self.milliseconds = milliseconds
        self.testedAt = testedAt
        self.detail = detail
        self.interface = interface
        self.exitCode = exitCode
        self.durationMilliseconds = durationMilliseconds
        self.batchID = batchID
        self.batchLabel = batchLabel
        self.transport = transport
        self.targetKind = targetKind
    }
}

/// ICMP only. Uses transport-specific public relay metadata; never starts or changes a tunnel.
enum QuickPing {
    static func targets(transport: String = "ss", relays: [RelayInfo]) -> [String: RelayPingTarget] {
        Dictionary(relays.compactMap { relay in
            relay.quickPing?.target(for: transport).flatMap { target in
                guard let value = target.target, !value.isEmpty else { return nil }
                return (relay.hostname, target)
            }
        }, uniquingKeysWith: { first, _ in first })
    }

    static func probe(_ target: String, interface: String? = nil) async -> QuickPingResult {
        guard !Task.isCancelled else {
            return QuickPingResult(target: target, milliseconds: nil, detail: "已取消", interface: interface)
        }
        // Keep blocking Process work off the main actor. Each probe has a hard
        // two-second process deadline, including when its parent is cancelled.
        return await Task.detached(priority: .utility) { () async -> QuickPingResult in
            let started = ProcessInfo.processInfo.systemUptime
            var address = in_addr()
            var address6 = in6_addr()
            let ipv4 = target.withCString { inet_pton(AF_INET, $0, &address) } == 1
            let ipv6 = target.withCString { inet_pton(AF_INET6, $0, &address6) } == 1
            guard ipv4 || ipv6 else {
                return QuickPingResult(target: target, milliseconds: nil, detail: "无有效 IP 入口", interface: interface)
            }
            let process = Process()
            let output = Pipe()
            process.executableURL = URL(fileURLWithPath: ipv6 ? "/sbin/ping6" : "/sbin/ping")
            process.arguments = ["-n", "-c", "1", "-W", "1500"] + (interface.map { ["-b", $0] } ?? []) + [target]
            process.standardOutput = output
            process.standardError = output
            do {
                try process.run()
                let deadline = ProcessInfo.processInfo.systemUptime + 2
                while process.isRunning && ProcessInfo.processInfo.systemUptime < deadline {
                    try? await Task.sleep(nanoseconds: 20_000_000)
                }
                let exceededDeadline = process.isRunning
                if exceededDeadline { process.terminate() }
                process.waitUntilExit()
                let data = output.fileHandleForReading.readDataToEndOfFile()
                let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                let regex = try NSRegularExpression(pattern: "time[=<]([0-9.]+)\\s*ms")
                let range = NSRange(text.startIndex..., in: text)
                let match = regex.firstMatch(in: text, range: range)
                let delay = match.flatMap { Range($0.range(at: 1), in: text) }.flatMap { Double(text[$0]) }
                let value = process.terminationStatus == 0 ? delay : nil
                let elapsed = (ProcessInfo.processInfo.systemUptime - started) * 1_000
                let route = interface.map { "绑定接口 \($0)" } ?? "未绑定物理接口"
                let outcome: String
                if value != nil {
                    outcome = "收到 ICMP 回复；这只验证入口，不验证隧道"
                } else if exceededDeadline {
                    outcome = "等待 2 秒仍无回复，已停止探测进程"
                } else {
                    outcome = "未收到 ICMP 回复（退出码 \(process.terminationStatus)）；节点可能不响应 Ping，不代表完整连接不可用"
                }
                return QuickPingResult(target: target, milliseconds: value, detail: "\(route)；\(outcome)；\(text.suffix(320))",
                    interface: interface, exitCode: Int(process.terminationStatus), durationMilliseconds: elapsed)
            } catch {
                let elapsed = (ProcessInfo.processInfo.systemUptime - started) * 1_000
                return QuickPingResult(target: target, milliseconds: nil, detail: "Ping 启动失败：\(error.localizedDescription)",
                    interface: interface, durationMilliseconds: elapsed)
            }
        }.value
    }

    /// City requests are bounded to four; country requests are strictly serial.
    static func run(hostnames: [String], targets: [String: RelayPingTarget], cityConcurrency: Bool,
                    probe: @escaping @Sendable (String) async -> QuickPingResult = { await QuickPing.probe($0) },
                    receive: @escaping @MainActor @Sendable (String, QuickPingResult) async -> Void) async {
        let width = cityConcurrency ? 4 : 1
        let names = Array(Set(hostnames)).sorted()
        for start in stride(from: 0, to: names.count, by: width) {
            if Task.isCancelled { break }
            await withTaskGroup(of: (String, QuickPingResult).self) { group in
                for name in names[start..<min(start + width, names.count)] {
                    group.addTask {
                        let target = targets[name]
                        let result = await probe(target?.target ?? "")
                        return (name, result)
                    }
                }
                for await (name, result) in group {
                    if !Task.isCancelled { await receive(name, result) }
                }
            }
        }
    }
}
