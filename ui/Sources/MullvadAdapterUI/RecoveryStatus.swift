import Foundation

struct RecoveryStatus: Decodable {
    let phase: String
    let running: Bool
    let attempt: Int?
    let targetRelay: String?
    let originalRelay: String?
    let endpoint: String?
    let endpointPort: Int?
    let transport: String?
    let inletAttempt: Int?
    let cityAttempt: Int?
    let elapsedSeconds: Int?
    let remainingSeconds: Int?
    let budgetSeconds: Int?
    let retryInSeconds: Int?
    let message: String?
    let nextStep: String?
    let updatedAt: String?

    enum CodingKeys: String, CodingKey {
        case phase, running, attempt, endpoint, transport, message
        case targetRelay = "target_relay", originalRelay = "original_relay", endpointPort = "endpoint_port"
        case inletAttempt = "inlet_attempt", cityAttempt = "city_attempt"
        case elapsedSeconds = "elapsed_seconds", remainingSeconds = "remaining_seconds", budgetSeconds = "budget_seconds"
        case retryInSeconds = "retry_in_seconds", nextStep = "next_step", updatedAt = "updated_at"
    }

    var title: String {
        switch phase {
        case "original", "current_relay", "retry_wait": return "1 · 重试原节点、原入口"
        case "alternate_ss": return "2 · 尝试原节点的备用 SS"
        case "same_city": return "3 · 尝试同城备用节点"
        case "restored": return "连接已恢复"
        case "local_wait": return "等待本机组件就绪"
        case "waiting_network": return "等待本机网络"
        case "exhausted": return "本轮恢复未成功"
        case "stopped": return running ? "正在停止恢复" : "自动恢复已停止"
        case "interrupted": return "正在结束旧恢复流程"
        default: return "自动恢复待命"
        }
    }

    var target: String {
        let relay = targetRelay ?? originalRelay ?? "当前节点"
        let inlet = endpoint.map { "\($0)\(endpointPort.map { ":\($0)" } ?? "")" }
        return inlet.map { "\(relay) · \($0)" } ?? relay
    }

    var timing: String {
        guard phase != "idle" else { return "原入口 3 次 → 备用 SS 最多 2 个 → 同城最多 4 节点，每个最多 2 入口" }
        let used = "已尝试 \(attempt ?? 0) 次 · 用时 \(elapsedSeconds ?? 0) 秒 / \(budgetSeconds ?? 300) 秒预算"
        if let wait = retryInSeconds, wait > 0 {
            return "\(used) · \(wait) 秒后\(running ? "重试" : "再开一轮")"
        }
        return used
    }
}
