import Foundation

struct OperationReceipt: Decodable {
    let id: String
}

struct AdapterOperation: Decodable {
    let id: String
    let kind: String?
    let relay: String?
    let state: String
    let stage: String?
    let message: String?
    let error: String?
    let result: RelaySpeedTestResult?
    let acceptedAt: String?
    let finishedAt: String?

    enum CodingKeys: String, CodingKey {
        case id, kind, relay, state, stage, message, error, result
        case acceptedAt = "accepted_at"
        case finishedAt = "finished_at"
    }

    var isRunning: Bool { state == "queued" || state == "running" }
}

struct NetworkDiagnosis: Decodable {
    let code: String
    let summary: String
    let advice: String
    let scope: String?
    let checkedAt: String?
    let layers: [String: DiagnosticLayer]?

    enum CodingKeys: String, CodingKey {
        case code, summary, advice, scope, layers
        case checkedAt = "checked_at"
    }
}

struct DiagnosticLayer: Decodable {
    let status: String?
    let detail: String?
    let readiness: String?
}
