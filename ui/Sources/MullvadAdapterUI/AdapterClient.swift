import Foundation

struct AdapterClient: Sendable {
    let baseURL: URL
    let session: URLSession
    let accountCapability: @Sendable () throws -> String

    init(baseURL: URL = URL(string: "http://127.0.0.1:17891")!, session: URLSession = .shared,
         accountCapability: @escaping @Sendable () throws -> String = {
             let path = FileManager.default.homeDirectoryForCurrentUser
                 .appendingPathComponent("Library/Application Support/MullvadLocalAdapter/account-capability")
             guard let value = try? String(contentsOf: path, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
                   value.count == 64, value.allSatisfy({ $0.isHexDigit }) else {
                 throw AdapterClientError.invalidResponse("后台尚未提供本机控制授权；需要配套的新版后台。现有连接可继续使用。")
             }
             return value
         }) {
        self.baseURL = baseURL
        self.session = session
        self.accountCapability = accountCapability
    }

    func account(_ action: String? = nil, payload: [String: Any] = [:]) async throws -> AccountSnapshot {
        let request = try accountRequest(action, payload: payload)
        return try decode(try await data(for: request), path: "account")
    }

    func createDevice(publicKey: String) async throws -> CreatedAccountDevice {
        let request = try accountRequest("devices/create", payload: ["public_key": publicKey, "confirm": true])
        return try decode(try await data(for: request), path: "account/devices/create")
    }

    func revealPrivateKey() async throws -> String {
        let request = try accountRequest("key", payload: ["reveal": true])
        let result: LocalKey = try decode(try await data(for: request), path: "account/key")
        return result.privateKey
    }

    private func accountRequest(_ action: String?, payload: [String: Any]) throws -> URLRequest {
        var request = URLRequest(url: baseURL.appendingPathComponent("account" + (action.map { "/" + $0 } ?? "")))
        request.httpMethod = action == nil ? "GET" : "POST"
        request.timeoutInterval = 75 // bounded token + validation + device reads; never retry mutations
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("Bearer " + (try accountCapability()), forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if action != nil { request.httpBody = try JSONSerialization.data(withJSONObject: payload) }
        return request
    }

    func fetchProtection() async throws -> ProtectionSnapshot {
        try await get("protection", as: ProtectionSnapshot.self)
    }

    func applyProtection(_ profile: ProtectionProfile) async throws -> OperationReceipt {
        var request = URLRequest(url: baseURL.appendingPathComponent("protection"))
        request.httpMethod = "POST"
        request.timeoutInterval = 15
        request.setValue("Bearer " + (try accountCapability()), forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(profile)
        return try decode(try await data(for: request), path: "protection")
    }

    func fetchStatus() async throws -> AdapterStatus {
        try await get("status", as: AdapterStatus.self)
    }

    func fetchMetrics() async throws -> AdapterMetrics {
        try await get("metrics", as: AdapterMetrics.self)
    }

    func fetchCities() async throws -> CityWorkspace {
        try await get("cities", as: CityWorkspace.self)
    }

    func saveFavoriteCities(_ cities: [String]) async throws -> CityWorkspace {
        let data = try await post("cities", json: ["favorite_cities": cities])
        return try decode(data, path: "cities")
    }

    func selectCity(_ city: String) async throws -> OperationReceipt {
        try await startOperation("cities/select", payload: ["city": city, "transport": "auto"])
    }

    func fetchRelays() async throws -> [RelayInfo] {
        try await get("relays", as: [RelayInfo].self)
    }

    func fetchSpeedTests() async throws -> [RelaySpeedTestResult] {
        try await get("speedtests", as: [RelaySpeedTestResult].self)
    }

    func fetchRelayHistory() async throws -> [RelayHistorySummary] {
        try await get("relay-history", as: [RelayHistorySummary].self)
    }

    func reportData(_ path: String) async throws -> Data {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.timeoutInterval = 3
        return try await data(for: request)
    }

    func reconnect(transport: String? = nil) async throws -> OperationReceipt {
        var payload: [String: String] = [:]
        if let transport, !transport.isEmpty {
            payload["transport"] = transport
        }
        return try await startOperation("reconnect", payload: payload)
    }

    func select(relay: String, transport: String? = nil) async throws -> OperationReceipt {
        var payload = ["relay": relay]
        if let transport, !transport.isEmpty {
            payload["transport"] = transport
        }
        return try await startOperation("select", payload: payload)
    }

    func startOperation(_ path: String, payload: [String: String] = [:]) async throws -> OperationReceipt {
        let data = try await post(path, json: payload)
        return try decode(data, path: path)
    }

    func fetchOperation(_ id: String) async throws -> AdapterOperation {
        try await get("operations/\(id)", as: AdapterOperation.self)
    }

    func cancelOperation(_ id: String) async {
        _ = try? await post("cancel", json: ["id": id])
    }

    func speedTest(relay: String, transport: String? = nil) async throws -> RelaySpeedTestResult {
        var payload = ["relay": relay]
        if let transport { payload["transport"] = transport }
        // Once POST is sent, get its receipt even if the UI cancels meanwhile.
        // Otherwise the accepted backend task can lose its only cancellation ID.
        let requestPayload = payload
        let receipt = try await Task.detached {
            try await startOperation("speedtest/start", payload: requestPayload)
        }.value
        do {
            return try await withTaskCancellationHandler {
                let deadline = Date().addingTimeInterval(120)
                var readFailures = 0
                while Date() < deadline {
                    try Task.checkCancellation()
                    let operation: AdapterOperation
                    do {
                        operation = try await fetchOperation(receipt.id)
                        readFailures = 0
                    } catch {
                        try Task.checkCancellation()
                        readFailures += 1
                        guard readFailures <= 3, case AdapterClientError.transport = error else { throw error }
                        try await Task.sleep(nanoseconds: 500_000_000)
                        continue // Retry only the read, never repeat the POST.
                    }
                    if !operation.isRunning {
                        if operation.state == "cancelled" { throw CancellationError() }
                        guard operation.state == "succeeded", let result = operation.result else {
                            throw AdapterClientError.invalidResponse(operation.error ?? operation.message ?? "测速未完成")
                        }
                        return result
                    }
                    try await Task.sleep(nanoseconds: 500_000_000)
                }
                await cancelOperation(receipt.id)
                throw AdapterClientError.invalidResponse("测速等待超时，已请求停止后台测速")
            } onCancel: {
                Task { await cancelOperation(receipt.id) }
            }
        } catch {
            if Task.isCancelled || error is CancellationError {
                // Cancellation must not release the UI lock before backend cleanup.
                let confirmed = await Task.detached {
                    await cancelOperation(receipt.id)
                    let deadline = Date().addingTimeInterval(15)
                    while Date() < deadline {
                        if let operation = try? await fetchOperation(receipt.id), !operation.isRunning { return true }
                        try? await Task.sleep(nanoseconds: 500_000_000)
                    }
                    return false
                }.value
                guard confirmed else { throw AdapterClientError.cancellationUnconfirmed }
                throw CancellationError()
            }
            throw error
        }
    }

    private func get<T: Decodable>(_ path: String, as type: T.Type) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "GET"
        request.timeoutInterval = 5
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let data = try await data(for: request)
        return try decode(data, path: "/\(path)")
    }

    private func post(_ path: String, json: [String: Any]) async throws -> Data {
        var request = URLRequest(url: baseURL.appendingPathComponent(path))
        request.httpMethod = "POST"
        request.timeoutInterval = 5
        request.setValue("Bearer " + (try accountCapability()), forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try JSONSerialization.data(withJSONObject: json)
        return try await data(for: request)
    }

    private func decode<T: Decodable>(_ data: Data, path: String) throws -> T {
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw AdapterClientError.invalidResponse("无法解析 \(path) 响应：\(error.localizedDescription)")
        }
    }

    private func data(for request: URLRequest) async throws -> Data {
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                throw AdapterClientError.invalidResponse("适配器返回了非 HTTP 响应")
            }
            guard (200...299).contains(http.statusCode) else {
                let payload = Self.errorPayload(from: data)
                let fallback = HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
                throw AdapterClientError.http(
                    status: http.statusCode,
                    code: payload.code,
                    message: payload.message ?? fallback
                )
            }
            return data
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as AdapterClientError {
            throw error
        } catch {
            throw AdapterClientError.transport(error.localizedDescription)
        }
    }

    private static func errorPayload(from data: Data) -> (code: String?, message: String?) {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return (nil, nil)
        }
        let code = object["code"] as? String
        let message = (object["error"] as? String) ?? (object["message"] as? String)
        return (code, message)
    }
}

enum AdapterClientError: LocalizedError {
    case cancellationUnconfirmed
    case transport(String)
    case http(status: Int, code: String?, message: String)
    case invalidResponse(String)

    var errorDescription: String? {
        switch self {
        case .cancellationUnconfirmed:
            return "已请求停止测速，但未确认后台已结束；请查看后台状态，暂勿重复测速。"
        case .transport(let message):
            return "无法连接本地适配器：\(message)"
        case .http(let status, let code, let message):
            if let code, !code.isEmpty {
                return "适配器 HTTP \(status)（\(code)）：\(message)"
            }
            return "适配器 HTTP \(status)：\(message)"
        case .invalidResponse(let message):
            return message
        }
    }
}
