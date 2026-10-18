import Foundation

// Explicit design preview: all API traffic stays inside URLProtocol. No socket,
// tunnel, preferences, or production daemon is used for preview interactions.
enum CityPreview {
    static func isEnabled(arguments: [String], bundleIdentifier: String?) -> Bool {
        arguments.contains("--preview-cities") ||
            ["local.mullvad.adapter.city-preview", "local.mullvad.adapter.account.preview"].contains(bundleIdentifier ?? "")
    }
    static func client() -> AdapterClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [CityPreviewProtocol.self]
        return AdapterClient(baseURL: URL(string: "https://preview.mullvad.invalid")!, session: URLSession(configuration: configuration), accountCapability: { String(repeating: "0", count: 64) })
    }

    static func data(_ path: String, selected: String = "us-sjc", favorites: [String] = ["us-sjc", "us-sea", "de-ber"]) -> Data {
        let now = ISO8601DateFormatter().string(from: Date())
        let old = ISO8601DateFormatter().string(from: Date().addingTimeInterval(-3600))
        let locations = [("us-sjc", "United States", "San Jose"), ("us-sea", "United States", "Seattle"), ("de-ber", "Germany", "Berlin"), ("jp-osa", "Japan", "Osaka")]
        func node(_ city: String, _ suffix: Int, _ evidence: String, active: Bool = false) -> [String: Any] {
            ["relay": "\(city)-wg-\(suffix)", "transport": "ipv6", "evidence": evidence,
             "active": active, "checked_at": evidence == "recent_ready" ? now : old,
             "age_seconds": evidence == "recent_ready" ? 2 : 3600,
             "outer_probe": ["status": "pass", "transport": "ipv6", "delay_ms": 176, "checked_at": now]]
        }
        let object: Any
        switch path {
        case "protection":
            object = ["profile": ["multihop": true, "entry_city": "jp-osa"],
                      "capabilities": ["multihop": "mihomo-nested-wireguard", "shadowsocks": "supported", "post_quantum": "single-hop-supported"],
                      "effective": ["relay": "\(selected)-wg-506", "entry_relay": "jp-osa-wg-506",
                                    "entry_city": "jp-osa", "multihop": true, "transport_mode": "ss",
                                    "post_quantum": false, "daita": false]]
        case "account":
            object = ["signed_in": true, "verified": true, "account_suffix": "示例", "expiry": "2027-01-01T00:00:00Z",
                      "checked_at": now, "public_key": "示例公钥 · 不是实际设备密钥", "device_match": "matched",
                      "devices": [
                        ["id": "11111111-1111-1111-1111-111111111111", "name": "Example Bird", "pubkey": "示例公钥 · 不是实际设备密钥", "created": now, "current": true],
                        ["id": "22222222-2222-2222-2222-222222222222", "name": "Example Otter", "pubkey": "第二台示例设备公钥", "created": old, "current": false]]]
        case "cities":
            object = ["generation": 1, "favorite_cities": favorites, "selected_city": selected, "auto_cross_city": false, "updated_at": now,
                      "cities": locations.filter { favorites.contains($0.0) }.map { id, country, city in
                        var value: [String: Any] = ["id": id, "country": country, "city": city, "relay_count": 18,
                            "backups": [node(id, 507, "recent_ready"), node(id, 508, "expired_or_failed")],
                            "maintenance_interval_seconds": id == selected ? 30 : 180]
                        if id == selected { value["primary"] = node(id, 506, "recent_ready", active: true) }
                        return value
                      }]
        case "status":
            object = ["status": "ready", "generation": 1, "active_slot": "a", "active_relay": "\(selected)-wg-506",
                      "active_transport_mode": "ipv6", "transport_preference": "auto", "relay_liveness": "pass",
                      "service_readiness": "ready", "health": ["last_check_at": now], "updated_at": now]
        case "relays":
            object = locations.flatMap { id, country, city in (506...508).map { suffix in
                ["hostname": "\(id)-wg-\(suffix)", "location": id, "country": country, "city": city,
                 "country_code": String(id.prefix(2)), "city_code": String(id.suffix(3)), "transports": ["ss", "ipv6", "ipv4"]] as [String: Any]
            } }
        case "metrics": object = [:] as [String: Any]
        default: object = [] as [String]
        }
        return try! JSONSerialization.data(withJSONObject: object)
    }
}

private final class CityPreviewProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let code = request.httpMethod == "POST" ? 409 : 200
        let data = code == 200 ? CityPreview.data(request.url!.lastPathComponent) : Data("{\"error\":\"设计预览不会执行后台操作\"}".utf8)
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: code, httpVersion: nil, headerFields: ["Content-Type": "application/json"])!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

extension AdapterViewModel {
    func loadCityPreview(selected: String = "us-sjc", favorites: [String] = ["us-sjc", "us-sea", "de-ber"]) {
        let decoder = JSONDecoder()
        cityWorkspace = try! decoder.decode(CityWorkspace.self, from: CityPreview.data("cities", selected: selected, favorites: favorites))
        status = try! decoder.decode(AdapterStatus.self, from: CityPreview.data("status", selected: selected))
        relays = try! decoder.decode([RelayInfo].self, from: CityPreview.data("relays"))
        metrics = try! decoder.decode(AdapterMetrics.self, from: CityPreview.data("metrics"))
    }
}
