import Foundation

struct CityWorkspace: Decodable {
    let generation: Int?
    let favoriteCities: [String]
    let selectedCity: String?
    let cities: [CitySummary]
    let autoCrossCity: Bool
    let updatedAt: String?

    enum CodingKeys: String, CodingKey {
        case favoriteCities = "favorite_cities", selectedCity = "selected_city"
        case cities, generation, autoCrossCity = "auto_cross_city", updatedAt = "updated_at"
    }

    var selected: CitySummary? { cities.first { $0.id == selectedCity } }
}

struct CitySummary: Decodable, Identifiable {
    let id: String
    let country: String?
    let city: String?
    let relayCount: Int
    let primary: CityNodeEvidence?
    let backups: [CityNodeEvidence]
    let maintenanceIntervalSeconds: Int

    enum CodingKeys: String, CodingKey {
        case id, country, city, primary, backups
        case relayCount = "relay_count", maintenanceIntervalSeconds = "maintenance_interval_seconds"
    }

    var cityName: String { city ?? id.uppercased() }
    var countryName: String {
        let code = String(id.prefix(2)).uppercased()
        return Locale(identifier: "zh_CN").localizedString(forRegionCode: code) ?? country ?? code
    }
}

struct CityNodeEvidence: Decodable, Identifiable {
    let relay: String
    let transport: String?
    let evidence: String
    let checkedAt: String?
    let ageSeconds: Int?
    let outerProbe: CityOuterProbe?
    let active: Bool
    var id: String { relay }

    enum CodingKeys: String, CodingKey {
        case relay, transport, evidence, active
        case checkedAt = "checked_at", ageSeconds = "age_seconds", outerProbe = "outer_probe"
    }

    var evidenceLabel: String {
        switch evidence {
        case "recent_ready": return "近期完整验证"
        case "quarantined": return "失败后冷却中"
        case "expired_or_failed": return "需要重新验证"
        default: return "尚未完整验证"
        }
    }
}

struct CityOuterProbe: Decodable {
    let status: String
    let transport: String?
    let delayMS: Int?
    let checkedAt: String?
    enum CodingKeys: String, CodingKey {
        case status, transport, delayMS = "delay_ms", checkedAt = "checked_at"
    }
}
