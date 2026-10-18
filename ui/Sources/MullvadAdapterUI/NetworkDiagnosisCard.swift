import SwiftUI

struct NetworkDiagnosisCard: View {
    let diagnosis: NetworkDiagnosis

    private let checks = [
        ("adapter_https", "适配器网页"),
        ("clash_https", "Clash 入口网页"),
        ("system_dns", "系统 DNS"),
        ("worker", "Mullvad 隧道")
    ]

    var body: some View {
        AppCard("最近一次网络检查") {
            VStack(alignment: .leading, spacing: 10) {
                Text(diagnosis.summary).font(.headline)
                Text(diagnosis.advice).font(.callout).foregroundStyle(.secondary)
                HStack(spacing: 20) {
                    ForEach(checks, id: \.0) { key, title in
                        VStack(alignment: .leading, spacing: 5) {
                            Text(title).font(.caption).foregroundStyle(.secondary)
                            AdapterStatusBadge(rawStatus: diagnosis.layers?[key]?.status)
                        }
                    }
                    Spacer(minLength: 0)
                }
                if let at = diagnosis.checkedAt {
                    Text("检查时间：\(shortAdapterTime(at))")
                        .font(.caption).foregroundStyle(.secondary)
                    if let date = ISO8601DateFormatter().date(from: at), Date().timeIntervalSince(date) > 120 {
                        Text("这次检查已超过两分钟；网络状态变化后请重新检查。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                if let scope = diagnosis.scope {
                    Text(scope).font(.caption2).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}
