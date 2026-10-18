import SwiftUI

struct ContentView: View {
    @ObservedObject var model: AdapterViewModel
    @State private var selectedSection: AppSection? = .cities

    private enum AppSection: String, CaseIterable, Identifiable, Hashable {
        case cities
        case overview
        case account
        case protection
        case history
        case relays
        case diagnostics

        var id: String { rawValue }

        var title: String {
            switch self {
            case .cities: return "常用城市"
            case .relays: return "全部节点"
            case .history: return "历史统计"
            case .overview: return "连接概览"
            case .protection: return "连接保护"
            case .account: return "账号与设备"
            case .diagnostics: return "网络诊断"
            }
        }

        var systemImage: String {
            switch self {
            case .cities: return "building.2.crop.circle"
            case .relays: return "network"
            case .history: return "chart.line.uptrend.xyaxis"
            case .overview: return "gauge.with.dots.needle.50percent"
            case .protection: return "shield.lefthalf.filled"
            case .account: return "person.crop.circle.badge.checkmark"
            case .diagnostics: return "stethoscope"
            }
        }
    }

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 180, ideal: 200, max: 220)
        } detail: {
            VStack(spacing: 0) {
                detail.frame(maxWidth: .infinity, maxHeight: .infinity)
                Divider()
                OperationStatusBar(model: model)
            }
        }
        // Keep the window size stable when the sidebar is shown.  The balanced
        // style makes the detail area yield width instead of asking AppKit to
        // grow the whole window beyond the visible screen.
        .navigationSplitViewStyle(.balanced)
        .frame(minWidth: 1040, idealWidth: 1280, minHeight: 720, idealHeight: 820)
        .task {
            model.startStatusPolling()
            async let snapshot: Void = model.loadSnapshot()
            async let relays: Void = model.loadRelays()
            _ = await (snapshot, relays)
        }
    }

    private var sidebar: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 7) {
                Text("Mullvad 本地适配器")
                    .font(.headline)
                HStack(spacing: 7) {
                    AdapterStatusBadge(rawStatus: model.displayedStatus)
                    if model.isBusy {
                        ProgressView()
                            .controlSize(.small)
                    }
                }
                Text(model.status?.activeRelay ?? "尚无活动节点")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(model.status?.activeRelay ?? "尚无活动节点")
            }
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)

            Divider()

            List(selection: $selectedSection) {
                Section("日常") {
                    ForEach(AppSection.allCases) { section in
                        Label(section.title, systemImage: section.systemImage)
                            .tag(section)
                    }
                }
            }
            .listStyle(.sidebar)

            Divider()

            VStack(alignment: .leading, spacing: 4) {
                Text(model.isPreview ? "隔离设计预览" : "本地控制 API")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Text(model.isPreview ? "不会连接生产后台" : "127.0.0.1:17891")
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder
    private var detail: some View {
        switch selectedSection ?? .cities {
        case .cities:
            CityDashboardView(model: model)
        case .relays:
            RelayBrowserView(model: model)
        case .history:
            HistoryView(model: model)
        case .overview:
            OverviewView(model: model)
        case .protection:
            ProtectionView(model: model)
        case .account:
            AccountView(model: model)
        case .diagnostics:
            DiagnosticsView(model: model)
        }
    }
}
