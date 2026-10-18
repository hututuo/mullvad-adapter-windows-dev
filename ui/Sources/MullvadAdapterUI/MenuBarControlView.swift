import AppKit
import SwiftUI

struct MenuBarStatusLabel: View {
    @ObservedObject var model: AdapterViewModel

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: symbolName)
            if let ping = menuPing {
                Text("\(ping)ms")
                    .monospacedDigit()
            }
            if model.status?.drainingConnections ?? 0 > 0 {
                Text("↓\(model.status?.drainingConnections ?? 0)")
                    .monospacedDigit()
            }
        }
        .help(helpText)
        .task {
            model.startStatusPolling()
        }
    }

    private var symbolName: String {
        let status = (model.displayedStatus ?? "").lowercased()
        switch status {
        case "ready", "pass", "active":
            return "network"
        case "waiting_network":
            return "wifi.slash"
        case "switching", "reconnecting", "network_recovering", "starting":
            return "arrow.triangle.2.circlepath"
        case "degraded", "degraded_dns", "degraded_service", "data_fail", "fail", "failed", "error":
            return "exclamationmark.triangle"
        default:
            return "network.badge.shield.half.filled"
        }
    }

    private var helpText: String {
        let relay = model.status?.activeRelay ?? "未连接"
        let state = localizedAdapterStatus(model.displayedStatus)
        let ping = menuPing.map { " · Ping \($0) ms" } ?? ""
        let drain = (model.status?.drainingConnections ?? 0) > 0
            ? " · 旧连接 \(model.status?.drainingConnections ?? 0)"
            : ""
        return "Mullvad 本地适配器 · \(relay) · \(state)\(ping)\(drain)"
    }

    private var menuPing: Int? {
        guard model.status?.localNetwork?.message == nil else { return nil }
        return model.status?.lastCanary?.pingData?.delayMs
    }
}

struct MenuBarControlView: View {
    @ObservedObject var model: AdapterViewModel
    @ObservedObject var loginLaunch: LoginLaunchController
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Group {
            Text("Mullvad 本地适配器")

            if let relay = model.status?.activeRelay {
                Text(relay)
                Text("\(TransportPreference.shortDisplayName(for: model.status?.activeTransportMode ?? model.status?.activeTransport)) · \(localizedAdapterStatus(model.displayedStatus))")
                if let status = model.status {
                    let facts = readinessFacts(for: status)
                    if !facts.isEmpty {
                        Text(facts.map { "\($0.label) \($0.detail)" }.joined(separator: " · "))
                    }
                }
                if model.status?.localNetwork?.message == nil, let ping = model.status?.lastCanary?.pingData?.delayMs {
                    Text("Ping：\(ping) ms")
                }
                if let message = model.status?.localNetwork?.message { Text(message) }
            } else {
                Text("尚未连接")
            }

            if let status = model.status, status.drainingConnections > 0 {
                Text("旧连接收尾中：\(status.drainingConnections) 条")
            }

            if model.status?.routingPolicy?.owner == "adapter" {
                Text("切换控制：Adapter · 新连接即时走新路径")
            }

            Divider()

            Button("打开主窗口") {
                showMainWindow()
            }
            .keyboardShortcut("o")

            Button("刷新状态") {
                model.refresh()
            }

            Button("检查并恢复") {
                model.checkConnection(repair: true)
            }
            .disabled(model.isBusy || model.isSpeedTesting)

            Button(model.isExportingReport ? "生成排查资料…" : "复制排查资料路径") {
                model.copyDiagnosticReport()
            }
            .disabled(model.isExportingReport)

            Divider()

            Toggle(
                "开机自启",
                isOn: Binding(
                    get: { loginLaunch.isEnabled },
                    set: { enabled in Task { await loginLaunch.setEnabled(enabled) } }
                )
            )

            .disabled(loginLaunch.isBusy || loginLaunch.state == .unknown)

            if loginLaunch.isBusy {
                Text("正在检查自启状态…")
            } else if loginLaunch.state == .needsRepair || loginLaunch.state == .unknown {
                Button("重试启用自启") { Task { await loginLaunch.setEnabled(true) } }
                Button("移除自启配置") { Task { await loginLaunch.setEnabled(false) } }
            }
            Button("刷新自启状态") { Task { await loginLaunch.refresh() } }
                .disabled(loginLaunch.isBusy)

            Toggle(
                "状态通知",
                isOn: Binding(
                    get: { model.notificationsEnabled },
                    set: { model.setNotificationsEnabled($0) }
                )
            )

            if let permission = model.notificationPermissionText {
                Text("通知权限：\(permission)")
            }

            if let error = loginLaunch.lastError, !error.isEmpty {
                Text(error)
            }

            Divider()

            Button("退出 Mullvad 本地适配器") {
                NSApp.terminate(nil)
            }
            .keyboardShortcut("q")
        }
        .onAppear {
            model.refresh()
            Task { await loginLaunch.refresh() }
        }
    }

    private func showMainWindow() {
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
        DispatchQueue.main.async {
            NSApp.windows
                .filter { $0.canBecomeKey }
                .forEach { $0.makeKeyAndOrderFront(nil) }
        }
    }
}
