import AppKit
import SwiftUI

final class MullvadAdapterAppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)

        if ProcessInfo.processInfo.arguments.contains("--background-login") {
            DispatchQueue.main.async {
                NSApp.windows.forEach { $0.orderOut(nil) }
            }
        }
    }
}

@main
struct MullvadAdapterUIApp: App {
    @NSApplicationDelegateAdaptor(MullvadAdapterAppDelegate.self) private var appDelegate
    @StateObject private var model = AdapterViewModel(preview: CityPreview.isEnabled(arguments: ProcessInfo.processInfo.arguments, bundleIdentifier: Bundle.main.bundleIdentifier))
    @StateObject private var loginLaunch = LoginLaunchController()

    var body: some Scene {
        WindowGroup(model.isPreview ? "Mullvad 设计预览" : "Mullvad 本地适配器", id: "main") {
            ContentView(model: model)
        }
        .windowStyle(.automatic)
        .defaultSize(width: 1280, height: 820)

        MenuBarExtra {
            MenuBarControlView(model: model, loginLaunch: loginLaunch)
        } label: {
            MenuBarStatusLabel(model: model)
        }
        .menuBarExtraStyle(.menu)
    }
}
