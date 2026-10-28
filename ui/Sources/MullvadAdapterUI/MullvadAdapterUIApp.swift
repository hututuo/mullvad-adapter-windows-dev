import AppKit
import SwiftUI

@MainActor
final class MullvadAdapterAppDelegate: NSObject, NSApplicationDelegate {
    let dockPresence = MainWindowDockPresence()
    var stopConnections: (() async -> Bool)?
    private var terminationPending = false
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !terminationPending else { return .terminateLater }
        guard let stopConnections else { return .terminateNow }
        terminationPending = true
        Task {
            let stopped = await stopConnections()
            terminationPending = false
            sender.reply(toApplicationShouldTerminate: stopped)
        }
        return .terminateLater
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        dockPresence.launchDidFinish()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        dockPresence.reopenMainWindow()
        return true
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationWillTerminate(_ notification: Notification) {
        dockPresence.stopObserving()
    }
}

@main
struct MullvadAdapterUIApp: App {
    @NSApplicationDelegateAdaptor(MullvadAdapterAppDelegate.self) private var appDelegate
    @StateObject private var model = AdapterViewModel(preview: CityPreview.isEnabled(arguments: ProcessInfo.processInfo.arguments, bundleIdentifier: Bundle.main.bundleIdentifier))
    @StateObject private var loginLaunch = LoginLaunchController()

    var body: some Scene {
        Window(model.isPreview ? "Mullvad 设计预览" : "Mullvad 本地适配器", id: "main") {
            ContentView(model: model)
                .onAppear { appDelegate.stopConnections = { await model.stopAllConnections() } }
                .background(MainWindowDockObserver(presence: appDelegate.dockPresence).frame(width: 0, height: 0))
        }
        .windowStyle(.automatic)
        .defaultSize(width: 1280, height: 820)

        MenuBarExtra {
            MenuBarControlView(model: model, loginLaunch: loginLaunch, dockPresence: appDelegate.dockPresence)
        } label: {
            MenuBarStatusLabel(model: model)
                .onAppear { appDelegate.stopConnections = { await model.stopAllConnections() } }
        }
        .menuBarExtraStyle(.menu)
    }
}
