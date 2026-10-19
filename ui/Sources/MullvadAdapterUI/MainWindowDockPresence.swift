import AppKit
import SwiftUI

/// Dock presence follows the main scene, never the menu's hosting windows.
@MainActor
final class MainWindowDockPresence {
    private weak var mainWindow: NSWindow?
    private var visibility: NSKeyValueObservation?
    private var miniaturization: NSKeyValueObservation?
    private var notifications: [NSObjectProtocol] = []
    private var backgroundLaunchPending: Bool
    private let setPolicy: @MainActor (NSApplication.ActivationPolicy) -> Void
    private var appliedPolicy: NSApplication.ActivationPolicy?

    init(backgroundLaunch: Bool = ProcessInfo.processInfo.arguments.contains("--background-login"),
         setPolicy: @escaping @MainActor (NSApplication.ActivationPolicy) -> Void = { NSApp.setActivationPolicy($0) }) {
        self.backgroundLaunchPending = backgroundLaunch
        self.setPolicy = setPolicy
    }

    func attach(_ window: NSWindow) {
        guard mainWindow !== window else { return }
        stopObserving()
        mainWindow = window
        visibility = window.observe(\.isVisible, options: [.new]) { [weak self] _, _ in
            Task { @MainActor [weak self] in self?.reconcile() }
        }
        miniaturization = window.observe(\.isMiniaturized, options: [.new]) { [weak self] _, _ in
            Task { @MainActor [weak self] in self?.reconcile() }
        }
        for name in [NSWindow.didBecomeKeyNotification, NSWindow.didBecomeMainNotification,
                     NSWindow.didChangeOcclusionStateNotification, NSWindow.didDeminiaturizeNotification] {
            notifications.append(NotificationCenter.default.addObserver(forName: name, object: window, queue: .main) { [weak self] _ in
                Task { @MainActor [weak self] in self?.reconcile() }
            })
        }
        notifications.append(NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window, queue: .main) { [weak self] _ in
            Task { @MainActor [weak self] in self?.apply(.accessory) }
        })
        DispatchQueue.main.async { [weak self] in self?.reconcile() }
    }

    func launchDidFinish() {
        reconcile()
    }

    func prepareToShowMainWindow() {
        backgroundLaunchPending = false
        apply(.regular)
        if mainWindow?.isMiniaturized == true { mainWindow?.deminiaturize(nil) }
    }

    func reopenMainWindow() {
        prepareToShowMainWindow()
        // This is the exact window attached by the main scene, not a menu.
        mainWindow?.makeKeyAndOrderFront(nil)
    }

    private func reconcile() {
        guard !backgroundLaunchPending else {
            if mainWindow?.isVisible == true { mainWindow?.orderOut(nil) }
            apply(.accessory)
            return
        }
        apply(mainWindow.map { $0.isVisible || $0.isMiniaturized } == true ? .regular : .accessory)
    }

    private func apply(_ policy: NSApplication.ActivationPolicy) {
        guard appliedPolicy != policy else { return }
        setPolicy(policy)
        appliedPolicy = policy
    }

    func stopObserving() {
        visibility?.invalidate()
        miniaturization?.invalidate()
        visibility = nil
        miniaturization = nil
        notifications.forEach(NotificationCenter.default.removeObserver)
        notifications.removeAll()
    }
}

struct MainWindowDockObserver: NSViewRepresentable {
    let presence: MainWindowDockPresence

    final class Probe: NSView {
        var attach: ((NSWindow) -> Void)?
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if let window { attach?(window) }
        }
    }

    func makeNSView(context: Context) -> Probe {
        let view = Probe()
        view.attach = { presence.attach($0) }
        return view
    }

    func updateNSView(_ view: Probe, context: Context) {
        view.attach = { presence.attach($0) }
        if let window = view.window { presence.attach(window) }
    }
}
