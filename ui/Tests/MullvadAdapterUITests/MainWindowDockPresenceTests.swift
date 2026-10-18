import AppKit
import XCTest
@testable import MullvadAdapterUI

final class MainWindowDockPresenceTests: XCTestCase {
    @MainActor
    private func window() -> NSWindow {
        _ = NSApplication.shared
        let window = NSWindow(contentRect: NSRect(x: -10_000, y: -10_000, width: 300, height: 200),
                              styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        return window
    }

    @MainActor
    private func eventually(_ condition: () -> Bool, file: StaticString = #filePath, line: UInt = #line) async {
        for _ in 0..<100 {
            if condition() { return }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertTrue(condition(), file: file, line: line)
    }

    @MainActor
    func testDockTracksActualMainWindowOrderingAndCloseReopen() async {
        let main = window()
        var policy: NSApplication.ActivationPolicy?
        let presence = MainWindowDockPresence(backgroundLaunch: false, setPolicy: { policy = $0 })
        defer { presence.stopObserving(); main.close() }
        presence.attach(main)
        presence.launchDidFinish()
        XCTAssertEqual(policy, .accessory)
        main.orderFront(nil)
        await eventually { policy == .regular }
        main.orderOut(nil)
        await eventually { policy == .accessory }
        main.orderFront(nil)
        await eventually { policy == .regular }
        main.close()
        await eventually { policy == .accessory }
        presence.prepareToShowMainWindow()
        main.orderFront(nil)
        await eventually { policy == .regular }
    }

    @MainActor
    func testOtherWindowNotificationsCannotMakeMenuOnlyAppAppearInDock() async {
        let main = window()
        let menu = window()
        menu.level = .popUpMenu
        var policy: NSApplication.ActivationPolicy?
        let presence = MainWindowDockPresence(backgroundLaunch: false, setPolicy: { policy = $0 })
        defer { presence.stopObserving(); main.close(); menu.close() }
        presence.attach(main)
        presence.launchDidFinish()
        menu.orderFront(nil)
        NotificationCenter.default.post(name: NSWindow.didBecomeKeyNotification, object: menu)
        try? await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(policy, .accessory)
        XCTAssertFalse(main.isVisible)
    }

    @MainActor
    func testBackgroundLoginHidesOnlyMainUntilExplicitOpen() async {
        let main = window()
        let other = window()
        var policy: NSApplication.ActivationPolicy?
        let presence = MainWindowDockPresence(backgroundLaunch: true, setPolicy: { policy = $0 })
        defer { presence.stopObserving(); main.close(); other.close() }
        other.orderFront(nil)
        presence.attach(main)
        main.orderFront(nil)
        presence.launchDidFinish()
        await eventually { !main.isVisible && policy == .accessory }
        XCTAssertTrue(other.isVisible)
        presence.prepareToShowMainWindow()
        main.orderFront(nil)
        await eventually { main.isVisible && policy == .regular }
    }
}
