import AppKit

enum VPNEnvironment: String, CaseIterable {
    case dev, audit
    var title: String { self == .dev ? "개발 VPN 연결…" : "심사 VPN 연결…" }
    var commandURL: URL {
        Bundle.main.resourceURL!
            .appendingPathComponent("vpn/\(rawValue).command")
    }
}

func openTerminal(_ command: URL, completion: @escaping (Error?) -> Void) {
    guard FileManager.default.isExecutableFile(atPath: command.path) else {
        completion(NSError(domain: "VPNMenu", code: 1, userInfo: [
            NSLocalizedDescriptionKey: "VPN 실행 파일을 찾을 수 없습니다: \(command.path)"
        ]))
        return
    }
    guard let terminal = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Terminal") else {
        completion(NSError(domain: "VPNMenu", code: 2, userInfo: [
            NSLocalizedDescriptionKey: "Terminal 앱을 찾을 수 없습니다."
        ]))
        return
    }
    let configuration = NSWorkspace.OpenConfiguration()
    configuration.activates = true
    NSWorkspace.shared.open([command], withApplicationAt: terminal, configuration: configuration) { _, error in
        DispatchQueue.main.async { completion(error) }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var launching = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.title = "VPN"
        statusItem.button?.image = NSImage(systemSymbolName: "network.badge.shield.half.filled", accessibilityDescription: "VPN")
        statusItem.button?.imagePosition = .imageLeading
        statusItem.button?.toolTip = "개발 · 심사 VPN 터미널 열기"
        let menu = NSMenu()
        for environment in VPNEnvironment.allCases {
            let item = NSMenuItem(title: environment.title, action: #selector(connect(_:)), keyEquivalent: "")
            item.representedObject = environment.rawValue
            item.target = self
            menu.addItem(item)
        }
        menu.addItem(.separator())
        let hint = NSMenuItem(title: "암호 · OTP는 터미널에서 입력", action: nil, keyEquivalent: "")
        hint.isEnabled = false
        menu.addItem(hint)
        menu.addItem(.separator())
        let quit = NSMenuItem(title: "메뉴바 앱 종료", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        quit.target = NSApplication.shared
        menu.addItem(quit)
        statusItem.menu = menu

        if CommandLine.arguments.contains("--check") {
            let valid = statusItem.button != nil && VPNEnvironment.allCases.allSatisfy {
                FileManager.default.isExecutableFile(atPath: $0.commandURL.path)
            }
            print("menu=\(menu.items.prefix(2).map(\.title)) commands=\(valid ? "PASS" : "FAIL")")
            exit(valid ? 0 : 1)
        }
        if let index = CommandLine.arguments.firstIndex(of: "--check-terminal"),
           CommandLine.arguments.count > index + 1 {
            openTerminal(URL(fileURLWithPath: CommandLine.arguments[index + 1])) { error in
                print(error?.localizedDescription ?? "Terminal dispatch PASS")
                exit(error == nil ? 0 : 1)
            }
        }
    }

    @objc private func connect(_ sender: NSMenuItem) {
        guard !launching, let name = sender.representedObject as? String,
              let environment = VPNEnvironment(rawValue: name) else { return }
        launching = true
        openTerminal(environment.commandURL) { [weak self] error in
            self?.launching = false
            if let error {
                NSApplication.shared.activate(ignoringOtherApps: true)
                let alert = NSAlert()
                alert.messageText = "VPN 터미널을 열지 못했습니다"
                alert.informativeText = error.localizedDescription
                alert.runModal()
            }
        }
    }
}

let application = NSApplication.shared
application.setActivationPolicy(.accessory)
let delegate = AppDelegate()
application.delegate = delegate
application.run()
