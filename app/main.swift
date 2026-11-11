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

enum StatusColor: String, CaseIterable {
    case green, gray, orange, red, blue, purple
    var title: String {
        switch self {
        case .green: return "초록"
        case .gray: return "회색"
        case .orange: return "주황"
        case .red: return "빨강"
        case .blue: return "파랑"
        case .purple: return "보라"
        }
    }
    var color: NSColor {
        switch self {
        case .green: return .systemGreen
        case .gray: return .systemGray
        case .orange: return .systemOrange
        case .red: return .systemRed
        case .blue: return .systemBlue
        case .purple: return .systemPurple
        }
    }
}

struct MenuPreferences {
    let defaults: UserDefaults
    var showEnvironment: Bool {
        get { defaults.object(forKey: "showEnvironment") as? Bool ?? true }
        nonmutating set { defaults.set(newValue, forKey: "showEnvironment") }
    }
    var interval: TimeInterval {
        get {
            let value = defaults.double(forKey: "refreshInterval")
            return [5.0, 10, 30, 60].contains(value) ? value : 10
        }
        nonmutating set { defaults.set(newValue, forKey: "refreshInterval") }
    }
    func color(for state: VPNState) -> StatusColor {
        if let value = defaults.string(forKey: "color." + state.rawValue),
           let color = StatusColor(rawValue: value) { return color }
        switch state {
        case .connected: return .green
        case .disconnected: return .gray
        case .connecting: return .orange
        case .unknown: return .red
        }
    }
    func setColor(_ color: StatusColor, for state: VPNState) {
        defaults.set(color.rawValue, forKey: "color." + state.rawValue)
    }
    func reset() {
        defaults.removeObject(forKey: "showEnvironment")
        defaults.removeObject(forKey: "refreshInterval")
        for state in VPNState.allCases { defaults.removeObject(forKey: "color." + state.rawValue) }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var launching = false
    private let preferences = MenuPreferences(defaults: .standard)
    private let probe = VPNStatusProbe()
    private var timer: Timer?
    private var snapshot = VPNSnapshot(state: .unknown, environment: nil)
    private var updatedAt: Date?
    private var statusLine: NSMenuItem!
    private var settingsMenu: NSMenu!
    private var environmentItems: [String: NSMenuItem] = [:]

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.imagePosition = .imageLeading
        let menu = NSMenu()
        statusLine = NSMenuItem(title: "상태 확인 중…", action: nil, keyEquivalent: "")
        menu.addItem(statusLine)
        menu.addItem(.separator())
        for environment in VPNEnvironment.allCases {
            let item = actionItem(environment.title, #selector(connect(_:)))
            item.representedObject = environment.rawValue
            environmentItems[environment.rawValue] = item
            menu.addItem(item)
        }
        menu.addItem(.separator())
        menu.addItem(actionItem("지금 새로고침", #selector(refresh)))
        let settings = NSMenuItem(title: "표시 설정", action: nil, keyEquivalent: "")
        settingsMenu = NSMenu()
        settings.submenu = settingsMenu
        menu.addItem(settings)
        let hint = NSMenuItem(title: "암호 · OTP는 터미널에서 입력", action: nil, keyEquivalent: "")
        menu.addItem(hint)
        menu.addItem(.separator())
        let quit = NSMenuItem(title: "메뉴바 앱 종료", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        quit.target = NSApplication.shared
        menu.addItem(quit)
        statusItem.menu = menu
        rebuildSettings()
        render()

        if CommandLine.arguments.contains("--check") {
            let valid = statusItem.button != nil && VPNEnvironment.allCases.allSatisfy {
                FileManager.default.isExecutableFile(atPath: $0.commandURL.path)
            }
            for state in VPNState.allCases {
                snapshot = VPNSnapshot(state: state, environment: state == .connected ? "dev" : nil)
                render()
                precondition(statusItem.button?.image?.isTemplate == false)
                precondition(statusLine.title == snapshot.label)
            }
            let suite = "vpn-menu-check-" + UUID().uuidString
            let defaults = UserDefaults(suiteName: suite)!
            let test = MenuPreferences(defaults: defaults)
            precondition(test.showEnvironment && test.interval == 10)
            test.showEnvironment = false
            test.interval = 30
            test.setColor(.purple, for: .connected)
            let reloaded = MenuPreferences(defaults: UserDefaults(suiteName: suite)!)
            precondition(!reloaded.showEnvironment && reloaded.interval == 30)
            precondition(reloaded.color(for: .connected) == .purple)
            test.reset()
            precondition(test.showEnvironment && test.color(for: .connected) == .green)
            defaults.removePersistentDomain(forName: suite)
            print("Menu rendering (4 states), preferences, bundled commands: \(valid ? "PASS" : "FAIL")")
            exit(valid ? 0 : 1)
        }
        if let index = CommandLine.arguments.firstIndex(of: "--check-terminal"),
           CommandLine.arguments.count > index + 1 {
            openTerminal(URL(fileURLWithPath: CommandLine.arguments[index + 1])) { error in
                print(error?.localizedDescription ?? "Terminal dispatch PASS")
                exit(error == nil ? 0 : 1)
            }
            return
        }
        restartTimer()
        refresh()
        NSWorkspace.shared.notificationCenter.addObserver(self, selector: #selector(woke), name: NSWorkspace.didWakeNotification, object: nil)
    }

    func applicationWillTerminate(_ notification: Notification) {
        timer?.invalidate()
        probe.cancel()
    }

    private func actionItem(_ title: String, _ action: Selector) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
        item.target = self
        return item
    }

    private func rebuildSettings() {
        settingsMenu.removeAllItems()
        let name = actionItem("환경명 표시", #selector(toggleEnvironment))
        name.state = preferences.showEnvironment ? .on : .off
        settingsMenu.addItem(name)
        let interval = NSMenuItem(title: "갱신 주기", action: nil, keyEquivalent: "")
        let intervals = NSMenu()
        for seconds in [5, 10, 30, 60] {
            let item = actionItem("\(seconds)초", #selector(changeInterval(_:)))
            item.tag = seconds
            item.state = preferences.interval == Double(seconds) ? .on : .off
            intervals.addItem(item)
        }
        interval.submenu = intervals
        settingsMenu.addItem(interval)
        for state in VPNState.allCases {
            let title: String
            switch state {
            case .connected: title = "연결됨"
            case .disconnected: title = "미연결"
            case .connecting: title = "연결 중"
            case .unknown: title = "확인 실패"
            }
            let item = NSMenuItem(title: title + " 색상", action: nil, keyEquivalent: "")
            let colors = NSMenu()
            for color in StatusColor.allCases {
                let choice = actionItem(color.title, #selector(changeColor(_:)))
                choice.representedObject = [state.rawValue, color.rawValue]
                choice.image = dot(color.color)
                choice.state = preferences.color(for: state) == color ? .on : .off
                colors.addItem(choice)
            }
            item.submenu = colors
            settingsMenu.addItem(item)
        }
        settingsMenu.addItem(.separator())
        settingsMenu.addItem(actionItem("기본 설정 복원", #selector(resetPreferences)))
    }

    private func dot(_ color: NSColor) -> NSImage {
        let image = NSImage(size: NSSize(width: 14, height: 14), flipped: false) { rect in
            color.setFill()
            NSBezierPath(ovalIn: rect.insetBy(dx: 2, dy: 2)).fill()
            return true
        }
        image.isTemplate = false
        return image
    }

    private func render() {
        statusLine.title = snapshot.label
        statusItem.button?.image = dot(preferences.color(for: snapshot.state).color)
        if preferences.showEnvironment, let environment = snapshot.environment {
            statusItem.button?.title = environment == "dev" ? "개발" : "심사"
        } else {
            statusItem.button?.title = "VPN"
        }
        var tooltip = snapshot.label
        if let date = updatedAt {
            tooltip += " · " + DateFormatter.localizedString(from: date, dateStyle: .none, timeStyle: .medium)
        }
        statusItem.button?.toolTip = tooltip
        statusItem.button?.setAccessibilityLabel(tooltip)
        for (environment, item) in environmentItems {
            item.state = snapshot.state == .connected && snapshot.environment == environment ? .on : .off
        }
    }

    private func restartTimer() {
        timer?.invalidate()
        let next = Timer(timeInterval: preferences.interval, repeats: true) { [weak self] _ in self?.refresh() }
        RunLoop.main.add(next, forMode: .common)
        timer = next
    }

    @objc private func refresh() {
        let command = Bundle.main.resourceURL!.appendingPathComponent("vpn/vpn")
        probe.refresh(command: command) { [weak self] result in
            guard let self else { return }
            self.snapshot = result
            self.updatedAt = Date()
            self.render()
            if CommandLine.arguments.contains("--check-live") {
                print("state=\(result.state.rawValue) environment=\(result.environment ?? "none") label=\(result.label)")
                exit(result.state == .unknown ? 1 : 0)
            }
        }
    }

    @objc private func woke() {
        snapshot = VPNSnapshot(state: .unknown, environment: nil)
        updatedAt = nil
        render()
        refresh()
    }
    @objc private func toggleEnvironment() {
        preferences.showEnvironment.toggle()
        rebuildSettings()
        render()
    }
    @objc private func changeInterval(_ sender: NSMenuItem) {
        preferences.interval = Double(sender.tag)
        rebuildSettings()
        restartTimer()
        refresh()
    }
    @objc private func changeColor(_ sender: NSMenuItem) {
        guard let values = sender.representedObject as? [String], values.count == 2,
              let state = VPNState(rawValue: values[0]), let color = StatusColor(rawValue: values[1]) else { return }
        preferences.setColor(color, for: state)
        rebuildSettings()
        render()
    }
    @objc private func resetPreferences() {
        preferences.reset()
        rebuildSettings()
        restartTimer()
        render()
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
            self?.refresh()
        }
    }
}

let application = NSApplication.shared
application.setActivationPolicy(.accessory)
let delegate = AppDelegate()
application.delegate = delegate
application.run()
