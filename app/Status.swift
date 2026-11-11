import Foundation
import Darwin

enum VPNState: String, CaseIterable {
    case connected, disconnected, connecting, unknown
}

struct VPNSnapshot {
    let state: VPNState
    let environment: String?

    var label: String {
        switch state {
        case .connected:
            if environment == "dev" { return "개발 연결됨" }
            if environment == "audit" { return "심사 연결됨" }
            return "확인 실패"
        case .disconnected: return "미연결"
        case .connecting: return "연결 중"
        case .unknown: return "확인 실패"
        }
    }

    private struct Report: Decodable {
        struct Active: Decodable {
            let pid: Int
            let profile: String
            let managed: Bool
            let mode: String
            let state: String
        }
        let signature: String
        let active: [Active]
        let startup: String?
    }

    static func decode(data: Data, exitCode: Int32) -> VPNSnapshot {
        let unknown = VPNSnapshot(state: .unknown, environment: nil)
        guard exitCode == 0, data.count <= 65_536,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              object["process_error"] == nil, object["error"] == nil,
              object["busy"] == nil || (object["busy"] as? Bool) == false,
              let report = try? JSONDecoder().decode(Report.self, from: data),
              report.signature == "valid",
              report.startup == nil || report.startup == "pending",
              report.active.count <= 1 else { return unknown }

        guard let active = report.active.first else {
            return VPNSnapshot(state: report.startup == "pending" ? .connecting : .disconnected,
                               environment: nil)
        }
        guard active.pid > 1, ["dev", "audit"].contains(active.profile),
              ["foreground", "daemon"].contains(active.mode) else { return unknown }
        switch active.state {
        case "CONNECTED":
            return VPNSnapshot(state: .connected, environment: active.profile)
        case "not_connected":
            return VPNSnapshot(state: .connecting, environment: active.profile)
        default:
            return unknown
        }
    }
}

/// Runs only the read-only wrapper. Its exec'd Python process is the only process signalled.
final class VPNStatusProbe {
    private final class Attempt {
        let process = Process()
        let pipe = Pipe()
        var data = Data()
        var completions: [(VPNSnapshot) -> Void]
        var timer: DispatchSourceTimer?
        var exitCode: Int32?
        var outputEnded = false
        var finished = false

        init(completion: @escaping (VPNSnapshot) -> Void) { completions = [completion] }
    }

    private let queue = DispatchQueue(label: "com.cskwork.aidt-vpn.status")
    private var active: Attempt?
    private static let unknown = VPNSnapshot(state: .unknown, environment: nil)

    func refresh(command: URL, completion: @escaping (VPNSnapshot) -> Void) {
        queue.async { [self] in
            // Concurrent refreshes share one probe; they never launch another process.
            if let active {
                if active.finished { DispatchQueue.main.async { completion(Self.unknown) } }
                else { active.completions.append(completion) }
                return
            }
            let attempt = Attempt(completion: completion)
            active = attempt
            let process = attempt.process
            process.executableURL = URL(fileURLWithPath: "/bin/zsh")
            process.arguments = [command.path, "--status"]
            var environment = ProcessInfo.processInfo.environment
            environment["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
            process.environment = environment
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = attempt.pipe
            process.standardError = FileHandle.nullDevice

            attempt.pipe.fileHandleForReading.readabilityHandler = { [weak self, weak attempt] handle in
                do {
                    let chunk = try handle.read(upToCount: 4_096) ?? Data()
                    self?.queue.async { [weak self, weak attempt] in
                        guard let self, let attempt, self.active === attempt, !attempt.finished else { return }
                        if chunk.isEmpty {
                            attempt.outputEnded = true
                            attempt.pipe.fileHandleForReading.readabilityHandler = nil
                        } else if attempt.data.count + chunk.count <= 65_536 {
                            attempt.data.append(chunk)
                        } else {
                            self.finish(attempt, snapshot: Self.unknown, stop: true)
                            return
                        }
                        self.finishIfReady(attempt)
                    }
                } catch {
                    self?.queue.async { [weak self, weak attempt] in
                        guard let self, let attempt, self.active === attempt, !attempt.finished else { return }
                        self.finish(attempt, snapshot: Self.unknown, stop: true)
                    }
                }
            }
            process.terminationHandler = { [weak self, weak attempt] process in
                self?.queue.async { [weak self, weak attempt] in
                    guard let self, let attempt, self.active === attempt else { return }
                    attempt.exitCode = process.terminationReason == .exit ? process.terminationStatus : -1
                    if attempt.finished { self.active = nil }
                    else { self.finishIfReady(attempt) }
                }
            }
            do {
                try process.run()
                // Ten seconds for status, plus at most 250 ms before force-stopping this probe.
                let timer = DispatchSource.makeTimerSource(queue: queue)
                attempt.timer = timer
                timer.schedule(deadline: .now() + 10)
                timer.setEventHandler { [weak self, weak attempt] in
                    guard let self, let attempt, self.active === attempt, !attempt.finished else { return }
                    self.finish(attempt, snapshot: Self.unknown, stop: true)
                }
                timer.resume()
            } catch {
                finish(attempt, snapshot: Self.unknown, stop: false)
            }
        }
    }

    func cancel() {
        queue.async { [self] in
            guard let active, !active.finished else { return }
            finish(active, snapshot: Self.unknown, stop: true)
        }
    }

    private func finishIfReady(_ attempt: Attempt) {
        guard attempt.outputEnded, let exitCode = attempt.exitCode else { return }
        finish(attempt, snapshot: VPNSnapshot.decode(data: attempt.data, exitCode: exitCode), stop: false)
    }

    private func finish(_ attempt: Attempt, snapshot: VPNSnapshot, stop: Bool) {
        guard !attempt.finished else { return }
        attempt.finished = true
        attempt.timer?.cancel()
        attempt.timer = nil
        attempt.pipe.fileHandleForReading.readabilityHandler = nil
        try? attempt.pipe.fileHandleForReading.close()
        if stop && attempt.process.isRunning {
            attempt.process.terminate()
            queue.asyncAfter(deadline: .now() + 0.25) { [weak self, weak attempt] in
                guard let self, let attempt, self.active === attempt, attempt.process.isRunning else { return }
                // Never enumerate or signal VPN processes, process groups, or descendants.
                kill(attempt.process.processIdentifier, SIGKILL)
            }
        } else {
            active = nil
        }
        let completions = attempt.completions
        attempt.completions.removeAll()
        DispatchQueue.main.async { completions.forEach { $0(snapshot) } }
    }

    deinit {
        active?.timer?.cancel()
        active?.pipe.fileHandleForReading.readabilityHandler = nil
        try? active?.pipe.fileHandleForReading.close()
        if let process = active?.process, process.isRunning {
            kill(process.processIdentifier, SIGKILL)
        }
    }
}
