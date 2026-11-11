import Foundation
import Darwin

@main
struct StatusTests {
    static func main() throws {
        var count = 0
        func check(_ name: String, _ json: String, _ state: VPNState,
                   _ environment: String? = nil, exitCode: Int32 = 0, label: String? = nil) {
            let result = VPNSnapshot.decode(data: Data(json.utf8), exitCode: exitCode)
            guard result.state == state, result.environment == environment,
                  label == nil || result.label == label else {
                fatalError("FAIL \(name): \(result.state) \(result.environment ?? "nil") \(result.label)")
            }
            count += 1
        }
        let dev = #"{"signature":"valid","active":[{"pid":42,"profile":"dev","managed":true,"mode":"daemon","state":"CONNECTED"}]}"#
        let audit = dev.replacingOccurrences(of: "dev", with: "audit")
        check("development", dev, .connected, "dev", label: "개발 연결됨")
        check("audit", audit, .connected, "audit", label: "심사 연결됨")
        check("disconnected", #"{"signature":"valid","active":[]}"#, .disconnected, label: "미연결")
        check("pending startup", #"{"signature":"valid","startup":"pending","active":[]}"#, .connecting, label: "연결 중")
        check("active handshake", dev.replacingOccurrences(of: "CONNECTED", with: "not_connected"), .connecting, "dev")
        check("unavailable management", dev.replacingOccurrences(of: "CONNECTED", with: "unknown"), .unknown, label: "확인 실패")
        check("other management state", dev.replacingOccurrences(of: "CONNECTED", with: "RECONNECTING"), .unknown)
        check("unknown profile", dev.replacingOccurrences(of: "dev", with: "prd"), .unknown)
        check("multiple processes", #"{"signature":"valid","active":[{"pid":42,"profile":"dev","managed":true,"mode":"daemon","state":"CONNECTED"},{"pid":43,"profile":"audit","managed":true,"mode":"daemon","state":"CONNECTED"}]}"#, .unknown)
        check("invalid signature", dev.replacingOccurrences(of: "valid", with: "invalid"), .unknown)
        check("legacy auth signature", dev.replacingOccurrences(of: "valid", with: "legacy_auth_file_present"), .unknown)
        check("pending invalid signature", #"{"signature":"invalid","startup":"pending","active":[]}"#, .unknown)
        check("process inspection failure", #"{"signature":"valid","process_error":"busy","active":[]}"#, .unknown)
        check("pending inspection failure", #"{"signature":"valid","startup":"pending","process_error":"launcher running","active":[]}"#, .unknown)
        check("busy", #"{"signature":"valid","busy":true,"active":[]}"#, .unknown)
        check("malformed", "not JSON", .unknown)
        check("truncated", "{", .unknown)
        check("nonzero", dev, .unknown, exitCode: 1)
        check("missing signature", #"{"active":[]}"#, .unknown)
        check("missing process list", #"{"signature":"valid"}"#, .unknown)
        check("invalid process identity", dev.replacingOccurrences(of: "42", with: "0"), .unknown)
        check("invalid process mode", dev.replacingOccurrences(of: "daemon", with: "other"), .unknown)
        check("invalid startup", #"{"signature":"valid","startup":"other","active":[]}"#, .unknown)
        check("oversized", dev + String(repeating: " ", count: 65_536), .unknown)
        print("PASS \(count) status decoder cases")

        // All process fixtures are synthetic: no VPN commands or credentials are touched.
        let scratch = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: scratch) }
        func script(_ name: String, _ body: String) throws -> URL {
            let url = scratch.appendingPathComponent(name)
            try Data(body.utf8).write(to: url)
            return url
        }
        func wait(_ seconds: TimeInterval, until completed: () -> Bool) {
            let deadline = Date().addingTimeInterval(seconds)
            while !completed() && Date() < deadline {
                _ = RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.01))
            }
            guard completed() else { fatalError("FAIL probe deadline") }
        }
        let probe = VPNStatusProbe()
        var results: [VPNSnapshot] = []
        let collect: (VPNSnapshot) -> Void = { snapshot in
            precondition(Thread.isMainThread, "probe callback must use the main queue")
            results.append(snapshot)
        }
        let marker = scratch.appendingPathComponent("launches")
        let success = try script("success", "printf x >> '\(marker.path)'\n/bin/sleep 0.1\nprintf '%s\\n' '\(dev)'\n")
        probe.refresh(command: success, completion: collect)
        probe.refresh(command: success, completion: collect)
        wait(3) { results.count == 2 }
        precondition(results.allSatisfy { $0.state == .connected && $0.environment == "dev" })
        let launches = try String(contentsOf: marker, encoding: .utf8)
        precondition(launches == "x", "overlapping refresh launched twice")
        results.removeAll()
        let failure = try script("failure", "printf '%s\\n' '\(dev)'\nexit 1\n")
        probe.refresh(command: failure, completion: collect)
        wait(3) { results.count == 1 }
        precondition(results[0].state == .unknown, "a failed probe must clear stale green")
        results.removeAll()
        let overflow = try script("overflow", "/usr/bin/head -c 70000 /dev/zero\n")
        probe.refresh(command: overflow, completion: collect)
        wait(3) { results.count == 1 }
        precondition(results[0].state == .unknown)
        let overflowSettled = Date().addingTimeInterval(0.5)
        wait(1) { Date() >= overflowSettled }
        results.removeAll()
        // A subsequent request also proves the overflow probe was reaped.
        let sleeping = try script("sleeping", "exec /bin/sleep 30\n")
        probe.refresh(command: sleeping, completion: collect)
        probe.cancel()
        wait(3) { results.count == 1 }
        precondition(results[0].state == .unknown)
        // Allow termination delivery before starting the independent timeout case.
        let settle = Date().addingTimeInterval(0.5)
        wait(1) { Date() >= settle }
        results.removeAll()
        let pidFile = scratch.appendingPathComponent("probe-pid")
        let timeout = try script("timeout", "printf '%s' $$ > '\(pidFile.path)'\ntrap '' TERM\nexec /bin/sleep 30\n")
        let started = Date()
        probe.refresh(command: timeout, completion: collect)
        wait(11.5) { results.count == 1 }
        precondition(results[0].state == .unknown && Date().timeIntervalSince(started) < 12)
        let pid = Int32(try String(contentsOf: pidFile, encoding: .utf8))!
        wait(1) { kill(pid, 0) == -1 && errno == ESRCH }
        print("PASS 5 synthetic probe cases (coalescing/main queue, exit failure, output bound, cancellation, timeout/reap)")
    }
}
