//
//  AegisFirewall.swift
//  Aegis Antivirus — content filter system extension (NEFilterDataProvider).
//
//  Comments are in English on purpose: only the user facing documentation
//  (native-daemon/README.md) is written in Turkish.
//
//  Target
//  ------
//  macOS System Extension of type "Network Extension" with the
//  `com.apple.networkextension.filter-data` provider class, entitlement
//  `com.apple.developer.networking.networkextension` (content filter).
//
//  How a decision is made
//  ----------------------
//  `handleNewFlow(_:)` is called once per new socket flow.  We resolve the
//  remote endpoint (host + port) and the transport protocol, then run the rule
//  list exported by the Electron side (`src/firewall.js` / `src/store.js`):
//
//      [{"id":"r1","type":"block","proto":"tcp","host":"evil.example.com",
//        "port":443,"note":"..."}]
//
//  Precedence: an explicit `allow` rule always beats a `block` rule, and the
//  default is `allow` (a firewall that fails open only fails the rules it did
//  not understand — everything is logged, nothing is silently blackholed).
//
//  Honest limitation: the remote endpoint comes from `remoteFlowEndpoint`
//  (macOS 15+) with `remoteHostname` as a fallback, and the framework may not
//  have populated either one when `handleNewFlow` runs.  In that case host and
//  port specific rules cannot match (the flow is allowed), while rules that
//  only constrain the transport protocol still apply.  Nothing is silently
//  dropped and the situation is logged once.
//

import Foundation
import NetworkExtension
import Network
import Darwin
import os.log

// MARK: - Logging

private let log = Logger(subsystem: "com.aegis.antivirus.firewall", category: "filter")

// MARK: - Locations

enum FirewallPaths {
    /// UNIX domain socket created by the Electron main process (newline JSON).
    static let socket = ProcessInfo.processInfo.environment["AEGIS_IPC_SOCKET"]
        ?? "/Library/Application Support/Aegis/aegis.sock"

    /// Canonical export of the rule list (documented in native-daemon/README.md).
    static let canonicalRules = "/Library/Application Support/Aegis/firewall-rules.json"

    /// Rule files probed when the canonical export does not exist yet:
    /// `aegis-store.json` is what `src/store.js` actually writes.
    static let storeFileNames = ["firewall-rules.json", "aegis-store.json"]

    /// Candidate paths, most specific first.
    static func ruleCandidates() -> [String] {
        var candidates = [canonicalRules]
        if let override = ProcessInfo.processInfo.environment["AEGIS_RULES_FILE"] {
            candidates.insert(override, at: 0)
        }

        let fm = FileManager.default
        guard let users = try? fm.contentsOfDirectory(atPath: "/Users") else { return candidates }
        for user in users.sorted() {
            let base = "/Users/\(user)/Library/Application Support"
            guard let apps = try? fm.contentsOfDirectory(atPath: base) else { continue }
            for app in apps.sorted() {
                for name in storeFileNames {
                    candidates.append("\(base)/\(app)/\(name)")
                }
            }
        }
        return candidates
    }
}

// MARK: - Rules

/// One rule, exactly as `src/store.js` writes it.  Unknown keys in the JSON
/// are ignored, missing keys mean "matches everything" for that dimension.
struct FirewallRule: Codable, Equatable {
    enum Kind: String, Codable {
        case allow
        case block
    }

    let id: String
    let type: Kind
    let proto: String?
    let host: String?
    let port: Int?
    let note: String?

    enum CodingKeys: String, CodingKey {
        case id, type, proto, host, port, note
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(String.self, forKey: .id) ?? UUID().uuidString
        type = (try? container.decode(Kind.self, forKey: .type)) ?? .block
        proto = try container.decodeIfPresent(String.self, forKey: .proto)
        host = try container.decodeIfPresent(String.self, forKey: .host)
        // `port` may arrive as a number, null, or even a numeric string.
        if let number = try? container.decode(Int.self, forKey: .port) {
            port = number
        } else if let text = try? container.decode(String.self, forKey: .port), let number = Int(text) {
            port = number
        } else {
            port = nil
        }
        note = try container.decodeIfPresent(String.self, forKey: .note)
    }

    init(id: String, type: Kind, proto: String?, host: String?, port: Int?, note: String?) {
        self.id = id
        self.type = type
        self.proto = proto
        self.host = host
        self.port = port
        self.note = note
    }

    // MARK: Matching

    /// `flowProto` is "tcp" / "udp".
    func matches(host flowHost: String, port flowPort: Int, proto flowProto: String) -> Bool {
        protoMatches(flowProto) && portMatches(flowPort) && hostMatches(flowHost)
    }

    private func protoMatches(_ flowProto: String) -> Bool {
        guard let proto = proto?.trimmingCharacters(in: .whitespaces),
              !proto.isEmpty else { return true }
        let accepted = proto
            .lowercased()
            .split(whereSeparator: { $0 == "," || $0 == "|" || $0 == " " })
            .map(String.init)
        if accepted.contains(where: { $0 == "*" || $0 == "any" }) { return true }
        return accepted.contains(flowProto.lowercased())
    }

    private func portMatches(_ flowPort: Int) -> Bool {
        guard let port = port, port > 0 else { return true } // "any port"
        guard flowPort > 0 else { return false }             // unknown port: cannot confirm
        return port == flowPort
    }

    private func hostMatches(_ flowHost: String) -> Bool {
        guard let host = host?.trimmingCharacters(in: .whitespaces),
              !host.isEmpty, host != "*" else { return true }
        guard !flowHost.isEmpty else { return false }

        let target = flowHost.lowercased()
        let pattern = host.lowercased()

        if pattern == target { return true }
        if pattern.hasPrefix("*.") {
            let suffix = String(pattern.dropFirst(1)) // ".example.com"
            return target.hasSuffix(suffix) || target.contains(String(pattern.dropFirst(2)))
        }
        // Mirrors src/firewall.js: exact, suffix or substring match.
        return target.contains(pattern) || target.hasSuffix("." + pattern)
    }
}

/// Loads the rule list and re-reads it when the file on disk changes.
final class FirewallRuleStore {
    private let lock = NSLock()
    private var rules: [FirewallRule] = []
    private var loadedPath: String?
    private var modificationTime: TimeInterval = 0
    private var lastCheck: TimeInterval = 0

    private static let reloadInterval: TimeInterval = 2

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        reloadIfNeeded()
        return rules.count
    }

    var sourcePath: String? {
        lock.lock()
        defer { lock.unlock() }
        return loadedPath
    }

    /// Block only when a `block` rule matches and no `allow` rule exempts it.
    func shouldBlock(host: String, port: Int, proto: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        reloadIfNeeded()

        if let exception = rules.first(where: { $0.type == .allow && $0.matches(host: host, port: port, proto: proto) }) {
            log.debug("kural izin verdi: \(exception.id, privacy: .public)")
            return nil
        }
        guard let hit = rules.first(where: { $0.type == .block && $0.matches(host: host, port: port, proto: proto) }) else {
            return nil
        }
        return hit.id
    }

    // MARK: Loading

    private func reloadIfNeeded() {
        let now = Date().timeIntervalSince1970
        guard now - lastCheck >= Self.reloadInterval else { return }
        lastCheck = now

        for path in FirewallPaths.ruleCandidates() {
            guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
                  let modified = (attributes[.modificationDate] as? Date)?.timeIntervalSince1970
            else { continue }

            if path == loadedPath && modified == modificationTime { return }

            guard let data = FileManager.default.contents(atPath: path),
                  let decoded = Self.decode(data: data)
            else { continue }

            loadedPath = path
            modificationTime = modified
            rules = decoded
            log.info("Kurallar yüklendi: \(path, privacy: .public) — \(decoded.count) kural")
            return
        }
    }

    /// Accepts both shapes: a bare JSON array and `{"rules": [...]}` (the
    /// `aegis-store.json` document written by `src/store.js`).
    private static func decode(data: Data) -> [FirewallRule]? {
        let object = try? JSONSerialization.jsonObject(with: data)
        if let array = object as? [[String: Any]] {
            return (try? JSONDecoder().decode([FirewallRule].self, from: JSONSerialization.data(withJSONObject: array))) ?? []
        }
        if let document = object as? [String: Any],
           let array = document["rules"] as? [[String: Any]] {
            return (try? JSONDecoder().decode([FirewallRule].self, from: JSONSerialization.data(withJSONObject: array))) ?? []
        }
        return nil
    }
}

// MARK: - IPC telemetry

/// Best effort newline-delimited JSON client, identical wire format to the
/// shield's `IPCClient`: connect → write one JSON object per line → on any
/// error close the socket, drop the event silently and retry later.
final class FirewallTelemetry: @unchecked Sendable {
    private let path: String
    private let queue = DispatchQueue(label: "com.aegis.antivirus.firewall.ipc")
    private var descriptor: Int32 = -1
    private var lastAttempt: TimeInterval = 0
    private let reconnectInterval: TimeInterval = 5

    init(path: String) {
        self.path = path
    }

    deinit {
        queue.sync { closeDescriptorLocked() }
    }

    func send(_ payload: [String: Any]) {
        // Serialize on the caller's thread: JSONSerialization is not
        // @Sendable-safe and the queue must only touch socket state.
        guard JSONSerialization.isValidJSONObject(payload),
              let data = try? JSONSerialization.data(withJSONObject: payload)
        else { return }
        let bytes = [UInt8](data) + [0x0A]

        queue.async { [self] in
            guard connectIfNeeded() else { return }
            emit(bytes)
        }
    }

    func close() {
        queue.sync { closeDescriptorLocked() }
    }

    private func connectIfNeeded() -> Bool {
        if descriptor >= 0 { return true }

        let now = Date().timeIntervalSince1970
        guard now - lastAttempt >= reconnectInterval else { return false }
        lastAttempt = now

        let socketFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketFD >= 0 else { return false }

        var noSigPipe: Int32 = 1
        setsockopt(socketFD, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe,
                   socklen_t(MemoryLayout<Int32>.size))

        var timeout = timeval(tv_sec: 0, tv_usec: 200_000)
        setsockopt(socketFD, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   socklen_t(MemoryLayout<timeval>.size))

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        let copied = withUnsafeMutablePointer(to: &address.sun_path) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: capacity) { destination in
                path.utf8CString.withUnsafeBufferPointer { source in
                    guard let base = source.baseAddress else { return false }
                    let count = min(source.count, capacity - 1)
                    memcpy(destination, base, count)
                    destination[count] = 0
                    return true
                }
            }
        }
        guard copied else {
            Darwin.close(socketFD)
            return false
        }

        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(socketFD, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            Darwin.close(socketFD)
            return false
        }

        descriptor = socketFD
        log.info("IPC bağlantısı kuruldu: \(self.path, privacy: .public)")
        return true
    }

    private func emit(_ bytes: [UInt8]) {
        var offset = 0
        while offset < bytes.count {
            let written = bytes.withUnsafeBufferPointer { buffer -> Int in
                guard let base = buffer.baseAddress else { return -1 }
                return Darwin.write(descriptor, base + offset, buffer.count - offset)
            }
            if written > 0 {
                offset += written
                continue
            }
            if written < 0 && errno == EINTR { continue }
            closeDescriptorLocked()
            return
        }
    }

    private func closeDescriptorLocked() {
        if descriptor >= 0 {
            Darwin.close(descriptor)
            descriptor = -1
        }
    }
}

// MARK: - Filter provider

/// `@objc(...)` pins the Objective-C runtime name so the value used in
/// `Info.plist > NetworkExtension > NEProviderClasses` never depends on the
/// Swift module name.
@objc(AegisFirewall)
final class AegisFirewall: NEFilterDataProvider {
    private let ruleStore = FirewallRuleStore()
    private let telemetry = FirewallTelemetry(path: FirewallPaths.socket)
    private var warnedAboutEndpoint = false

    // MARK: Lifecycle

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let loaded = ruleStore.count // force the first load before traffic arrives
        log.info("AegisFirewall başladı — \(loaded) kural, kaynak=\(self.ruleStore.sourcePath ?? "yok", privacy: .public)")
        enableLoopbackFiltering()
        completionHandler(nil)
    }

    /// Loopback traffic is excluded from the framework defaults, so plain
    /// 127.0.0.1 connections would never reach `handleNewFlow`.  Pushing
    /// explicit rules whose action is `.filterData` ("ask this provider")
    /// closes that gap without changing anything else.
    private func enableLoopbackFiltering() {
        guard #available(macOS 15.0, *) else {
            log.warning("Döngü içi trafik filtrelenemiyor — macOS 15 gerektirir")
            return
        }

        // Port 0 means "any port" for NENetworkRule endpoints.
        let anyPort = NWEndpoint.Port(rawValue: 0)!
        let endpoints = [
            NWEndpoint.hostPort(host: NWEndpoint.Host("127.0.0.1"), port: anyPort),
            NWEndpoint.hostPort(host: NWEndpoint.Host("::1"), port: anyPort)
        ]
        let prefixes: [Int] = [32, 128]
        let rules = zip(endpoints, prefixes).map { endpoint, prefix in
            NEFilterRule(
                networkRule: NENetworkRule(destinationNetworkEndpoint: endpoint,
                                           prefix: prefix,
                                           protocol: .any),
                action: .filterData
            )
        }

        apply(NEFilterSettings(rules: rules, defaultAction: .filterData)) { error in
            if let error {
                log.error("Döngü içi filtre ayarı uygulanamadı: \(error.localizedDescription, privacy: .public)")
            } else {
                log.info("Döngü içi (loopback) trafik de filtreleniyor")
            }
        }
    }

    override func stopFilter(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        telemetry.close()
        log.info("AegisFirewall durduruldu (reason=\(reason.rawValue))")
        completionHandler()
    }

    // MARK: Decision

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socket = flow as? NEFilterSocketFlow else {
            // Only socket flows exist on macOS (NEFilterBrowserFlow is iOS).
            return .allow()
        }

        let target = resolve(socket)
        if !target.resolved, !warnedAboutEndpoint {
            warnedAboutEndpoint = true
            log.error("Uzak uç nokta henüz çözümlenemedi — yalnızca protokol/port bağımsız kurallar uygulanabilir")
        }

        guard let ruleID = ruleStore.shouldBlock(host: target.host,
                                                 port: target.port,
                                                 proto: target.proto)
        else { return .allow() }

        log.error("ENGELLENDİ: \(target.host, privacy: .public):\(target.port) [\(target.proto, privacy: .public)] kural=\(ruleID, privacy: .public)")
        report(flow: flow, target: target, ruleID: ruleID)
        return .drop()
    }

    // MARK: Endpoint resolution

    struct Target {
        /// Remote host (name or address), empty when the framework did not
        /// expose it yet — rules that name a host then simply cannot match.
        let host: String
        /// Remote port, 0 when unknown.
        let port: Int
        /// "tcp" / "udp", always known from `socketProtocol`.
        let proto: String
        /// False when neither host nor port could be resolved.
        let resolved: Bool
    }

    private func resolve(_ socket: NEFilterSocketFlow) -> Target {
        let proto = socket.socketProtocol == IPPROTO_UDP ? "udp" : "tcp"
        var host = ""
        var port = 0

        if #available(macOS 15.0, *) {
            if let endpoint = socket.remoteFlowEndpoint {
                if case let .hostPort(destination, service) = endpoint {
                    host = "\(destination)"
                    port = Int(service.rawValue)
                } else {
                    host = "\(endpoint)"
                }
            }
        }

        if host.isEmpty, let hostname = socket.remoteHostname {
            host = hostname
        }

        return Target(host: host, port: port, proto: proto,
                      resolved: !host.isEmpty || port > 0)
    }

    // MARK: Reporting

    private func report(flow: NEFilterFlow, target: Target, ruleID: String) {
        var payload: [String: Any] = [
            "v": 1,
            "event": "flow-block",
            "verdict": "deny",
            "host": target.host,
            "port": target.port,
            "proto": target.proto,
            "endpointResolved": target.resolved,
            "rule": ruleID,
            "direction": flow.direction.rawValue
        ]
        if let token = flow.sourceAppAuditToken, token.count >= MemoryLayout<audit_token_t>.size {
            // Copy the bytes out instead of reinterpreting the buffer: `Data`
            // storage is not guaranteed to be aligned for audit_token_t.
            let pid: Int32 = token.withUnsafeBytes { raw -> Int32 in
                var auditToken = audit_token_t()
                withUnsafeMutableBytes(of: &auditToken) { destination in
                    destination.copyBytes(from: raw.prefix(MemoryLayout<audit_token_t>.size))
                }
                return audit_token_to_pid(auditToken)
            }
            payload["sourcePid"] = Int(pid)
        }
        if let url = flow.url {
            payload["url"] = url.absoluteString
        }

        payload["ts"] = Date().formatted(.iso8601)
        payload["source"] = "firewall"
        telemetry.send(payload)
    }
}

// MARK: - Filter activation
//
// The content filter is registered with `NEFilterManager`.  Apple's samples do
// this from the containing app; the extension does it as well so the feature
// works without touching the Electron sources (set AEGIS_SKIP_FILTER_SETUP=1
// when the app takes care of it instead).

enum FilterSettings {
    static func installIfNeeded() {
        // `NEFilterManager.shared()` is re-fetched inside each @Sendable
        // completion handler instead of capturing it across the boundary.
        NEFilterManager.shared().loadFromPreferences { error in
            if let error {
                log.error("Filtre tercihleri okunamadı: \(error.localizedDescription, privacy: .public)")
                return
            }

            let manager = NEFilterManager.shared()
            let configuration = NEFilterProviderConfiguration()
            configuration.filterSockets = true

            let needsUpdate = !manager.isEnabled
                || manager.providerConfiguration?.filterSockets != true
            manager.providerConfiguration = configuration
            manager.isEnabled = true
            manager.localizedDescription = "Aegis Antivirus Güvenlik Duvarı"

            guard needsUpdate else {
                log.info("Filtre zaten etkin")
                return
            }
            manager.saveToPreferences { error in
                if let error {
                    log.error("Filtre etkinleştirilemedi: \(error.localizedDescription, privacy: .public)")
                } else {
                    log.info("İçerik filtresi etkinleştirildi")
                }
            }
        }
    }
}

// MARK: - Entry point
//
// The Xcode target contains this single file, so it owns `main`.  If you add a
// `main.swift` to the target, delete the `@main` attribute below and call
// `AegisFirewallMain.main()` from it instead.

@main
struct AegisFirewallMain {
    static func main() {
        // Required entry point for every Network Extension system extension.
        autoreleasepool {
            NEProvider.startSystemExtensionMode()
        }

        if ProcessInfo.processInfo.environment["AEGIS_SKIP_FILTER_SETUP"] == nil {
            FilterSettings.installIfNeeded()
        }

        dispatchMain()
    }
}
