//
//  AegisShield.swift
//  Aegis Antivirus — Endpoint Security system extension (real-time shield).
//
//  Comments are in English on purpose: only the user facing documentation
//  (native-daemon/README.md) is written in Turkish.
//
//  Target
//  ------
//  macOS System Extension, bundle id `com.aegis.antivirus.shield`,
//  entitlement `com.apple.developer.endpoint-security.client`.
//
//  Hard rules of the Endpoint Security API (do not "simplify" these):
//
//  1. Every AUTH message must be answered exactly once, from inside the
//     handler, before the ES deadline expires.  If we stay silent the calling
//     thread stays blocked in the kernel and the ES subsystem kills this
//     client (default `ES_DEADLINE_MISS_MODE_KILL`).  The response is therefore
//     issued from a `defer` block so no early `return` can skip it.
//  2. `AUTH_OPEN` is the only event that takes a *flags* answer
//     (`es_respond_flags_result`), every other AUTH event takes
//     `es_respond_auth_result`.  Using the wrong call returns
//     `ES_RESPOND_RESULT_ERR_EVENT_TYPE`.
//  3. NOTIFY events are notification only — there is no valid response for
//     them and calling a respond API would fail.
//  4. `es_string_token_t` (and every other pointer inside `es_message_t`)
//     points into the message buffer, which is only alive for the duration of
//     the handler.  Strings are copied out (`esCopyString`) before returning;
//     nothing is freed, the message is owned by the framework.
//

import Foundation
import EndpointSecurity
import Security
import CryptoKit
import Darwin
import os.log

// MARK: - Logging

private let log = Logger(subsystem: "com.aegis.antivirus.shield", category: "endpoint-security")

// MARK: - Well-known locations
//
// The system extension runs as root, the Electron app runs as the logged in
// user, so the exchange directory is a root owned, world readable folder.
// Environment overrides exist for development builds.

enum ShieldPaths {
    /// UNIX domain socket created by the Electron main process (newline JSON).
    /// The app runs as the logged in user and cannot create files in the root
    /// owned exchange folder, so it listens in its own userData folder; that
    /// location is found through `socketCandidates()`.
    static let socket = ProcessInfo.processInfo.environment["AEGIS_IPC_SOCKET"]
        ?? "/Library/Application Support/Aegis/aegis.sock"

    /// Sockets to try, most specific first.  An explicit override is never
    /// second-guessed.
    static func socketCandidates() -> [String] {
        if ProcessInfo.processInfo.environment["AEGIS_IPC_SOCKET"] != nil { return [socket] }
        return [socket] + userGlobCandidates(suffix: "aegis.sock")
    }

    /// Policy file (`shield-policy.json`), optional.
    static let policy = ProcessInfo.processInfo.environment["AEGIS_POLICY"]
        ?? "/Library/Application Support/Aegis/shield-policy.json"

    /// Signature database in the Electron format `{"version":..,"sha256":{hash:name}}`.
    static let signatureDB = ProcessInfo.processInfo.environment["AEGIS_SIGNATURE_DB"]
        ?? "/Library/Application Support/Aegis/signatures/db.json"

    /// Directories that are probed when the canonical file does not exist yet.
    static func userGlobCandidates(suffix: String) -> [String] {
        var candidates: [String] = []
        let fm = FileManager.default
        guard let users = try? fm.contentsOfDirectory(atPath: "/Users") else { return candidates }
        for user in users.sorted() {
            let base = "/Users/\(user)/Library/Application Support"
            guard let apps = try? fm.contentsOfDirectory(atPath: base) else { continue }
            for app in apps.sorted() {
                candidates.append("\(base)/\(app)/\(suffix)")
            }
        }
        return candidates
    }
}

// MARK: - Message helpers

/// Copies an `es_string_token_t` out of the message buffer.
///
/// Tokens are *not* NUL terminated (`length` is authoritative) and the buffer
/// dies with the message, so this is the only safe way to keep a string.
/// Returns `nil` when the framework did not carry a value (`data == nil`).
func esCopyString(_ token: es_string_token_t) -> String? {
    guard let data = token.data else { return nil }
    let length: Int = token.length
    guard length > 0 else { return "" }
    return String(decoding: UnsafeRawBufferPointer(start: data, count: length), as: UTF8.self)
}

// MARK: - Policy

/// Runtime policy, loaded from `shield-policy.json`.  Every field has a safe
/// default so a missing file never disables protection silently.
struct ShieldPolicy: Codable {
    /// Master switch for enforcement (telemetry keeps running when false).
    var enabled: Bool
    /// Refuse to run binaries that fail a full code signature validation.
    var denyUnsigned: Bool
    /// Compute SHA-256 of exec targets and consult the signature database.
    var hashing: Bool
    /// Files larger than this are not hashed (keeps us inside the ES deadline).
    var maxHashBytes: Int
    /// Exec targets below these prefixes are always denied.
    var denyPaths: [String]
    /// Exec targets below these prefixes are always allowed (fast path).
    var allowPaths: [String]
    /// Directories that non-root processes may never mutate (create/unlink/
    /// rename/truncate).  Root (installers, `sudo`) is never blocked.
    var protectedPaths: [String]

    static let `default` = ShieldPolicy(
        enabled: true,
        denyUnsigned: false,
        hashing: true,
        maxHashBytes: 16 * 1024 * 1024,
        denyPaths: ["/private/tmp/", "/var/tmp/"],
        allowPaths: [],
        protectedPaths: [
            "/System/",
            "/usr/",
            "/bin/",
            "/sbin/",
            "/etc/",
            "/Library/LaunchDaemons/",
            "/Library/LaunchAgents/",
            "/Library/Preferences/"
        ]
    )

    init(enabled: Bool, denyUnsigned: Bool, hashing: Bool, maxHashBytes: Int,
         denyPaths: [String], allowPaths: [String], protectedPaths: [String]) {
        self.enabled = enabled
        self.denyUnsigned = denyUnsigned
        self.hashing = hashing
        self.maxHashBytes = maxHashBytes
        self.denyPaths = denyPaths
        self.allowPaths = allowPaths
        self.protectedPaths = protectedPaths
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = ShieldPolicy.default
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? d.enabled
        denyUnsigned = try c.decodeIfPresent(Bool.self, forKey: .denyUnsigned) ?? d.denyUnsigned
        hashing = try c.decodeIfPresent(Bool.self, forKey: .hashing) ?? d.hashing
        maxHashBytes = try c.decodeIfPresent(Int.self, forKey: .maxHashBytes) ?? d.maxHashBytes
        denyPaths = try c.decodeIfPresent([String].self, forKey: .denyPaths) ?? d.denyPaths
        allowPaths = try c.decodeIfPresent([String].self, forKey: .allowPaths) ?? d.allowPaths
        protectedPaths = try c.decodeIfPresent([String].self, forKey: .protectedPaths) ?? d.protectedPaths
    }
}

/// Loads the policy and re-reads it when the file changes (at most once every
/// two seconds so exec events never pay for a `stat` storm).
final class PolicyStore {
    private let lock = NSLock()
    private var policy = ShieldPolicy.default
    private var loadedPath: String?
    private var modificationTime: TimeInterval = 0
    private var lastCheck: TimeInterval = 0

    private static let reloadInterval: TimeInterval = 2

    func current() -> ShieldPolicy {
        lock.lock()
        defer { lock.unlock() }
        reloadIfNeeded()
        return policy
    }

    private func reloadIfNeeded() {
        let now = Date().timeIntervalSince1970
        guard now - lastCheck >= Self.reloadInterval else { return }
        lastCheck = now

        for path in candidates() {
            guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
                  let modified = (attributes[.modificationDate] as? Date)?.timeIntervalSince1970
            else { continue }

            if path == loadedPath && modified == modificationTime { return }

            guard let data = FileManager.default.contents(atPath: path),
                  let decoded = try? JSONDecoder().decode(ShieldPolicy.self, from: data)
            else {
                log.error("shield-policy.json okunamadı, varsayılan politika kullanılıyor: \(path, privacy: .public)")
                return
            }

            loadedPath = path
            modificationTime = modified
            policy = decoded
            log.info("Politika yüklendi: \(path, privacy: .public) (enabled=\(decoded.enabled), denyUnsigned=\(decoded.denyUnsigned))")
            return
        }
    }

    private func candidates() -> [String] {
        var list = [ShieldPaths.policy]
        if loadedPath == nil {
            list += ShieldPaths.userGlobCandidates(suffix: "shield-policy.json")
        }
        return list
    }
}

// MARK: - Signature database

/// Reads `signatures/db.json` written by the Electron side:
/// `{"version": "42", "updated": "...", "sha256": {"<hex>": "<name>"}}`.
final class SignatureStore {
    private let lock = NSLock()
    private var hashes: [String: String] = [:]
    private var version: String = "-"
    private var loadedPath: String?
    private var modificationTime: TimeInterval = 0
    private var lastCheck: TimeInterval = 0

    private static let reloadInterval: TimeInterval = 5

    /// Returns the threat name for a lowercase hex digest, if known.
    func threat(sha256: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        reloadIfNeeded()
        return hashes[sha256]
    }

    var databaseVersion: String {
        lock.lock()
        defer { lock.unlock() }
        return version
    }

    var entryCount: Int {
        lock.lock()
        defer { lock.unlock() }
        reloadIfNeeded()
        return hashes.count
    }

    private func reloadIfNeeded() {
        let now = Date().timeIntervalSince1970
        guard now - lastCheck >= Self.reloadInterval else { return }
        lastCheck = now

        for path in candidates() {
            guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
                  let modified = (attributes[.modificationDate] as? Date)?.timeIntervalSince1970
            else { continue }

            if path == loadedPath && modified == modificationTime { return }

            guard let data = FileManager.default.contents(atPath: path) else { continue }
            parse(data: data, path: path, modified: modified)
            return
        }
    }

    private func parse(data: Data, path: String, modified: TimeInterval) {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            log.error("İmza veritabanı çözümlenemedi: \(path, privacy: .public)")
            return
        }
        guard let sha = object["sha256"] as? [String: String] else {
            log.error("İmza veritabanında 'sha256' alanı yok: \(path, privacy: .public)")
            return
        }

        let parsedVersion: String
        if let text = object["version"] as? String {
            parsedVersion = text
        } else if let number = object["version"] as? Int {
            parsedVersion = String(number)
        } else {
            parsedVersion = "-"
        }

        hashes = sha
        version = parsedVersion
        loadedPath = path
        modificationTime = modified
        log.info("İmza veritabanı yüklendi: \(path, privacy: .public) sürüm=\(parsedVersion, privacy: .public) kayıt=\(sha.count)")
    }

    private func candidates() -> [String] {
        var list = [ShieldPaths.signatureDB]
        if loadedPath == nil {
            list += ShieldPaths.userGlobCandidates(suffix: "signatures/db.json")
        }
        return list
    }
}

// MARK: - Code signing / hashing helpers

/// Full static code signature validation through the Security framework.
/// The ES message already carries kernel validated flags; this is the extra
/// "all pages really match" check used for `denyUnsigned` deployments.
enum CodeSignature {
    static func validate(path: String) -> Bool {
        let url = URL(fileURLWithPath: path) as CFURL
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, SecCSFlags(), &staticCode) == errSecSuccess,
              let code = staticCode
        else { return false }

        let flags = SecCSFlags(rawValue:
            kSecCSSigningInformation | kSecCSCheckAllArchitectures | kSecCSStrictValidate)
        return SecStaticCodeCheckValidity(code, flags, nil) == errSecSuccess
    }
}

/// Streaming SHA-256 (never loads the whole file into memory).
enum FileHasher {
    /// Returns a lowercase hex digest, or `nil` when the file is unreadable or
    /// bigger than `limit` bytes (the caller reports the skip).
    static func sha256(path: String, limit: Int) -> String? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }

        var hasher = SHA256()
        var total = 0
        while let chunk = try? handle.read(upToCount: 1 << 20), !chunk.isEmpty {
            hasher.update(data: chunk)
            total += chunk.count
            if total > limit { return nil }
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

/// Small `(path, size, mtime) -> sha256` memoisation.  Repeated execs of the
/// same binary (the common case) then cost one `stat` instead of a full read.
final class HashCache {
    private let lock = NSLock()
    private var storage: [String: String] = [:]
    private let limit = 4096

    func get(_ key: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return storage[key]
    }

    func set(_ key: String, _ value: String) {
        lock.lock()
        defer { lock.unlock() }
        if storage.count >= limit { storage.removeAll(keepingCapacity: true) }
        storage[key] = value
    }
}

// MARK: - IPC
//
// Newline delimited JSON over a UNIX domain socket.  The Electron main
// process is the *server*: it listens on `ShieldPaths.socket`, this extension
// connects as a client.  The link is best effort — when it is down events are
// dropped silently (never blocking or killing the shield) and reconnection is
// retried at most every 5 seconds.

/// `@unchecked Sendable`: every mutable field is confined to `queue`, so the
/// class can safely cross the `DispatchQueue.async` boundary (Swift 6 mode).
final class IPCClient: @unchecked Sendable {
    private let preferredPath: String
    private var path: String
    private let queue = DispatchQueue(label: "com.aegis.antivirus.shield.ipc")
    private var descriptor: Int32 = -1
    private var lastAttempt: TimeInterval = 0
    private let reconnectInterval: TimeInterval = 5

    init(path: String) {
        self.preferredPath = path
        self.path = path
    }

    deinit {
        closeDescriptor()
    }

    /// First candidate socket that exists; the preferred path otherwise.
    private func resolvePath() -> String {
        let candidates = preferredPath == ShieldPaths.socket ? ShieldPaths.socketCandidates() : [preferredPath]
        let fm = FileManager.default
        return candidates.first(where: { fm.fileExists(atPath: $0) }) ?? preferredPath
    }

    /// Encodes `payload` as one newline terminated JSON line and queues it.
    /// Never throws, never blocks the caller: if the link is down the event is
    /// dropped silently.
    func send(_ payload: [String: Any]) {
        guard JSONSerialization.isValidJSONObject(payload),
              var data = try? JSONSerialization.data(withJSONObject: payload)
        else { return }
        data.append(0x0A) // newline delimiter
        let bytes = [UInt8](data)

        queue.async { [self] in
            guard connectIfNeeded() else { return } // silent drop
            emit(bytes)
        }
    }

    func closeDescriptor() {
        queue.sync {
            if descriptor >= 0 {
                Darwin.close(descriptor)
                descriptor = -1
            }
        }
    }

    // MARK: private

    private func connectIfNeeded() -> Bool {
        if descriptor >= 0 { return true }

        let now = Date().timeIntervalSince1970
        guard now - lastAttempt >= reconnectInterval else { return false }
        lastAttempt = now
        path = resolvePath()

        let socketFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketFD >= 0 else { return false }

        // Never die on SIGPIPE when the Electron side goes away mid-write.
        var noSigPipe: Int32 = 1
        setsockopt(socketFD, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe,
                   socklen_t(MemoryLayout<Int32>.size))

        // Bounded write budget so a stalled reader cannot wedge the shield.
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
            dropConnection() // reader went away: drop this event silently
            return
        }
    }

    private func dropConnection() {
        if descriptor >= 0 {
            Darwin.close(descriptor)
            descriptor = -1
        }
        log.debug("IPC bağlantısı kapatıldı, olay sessizce atlanacak")
    }
}

// MARK: - Shield

/// Verdict produced for one event.  `reason` is reported to the Electron UI.
struct ShieldDecision {
    var allowed: Bool
    var reason: String
    var threat: String?

    static let allow = ShieldDecision(allowed: true, reason: "default-allow", threat: nil)
}

final class AegisShield {
    private let ipc: IPCClient
    private let signatures = SignatureStore()
    private let policy = PolicyStore()
    private let hashCache = HashCache()

    private let stateLock = NSLock()
    private var client: OpaquePointer?
    private var running = false

    init(ipcPath: String = ShieldPaths.socket) {
        ipc = IPCClient(path: ipcPath)
    }

    // MARK: Lifecycle

    func start() throws {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard !running else { return }

        var newClient: OpaquePointer?
        let result = es_new_client(&newClient) { [self] client, message in
            handle(client: client, message: message)
        }
        guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let newClient else {
            throw Self.startupError(result)
        }
        client = newClient

        // Subscribed events — every one of them is answered (AUTH) or reported
        // (NOTIFY) inside `handle(client:message:)`.
        let events: [es_event_type_t] = [
            ES_EVENT_TYPE_AUTH_EXEC,     // process execution: the real verdict
            ES_EVENT_TYPE_AUTH_OPEN,     // flags verdict, write opens of protected files
            ES_EVENT_TYPE_AUTH_UNLINK,   // deletion of protected paths
            ES_EVENT_TYPE_AUTH_RENAME,   // rename of protected paths
            ES_EVENT_TYPE_AUTH_CREATE,   // creation inside protected paths
            ES_EVENT_TYPE_AUTH_TRUNCATE, // truncation of protected paths
            ES_EVENT_TYPE_NOTIFY_EXEC    // telemetry only, no response possible
        ]
        let subscription = events.withUnsafeBufferPointer { buffer in
            es_subscribe(newClient, buffer.baseAddress!, UInt32(buffer.count))
        }
        guard subscription == ES_RETURN_SUCCESS else {
            _ = es_delete_client(newClient)
            client = nil
            throw NSError(domain: "com.aegis.antivirus.shield", code: 3,
                          userInfo: [NSLocalizedDescriptionKey: "es_subscribe failed"])
        }

        // Mute our own bundle: without this our logging/IPC file access would
        // feed events back into us and could build a feedback loop.
        let bundlePath = Bundle.main.bundlePath
        _ = es_mute_path(newClient, bundlePath, ES_MUTE_PATH_TYPE_PREFIX)

        // If a release ever makes us miss a deadline, prefer denying the
        // operation over killing the client (macOS 27+).  The symbol only
        // exists in the macOS 27 SDK; builds against an older SDK (e.g. the
        // CI runner) pass `-D AEGIS_PRE_MACOS27_SDK` and keep the default.
        #if !AEGIS_PRE_MACOS27_SDK
        if #available(macOS 27.0, *) {
            _ = es_set_deadline_miss_mode(newClient, ES_DEADLINE_MISS_MODE_FAIL_CLOSED)
        }
        #endif

        running = true
        log.info("AegisShield başladı — \(events.count) olay abonesi, imzaDB=\(self.signatures.databaseVersion, privacy: .public)")
    }

    func stop() {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard running else { return }
        running = false

        if let existing = client {
            // After es_delete_client returns no further handler can run, so the
            // strong capture in the handler block is released here.
            _ = es_delete_client(existing)
            client = nil
        }
        ipc.closeDescriptor()
        log.info("AegisShield durduruldu")
    }

    private static func startupError(_ result: es_new_client_result_t) -> NSError {
        let message: String
        switch result {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            message = "com.apple.developer.endpoint-security.client yetkisi yok"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            message = "TCC / Full Disk Access izni yok (Sistem Ayarları > Gizlilik ve Güvenlik)"
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            message = "root olarak çalışmıyor"
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            message = "Eşzamanlı ES istemcisi sınırına ulaşıldı"
        default:
            message = "es_new_client başarısız (\(result.rawValue))"
        }
        log.error("AegisShield başlatılamadı: \(message, privacy: .public)")
        return NSError(domain: "com.aegis.antivirus.shield", code: Int(result.rawValue),
                       userInfo: [NSLocalizedDescriptionKey: message])
    }

    // MARK: Event handling

    private func handle(client: OpaquePointer, message: UnsafePointer<es_message_t>) {
        // Guarantees exactly one response per AUTH message, whatever happens
        // below.  NOTIFY messages are ignored inside `respond(...)` because
        // they have no valid response.
        var decision = ShieldDecision.allow
        defer { respond(client: client, message: message, decision: decision) }

        let eventType = message.pointee.event_type

        // Other Endpoint Security clients can trigger events in us and vice
        // versa; letting them through breaks the cycle (see ES header notes).
        if message.pointee.process.pointee.is_es_client {
            return
        }

        switch eventType {
        case ES_EVENT_TYPE_AUTH_EXEC:
            decision = evaluateExec(message)
        case ES_EVENT_TYPE_AUTH_OPEN:
            decision = evaluateOpen(message)
        case ES_EVENT_TYPE_AUTH_UNLINK, ES_EVENT_TYPE_AUTH_RENAME,
             ES_EVENT_TYPE_AUTH_CREATE, ES_EVENT_TYPE_AUTH_TRUNCATE:
            decision = evaluateMutation(message)
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            reportExec(message, decision: .allow)
        default:
            break
        }
    }

    /// Issues the response required by `action_type`.
    private func respond(client: OpaquePointer,
                         message: UnsafePointer<es_message_t>,
                         decision: ShieldDecision) {
        switch message.pointee.action_type {
        case ES_ACTION_TYPE_AUTH:
            if message.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN {
                // 0 denies, UInt32.max allows every requested access flag.
                let flags: UInt32 = decision.allowed ? UInt32.max : 0
                _ = es_respond_flags_result(client, message, flags, false)
            } else {
                let verdict = decision.allowed ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY
                _ = es_respond_auth_result(client, message, verdict, false)
            }
            if !decision.allowed {
                log.error("ENGELLENDİ (\(decision.reason, privacy: .public))")
            }
        case ES_ACTION_TYPE_NOTIFY:
            break // notification only — no response API applies
        default:
            break
        }
    }

    // MARK: Evaluation

    private func evaluateExec(_ message: UnsafePointer<es_message_t>) -> ShieldDecision {
        let started = DispatchTime.now().uptimeNanoseconds
        let policy = self.policy.current()
        let target = message.pointee.event.exec.target.pointee
        let path = esCopyString(target.executable.pointee.path) ?? ""
        let signingID = esCopyString(target.signing_id) ?? ""
        let teamID = esCopyString(target.team_id) ?? ""
        let platformBinary = target.is_platform_binary

        var decision = ShieldDecision.allow
        var resolvedDigest: String?
        if !policy.enabled {
            decision.reason = "shield-disabled"
        } else if Self.matches(path, prefixes: policy.allowPaths) {
            decision.reason = "allow-path"
        } else if platformBinary && signingID.hasPrefix("com.apple.") {
            // Fast path: XNU already validated the platform image.  Hashing
            // every Apple binary would blow the ES deadline for no value.
            decision.reason = "platform-binary"
        } else if Self.matches(path, prefixes: policy.denyPaths) {
            decision = ShieldDecision(allowed: false, reason: "deny-path", threat: nil)
        } else {
            let (verdict, digest) = inspectTarget(path: path, policy: policy)
            decision = verdict
            resolvedDigest = digest
        }

        reportExec(message, decision: decision,
                   sha256: resolvedDigest, signingID: signingID, teamID: teamID,
                   platformBinary: platformBinary)

        let elapsedMs = Double(DispatchTime.now().uptimeNanoseconds - started) / 1_000_000
        if elapsedMs > 20 {
            log.warning("exec değerlendirmesi yavaş: \(elapsedMs, format: .fixed(precision: 1)) ms — ES deadline riski")
        }
        return decision
    }

    /// Hash + signature database + optional signature validation.
    /// Returns the verdict plus the digest that was computed (used for reporting).
    private func inspectTarget(path: String, policy: ShieldPolicy) -> (ShieldDecision, String?) {
        var digest: String?
        if policy.hashing {
            digest = hashed(path: path, limit: policy.maxHashBytes)
            if let digest, let threat = signatures.threat(sha256: digest) {
                return (ShieldDecision(allowed: false, reason: "signature-hit", threat: threat), digest)
            }
        }

        if policy.denyUnsigned, !CodeSignature.validate(path: path) {
            return (ShieldDecision(allowed: false, reason: "unsigned-binary", threat: nil), digest)
        }

        return (.allow, digest)
    }

    /// Returns the digest, consulting the `(path,size,mtime)` cache first.
    private func hashed(path: String, limit: Int) -> String? {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
              let size = attributes[.size] as? NSNumber,
              let modified = attributes[.modificationDate] as? Date
        else { return nil }

        let key = "\(path)|\(size.intValue)|\(modified.timeIntervalSince1970)"
        if let cached = hashCache.get(key) { return cached }

        guard let digest = FileHasher.sha256(path: path, limit: limit) else {
            log.debug("hash atlandı (okunamadı veya boyut sınırı): \(path, privacy: .public)")
            return nil
        }
        hashCache.set(key, digest)
        return digest
    }

    private func evaluateOpen(_ message: UnsafePointer<es_message_t>) -> ShieldDecision {
        let policy = self.policy.current()
        guard policy.enabled else { return .allow }

        // `fflag` carries the open flags; only write access matters here.
        let writeRequested = message.pointee.event.open.fflag & O_ACCMODE != O_RDONLY
        let path = esCopyString(message.pointee.event.open.file.pointee.path) ?? ""
        guard writeRequested, !Self.matches(path, prefixes: policy.allowPaths) else { return .allow }

        let uid = audit_token_to_ruid(message.pointee.process.pointee.audit_token)
        guard uid != 0, Self.matches(path, prefixes: policy.protectedPaths) else { return .allow }

        return ShieldDecision(allowed: false, reason: "protected-path-write", threat: nil)
    }

    private func evaluateMutation(_ message: UnsafePointer<es_message_t>) -> ShieldDecision {
        let policy = self.policy.current()
        guard policy.enabled else { return .allow }

        let uid = audit_token_to_ruid(message.pointee.process.pointee.audit_token)
        guard uid != 0 else { return .allow } // root / installers are never blocked

        let path = mutatedPath(message)
        guard !path.isEmpty, Self.matches(path, prefixes: policy.allowPaths) == false,
              Self.matches(path, prefixes: policy.protectedPaths)
        else { return .allow }

        return ShieldDecision(allowed: false, reason: "protected-path-mutation", threat: nil)
    }

    /// Best-effort path extraction for the mutation events we subscribe to.
    private func mutatedPath(_ message: UnsafePointer<es_message_t>) -> String {
        switch message.pointee.event_type {
        case ES_EVENT_TYPE_AUTH_UNLINK:
            return esCopyString(message.pointee.event.unlink.target.pointee.path) ?? ""
        case ES_EVENT_TYPE_AUTH_TRUNCATE:
            return esCopyString(message.pointee.event.truncate.target.pointee.path) ?? ""
        case ES_EVENT_TYPE_AUTH_RENAME:
            let rename = message.pointee.event.rename
            if rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                return esCopyString(rename.destination.existing_file.pointee.path) ?? ""
            }
            let dir = esCopyString(rename.destination.new_path.dir.pointee.path) ?? ""
            let name = esCopyString(rename.destination.new_path.filename) ?? ""
            return dir + "/" + name
        case ES_EVENT_TYPE_AUTH_CREATE:
            let create = message.pointee.event.create
            if create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                return esCopyString(create.destination.existing_file.pointee.path) ?? ""
            }
            let dir = esCopyString(create.destination.new_path.dir.pointee.path) ?? ""
            let name = esCopyString(create.destination.new_path.filename) ?? ""
            return dir + "/" + name
        default:
            return ""
        }
    }

    // MARK: Reporting

    private func reportExec(_ message: UnsafePointer<es_message_t>,
                            decision: ShieldDecision,
                            sha256: String? = nil,
                            signingID: String? = nil,
                            teamID: String? = nil,
                            platformBinary: Bool? = nil) {
        let process = message.pointee.process.pointee
        let target = message.pointee.event.exec.target.pointee
        let path = esCopyString(target.executable.pointee.path) ?? ""
        let cwdToken = message.pointee.event.exec.cwd.pointee.path

        var payload: [String: Any] = [
            "v": 1,
            "event": "exec",
            "verdict": decision.allowed ? "allow" : "deny",
            "reason": decision.reason,
            "pid": Int(audit_token_to_pid(process.audit_token)),
            "ppid": Int(process.ppid),
            "uid": Int(audit_token_to_ruid(process.audit_token)),
            "path": path,
            "args": execArguments(message),
            "cwd": esCopyString(cwdToken) ?? "",
            "signingID": signingID ?? esCopyString(process.signing_id) ?? "",
            "teamID": teamID ?? esCopyString(process.team_id) ?? "",
            "platformBinary": platformBinary ?? target.is_platform_binary
        ]
        if let sha256 { payload["sha256"] = sha256 }
        if let threat = decision.threat { payload["threat"] = threat }

        report(payload)
    }

    private func report(_ payload: [String: Any]) {
        var enriched = payload
        enriched["ts"] = Date().formatted(.iso8601)
        enriched["source"] = "shield"
        ipc.send(enriched)
    }

    /// Copies up to 32 argv entries out of the message.
    private func execArguments(_ message: UnsafePointer<es_message_t>) -> [String] {
        let type = message.pointee.event_type
        guard type == ES_EVENT_TYPE_AUTH_EXEC || type == ES_EVENT_TYPE_NOTIFY_EXEC else { return [] }

        let event = message.pointee.event.exec
        return withUnsafePointer(to: event) { pointer -> [String] in
            let count = es_exec_arg_count(pointer)
            var arguments: [String] = []
            let bounded = min(count, 32)
            arguments.reserveCapacity(Int(bounded))
            for index in 0..<bounded {
                if let value = esCopyString(es_exec_arg(pointer, index)) {
                    arguments.append(value)
                }
            }
            return arguments
        }
    }

    private static func matches(_ path: String, prefixes: [String]) -> Bool {
        guard !prefixes.isEmpty else { return false }
        return prefixes.contains { path.hasPrefix($0) }
    }
}

// MARK: - Signal handling

/// Turns SIGINT/SIGTERM/SIGHUP into a graceful `AegisShield.stop()`.
final class SignalWatcher {
    private var sources: [DispatchSourceSignal] = []

    func start(onSignal handler: @escaping () -> Void) {
        for value in [SIGINT, SIGTERM, SIGHUP] {
            signal(value, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: value, queue: .global())
            source.setEventHandler(handler: handler)
            source.resume()
            sources.append(source)
        }
    }
}

// MARK: - Entry point
//
// The Xcode target contains this single file, so it owns `main`.  If you add a
// `main.swift` to the target, delete the `@main` attribute below and call
// `AegisShieldMain.main()` from it instead.

@main
struct AegisShieldMain {
    static func main() {
        let shield = AegisShield()
        let watcher = SignalWatcher()
        watcher.start {
            shield.stop()
            exit(EXIT_SUCCESS)
        }

        do {
            try shield.start()
        } catch {
            // Startup failures (missing entitlement, missing TCC grant) are
            // fatal: a shield that is not watching is a false sense of safety.
            FileHandle.standardError.write(Data("AegisShield: \(error.localizedDescription)\n".utf8))
            exit(EXIT_FAILURE)
        }

        dispatchMain()
    }
}
