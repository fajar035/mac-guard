import Foundation

public struct ScanConfig: Codable, Sendable {
    public var minSeverity: Severity = .low
    public var includeAppleBinaries = false
    public var checkNotarization = true
    public var maxBytesPerBinary: Int = 64 * 1024 * 1024
    public var followLaunchAgentTargets = true
    public var maxProcessesDeepScan = 0

    public init() {}
}

public final class ConfigStore {
    public static let shared = ConfigStore()
    private var url: String { (Home.configDir as NSString).appendingPathComponent("config.json") }

    public func load() -> ScanConfig {
        guard let data = FileManager.default.contents(atPath: url),
              let cfg = try? JSONDecoder().decode(ScanConfig.self, from: data)
        else { return ScanConfig() }
        // Clamp anything a hand-edited file could have set to a hostile value:
        // an unbounded byte limit is a memory-exhaustion lever on our own scan.
        var safe = cfg
        safe.maxBytesPerBinary = min(max(cfg.maxBytesPerBinary, 0), 1 << 30)
        return safe
    }

    public func save(_ config: ScanConfig) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(config) {
            _ = SecureFile.writeAtomic(data, to: url, mode: 0o600)
        }
    }
}

public final class AuditLog {
    public static let shared = AuditLog()
    private let chain: HashChain

    private init() {
        chain = HashChain(url: (Home.stateDir as NSString).appendingPathComponent("audit.jsonl"))
    }

    public typealias Entry = HashChain.Entry

    /// Written synchronously and fsynced. An audit entry for a privileged action
    /// must not be lost because the process exits or the machine dies.
    public func record(action: String, target: String, detail: String) {
        chain.append(action: action, target: target, detail: detail)
    }

    public func tail(_ lines: Int) -> [String] {
        chain.tail(lines)
    }

    /// Recomputes the digest chain to prove the log has not been edited.
    public func verify() -> (ok: Bool, checked: Int, brokenAt: Int?) {
        chain.verify()
    }

    /// Total lines on disk, including any that fail to decode.
    public func lineCount() -> Int { chain.lineCount() }

    /// Why the last verification failed, in plain language.
    public func lastVerificationFailure() -> String? { chain.lastVerificationFailure() }

    /// True when every entry is present and correctly signed.
    public func isFullySigned() -> Bool { chain.isFullySigned() }
}
