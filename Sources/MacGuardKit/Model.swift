import Foundation

public enum Severity: Int, Codable, CaseIterable, Comparable, Sendable {
    case info = 0
    case low = 1
    case medium = 2
    case high = 3
    case critical = 4

    public static func < (lhs: Severity, rhs: Severity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    public var label: String {
        switch self {
        case .info: return "INFO"
        case .low: return "LOW"
        case .medium: return "MED"
        case .high: return "HIGH"
        case .critical: return "CRIT"
        }
    }
}

public enum ThreatCategory: String, Codable, CaseIterable, Sendable {
    case persistence
    case loginItem
    case signature
    case notarization
    case process
    case network
    case heuristic
    case signatureDB
    case quarantine
    case system

    public var label: String {
        switch self {
        case .persistence: return "PERSISTENCE"
        case .loginItem: return "LOGIN-ITEM"
        case .signature: return "CODE-SIGN"
        case .notarization: return "NOTARIZE"
        case .process: return "PROCESS"
        case .network: return "NETWORK"
        case .heuristic: return "HEURISTIC"
        case .signatureDB: return "MATCH"
        case .quarantine: return "QUARANTINE"
        case .system: return "SYSTEM"
        }
    }
}

public struct Evidence: Codable, Hashable, Sendable {
    public var key: String
    public var value: String

    public init(key: String, value: String) {
        self.key = key
        self.value = value
    }
}

public struct Finding: Codable, Sendable {
    public var id: String
    public var severity: Severity
    public var category: ThreatCategory
    public var title: String
    public var detail: String
    public var path: String?
    public var processName: String?
    public var pid: Int32?
    public var ruleID: String?
    public var remediation: String?
    public var evidence: [Evidence]
    public var sha256: String?
    public var timestamp: Date

    public init(
        id: String,
        severity: Severity,
        category: ThreatCategory,
        title: String,
        detail: String,
        path: String? = nil,
        processName: String? = nil,
        pid: Int32? = nil,
        ruleID: String? = nil,
        remediation: String? = nil,
        evidence: [Evidence] = [],
        sha256: String? = nil,
        timestamp: Date = Date()
    ) {
        self.id = id
        self.severity = severity
        self.category = category
        self.title = title
        self.detail = detail
        self.path = path
        self.processName = processName
        self.pid = pid
        self.ruleID = ruleID
        self.remediation = remediation
        self.evidence = evidence
        self.sha256 = sha256
        self.timestamp = timestamp
    }

    /// Stable identifier derived from the subject + rule, so repeat scans are de-duplicable.
    public static func makeID(subject: String, rule: String) -> String {
        let joined = "\(rule)|\(subject)"
        let digest = Digesting.sha256Hex(Data(joined.utf8))
        return String(digest.prefix(16))
    }
}

public struct ThreatReport: Codable, Sendable {
    public var tool: String = "MacGuard"
    public var version: String = MacGuardVersion.current
    public var host: String
    public var user: String
    public var startedAt: Date
    public var finishedAt: Date
    public var durationSeconds: Double
    public var scopes: [String]
    public var findings: [Finding]
    public var scannedItems: Int
    public var quarantinedCount: Int
    public var baselineApproved: Int

    public init(
        host: String,
        user: String,
        startedAt: Date,
        finishedAt: Date,
        durationSeconds: Double,
        scopes: [String],
        findings: [Finding],
        scannedItems: Int,
        quarantinedCount: Int,
        baselineApproved: Int
    ) {
        self.host = host
        self.user = user
        self.startedAt = startedAt
        self.finishedAt = finishedAt
        self.durationSeconds = durationSeconds
        self.scopes = scopes
        self.findings = findings
        self.scannedItems = scannedItems
        self.quarantinedCount = quarantinedCount
        self.baselineApproved = baselineApproved
    }

    public var counts: [Severity: Int] {
        var out: [Severity: Int] = [:]
        for f in findings { out[f.severity, default: 0] += 1 }
        return out
    }

    public var topSeverity: Severity {
        findings.map(\.severity).max() ?? .info
    }

    public func sortedFindings() -> [Finding] {
        findings.sorted { a, b in
            if a.severity != b.severity { return a.severity > b.severity }
            return (a.path ?? a.processName ?? a.title) < (b.path ?? b.processName ?? b.title)
        }
    }
}

public enum MacGuardVersion {
    public static let current = "1.0.0"
}

public struct QuarantineRecord: Codable, Sendable {
    public var id: String
    public var originalPath: String
    public var payloadPath: String
    public var sha256: String
    public var sizeBytes: Int
    public var isDirectory: Bool
    public var quarantinedAt: Date
    public var reason: String
    public var findings: [Finding]
    public var killedPIDs: [Int32]
    public var removedPersistencePaths: [String]
    public var backupManifest: [String: String]
    public var restoredAt: Date?
    public var deleted: Bool
    /// Digest binding this record to its own contents. Absent on records written
    /// by older versions, which are then treated as unverified.
    public var integrityDigest: String = ""
    /// HMAC over the same bytes as the digest, keyed so it cannot be recomputed
    /// by anyone who can write this file.
    public var integrityMAC: String = ""
    public var integrityKeyID: String = ""

    public var hasIntegrityDigest: Bool { !integrityDigest.isEmpty }
    public var isSigned: Bool { !integrityMAC.isEmpty }

    private enum CodingKeys: String, CodingKey {
        case id, originalPath, payloadPath, sha256, sizeBytes, isDirectory, quarantinedAt
        case reason, findings, killedPIDs, removedPersistencePaths, backupManifest
        case restoredAt, deleted, integrityDigest, integrityMAC, integrityKeyID
    }

    public init(
        id: String,
        originalPath: String,
        payloadPath: String,
        sha256: String,
        sizeBytes: Int,
        isDirectory: Bool,
        quarantinedAt: Date,
        reason: String,
        findings: [Finding],
        killedPIDs: [Int32],
        removedPersistencePaths: [String],
        backupManifest: [String: String],
        restoredAt: Date?,
        deleted: Bool,
        integrityDigest: String = "",
        integrityMAC: String = "",
        integrityKeyID: String = ""
    ) {
        self.id = id
        self.originalPath = originalPath
        self.payloadPath = payloadPath
        self.sha256 = sha256
        self.sizeBytes = sizeBytes
        self.isDirectory = isDirectory
        self.quarantinedAt = quarantinedAt
        self.reason = reason
        self.findings = findings
        self.killedPIDs = killedPIDs
        self.removedPersistencePaths = removedPersistencePaths
        self.backupManifest = backupManifest
        self.restoredAt = restoredAt
        self.deleted = deleted
        self.integrityDigest = integrityDigest
        self.integrityMAC = integrityMAC
        self.integrityKeyID = integrityKeyID
    }

    /// Decoding tolerates records written before `integrityDigest` existed. The
    /// synthesized decoder would throw `keyNotFound` and make those records
    /// vanish entirely, hiding payload that still sits in the quarantine dir.
    /// They decode with an empty digest, which `validate` then refuses.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try container.decode(String.self, forKey: .id)
        self.originalPath = try container.decode(String.self, forKey: .originalPath)
        self.payloadPath = try container.decode(String.self, forKey: .payloadPath)
        self.sha256 = try container.decode(String.self, forKey: .sha256)
        self.sizeBytes = try container.decode(Int.self, forKey: .sizeBytes)
        self.isDirectory = try container.decode(Bool.self, forKey: .isDirectory)
        self.quarantinedAt = try container.decode(Date.self, forKey: .quarantinedAt)
        self.reason = try container.decode(String.self, forKey: .reason)
        self.findings = try container.decodeIfPresent([Finding].self, forKey: .findings) ?? []
        self.killedPIDs = try container.decodeIfPresent([Int32].self, forKey: .killedPIDs) ?? []
        self.removedPersistencePaths = try container
            .decodeIfPresent([String].self, forKey: .removedPersistencePaths) ?? []
        self.backupManifest = try container
            .decodeIfPresent([String: String].self, forKey: .backupManifest) ?? [:]
        self.restoredAt = try container.decodeIfPresent(Date.self, forKey: .restoredAt)
        self.deleted = try container.decodeIfPresent(Bool.self, forKey: .deleted) ?? false
        self.integrityDigest = try container
            .decodeIfPresent(String.self, forKey: .integrityDigest) ?? ""
        self.integrityMAC = try container
            .decodeIfPresent(String.self, forKey: .integrityMAC) ?? ""
        self.integrityKeyID = try container
            .decodeIfPresent(String.self, forKey: .integrityKeyID) ?? ""
    }
}

public struct BaselineEntry: Codable, Sendable {
    public var path: String
    public var sha256: String?
    public var teamID: String?
    public var bundleID: String?
    public var addedAt: Date
    public var note: String?
}

public struct Baseline: Codable, Sendable {
    public var version: Int = 1
    public var createdAt: Date = Date()
    public var entries: [BaselineEntry] = []

    public init() {}
}
