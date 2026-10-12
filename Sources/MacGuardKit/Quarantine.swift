import Foundation

public struct QuarantineOptions {
    public var killProcesses = true
    public var unloadLaunchItems = true
    public var deleteInsteadOfQuarantine = false
    public var dryRun = false
    /// Restore re-registers a launch item with launchd. That re-arms the malware,
    /// so it is opt-in and must be requested explicitly.
    public var reloadAfterRestore = false
    /// Bypass the SIP / writable-root gate. Only for recovering from a mistake.
    public var allowProtectedPath = false

    public init() {}
}

public enum QuarantineError: LocalizedError {
    case notFound(String)
    case alreadyRestored(String)
    case notQuarantined(String)
    case moveFailed(String, String)
    case integrityFailed(String)

    public var errorDescription: String? {
        switch self {
        case .notFound(let id): return "No quarantine record with id \(id)."
        case .alreadyRestored(let id): return "Quarantine record \(id) was already restored."
        case .notQuarantined(let id): return "Quarantine record \(id) has no payload on disk."
        case .moveFailed(let src, let dst): return "Could not move \(src) to \(dst)."
        case .integrityFailed(let detail): return "Refusing to act: \(detail)"
        }
    }
}

public final class QuarantineEngine {
    public init() {}

    public static var recordsDir: String {
        let dir = (Home.quarantineDir as NSString).appendingPathComponent("records")
        try? FileManager.default.createDirectory(
            atPath: dir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        // Same reasoning as `ensureOwnedDir`: created by root under `sudo`, this
        // directory has to end up owned by the user, or the records inside are
        // unreachable from a normal run.
        if let owner = Home.stateOwner {
            chown(dir, owner.uid, owner.gid)
            chmod(dir, 0o700)
        }
        return dir
    }

    private static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        e.dateEncodingStrategy = .iso8601
        return e
    }()

    internal static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()

    // MARK: - Quarantine

    @discardableResult
    public func quarantine(
        path: String,
        reason: String,
        findings: [Finding] = [],
        options: QuarantineOptions = QuarantineOptions()
    ) throws -> QuarantineRecord {
        guard PathUtil.exists(path) else { throw QuarantineError.notFound(path) }

        let expanded = PathUtil.expand(path)
        if !options.dryRun, !options.allowProtectedPath {
            try SecurePath.requireWritable(expanded)
        }
        let stamp = Self.stamp()
        let base = ((expanded as NSString).lastPathComponent as NSString).deletingPathExtension
        let id = "\(stamp)-\(base)"
        let bundleDir = (Home.quarantineDir as NSString).appendingPathComponent(id)
        let payload = (bundleDir as NSString).appendingPathComponent((expanded as NSString).lastPathComponent)

        let isDirectory = PathUtil.isDirectory(expanded)
        let originalMode = PathUtil.posixMode(expanded)
        let originalXattrs = Xattr.list(expanded).filter { $0 != "com.apple.quarantine" }
        let sha = isDirectory ? nil : Digesting.sha256Hex(ofFile: expanded)
        let size = PathUtil.size(expanded)

        var killed: [Int32] = []
        var removedPersistence: [String] = []

        if options.killProcesses {
            let targets = runningProcesses(usingBinaryAt: expanded)
            for target in targets where options.dryRun == false {
                _ = ProcessScanner.killTree(pid: target.pid)
                killed.append(target.pid)
            }
            if !options.dryRun, !killed.isEmpty {
                AuditLog.shared.record(action: "kill", target: expanded, detail: "pids \(killed)")
            }
        }

        let isLaunchItem = Self.isLaunchItem(expanded)
        if options.unloadLaunchItems, isLaunchItem {
            if options.dryRun == false {
                _ = Self.unloadLaunchItem(plist: expanded)
            }
            removedPersistence.append(expanded)
        }

        if options.dryRun {
            return QuarantineRecord(
                id: id,
                originalPath: expanded,
                payloadPath: payload,
                sha256: sha ?? "n/a",
                sizeBytes: size,
                isDirectory: isDirectory,
                quarantinedAt: Date(),
                reason: reason,
                findings: findings,
                killedPIDs: killed,
                removedPersistencePaths: removedPersistence,
                backupManifest: [:],
                restoredAt: nil,
                deleted: false
            )
        }

        if options.deleteInsteadOfQuarantine {
            try? FileManager.default.removeItem(atPath: expanded)
            AuditLog.shared.record(action: "delete", target: expanded, detail: reason)
        } else {
            try FileManager.default.createDirectory(atPath: bundleDir, withIntermediateDirectories: true)
            do {
                try FileManager.default.moveItem(atPath: expanded, toPath: payload)
            } catch {
                // Cross-volume move: copy then remove.
                do {
                    try FileManager.default.copyItem(atPath: expanded, toPath: payload)
                    try FileManager.default.removeItem(atPath: expanded)
                } catch {
                    throw QuarantineError.moveFailed(expanded, payload)
                }
            }

            // Under sudo the payload is root-owned, so the unprivileged user
            // cannot chmod it back and re-run it.
            if geteuid() == 0 { SecureFile.lockDown(payload, mode: 0o000, uid: 0, gid: 0) }
            SecureFile.lockDown(bundleDir, mode: 0o700, uid: geteuid() == 0 ? 0 : geteuid(), gid: geteuid() == 0 ? 0 : getgid())
            // Lock the payload down so it cannot be executed by accident.
            try? FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: payload)
            for xattr in originalXattrs {
                let value = Xattr.read(payload, xattr) ?? ""
                _ = Xattr.write(payload, xattr, value)
            }
            AuditLog.shared.record(action: "quarantine", target: expanded, detail: reason)
        }

        var record = QuarantineRecord(
            id: id,
            originalPath: expanded,
            payloadPath: options.deleteInsteadOfQuarantine ? "" : payload,
            sha256: sha ?? "n/a",
            sizeBytes: size,
            isDirectory: isDirectory,
            quarantinedAt: Date(),
            reason: reason,
            findings: findings,
            killedPIDs: killed,
            removedPersistencePaths: removedPersistence,
            backupManifest: ["mode": originalMode],
            restoredAt: nil,
            deleted: options.deleteInsteadOfQuarantine
        )
        try Self.seal(&record)
        try Self.saveRecord(record)

        // The payload moved before the record was written. If we cannot persist a
        // verifiable record, that is unrecoverable state: the file is in
        // quarantine with no signed trail. Say so instead of returning success.
        guard PathUtil.exists(record.payloadPath) else {
            throw SecurityError.integrityMismatch(
                "\(record.originalPath) is in quarantine but its record could not be written")
        }
        return record
    }

    // MARK: - Restore

    @discardableResult
    public func restore(id: String, options: QuarantineOptions = QuarantineOptions()) throws -> QuarantineRecord {
        var record = try load(id: id)
        guard record.restoredAt == nil else { throw QuarantineError.alreadyRestored(id) }
        guard !record.deleted else { throw QuarantineError.notQuarantined(id) }

        let destination = record.originalPath
        if !options.dryRun, !options.allowProtectedPath {
            try SecurePath.requireWritable(destination)
        }

        if record.payloadPath.isEmpty || !PathUtil.exists(record.payloadPath) {
            throw QuarantineError.notQuarantined(id)
        }

        // A payload that was replaced inside the quarantine area would be
        // re-introduced (and re-armed) under the guise of a restore.
        if record.sha256 != "n/a", !record.isDirectory,
           let current = Digesting.sha256Hex(ofFile: record.payloadPath),
           current != record.sha256 {
            throw QuarantineError.integrityFailed(
                "\(PathUtil.contractHome(record.payloadPath)) no longer matches the hash recorded at quarantine time"
            )
        }

        if !options.dryRun {
            do {
                try FileManager.default.moveItem(atPath: record.payloadPath, toPath: destination)
            } catch {
                try FileManager.default.copyItem(atPath: record.payloadPath, toPath: destination)
                try? FileManager.default.removeItem(atPath: record.payloadPath)
            }
            if let mode = record.backupManifest["mode"], let value = UInt32(mode, radix: 8) {
                try? FileManager.default.setAttributes([.posixPermissions: value], ofItemAtPath: destination)
            }
            for (name, value) in record.backupManifest where name != "mode" {
                _ = Xattr.write(destination, name, value)
            }
            // Only re-register with launchd when explicitly asked. A restored
            // LaunchAgent starts running again the moment it is bootstrapped.
            if Self.isLaunchItem(destination) {
                if options.reloadAfterRestore {
                    _ = Self.loadLaunchItem(plist: destination)
                } else {
                    AuditLog.shared.record(
                        action: "restore-inert",
                        target: destination,
                        detail: "restored but not loaded — pass --reload to re-register with launchd"
                    )
                }
            }
            AuditLog.shared.record(action: "restore", target: destination, detail: "from quarantine \(id)")
        }

        record.restoredAt = Date()
        try save(record)
        try? FileManager.default.removeItem(atPath: (Home.quarantineDir as NSString).appendingPathComponent(id))
        try? FileManager.default.removeItem(atPath: (Self.recordsDir as NSString).appendingPathComponent("\(id).json"))
        return record
    }

public func purge(id: String) throws {
        var record = try load(id: id)
        if !record.payloadPath.isEmpty, PathUtil.exists(record.payloadPath) {
            // The payload may be root-owned with mode 000, so confirm we can
            // actually reach it before touching anything on disk.
            let parent = (record.payloadPath as NSString).deletingLastPathComponent
            if let owner = PathUtil.uid(parent), owner != geteuid(), geteuid() != 0 {
                throw QuarantineError.integrityFailed("quarantine area is not owned by the current user")
            }
            try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: record.payloadPath)
            try? FileManager.default.removeItem(atPath: record.payloadPath)
            AuditLog.shared.record(action: "purge", target: record.originalPath, detail: "permanently deleted from quarantine")
        }
        try? FileManager.default.removeItem(atPath: (Home.quarantineDir as NSString).appendingPathComponent(id))
        record.deleted = true
        try save(record)
    }

    public func list() -> [QuarantineRecord] {
        let files = (try? FileManager.default.contentsOfDirectory(atPath: Self.recordsDir)) ?? []
        return files
            .filter { $0.hasSuffix(".json") }
            .compactMap { file -> QuarantineRecord? in
                let url = URL(fileURLWithPath: (Self.recordsDir as NSString).appendingPathComponent(file))
                guard let data = try? Data(contentsOf: url),
                      let record = try? Self.decoder.decode(QuarantineRecord.self, from: data)
                else { return nil }
                return record
            }
            .sorted { $0.quarantinedAt > $1.quarantinedAt }
    }

    /// Digest over every field that decides what a restore does, including the
    /// mode/xattr manifest that gets applied back onto the restored file.
    /// Editing any of them invalidates it, so a modified record cannot redirect
    /// a restore or smuggle in a setuid bit or extra attribute.
    static func digest(_ record: QuarantineRecord) -> String {
        Digesting.sha256Hex(signingPayload(record))
    }

    /// Canonical bytes the record's signature covers. The digest is computed over
    /// these too, so the signature cannot be made to cover different bytes than
    /// the digest does.
    private static func signingPayload(_ record: QuarantineRecord) -> Data {
        let canonical = [
            record.id,
            record.originalPath,
            record.payloadPath,
            record.sha256,
            String(record.sizeBytes),
            String(record.isDirectory),
            ISO8601DateFormatter().string(from: record.quarantinedAt),
            record.reason,
            record.killedPIDs.map(String.init).joined(separator: ","),
            record.removedPersistencePaths.joined(separator: ","),
            // Sorted so dictionary iteration order cannot change the digest.
            record.backupManifest.keys.sorted().map { "\($0)=\(record.backupManifest[$0] ?? "")" }
                .joined(separator: ","),
        ].joined(separator: "\u{1F}")
        return Data(canonical.utf8)
    }

    /// Stamps the record with its digest and an HMAC over the same bytes. Without
    /// the MAC the digest is self-certifying only: anyone able to write the
    /// record can edit it and recompute the digest.
    public static func seal(_ record: inout QuarantineRecord) throws {
        record.integrityDigest = digest(record)
        let key = try IntegrityKey.load()
        record.integrityMAC = IntegrityKey.sign(signingPayload(record), with: key)
        record.integrityKeyID = IntegrityKey.keyID(key)
    }

    public static func validate(_ record: QuarantineRecord) throws {
        guard record.hasIntegrityDigest else {
            throw SecurityError.recordTampered("\(record.id) predates integrity records and cannot be verified")
        }
        guard digest(record) == record.integrityDigest else {
            throw SecurityError.recordTampered("\(record.id) was modified after it was written")
        }
        // The payload must stay inside the quarantine dir. Without this, a
        // rewritten record could point restore at any file it can read.
        // Lexical, not canonical: a purged record has no payload left, and the
        // digest already binds payloadPath.
        guard SecurePath.isLexicallyContained(record.payloadPath, in: Home.quarantineDir) else {
            throw SecurityError.recordTampered("\(record.id) points outside the quarantine directory")
        }
        // The signature is what makes the digest trustworthy. Without a valid MAC
        // anyone able to write this file could edit a field and recompute the
        // digest to match.
        guard !record.integrityMAC.isEmpty else {
            throw SecurityError.recordTampered("\(record.id) is not signed")
        }
        let mac = record.integrityMAC
        guard let key = IntegrityKey.key(forID: record.integrityKeyID) else {
            throw SecurityError.recordTampered(
                "\(record.id) was signed with a key this machine no longer has")
        }
        guard IntegrityKey.verify(mac, message: signingPayload(record), with: key) else {
            throw SecurityError.recordTampered("\(record.id) signature does not match its contents")
        }
    }

    /// Loads a record and refuses it unless the id is safe to use as a filename,
    /// the record matches that id, and its digest still checks out.
    public func load(id: String) throws -> QuarantineRecord {
        try SecurePath.validateID(id)
        let url = URL(fileURLWithPath: (Self.recordsDir as NSString).appendingPathComponent("\(id).json"))
        guard let data = try? Data(contentsOf: url),
              let record = try? Self.decoder.decode(QuarantineRecord.self, from: data)
        else { throw QuarantineError.notFound(id) }
        guard record.id == id else {
            throw SecurityError.recordTampered("id mismatch: file says \(record.id), requested \(id)")
        }
        try Self.validate(record)
        return record
    }

    /// Writes a record atomically. Static so quarantine and reseal share one path.
    public static func saveRecord(_ record: QuarantineRecord) throws {
        try SecurePath.validateID(record.id)
        let path = (Self.recordsDir as NSString).appendingPathComponent("\(record.id).json")
        let data = try Self.encoder.encode(record)
        guard SecureFile.writeAtomic(data, to: path, mode: 0o600) else {
            throw QuarantineError.moveFailed(path, "could not write record")
        }
        // Records belong to the user whose state dir they live in. Written under
        // `sudo` they would otherwise stay root-owned and mode 0600, so the
        // user could neither list nor restore their own quarantined items.
        if let owner = Home.stateOwner {
            SecureFile.lockDown(path, mode: 0o600, uid: owner.uid, gid: owner.gid)
        }
    }

    public func save(_ record: QuarantineRecord) throws {
        try Self.saveRecord(record)
    }

    // MARK: - Helpers

    public func runningProcesses(usingBinaryAt path: String) -> [ProcInfo] {
        let target = (path as NSString).resolvingSymlinksInPath
        return ProcessScanner.allProcesses().filter { proc in
            guard let exe = proc.path else { return false }
            return exe == target || exe == path
        }
    }

    public static func isLaunchItem(_ path: String) -> Bool {
        let name = path.lowercased()
        guard name.hasSuffix(".plist") else { return false }
        return name.contains("launchagents") || name.contains("launchdaemons")
    }

    /// Validates a plist `Label` before it is interpolated into a `domain/label`
    /// target. launchctl parses that string itself, so an untrusted label could
    /// escape the intended domain or address an unrelated service.
    private static func sanitizeLaunchLabel(_ raw: String) -> String? {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        guard !raw.isEmpty, raw.count <= 255 else { return nil }
        guard raw.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { return nil }
        guard !raw.hasPrefix("."), !raw.hasPrefix("-") else { return nil }
        return raw
    }

    /// Label declared inside a launch plist, which is what launchctl addresses a
    /// service by. Falls back to the filename when the plist cannot be read or
    /// declares a label that would be unsafe as a service target.
    public static func launchLabel(plist: String) -> String {
        guard let data = FileManager.default.contents(atPath: plist),
              let dict = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
              let raw = dict["Label"] as? String,
              let label = sanitizeLaunchLabel(raw)
        else { return (plist as NSString).deletingPathExtension }
        return label
    }

    /// UID of the account whose GUI domain we manage. Under `sudo` the effective
    /// UID is 0, so `getuid()` would target `gui/0` and miss the real user's
    /// session. `SUDO_UID` identifies the invoking user instead.
    private static func guiUID() -> Int {
        if geteuid() == 0, let raw = ProcessInfo.processInfo.environment["SUDO_UID"],
           let uid = Int(raw), uid > 0 {
            return uid
        }
        return Int(getuid())
    }

    private static func launchDomain(for plist: String) -> String {
        plist.contains("LaunchDaemons") ? "system" : "gui/\(guiUID())"
    }

    /// `bootout` needs the service target as `domain/label`. Passing a plist path
    /// there makes launchctl fail to resolve the target, and the legacy `unload`
    /// fallback then tears down far more than the intended job.
    public static func unloadLaunchItem(plist: String) -> Bool {
        guard let launchctl = Shell.which("launchctl") else { return false }
        let target = "\(launchDomain(for: plist))/\(launchLabel(plist: plist))"
        let bootout = Shell.run(launchctl, ["bootout", target], timeout: 10)
        return bootout.succeeded
    }

    public static func loadLaunchItem(plist: String) -> Bool {
        guard let launchctl = Shell.which("launchctl") else { return false }
        let plistPath = SecurePath.stripTrailingSlash(plist)
        return Shell.run(launchctl, ["bootstrap", launchDomain(for: plistPath), plistPath], timeout: 10).succeeded
    }

    private static func stamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter.string(from: Date())
    }
}
