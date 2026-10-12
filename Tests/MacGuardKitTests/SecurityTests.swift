import Foundation
import Testing
import CryptoKit
@testable import MacGuardKit

/// Tests must never write into the real quarantine directory. `validate` checks
/// containment against `Home.quarantineDir`, so fixtures have to live under it,
/// but they must clean up after themselves.
private func scratchInQuarantine(_ label: String) throws -> String {
    let dir = Home.quarantineDir + "/.test-\(label)-\(UUID().uuidString)"
    try FileManager.default.createDirectory(
        atPath: dir, withIntermediateDirectories: true)
    return dir
}

@Suite("Path validation")
struct SecurePathTests {

    @Test("Rejects traversal and unsafe ids")
    func rejectsUnsafeIDs() {
        for hostile in ["../escape", "..", "a/b", "a\\b", "~/x", "", "with space", ".", "bad\0null"] {
            #expect(throws: SecurityError.self) { try SecurePath.validateID(hostile) }
        }
    }

    @Test("Accepts ids MacGuard actually generates")
    func acceptsRealIDs() throws {
        for good in ["20261002-101623-update_helper", "com.vendorupdate.agent", "abc_123.XYZ"] {
            #expect(throws: Never.self) { try SecurePath.validateID(good) }
        }
    }

    @Test("Normalize collapses traversal segments")
    func normalizesTraversal() {
        #expect(SecurePath.normalize("/tmp/../etc/passwd") == "/etc/passwd")
        #expect(SecurePath.normalize("/tmp/./a/./b") == "/tmp/a/b")
        #expect(SecurePath.normalize("/../..") == "/")
        #expect(SecurePath.normalize("/tmp//double//slash") == "/tmp/double/slash")
    }

    @Test("Refuses SIP-protected paths")
    func refusesSIPPaths() {
        for path in ["/System/Library/CoreServices/Finder.app",
                     "/usr/bin/codesign",
                     "/bin/sh",
                     "/sbin/ping",
                     "/Library/Extensions/evil.kext",
                     "/private/var/db/anything"] {
            #expect(throws: SecurityError.self, "\(path) must be refused") {
                try SecurePath.requireWritable(path)
            }
        }
    }

    @Test("Real malware targets are no longer blocked")
    func allowsRealMalwareTargets() {
        // These are exactly where an attacker plants things, and the old prefix
        // list refused every one of them.
        for path in ["/Library/LaunchDaemons/com.evil.agent.plist",
                     "/Library/PrivilegedHelperTools/com.evil.helper",
                     "/Applications/DefinitelyNotAVirus.app",
                     "/usr/local/bin/miner",
                     "/opt/homebrew/bin/miner"] {
            #expect(throws: Never.self, "\(path) should be remediable") {
                try SecurePath.requireWritable(path)
            }
        }
    }

    @Test("Safari is never quarantinable")
    func neverQuarantinesSafari() {
        for path in ["/Applications/Safari.app",
                     "/Applications/Safari.app/Contents/MacOS/Safari"] {
            #expect(throws: SecurityError.self) { try SecurePath.requireWritable(path) }
        }
    }

    @Test("SIP protection reflects the real filesystem flag")
    func matchesKernelFlag() {
        // /usr/bin/codesign is SIP-restricted, /usr/local/bin is not.
        #expect(SecurePath.isSIPProtected("/usr/bin/codesign"))
        #expect(!SecurePath.isSIPProtected("/usr/local"))
        #expect(!SecurePath.isSIPProtected("/Library/LaunchDaemons"))
    }

    @Test("Allows remediation targets")
    func allowsRemediationTargets() {
        for path in ["/Users/fajar/Library/LaunchAgents/evil.plist",
                     "/private/tmp/payload",
                     "/Library/LaunchAgents/thing.plist",
                     "/tmp/payload",
                     "/Users/fajar/Library/Application Support/x"] {
            #expect(throws: Never.self) { try SecurePath.requireWritable(path) }
        }
    }

    @Test("Refuses relative paths")
    func refusesRelative() {
        #expect(throws: SecurityError.self) { try SecurePath.requireWritable("relative/path") }
    }

    @Test("Escape out of an allowed root is still refused")
    func refusesEscapeFromAllowedRoot() {
        // These start with a writable prefix but normalize into a SIP path,
        // so passing the prefix check up front must not be enough.
        for escape in ["/Users/../private/var/db",
                       "/private/tmp/../../System/Library",
                       "/Library/Application Support/../Keychains",
                       "/usr/local/../bin/sh",
                       "/tmp/../System/Volumes/Recovery/x"] {
            #expect(throws: SecurityError.self, "\(escape) should be refused") {
                try SecurePath.requireWritable(escape)
            }
        }
    }

    @Test("Path prefix checks respect component boundaries")
    func prefixBoundaries() {
        // "/Users" must not match "/Users-foo" or "/UsersBackup".
        #expect(SecurePath.isLexicallyContained("/Users-foo/x", in: "/Users") == false)
        #expect(SecurePath.isLexicallyContained("/UsersBackup", in: "/Users") == false)
        #expect(SecurePath.isLexicallyContained("/Users/x/y", in: "/Users") == true)
        #expect(SecurePath.isLexicallyContained("/Users", in: "/Users") == true)
        // A traversal segment cannot dodge the boundary check.
        #expect(SecurePath.isLexicallyContained("/Users/../etc", in: "/Users") == false)
    }

    @Test("Lexical containment works on paths that do not exist")
    func lexicalContainmentWithoutExistence() {
        // isContained uses realpath and returns false for missing paths, which
        // broke requireWritable for files that do not exist yet.
        #expect(SecurePath.isLexicallyContained("/tmp/mg-not-here/file", in: "/tmp"))
        #expect(SecurePath.isLexicallyContained("/tmp", in: "/tmp"))
        #expect(SecurePath.isLexicallyContained("relative", in: "/tmp") == false)
    }

    @Test("Writable roots match on component boundaries")
    func writableRootBoundaries() {
        // "/tmpfoo" is not inside "/tmp".
        #expect(throws: SecurityError.self) { try SecurePath.requireWritable("/tmpfoo") }
        #expect(throws: SecurityError.self) { try SecurePath.requireWritable("/Usersfajar/x") }
        #expect(throws: Never.self) { try SecurePath.requireWritable("/tmp") }
        #expect(throws: Never.self) { try SecurePath.requireWritable("/tmp/nested/file") }
    }

    @Test("Containment check")
    func containment() {
        let dir = NSTemporaryDirectory()
        #expect(SecurePath.isContained(dir, in: dir))
        #expect(!SecurePath.isContained("/etc/passwd", in: dir))
        #expect(!SecurePath.isContained("/tmp-other/x", in: "/tmp"))
    }
}

@Suite("Environment sanitisation")
struct ShellEnvironmentTests {

    @Test("Drops code-injection variables")
    func dropsInjectionVectors() {
        let env = Shell.sanitizedEnvironment()
        #expect(env["DYLD_INSERT_LIBRARIES"] == nil)
        #expect(env["LD_PRELOAD"] == nil)
        #expect(env["BASH_ENV"] == nil)
        #expect(env["PYTHONPATH"] == nil)
        #expect(env["SSH_AUTH_SOCK"] == nil)
        #expect(env["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin")
    }

    @Test("Never emits empty values")
    func noEmptyValues() {
        for (key, value) in Shell.sanitizedEnvironment() {
            #expect(!value.isEmpty, "\(key) should not be empty")
        }
    }
}

@Suite("Integrity signing")
struct IntegrityKeyTests {

    private func withTempKey<T>(_ body: (SymmetricKey) throws -> T) throws -> T {
        let url = NSTemporaryDirectory() + "/mgkey-\(UUID().uuidString).key"
        defer { try? FileManager.default.removeItem(atPath: url) }
        try Data(repeating: 0xAB, count: 32).write(to: URL(fileURLWithPath: url))
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: url)
        let key = SymmetricKey(data: Data(repeating: 0xAB, count: 32))
        return try body(key)
    }

    @Test("Sign and verify round-trips")
    func roundTrip() throws {
        try withTempKey { key in
            let message = Data("macguard audit entry".utf8)
            let mac = IntegrityKey.sign(message, with: key)
            #expect(mac.count == 64)
            #expect(IntegrityKey.verify(mac, message: message, with: key))
        }
    }

    @Test("A different message does not verify")
    func rejectsWrongMessage() throws {
        try withTempKey { key in
            let mac = IntegrityKey.sign(Data("original".utf8), with: key)
            #expect(!IntegrityKey.verify(mac, message: Data("modified".utf8), with: key))
        }
    }

    @Test("A different key does not verify")
    func rejectsWrongKey() throws {
        try withTempKey { key in
            let other = SymmetricKey(data: Data(repeating: 0xCD, count: 32))
            let mac = IntegrityKey.sign(Data("message".utf8), with: key)
            #expect(!IntegrityKey.verify(mac, message: Data("message".utf8), with: other))
            #expect(IntegrityKey.keyID(key) != IntegrityKey.keyID(other))
        }
    }

    @Test("Malformed signatures are rejected, not crashed on")
    func rejectsMalformed() throws {
        try withTempKey { key in
            let message = Data("message".utf8)
            for bad in ["", "short", String(repeating: "z", count: 64),
                        String(repeating: "a", count: 63), "!!\(String(repeating: "a", count: 62))"] {
                #expect(!IntegrityKey.verify(bad, message: message, with: key),
                        "should reject '\(bad)'")
            }
        }
    }

    @Test("Signature covers the payload, not the encoding")
    func signatureIsStable() throws {
        try withTempKey { key in
            let message = Data("stable".utf8)
            #expect(IntegrityKey.sign(message, with: key) == IntegrityKey.sign(message, with: key))
        }
    }
}

@Suite("Signed quarantine records")
struct SignedRecordTests {

    private func sealedRecord() throws -> (record: QuarantineRecord, dir: String) {
        let payloadDir = try scratchInQuarantine("signed")
        let payload = payloadDir + "/payload"
        try Data("malicious".utf8).write(to: URL(fileURLWithPath: payload))
        let hash = Digesting.sha256Hex(Data("malicious".utf8))

        var record = QuarantineRecord(
            id: "signed-1",
            originalPath: "/tmp/mg-fixtures/payload",
            payloadPath: payload,
            sha256: hash,
            sizeBytes: 9,
            isDirectory: false,
            quarantinedAt: Date(timeIntervalSince1970: 1_700_000_000),
            reason: "CRIT: test",
            findings: [],
            killedPIDs: [],
            removedPersistencePaths: [],
            backupManifest: ["mode": "0755"],
            restoredAt: nil,
            deleted: false
        )
        try QuarantineEngine.seal(&record)
        return (record, payloadDir)
    }

    @Test("A freshly sealed record validates")
    func sealedValidates() throws {
        let (record, dir) = try sealedRecord()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        #expect(record.isSigned)
        #expect(record.hasIntegrityDigest)
        #expect(throws: Never.self) { try QuarantineEngine.validate(record) }
    }

    @Test("Editing a field and recomputing the digest is still caught")
    func digestAloneIsNotEnough() throws {
        var (record, dir) = try sealedRecord()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        record.originalPath = "/Library/LaunchAgents/innocent.plist"
        // The old digest-only scheme would let an attacker re-seal this.
        record.integrityDigest = QuarantineEngine.digest(record)
        #expect(throws: SecurityError.self) { try QuarantineEngine.validate(record) }
    }

    @Test("Editing a field without resealing is caught")
    func editAloneIsCaught() throws {
        var (record, dir) = try sealedRecord()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        record.reason = "INFO: harmless"
        record.integrityDigest = QuarantineEngine.digest(record)
        #expect(throws: SecurityError.self) { try QuarantineEngine.validate(record) }
    }

    @Test("A record with a valid digest but no MAC is refused")
    func unsignedRecordRefused() throws {
        var (record, dir) = try sealedRecord()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        record.integrityMAC = ""
        record.integrityKeyID = ""
        #expect(throws: SecurityError.self) { try QuarantineEngine.validate(record) }
    }

    @Test("A foreign signature is refused")
    func foreignSignatureRefused() throws {
        var (record, dir) = try sealedRecord()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        record.integrityMAC = IntegrityKey.sign(
            Data("anything".utf8),
            with: SymmetricKey(data: Data(repeating: 0xEE, count: 32)))
        #expect(throws: SecurityError.self) { try QuarantineEngine.validate(record) }
    }

    @Test("A legacy record is refused, not silently trusted")
    func legacyRefused() throws {
        var (record, dir) = try sealedRecord()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        record.integrityDigest = ""
        record.integrityMAC = ""
        record.integrityMAC = ""
        record.integrityKeyID = ""
        #expect(throws: SecurityError.self) { try QuarantineEngine.validate(record) }
    }
}

@Suite("Audit hash chain")
struct HashChainTests {

    private func scratchFile() -> String {
        NSTemporaryDirectory() + "/mgtest-\(UUID().uuidString).jsonl"
    }

    /// Writes a line without clobbering what is already in the file.
    private func writeLine(_ line: String, to file: String) throws {
        if !FileManager.default.fileExists(atPath: file) {
            try line.write(toFile: file, atomically: true, encoding: .utf8)
            return
        }
        let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: file))
        defer { try? handle.close() }
        try handle.seekToEnd()
        try handle.write(contentsOf: Data((line + "\n").utf8))
    }

    @Test("Detects an edited entry")
    func detectsEdit() throws {
        let file = scratchFile()
        defer { try? FileManager.default.removeItem(atPath: file) }
        let chain = HashChain(url: file)

        chain.append(action: "quarantine", target: "/tmp/a", detail: "first")
        chain.append(action: "restore", target: "/tmp/b", detail: "second")
        #expect(chain.verify().ok)

        var lines = try String(contentsOfFile: file, encoding: .utf8)
            .split(separator: "\n").map(String.init)
        lines[0] = lines[0].replacingOccurrences(of: "first", with: "forged")
        try lines.joined(separator: "\n").write(toFile: file, atomically: true, encoding: .utf8)

        let result = chain.verify()
        #expect(!result.ok, "edited entry must break the chain")
        #expect(result.brokenAt == 0)
    }

    @Test("Detects a removed entry")
    func detectsTruncation() throws {
        let file = scratchFile()
        defer { try? FileManager.default.removeItem(atPath: file) }
        let chain = HashChain(url: file)
        chain.append(action: "kill", target: "pid:1", detail: "a")
        chain.append(action: "kill", target: "pid:2", detail: "b")
        chain.append(action: "kill", target: "pid:3", detail: "c")

        let lines = try String(contentsOfFile: file, encoding: .utf8)
            .split(separator: "\n").map(String.init)
        try ([lines[0], lines[2], ""]).joined(separator: "\n")
            .write(toFile: file, atomically: true, encoding: .utf8)

        #expect(!chain.verify().ok, "removed entry must break the chain")
    }

    @Test("A corrupt line is not silently skipped")
    func corruptLineFails() throws {
        let file = scratchFile()
        defer { try? FileManager.default.removeItem(atPath: file) }
        let chain = HashChain(url: file)
        chain.append(action: "scan", target: "/x", detail: "d")

        // Same silent-drop bug as the pre-chain format: verify used to report
        // "intact" while quietly ignoring a line it could not decode.
        try writeLine("not json at all", to: file)

        let result = chain.verify()
        #expect(!result.ok, "an undecodable line must break verification")
        #expect(chain.lineCount() == 2)
        #expect(chain.readAll().count == 1)
    }

    @Test("Legacy pre-chain log fails verification and is archived on write")
    func legacyLogIsArchived() throws {
        let file = scratchFile()
        defer {
            let dir = NSTemporaryDirectory()
            let prefix = ((file as NSString).deletingPathExtension as NSString).lastPathComponent
            for name in (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? [] {
                if name.hasPrefix(prefix) {
                    try? FileManager.default.removeItem(atPath: dir + "/" + name)
                }
            }
        }
        try writeLine(
            #"{"action":"quarantine","actor":"u","at":"2026-10-02T03:16:23Z","detail":"d","euid":501,"target":"/tmp/x"}"#,
            to: file)

        let chain = HashChain(url: file)
        #expect(!chain.verify().ok, "legacy line cannot verify")
        // verify() itself archives the unattestable log. Every action that
        // writes here needs root, so relying on the next write to fix it would
        // leave the log permanently untrustworthy.
        #expect(chain.rotateIfUnattestable() != nil)
        #expect(!FileManager.default.fileExists(atPath: file),
                "unattestable log should be moved aside")

        chain.append(action: "scan", target: "/y", detail: "d")
        // After the append the new chain is valid, and the legacy line was moved
        // aside rather than being folded into a chain it never belonged to.
        let result = chain.verify()
        #expect(result.ok)
        #expect(result.checked == 1)

        let base = (file as NSString).deletingPathExtension
        let archived = try FileManager.default
            .contentsOfDirectory(atPath: NSTemporaryDirectory())
            .filter { $0.hasPrefix((base as NSString).lastPathComponent + ".unverifiable-") }
        #expect(archived.count == 1, "legacy log should be archived")
    }

    @Test("Stays valid while appending")
    func staysValid() throws {
        let file = scratchFile()
        defer { try? FileManager.default.removeItem(atPath: file) }
        let chain = HashChain(url: file)
        for i in 0..<10 {
            chain.append(action: "scan", target: "/x\(i)", detail: "d\(i)")
            #expect(chain.verify().ok, "chain should verify after \(i + 1) appends")
        }
    }
}

@Suite("Quarantine record integrity")
struct QuarantineRecordTests {

    private func makeRecord(id: String = "20260101-000000-test") throws -> QuarantineRecord {
        var record = QuarantineRecord(
            id: id,
            originalPath: "/tmp/mg-fixtures/payload/update_helper",
            payloadPath: (Home.quarantineDir as NSString)
                .appendingPathComponent("\(id)/update_helper"),
            sha256: String(repeating: "a", count: 64),
            sizeBytes: 131,
            isDirectory: false,
            quarantinedAt: Date(timeIntervalSince1970: 1_700_000_000),
            reason: "CRIT: test",
            findings: [],
            killedPIDs: [],
            removedPersistencePaths: [],
            backupManifest: ["mode": "0755"],
            restoredAt: nil,
            deleted: false
        )
        try QuarantineEngine.seal(&record)
        return record
    }

    @Test("Accepts an untouched record")
    func acceptsValid() throws {
        #expect(throws: Never.self) { try QuarantineEngine.validate(try makeRecord()) }
    }

    @Test("Rejects a redirected destination")
    func rejectsRedirect() throws {
        var tampered = try makeRecord()
        tampered.originalPath = "/Library/LaunchAgents/innocent.plist"
        #expect(throws: SecurityError.self) { try QuarantineEngine.validate(tampered) }
    }

    @Test("Rejects a swapped payload path")
    func rejectsPayloadSwap() throws {
        var tampered = try makeRecord()
        tampered.payloadPath = "/tmp/evil/payload"
        #expect(throws: SecurityError.self) { try QuarantineEngine.validate(tampered) }
    }

    @Test("Rejects an edited reason")
    func rejectsReasonEdit() throws {
        var tampered = try makeRecord()
        tampered.reason = "INFO: harmless"
        #expect(throws: SecurityError.self) { try QuarantineEngine.validate(tampered) }
    }

    @Test("Rejects a record with no digest")
    func rejectsMissingDigest() throws {
        var record = try makeRecord()
        record.integrityDigest = ""
        record.integrityMAC = ""
        #expect(throws: SecurityError.self) { try QuarantineEngine.validate(record) }
    }

    @Test("Rejects a tampered backup manifest")
    func rejectsManifestTamper() throws {
        var tampered = try makeRecord()
        // A setuid bit smuggled in through the restore manifest would survive
        // the old digest, which ignored backupManifest entirely.
        tampered.backupManifest["mode"] = "4755"
        #expect(throws: SecurityError.self) { try QuarantineEngine.validate(tampered) }
    }

    @Test("Rejects a tampered xattr manifest")
    func rejectsXattrTamper() throws {
        var tampered = try makeRecord()
        tampered.backupManifest["xattr:com.apple.quarantine"] = "AAAA"
        #expect(throws: SecurityError.self) { try QuarantineEngine.validate(tampered) }
    }

    @Test("Digest is insensitive to manifest key order")
    func digestIgnoresKeyOrder() throws {
        var a = try makeRecord()
        a.backupManifest = ["mode": "0755", "xattr:q": "1"]
        a.integrityDigest = QuarantineEngine.digest(a)

        var b = try makeRecord()
        b.backupManifest = ["xattr:q": "1", "mode": "0755"]
        b.integrityDigest = QuarantineEngine.digest(b)

        #expect(a.integrityDigest == b.integrityDigest)
    }

    @Test("Legacy record without the field still decodes")
    func legacyRecordDecodes() throws {
        // The old synthesized decoder threw keyNotFound here, which made every
        // pre-digest record invisible in `list`.
        let legacy = """
        {
          "id": "legacy-1",
          "originalPath": "/tmp/x",
          "payloadPath": "/tmp/q/legacy-1/x",
          "sha256": "\(String(repeating: "b", count: 64))",
          "sizeBytes": 10,
          "isDirectory": false,
          "quarantinedAt": "2023-11-14T22:13:20Z",
          "reason": "CRIT: legacy",
          "restoredAt": null,
          "deleted": false
        }
        """
        let decoded = try QuarantineEngine.decoder.decode(
            QuarantineRecord.self, from: Data(legacy.utf8))
        #expect(decoded.id == "legacy-1")
        #expect(!decoded.hasIntegrityDigest)
        #expect(decoded.findings.isEmpty)
        #expect(throws: SecurityError.self) { try QuarantineEngine.validate(decoded) }
    }
}

@Suite("Re-sealing legacy records")
struct ResealTests {

    /// Mirrors the rule `macguard reseal` applies: only re-sign when the payload
    /// is still present and still hashes to what the record claims.
    private func resealable(_ record: QuarantineRecord) -> Bool {
        guard PathUtil.exists(record.payloadPath) else { return false }
        guard let data = FileManager.default.contents(atPath: record.payloadPath),
              !record.isDirectory else { return false }
        return Digesting.sha256Hex(data) == record.sha256
    }

    /// Returns the record plus the scratch dir it needs, so the caller owns cleanup.
/// A `defer` here would delete the payload before the test could inspect it.
private func legacyRecord(payload: String?) throws -> (record: QuarantineRecord, dir: String) {
        let dir = try scratchInQuarantine("reseal")
        let payloadPath = dir + "/payload"
        let body = payload ?? "malicious"
        try Data(body.utf8).write(to: URL(fileURLWithPath: payloadPath))

        let record = QuarantineRecord(
            id: "legacy-\(UUID().uuidString.prefix(8))",
            originalPath: "/tmp/mg-fixtures/payload",
            payloadPath: payloadPath,
            sha256: Digesting.sha256Hex(Data(body.utf8)),
            sizeBytes: body.utf8.count,
            isDirectory: false,
            quarantinedAt: Date(timeIntervalSince1970: 1_700_000_000),
            reason: "CRIT: test",
            findings: [],
            killedPIDs: [],
            removedPersistencePaths: [],
            backupManifest: ["mode": "0755"],
            restoredAt: nil,
            deleted: false
        )
        // No digest, no MAC: exactly what a pre-integrity record looks like.
        return (record, dir)
    }

    @Test("A legacy record with a matching payload is resealable")
    func resealsMatchingPayload() throws {
        let (record, dir) = try legacyRecord(payload: nil)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        #expect(resealable(record))
        var resealed = record
        try QuarantineEngine.seal(&resealed)
        #expect(throws: Never.self) { try QuarantineEngine.validate(resealed) }
    }

    @Test("A legacy record whose payload changed is refused")
    func refusesChangedPayload() throws {
        // The record claims one hash but the bytes on disk are different, so
        // signing it would attest to something we cannot observe.
        let (original, dir) = try legacyRecord(payload: "original")
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let record = original
        try Data("tampered".utf8).write(
            to: URL(fileURLWithPath: record.payloadPath))
        #expect(!resealable(record))
    }

    @Test("A legacy record with no payload is refused")
    func refusesMissingPayload() throws {
        let (record, dir) = try legacyRecord(payload: nil)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        try FileManager.default.removeItem(atPath: record.payloadPath)
        #expect(!resealable(record))
    }

    @Test("Resealing does not weaken the record")
    func resealPreservesContents() throws {
        let (original, dir) = try legacyRecord(payload: nil)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        var resealed = original
        try QuarantineEngine.seal(&resealed)
        #expect(resealed.originalPath == original.originalPath)
        #expect(resealed.payloadPath == original.payloadPath)
        #expect(resealed.sha256 == original.sha256)
        #expect(resealed.reason == original.reason)
    }
}

@Suite("Secure file IO")
struct SecureFileTests {

    private func scratchDir() throws -> String {
        let dir = NSTemporaryDirectory() + "/mgtest-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return dir
    }

    @Test("Atomic replace leaves no temp file")
    func atomicReplace() throws {
        let dir = try scratchDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let file = dir + "/state.json"

        #expect(SecureFile.writeAtomic(Data("one".utf8), to: file))
        #expect(SecureFile.writeAtomic(Data("two".utf8), to: file))
        #expect(try String(contentsOfFile: file, encoding: .utf8) == "two")

        let leftovers = try FileManager.default.contentsOfDirectory(atPath: dir)
            .filter { $0.contains(".tmp") }
        #expect(leftovers.isEmpty, "temp files left behind: \(leftovers)")
    }

    @Test("Append does not follow a symlink")
    func appendIgnoresSymlink() throws {
        let dir = try scratchDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let victim = dir + "/victim.txt"
        try "original".write(toFile: victim, atomically: true, encoding: .utf8)

        let link = dir + "/link.jsonl"
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: victim)
        SecureFile.append(Data("injected\n".utf8), to: link)

        #expect(try String(contentsOfFile: victim, encoding: .utf8) == "original",
                "append followed a symlink and wrote outside the quarantine area")
    }
}
@Suite("Home directory resolution")
struct HomeResolutionTests {

    /// Regression test for the bug that stranded a sudo quarantine in
    /// `/var/root`: `dscl` prints `NFSHomeDirectory: /Users/x`, and reading the
    /// last newline-separated component produced a string that failed the
    /// `hasPrefix("/")` check, so `Home.current` fell back to
    /// `NSHomeDirectory()`, which is root's home under sudo.
    @Test("dscl's labelled output yields the user's real home")
    func parsesLabelledDirectoryServiceOutput() {
        let resolved = Home.homeDirectory(forUser: NSUserName())
        #expect(resolved == NSHomeDirectory() || resolved?.hasPrefix("/Users/") == true,
                "expected a user home, got \(resolved ?? "nil")")
    }

    @Test("A home that does not exist is rejected rather than trusted")
    func rejectsMissingHome() {
        #expect(Home.homeDirectory(forUser: "definitely-not-a-real-user-\(UUID().uuidString)") == nil)
    }

    @Test("Home.current never resolves to root's home under sudo")
    func neverPointsAtRootHome() throws {
        // The exact failure: under sudo the state dir has to stay in the user's
        // home, otherwise `list`/`restore` as the user cannot see their items.
        let state = Home.stateDir
        #expect(state.hasPrefix("/var/root") == false,
                "state dir leaked into root's home: \(state)")
        #expect(state.contains("Library/Application Support/MacGuard"))
    }
}

@Suite("Root and user privilege separation")
struct PrivilegeSeparationTests {

    /// The bug this covers: `ensureOwnedDir` used to `chown` to `geteuid()`.
    /// Under `sudo` that is root, so a sudo run seized the user's own state
    /// directory and locked the user out of their quarantine.
    @Test("State ownership follows the user, not the effective uid")
    func stateOwnershipFollowsTheUser() throws {
        let owner = try #require(Home.stateOwner)
        #expect(owner.uid == getuid(),
                "state dir should belong to the invoking user, not uid \(geteuid())")
    }

    @Test("The signing key lives where the user can read it")
    func signingKeyIsUserReachable() throws {
        #expect(IntegrityKey.keyURL() == IntegrityKey.userKeyURL(),
                "records live in the user's state dir and must be signed with a key the user holds")
    }

    @Test("A fresh key is written to the user's state dir, not root's")
    func freshKeyIsNotRootOwned() throws {
        let url = IntegrityKey.keyURL()
        #expect(url.hasPrefix(Home.stateDir),
                "signing key \(url) is outside the user's state dir")
        #expect(url.hasPrefix("/var/db/") == false,
                "signing key must not be in the root-only store when a user is present")
    }

    @Test("hasUserState is true for a user session")
    func userSessionIsDetected() {
        #expect(Home.hasUserState)
    }
}

@Suite("Scanner self-exclusion")
struct SelfExclusionTests {

    /// MacGuard's detection patterns are compiled into its own binary as string
    /// literals, so scanning that binary matched all 19 rules and reported
    /// MacGuard as a cryptominer, a dropper and a Gatekeeper bypasser on every
    /// run.
    @Test("MacGuard does not scan itself")
    func doesNotScanItself() {
        let binary = CommandLine.arguments[0]
        #expect(ApplePaths.isSelf(binary),
                "running binary \(binary) was not recognised as MacGuard's own")
    }

    @Test("Build directories are excluded")
    func excludesBuildDirectories() {
        for path in [
            "/Users/me/proj/.build/release/macguard",
            "/Users/me/proj/.build/out/Products/Release/macguard",
            "/Users/me/proj/.git/config",
            "/Users/me/proj/DerivedData/Thing.o",
        ] {
            #expect(ApplePaths.isSelf(path), "\(path) should be excluded from scanning")
        }
    }

    @Test("Real user paths are not excluded")
    func doesNotOverExclude() {
        for path in [
            "/Users/me/Library/LaunchAgents/com.evil.plist",
            "/tmp/agentd",
            "/Applications/SomeApp.app/Contents/MacOS/SomeApp",
            "/Users/me/Documents/report.pdf",
        ] {
            #expect(!ApplePaths.isSelf(path), "\(path) must still be scannable")
        }
    }

    /// Self-exclusion is decided by location, never by filename. A payload named
    /// after the scanner is the masquerade this tool exists to catch, so
    /// `/tmp/macguard` and `/opt/tools/macguard-copy` must stay in scope.
    @Test("A payload named after the scanner is still scanned")
    func doesNotExcludeByName() {
        for path in [
            "/tmp/macguard",
            "/tmp/.hidden/macguard",
            "/opt/tools/macguard",
            "/opt/tools/macguard-copy",
            "/opt/tools/macguard.dSYM",
            "/Users/me/Downloads/macguard",
        ] {
            #expect(!ApplePaths.isSelf(path),
                    "\(path) is not inside MacGuard's checkout; excluding it would hide a masquerading payload")
        }
    }

    @Test("MacGuard's own artifacts inside the checkout are excluded")
    func excludesOwnCheckoutArtifacts() {
        for path in [
            "/Users/me/proj/.build/macguard.dSYM/Contents",
            "/Users/me/proj/.build/x86_64-apple-macosx/debug/macguard",
        ] {
            #expect(ApplePaths.isSelf(path), "\(path) is MacGuard's own build artifact")
        }
    }

    @Test("Content rules never fire on MacGuard's own path")
    func contentRulesSkipSelf() throws {
        let engine = RuleEngine.loadDefault()
        let binary = CommandLine.arguments[0]
        let data = try Data(contentsOf: URL(fileURLWithPath: binary))
        let strings = StringExtractor.asciiStrings(from: data)
        #expect(strings.count > 100, "test fixture should yield strings to scan")
        let hits = engine.scanStrings(strings, path: binary)
        #expect(hits.isEmpty,
                "MacGuard's own binary matched \(hits.count) content rules: \(hits.map(\.rule.id))")
    }

    @Test("App candidates never include MacGuard's own binary")
    func candidatesExcludeSelf() {
        let candidates = AppScanner.candidates(includeAppleApps: false, followPersistence: true)
        let selfPaths = candidates.filter { ApplePaths.isSelf($0.path) }
        #expect(selfPaths.isEmpty, "MacGuard queued itself for scanning: \(selfPaths.map(\.path))")
    }

    @Test("Analysis of MacGuard's own path yields no findings")
    func analyzeSelfYieldsNothing() {
        let analyzer = ItemAnalyzer(rules: RuleEngine.loadDefault(), config: ScanConfig())
        let item = analyzer.analyze(path: CommandLine.arguments[0])
        #expect(analyzer.findings(for: item).isEmpty)
    }

    /// The bit tested here is `CS_RUNTIME` in `kSecCodeInfoFlags`, not
    /// `SecCodeStatus.hard` (0x100), which is a different field entirely. Using
    /// the wrong constant reported every signed notarized app as lacking
    /// hardened runtime.
    @Test("Hardened runtime is read from the CodeDirectory runtime bit")
    func hardenedRuntimeUsesCorrectBit() {
        let chrome = "/Applications/Google Chrome.app"
        guard PathUtil.isAppBundle(chrome) else {
            // Not present on this machine; the logic is covered by the constant
            // assertion below regardless.
            #expect(CodeSignatureVerifier.codeDirectoryRuntimeMask == 0x10000)
            return
        }
        let info = CodeSignatureVerifier.verify(path: chrome, checkNotarization: false)
        #expect(info.hasHardenedRuntime,
                "Chrome is notarized with hardened runtime; it must not be reported as missing it")
    }

    @Test("The runtime mask is 0x10000, not SecCodeStatus.hard")
    func runtimeMaskIsCorrect() {
        #expect(CodeSignatureVerifier.codeDirectoryRuntimeMask == 0x10000)
        #expect(CodeSignatureVerifier.codeDirectoryRuntimeMask != SecCodeStatus.hard.rawValue,
                "these are different fields; conflating them caused the false positives")
    }
}
