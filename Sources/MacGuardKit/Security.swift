import Foundation
import CryptoKit

public enum SecurityError: LocalizedError {
    case unsafeID(String)
    case protectedPath(String)
    case integrityMismatch(String)
    case recordTampered(String)
    case untrustedBinary(String)
    case notAbsolute(String)

    public var errorDescription: String? {
        switch self {
        case .unsafeID(let id):
            return "Refusing to use malformed quarantine id '\(id)'."
        case .protectedPath(let path):
            return "Refusing to touch macOS-protected path: \(path)"
        case .integrityMismatch(let what):
            return "Integrity check failed for \(what) — it changed while quarantined."
        case .recordTampered(let detail):
            return "Quarantine record failed verification: \(detail)"
        case .untrustedBinary(let path):
            return "Refusing to run \(path): not a root-owned system binary."
        case .notAbsolute(let path):
            return "Path must be absolute: \(path)"
        }
    }
}

/// Path handling for privileged operations. Everything that runs as root has to
/// treat attacker-controlled strings as hostile: no traversal, no symlink
/// pivots, no writes outside a known-safe prefix.
public enum SecurePath {
    /// Paths macOS protects via SIP plus the directories that hold its own
    /// database and policy state. Quarantining any of these bricks the system,
    /// so they are refused outright rather than "handled carefully".
    public static let sipProtectedPrefixes: [String] = [
        "/System",
        "/bin",
        "/sbin",
        "/Library/Extensions",
        "/Library/SystemExtensions",
        "/Library/Keychains",
        "/System/Volumes/Preboot",
        "/System/Volumes/Recovery",
        "/System/Volumes/VM",
        "/System/Volumes/Update",
        "/private/var/db",
        "/private/var/vm",
        "/var/db",
        "/dev",
    ]

    /// Below "/usr" everything Apple ships is SIP-protected, but "/usr/local"
    /// is admin-managed and a normal malware target. Only the shipped subtree is
    /// refused; `SF_RESTRICTED` on the resolved path is checked as well.
    public static let usrShippedPrefixes: [String] = ["/usr"]

    /// `/Applications` is a first-class scan target, but Safari must never be
    /// quarantined.
    public static let neverQuarantineApps: [String] = [
        "/Applications/Safari.app",
        "/Applications/Utilities",
    ]

    /// Prefixes a privileged MacGuard run is allowed to modify at all.
    public static let writableRoots: [String] = [
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/Library/Application Support",
        "/Library/PrivilegedHelperTools",
        "/Applications",
        "/usr/local",
        "/opt/homebrew",
        "/Users",
        "/private/tmp",
        "/private/var/tmp",
        "/tmp",
        "/var/tmp",
    ]

    public static func isSIPProtected(_ path: String) -> Bool {
        let normalized = normalize(path)
        if sipProtectedPrefixes.contains(where: {
            normalized == $0 || normalized.hasPrefix($0 + "/")
        }) {
            return true
        }
        // Under /usr, everything Apple ships is protected but /usr/local is not.
        if usrShippedPrefixes.contains(where: {
            normalized == $0 || normalized.hasPrefix($0 + "/")
        }), !normalized.hasPrefix("/usr/local") {
            return true
        }
        if neverQuarantineApps.contains(where: {
            normalized == $0 || normalized.hasPrefix($0 + "/")
        }) {
            return true
        }
        // Ask the kernel instead of guessing. The hardcoded list above cannot
        // distinguish "/usr" (SIP, untouchable) from "/usr/local" (ordinary
        // admin territory that legitimately hosts malware), and it wrongly
        // covered "/Applications" and "/Library/LaunchDaemons".
        return hasRestrictedFlag(normalized)
    }

    /// `SF_RESTRICTED` is the flag SIP puts on protected files. A path without it
    /// is not SIP-protected, whatever the prefix list claims.
    ///
    /// Resolves symlinks first: `/tmp` is itself a symlink carrying the flag
    /// while `/private/tmp` is ordinary and writable, so testing the literal
    /// path would refuse a directory we are meant to be able to quarantine into.
    private static func hasRestrictedFlag(_ path: String) -> Bool {
        let resolved = canonical(path) ?? path
        var info = stat()
        guard lstat(resolved, &info) == 0 else { return false }
        return (UInt32(info.st_flags) & UInt32(SF_RESTRICTED)) != 0
    }

    /// Lexically resolves `.`/`..` without touching the filesystem. Used so a
    /// traversal attempt is rejected even when the target does not exist yet.
    public static func normalize(_ path: String) -> String {
        let isAbsolute = path.hasPrefix("/")
        var parts: [String] = []
        for component in path.split(separator: "/") {
            switch component {
            case ".":
                continue
            case "..":
                if let last = parts.last, last != ".." {
                    parts.removeLast()
                } else if !isAbsolute {
                    parts.append("..")
                }
            default:
                parts.append(String(component))
            }
        }
        let joined = parts.joined(separator: "/")
        if isAbsolute { return "/" + joined }
        return joined.isEmpty ? "." : joined
    }

    /// Resolves symlinks and normalizes. Returns nil when the path cannot exist.
    public static func canonical(_ path: String) -> String? {
        guard !path.isEmpty else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        guard realpath(path, &buffer) != nil else { return nil }
        return String(cString: buffer)
    }

    /// True when `path` is `root` itself or lives underneath it, compared on
    /// component boundaries after lexical normalization. Works for paths that do
    /// not exist yet, which `isContained` cannot do since `realpath` fails on them.
    public static func isLexicallyContained(_ path: String, in root: String) -> Bool {
        guard path.hasPrefix("/"), root.hasPrefix("/") else { return false }
        let child = normalize(path)
        let base = normalize(root)
        if child == base { return true }
        return child.hasPrefix(base.hasSuffix("/") ? base : base + "/")
    }

    /// True when `path` is `root` itself or lives underneath it. Both sides are
    /// canonicalized first so `/tmp/../etc` cannot pose as `/tmp`, and so a
    /// symlink cannot be used to step outside. Requires both to exist.
    public static func isContained(_ path: String, in root: String) -> Bool {
        guard let child = canonical(path), let base = canonical(root) else { return false }
        if child == base { return true }
        return child.hasPrefix(base.hasSuffix("/") ? base : base + "/")
    }

    /// Gate for any privileged write. Refuses SIP paths, relative paths, and
    /// anything outside the roots MacGuard is meant to remediate.
    public static func requireWritable(_ path: String) throws {
        guard path.hasPrefix("/") else { throw SecurityError.notAbsolute(path) }
        let normalized = normalize(path)
        guard !isSIPProtected(normalized) else { throw SecurityError.protectedPath(normalized) }
        // Compare on component boundaries. A bare hasPrefix would accept
        // "/tmpfoo" as being inside "/tmp".
        guard writableRoots.contains(where: { isLexicallyContained(normalized, in: $0) }) else {
            throw SecurityError.protectedPath(normalized)
        }
    }

    /// Quarantine ids are used to build filesystem paths, so they must never be
    /// able to contain a separator or a traversal segment.
    public static func validateID(_ id: String) throws {
        guard !id.isEmpty, id.count <= 255 else { throw SecurityError.unsafeID(id) }
        let allowed = CharacterSet.alphanumerics
            .union(CharacterSet(charactersIn: "-_."))
        guard id.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            throw SecurityError.unsafeID(id)
        }
        guard id != ".", id != ".." else { throw SecurityError.unsafeID(id) }
    }

    /// Strips a trailing slash so `/foo/bar/` and `/foo/bar` compare equal.
    public static func stripTrailingSlash(_ path: String) -> String {
        var result = path
        while result.count > 1, result.hasSuffix("/") { result.removeLast() }
        return result
    }
}

/// HMAC key used to sign audit entries and quarantine records.
///
/// A bare SHA-256 digest is not tamper-evident against anyone who can write the
/// file: they can edit a record and simply recompute the digest. Signing with a
/// key the caller cannot read turns "self-consistent" into "unforgeable without
/// root", which is the property the audit trail actually needs.
///
/// As root the key lives in `/var/db/macguard`, which no unprivileged process
/// can write. As a normal user it lives in the user state dir, which protects
/// against other accounts but not against that user.
public enum IntegrityKey {
    public static let rootDir = "/var/db/macguard"
    private static let keyName = "integrity.key"

    public enum KeyError: LocalizedError {
        case unavailable(String)

        public var errorDescription: String? {
            switch self {
            case .unavailable(let why): return "Integrity key unavailable: \(why)"
            }
        }
    }

    /// Where the key lives for the current privilege level.
    /// Where the signing key lives.
    ///
    /// This follows the *owner of the state directory*, not the effective UID.
    /// Records and the audit log are written into the user's home even when
    /// MacGuard runs under `sudo`, so keying off `geteuid()` signed them with
    /// the root key — which the user cannot read, leaving their own records
    /// permanently unverifiable from a normal run. A genuine root shell (no
    /// `SUDO_USER`) has no user state dir to sign for, so it uses the root key.
    public static func keyURL() -> String {
        if Home.hasUserState {
            return userKeyURL()
        }
        return (rootDir as NSString).appendingPathComponent(keyName)
    }

    public static func isRootBacked() -> Bool { geteuid() == 0 }

    /// The user's home state dir even when running as root, since that is where
    /// the records actually live.
    static func userKeyURL() -> String {
        (Home.stateDir as NSString).appendingPathComponent(keyName)
    }

    private static func rootKeyURL() -> String {
        (rootDir as NSString).appendingPathComponent(keyName)
    }

    /// Keys we are willing to verify against, newest-privilege first.
    ///
    /// Records live in the user's home directory even when MacGuard runs under
    /// `sudo`, but the signing key path follows the effective UID. So a record
    /// sealed by a user run has to stay verifiable during a root restore, and
    /// vice versa. Verification therefore accepts any key we can actually read,
    /// and refuses anything signed with a key we hold none of.
    public static func trustedKeys() -> [(id: String, key: SymmetricKey)] {
        var out: [(String, SymmetricKey)] = []
        for url in [keyURL(), userKeyURL(), rootKeyURL()] {
            guard let data = FileManager.default.contents(atPath: url), data.count == 32 else {
                continue
            }
            let key = SymmetricKey(data: data)
            let id = keyID(key)
            if out.contains(where: { $0.0 == id }) { continue }
            out.append((id, key))
        }
        return out
    }

    /// Finds the trusted key matching a recorded key id.
    public static func key(forID id: String) -> SymmetricKey? {
        trustedKeys().first { $0.id == id }?.key
    }

    /// Loads the signing key, creating it on first use. Never silently falls back
    /// to an unkeyed mode: an unsigned log must read as unverifiable.
    public static func load() throws -> SymmetricKey {
        let url = keyURL()
        if let data = FileManager.default.contents(atPath: url), data.count == 32 {
            // Refuse a key file anyone but the owner can read or write.
            let mode = PathUtil.posixMode(url)
            guard mode == "0600" else {
                throw KeyError.unavailable("\(url) is mode \(mode), expected 0600")
            }
            return SymmetricKey(data: data)
        }

        let key = SymmetricKey(size: .bits256)
        let data = key.withUnsafeBytes { Data($0) }
        let dir = (url as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: dir)
        guard SecureFile.writeAtomic(data, to: url, mode: 0o600) else {
            throw KeyError.unavailable("could not write \(url)")
        }
        // Hand the key to whoever owns the state dir, not to whoever ran the
        // command. Locking a user key to root under `sudo` makes it unreadable
        // to the very account whose records it signs.
        if let owner = Home.stateOwner {
            SecureFile.lockDown(url, mode: 0o600, uid: owner.uid, gid: owner.gid)
        }
        return key
    }

    /// Key identifier stored alongside each signature so verification can tell
    /// which key was used, and refuse to trust an entry that claims a key we do
    /// not hold.
    public static func keyID(_ key: SymmetricKey) -> String {
        let mac = HMAC<SHA256>.authenticationCode(
            for: Data("macguard-integrity-key-id-v1".utf8), using: key)
        return Digesting.sha256Hex(Data(mac)).prefix(16).description
    }

    public static func sign(_ message: Data, with key: SymmetricKey) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: key)
        return Data(mac).map { String(format: "%02x", $0) }.joined()
    }

    /// Constant-time compare. A plain `==` on hex strings leaks timing, and this
    /// is the check that stands between an attacker and a forged signature.
    public static func verify(_ signature: String, message: Data, with key: SymmetricKey) -> Bool {
        guard let provided = hexBytes(signature) else { return false }
        let expected = sign(message, with: key)
        guard let expectedBytes = hexBytes(expected) else { return false }
        return constantTimeEquals(provided, expectedBytes)
    }

    private static func hexBytes(_ hex: String) -> Data? {
        guard hex.count % 2 == 0 else { return nil }
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        return data
    }

    private static func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for (a, b) in zip(lhs, rhs) { difference |= a ^ b }
        return difference == 0
    }
}

/// Append-only log where every entry commits to the previous one and is signed
/// with a key the caller cannot read. Removing or editing a line breaks the chain
/// from that point on, which is what makes the audit trail tamper-evident rather
/// than merely append-only.
public final class HashChain {
    private let url: String
    private let queue = DispatchQueue(label: "macguard.hashchain")
    private let zeroHash = String(repeating: "0", count: 64)
    /// Why the last `verify` failed, so callers can explain it. nil when the
    /// chain is intact.
    private var lastFailure: String?

    public init(url: String) {
        self.url = url
    }

    public struct Entry: Codable {
        public var at: Date
        public var actor: String
        public var euid: UInt32
        public var action: String
        public var target: String
        public var detail: String
        public var prev: String
        public var hash: String
        /// HMAC over the entry, signed with the integrity key.
        public var mac: String?
        public var keyID: String?

        public init(
            at: Date, actor: String, euid: UInt32, action: String,
            target: String, detail: String, prev: String, hash: String,
            mac: String? = nil, keyID: String? = nil
        ) {
            self.at = at
            self.actor = actor
            self.euid = euid
            self.action = action
            self.target = target
            self.detail = detail
            self.prev = prev
            self.hash = hash
            self.mac = mac
            self.keyID = keyID
        }
    }

    private static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys]
        e.dateEncodingStrategy = .iso8601
        return e
    }()

    private static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()

    /// Canonical bytes an entry's signature covers. Identical fields in the same
    /// order for both signing and verification.
    private static func signingPayload(
        at: Date, actor: String, euid: UInt32,
        action: String, target: String, detail: String,
        prev: String, hash: String
    ) -> Data {
        let canonical = [
            ISO8601DateFormatter().string(from: at),
            actor,
            String(euid),
            action,
            target,
            detail,
            prev,
            hash,
        ].joined(separator: "\u{1F}")
        return Data(canonical.utf8)
    }

    /// Digest over the entry plus the previous hash. The previous hash is inside
    /// the digest, so rewriting history requires recomputing every later line.
    ///
    /// The chain hash keeps the log tamper-evident on its own; the signature is
    /// what stops someone who can write the file from recomputing the chain
    /// after an edit.
    private static func digest(
        at: Date, actor: String, euid: UInt32,
        action: String, target: String, detail: String, prev: String
    ) -> String {
        let canonical = [
            ISO8601DateFormatter().string(from: at),
            actor,
            String(euid),
            action,
            target,
            detail,
            prev,
        ].joined(separator: "\u{1F}")
        return Digesting.sha256Hex(Data(canonical.utf8))
    }

    /// Moves an unverifiable log aside and starts a fresh chain. Pre-chain log
    /// format cannot be verified, and silently continuing from it would make
    /// the new chain start from a hash that no longer describes the file.
    @discardableResult
    public func rotateIfUndecodable() -> String? {
        let (_, undecodable) = readLines()
        guard !undecodable.isEmpty else { return nil }
        return archiveCurrent()
    }

    /// Archives a log whose entries cannot be attested to: either lines that
    /// fail to decode, or entries written before signing existed.
    @discardableResult
    public func rotateIfUnattestable() -> String? {
        guard signatureProblem(readAll().first ?? Entry(
            at: Date(), actor: "", euid: 0, action: "", target: "",
            detail: "", prev: zeroHash, hash: "")) != nil else { return nil }
        return archiveCurrent()
    }

    private func archiveCurrent() -> String? {
        let stamp = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")
        let archived = (url as NSString)
            .deletingPathExtension + ".unverifiable-\(stamp).jsonl"
        do {
            try FileManager.default.moveItem(atPath: url, toPath: archived)
            return archived
        } catch {
            return nil
        }
    }

    public func append(action: String, target: String, detail: String) {
        queue.sync {
            _ = rotateIfUndecodable()
            let existing = readAll()
            let prev = existing.last?.hash ?? zeroHash
            let at = Date()
            let hash = Self.digest(
                at: at, actor: NSUserName(), euid: geteuid(),
                action: action, target: target, detail: detail, prev: prev
            )

            // An entry we cannot sign is still worth recording, but it must be
            // visibly unsigned so verification reports it rather than trusting
            // a bare hash an attacker could recompute.
            var mac: String?
            var keyID: String?
            if let key = try? IntegrityKey.load() {
                let payload = Self.signingPayload(
                    at: at, actor: NSUserName(), euid: geteuid(),
                    action: action, target: target, detail: detail,
                    prev: prev, hash: hash)
                mac = IntegrityKey.sign(payload, with: key)
                keyID = IntegrityKey.keyID(key)
            }

            let entry = Entry(
                at: at,
                actor: NSUserName(),
                euid: geteuid(),
                action: action,
                target: target,
                detail: detail,
                prev: prev,
                hash: hash,
                mac: mac,
                keyID: keyID
            )
            guard var data = try? Self.encoder.encode(entry) else { return }
            data.append(0x0A)
            SecureFile.append(data, to: url)
        }
    }

    /// Decodes every line, keeping track of any that fail. A line that cannot be
    /// decoded is dropped from the chain but reported, so it can never be
    /// silently ignored while `verify` still claims the log is intact.
    private func readLines() -> (entries: [Entry], undecodable: [Int]) {
        guard let data = FileManager.default.contents(atPath: url),
              let text = String(data: data, encoding: .utf8)
        else { return ([], []) }
        var entries: [Entry] = []
        var undecodable: [Int] = []
        for (index, line) in text.split(separator: "\n").enumerated() {
            if let entry = try? Self.decoder.decode(Entry.self, from: Data(line.utf8)) {
                entries.append(entry)
            } else {
                undecodable.append(index)
            }
        }
        return (entries, undecodable)
    }

    public func readAll() -> [Entry] { readLines().entries }

    /// Number of lines in the file, whether or not they decode.
    public func lineCount() -> Int {
        guard let data = FileManager.default.contents(atPath: url),
              let text = String(data: data, encoding: .utf8)
        else { return 0 }
        return text.split(separator: "\n").count
    }

    /// Recomputes the whole chain and checks every signature. Any edit, deletion or
    /// reorder shows up, as does a line that fails to decode or was signed with a
    /// key we do not hold.
    public func verify() -> (ok: Bool, checked: Int, brokenAt: Int?) {
        let (entries, undecodable) = readLines()
        lastFailure = nil
        if let first = undecodable.first {
            lastFailure = "undecodable line"
            return (false, entries.count, first)
        }
        // Entries written before signing exist as a chain but cannot be
        // attested to. Archive them now rather than on the next write: every
        // action that writes here needs root, so "it will fix itself later"
        // could leave the log permanently untrustworthy.
        if let unsigned = entries.firstIndex(where: { ($0.mac ?? "").isEmpty }) {
            lastFailure = "unsigned entry"
            rotateIfUnattestable()
            return (false, entries.count, unsigned)
        }
        var prev = zeroHash
        for (index, entry) in entries.enumerated() {
            guard entry.prev == prev else {
                return (false, entries.count, index)
            }
            let expected = Self.digest(
                at: entry.at, actor: entry.actor, euid: entry.euid,
                action: entry.action, target: entry.target,
                detail: entry.detail, prev: prev
            )
            guard expected == entry.hash else {
                return (false, entries.count, index)
            }
            if let reason = signatureProblem(entry) {
            lastFailure = reason
            // Archive here, not on the next write. A log that fails because it
            // predates the current key can only be superseded by a write, and
            // writes need root — leaving it in place can keep `selfcheck` red
            // indefinitely even though nothing is wrong with the current state.
            rotateIfUnattestable()
            return (false, entries.count, index)
        }
            prev = entry.hash
        }
        return (true, entries.count, nil)
    }

    /// Why an entry's signature cannot be trusted, or nil when it checks out.
    private func signatureProblem(_ entry: Entry) -> String? {
        // An entry with no signature predates signing. Its chain hash still
        // holds, but anyone could have recomputed it, so it is not trusted.
        guard let mac = entry.mac, !mac.isEmpty else { return "unsigned entry" }
        guard let claimedKeyID = entry.keyID, !claimedKeyID.isEmpty else {
            return "signature has no key id"
        }
        guard let key = IntegrityKey.key(forID: claimedKeyID) else {
            return "signed with a key we do not hold"
        }
        let payload = Self.signingPayload(
            at: entry.at, actor: entry.actor, euid: entry.euid,
            action: entry.action, target: entry.target, detail: entry.detail,
            prev: entry.prev, hash: entry.hash)
        guard IntegrityKey.verify(mac, message: payload, with: key) else {
            return "signature does not match its contents"
        }
        return nil
    }

    /// Reason the last `verify` failed, for a human-readable message.
    public func lastVerificationFailure() -> String? { lastFailure }

    /// True when every entry is present and correctly signed.
    public func isFullySigned() -> Bool {
        let (entries, undecodable) = readLines()
        guard undecodable.isEmpty else { return false }
        return entries.allSatisfy { signatureProblem($0) == nil }
    }

    public func tail(_ lines: Int) -> [String] {
        Array(readAll().suffix(lines).map { line in
            "\(ISO8601DateFormatter().string(from: line.at)) [\(line.action)] \(line.target) — \(line.detail)"
        })
    }
}

/// File writes that do not follow symlinks and do not leave a half-written file
/// behind. Used for every piece of state MacGuard will act on later.
public enum SecureFile {
    public static func append(_ data: Data, to path: String) {
        let fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { return }
        defer { close(fd) }
        data.withUnsafeBytes { raw in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return }
            var offset = 0
            while offset < raw.count {
                let written = write(fd, base + offset, raw.count - offset)
                if written <= 0 {
                    if errno == EINTR { continue }
                    break
                }
                offset += written
            }
        }
        // fsync so an audit entry survives a crash or a power loss.
        fsync(fd)
    }

    /// Atomic replace: writes a temp file in the same directory, fsyncs it, then
    /// renames. A crash leaves either the old file or the new one, never a
    /// truncated mix of the two.
    public static func writeAtomic(_ data: Data, to path: String, mode: mode_t = 0o600) -> Bool {
        let dir = (path as NSString).deletingLastPathComponent
        let temp = (dir as NSString).appendingPathComponent(
            ".\((path as NSString).lastPathComponent).\(getpid()).tmp"
        )
        let fd = open(temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode)
        guard fd >= 0 else { return false }

        var ok = true
        data.withUnsafeBytes { raw in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else {
                ok = false
                return
            }
            var offset = 0
            while offset < raw.count {
                let written = write(fd, base + offset, raw.count - offset)
                if written <= 0 {
                    if errno == EINTR { continue }
                    ok = false
                    return
                }
                offset += written
            }
        }
        guard ok, fsync(fd) == 0 else {
            close(fd)
            unlink(temp)
            return false
        }
        // Close exactly once, before the rename. A deferred close could free the
        // descriptor number and let the directory open below reuse it.
        close(fd)
        guard rename(temp, path) == 0 else {
            unlink(temp)
            return false
        }
        // fsync the directory so the rename itself is durable.
        let dirFD = open(dir, O_RDONLY)
        if dirFD >= 0 {
            fsync(dirFD)
            close(dirFD)
        }
        return true
    }

    /// Sets owner/mode without following a symlink at the destination.
    @discardableResult
    public static func lockDown(_ path: String, mode: mode_t, uid: uid_t? = nil, gid: gid_t? = nil) -> Bool {
        if let uid, let gid { chown(path, uid, gid) }
        return chmod(path, mode) == 0
    }
}