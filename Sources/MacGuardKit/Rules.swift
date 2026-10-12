import Foundation

public enum RuleScope: String, Codable, CaseIterable, Sendable {
    /// Match against the filesystem path of the item.
    case path
    /// Match against printable strings extracted from the item's bytes.
    case content
    /// Match against `name:path:args` of a running process.
    case process
    /// Match against Info.plist keys/values of an app bundle.
    case bundleInfo
}

public struct ScanRule: Codable, Sendable {
    public var id: String
    public var title: String
    public var severity: Severity
    public var category: ThreatCategory
    public var scope: RuleScope
    public var regex: String?
    public var literals: [String]?
    public var remediation: String?
    /// When set, the rule only applies to paths under these prefixes.
    public var pathPrefixes: [String]?
    /// Ignore matches inside Apple's own directories (platform binaries, system apps).
    public var ignoreApplePaths: Bool?

    public var detail: String {
        "Rule \(id) matched during \(scope.rawValue) analysis."
    }

    public init(
        id: String,
        title: String,
        severity: Severity,
        category: ThreatCategory,
        scope: RuleScope,
        regex: String? = nil,
        literals: [String]? = nil,
        remediation: String? = nil,
        pathPrefixes: [String]? = nil,
        ignoreApplePaths: Bool? = false
    ) {
        self.id = id
        self.title = title
        self.severity = severity
        self.category = category
        self.scope = scope
        self.regex = regex
        self.literals = literals
        self.remediation = remediation
        self.pathPrefixes = pathPrefixes
        self.ignoreApplePaths = ignoreApplePaths
    }
}

public struct RuleMatch: Sendable {
    public var rule: ScanRule
    public var evidenceKey: String
    public var evidenceValue: String
}

public struct CompiledRule: Sendable {
    public var rule: ScanRule
    var regex: NSRegularExpression?
    var literalNeedles: [String] = []
}

extension ScanRule {
    var compiled: CompiledRule {
        var copy = CompiledRule(rule: self)
        if let pattern = regex {
            copy.regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
        }
        if let literals = literals {
            copy.literalNeedles = literals.map { $0.lowercased() }
        }
        return copy
    }
}

public final class RuleEngine: @unchecked Sendable {
    public let rules: [CompiledRule]
    private let lock = NSLock()

    public init(rules: [ScanRule]) {
        self.rules = rules.map { $0.compiled }
    }

    /// Built-in detection rules. User rules from ~/.macguard/rules.json are merged on top.
    public static func loadDefault(extraRulesFrom path: String? = nil) -> RuleEngine {
        var all = DefaultRules.rules
        if let path, let data = FileManager.default.contents(atPath: path),
           let userRules = try? JSONDecoder().decode([ScanRule].self, from: data) {
            let userIDs = Set(userRules.map(\.id))
            all.removeAll { userIDs.contains($0.id) }
            all.append(contentsOf: userRules)
        }
        return RuleEngine(rules: all)
    }

    public func scanPath(_ path: String) -> [RuleMatch] {
        guard !ApplePaths.isSelf(path) else { return [] }
        lock.lock(); defer { lock.unlock() }
        var out: [RuleMatch] = []
        for compiled in rules where compiled.rule.scope == .path {
            guard passes(compiled.rule, for: path) else { continue }
            if let hit = match(compiled, haystack: path) {
                out.append(hit)
            }
        }
        return out
    }

    public func scanStrings(_ strings: [String], path: String) -> [RuleMatch] {
        // The haystack comes from the file itself, so self-exclusion has to be
        // checked here as well: every content pattern is a literal inside
        // MacGuard's own binary.
        guard !ApplePaths.isSelf(path) else { return [] }
        lock.lock(); defer { lock.unlock() }
        var out: [RuleMatch] = []
        for compiled in rules where compiled.rule.scope == .content {
            guard passes(compiled.rule, for: path) else { continue }
            for string in strings {
                if let hit = match(compiled, haystack: string) {
                    out.append(hit)
                    break
                }
            }
        }
        return out
    }

    public func scanProcess(name: String, path: String?, args: [String]) -> [RuleMatch] {
        if let path, ApplePaths.isSelf(path) { return [] }
        lock.lock(); defer { lock.unlock() }
        var out: [RuleMatch] = []
        var haystacks: [String] = [name]
        if !args.isEmpty { haystacks.append(args.joined(separator: " ")) }
        if let path, !path.isEmpty { haystacks.append(path) }
        for compiled in rules where compiled.rule.scope == .process {
            for haystack in haystacks where !haystack.isEmpty {
                if let prefixes = compiled.rule.pathPrefixes, !prefixes.isEmpty {
                    guard let path, prefixes.contains(where: { path.hasPrefix($0) }) else { continue }
                }
                if let hit = match(compiled, haystack: haystack) {
                    out.append(hit)
                    break
                }
            }
        }
        return out
    }

    public func scanBundleInfo(_ dict: [String: Any], path: String) -> [RuleMatch] {
        guard !ApplePaths.isSelf(path) else { return [] }
        lock.lock(); defer { lock.unlock() }
        var out: [RuleMatch] = []
        let flat = dict.map { "\($0.key)=\($0.value)" }.joined(separator: "\n")
        for compiled in rules where compiled.rule.scope == .bundleInfo {
            guard passes(compiled.rule, for: path) else { continue }
            if let hit = match(compiled, haystack: flat) {
                out.append(hit)
            }
        }
        return out
    }

    private func passes(_ rule: ScanRule, for path: String) -> Bool {
        if rule.ignoreApplePaths == true && ApplePaths.isApplePath(path) { return false }
        if let prefixes = rule.pathPrefixes, !prefixes.isEmpty {
            return prefixes.contains { path.hasPrefix($0) }
        }
        return true
    }

    private func match(_ compiled: CompiledRule, haystack: String) -> RuleMatch? {
        if let regex = compiled.regex {
            let range = NSRange(haystack.startIndex..., in: haystack)
            if let m = regex.firstMatch(in: haystack, options: [], range: range),
               let r = Range(m.range, in: haystack) {
                let matched = String(haystack[r])
                return RuleMatch(
                    rule: compiled.rule,
                    evidenceKey: "match",
                    evidenceValue: truncate(matched, limit: 120)
                )
            }
            return nil
        }
        let lower = haystack.lowercased()
        for needle in compiled.literalNeedles where lower.contains(needle) {
            return RuleMatch(rule: compiled.rule, evidenceKey: "match", evidenceValue: needle)
        }
        return nil
    }

    private func truncate(_ s: String, limit: Int) -> String {
        s.count <= limit ? s : String(s.prefix(limit)) + "…"
    }
}

public enum ApplePaths {
    public static let prefixes = [
        "/System/",
        "/System/Volumes/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/libexec/",
        "/usr/lib/",
        "/bin/",
        "/sbin/",
        "/Applications/Safari.app",
        "/System/Applications/",
    ]

    public static func isApplePath(_ path: String) -> Bool {
        prefixes.contains { path.hasPrefix($0) }
    }

    // MARK: - Self-exclusion

    /// Build and source directories of the scanning tool itself.
    ///
    /// Every detection pattern is compiled into MacGuard's own binary as a
    /// string literal, so a content scan of that binary matches all 19 rules and
    /// reports MacGuard as a cryptominer, a dropper, and a Gatekeeper bypasser.
    /// Those findings are always false positives, and worse, they train the user
    /// to ignore real output.
    public static let buildDirectoryNames: Set<String> = [
        ".build", "DerivedData", ".git", ".swiftpm",
    ]

    /// Paths belonging to MacGuard's own checkout, resolved from the running
    /// binary rather than the environment, so it holds even if `HOME` or `PWD`
    /// have been changed.
    public static func ownPaths() -> Set<String> {
        var out: Set<String> = [
            CommandLine.arguments.first ?? "",
            Bundle.main.bundlePath,
        ]
        if let executable = Bundle.main.executablePath {
            out.insert(executable)
        }
        // `/Users/me/proj/.build/release/macguard` → the checkout root is two
        // levels up from the binary's directory.
        let binaryDir = ((executablePath ?? CommandLine.arguments.first ?? "")
        as NSString).deletingLastPathComponent
        out.insert(binaryDir)
        out.insert((binaryDir as NSString).deletingLastPathComponent)
        out.insert(((binaryDir as NSString).deletingLastPathComponent as NSString)
            .deletingLastPathComponent)
        return Set(out.filter { !$0.isEmpty }.map {
            ($0 as NSString).resolvingSymlinksInPath
        })
    }

    private static var executablePath: String? {
        Bundle.main.executablePath ?? CommandLine.arguments.first
    }

    /// True when the path is MacGuard itself or one of its build artifacts.
    ///
    /// Matching is by location, never by filename. A basename check would exempt
    /// `/tmp/macguard` or `/opt/tools/macguard-copy` — and naming a payload after
    /// the scanner is precisely the masquerade this tool exists to catch, so that
    /// exemption would trade a false positive for a blind spot. Everything
    /// MacGuard legitimately scans of itself lives inside its checkout or a
    /// build directory, both of which the location checks below already cover.
    public static func isSelf(_ path: String) -> Bool {
        let resolved = (path as NSString).resolvingSymlinksInPath
        if ownPaths().contains(where: { resolved == $0 || resolved.hasPrefix($0 + "/") }) {
            return true
        }
        // Build output can appear as `.build/out/Products/Release/macguard`
        // while `ownPaths` only holds the `.build/release` symlink.
        return resolved.components(separatedBy: "/").contains { buildDirectoryNames.contains($0) }
    }

    public static func isWritableByUser(_ path: String) -> Bool {
        PathUtil.isWritableByCurrentUser(path)
    }

    /// Paths where unsigned binaries and foreign binaries are normal (dev toolchains,
    /// package managers, caches, editors). Masquerade heuristics skip these.
    public static let developmentPrefixes = [
        "/opt/homebrew/", "/usr/local/", "/opt/local/", "/Users/",
        "/Library/Developer/", "/Applications/Xcode.app", "/node_modules/",
        "/.git/", "/.cargo/", "/.rustup/", "/.npm/", "/.nvm/", "/.pyenv/",
    ]

    public static func isDevelopmentPath(_ path: String) -> Bool {
        if path.hasPrefix("/opt/homebrew/") || path.hasPrefix("/usr/local/") || path.hasPrefix("/opt/local/") {
            return true
        }
        guard let home = ProcessInfo.processInfo.environment["HOME"], path.hasPrefix(home) else {
            return developmentPrefixes.contains { path.hasPrefix($0) && $0.hasPrefix("/Users/") == false }
        }
        let relative = String(path.dropFirst(home.count))
        let devDirs = [
            "/.vscode/extensions", "/.cursor/extensions", "/Library/Caches/", "/.npm/",
            "/.nvm/", "/.pyenv/", "/.cargo/", "/.rustup/", "/go/", "/Library/Application Support/Code/",
        ]
        return devDirs.contains { relative.hasPrefix($0) } || relative.hasPrefix("/.local/")
    }
}

public enum DefaultRules {
    public static let rules: [ScanRule] = contentRules + pathRules + processRules + bundleRules

    static let contentRules: [ScanRule] = [
        ScanRule(
            id: "MAL-CRYPTOMINER-POOL",
            title: "Cryptominer mining pool protocol",
            severity: .critical,
            category: .signatureDB,
            scope: .content,
            literals: ["stratum+tcp://", "stratum+ssl://", "xmrig", "randomx", "cryptonight", "cpuminer", "minerd", "--donate-level", "nicehash", "nanopool.org", "supportxmr.com", "f2pool.com", "2miners.com", "minergate", "unmineable"],
            remediation: "Kill the process and quarantine the binary. Mining software is almost never legitimate on a workstation."
        ),
        ScanRule(
            id: "MAL-DOWNLOAD-EXEC",
            title: "Remote script downloaded and piped into a shell",
            severity: .critical,
            category: .heuristic,
            scope: .content,
            regex: #"(curl|wget)[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|k)?sh"#,
            remediation: "Classic dropper behaviour. Remove the persistence entry and quarantine the installer script."
        ),
        ScanRule(
            id: "MAL-PERSIST-LAUNCHAGENT",
            title: "Script installs a LaunchAgent/Daemon for persistence",
            severity: .high,
            category: .persistence,
            scope: .content,
            literals: ["launchctl load -w", "launchctl bootstrap system", "launchctl bootstrap gui/", "cat > /Library/LaunchDaemons", "cat > ~/Library/LaunchAgents", "defaults write com.apple.launchd"],
            remediation: "Inspect the installer; quarantine if the payload is not a legitimate vendor installer."
        ),
        ScanRule(
            id: "MAL-CREDENTIAL-ACCESS",
            title: "Access to credentials, keychain or SSH private keys",
            severity: .high,
            category: .heuristic,
            scope: .content,
            literals: ["security find-generic-password", "security dump-keychain", "aseutil dumpcreds", "keychain-password", "SecKeychainItemCopyData", "dump-keychain -d"],
            remediation: "Legit apps rarely shell out to `security` with these flags. Treat as possible credential theft."
        ),
        ScanRule(
            id: "MAL-OBFUSCATION",
            title: "Base64 / hex decode-then-execute obfuscation",
            severity: .high,
            category: .heuristic,
            scope: .content,
            regex: #"(base64\s+(-D|--decode)|openssl\s+enc\s+-d|xxd\s+-r)[^\n]{0,120}\|\s*(ba|z)?sh"#,
            remediation: "Obfuscated payload execution is a strong malware indicator."
        ),
        ScanRule(
            id: "MAL-GATEKEEPER-BYPASS",
            title: "Gatekeeper / SIP / FileVault protections being disabled",
            severity: .high,
            category: .system,
            scope: .content,
            literals: ["spctl --master-disable", "spctl --add", "csrutil disable", "csrutil enable --no-internal", "xattr -cr /", "kextutil -b", "nvram boot-args"],
            remediation: "Restore the protections immediately: `sudo spctl --master-enable`, keep SIP enabled."
        ),
        ScanRule(
            id: "MAL-REVERSE-SHELL",
            title: "Reverse shell pattern",
            severity: .critical,
            category: .heuristic,
            scope: .content,
            regex: #"(bash|sh|zsh)\s+-i\s*>&?\s*/dev/tcp/|nc\s+(-e|-c)\s|socat\s+.*exec:"#,
            remediation: "Active intrusion indicator. Isolate the machine and quarantine the process immediately."
        ),
        ScanRule(
            id: "MAL-DYLIB-INJECTION",
            title: "Dynamic library injection at runtime",
            severity: .high,
            category: .heuristic,
            scope: .content,
            literals: ["DYLD_INSERT_LIBRARIES=@executable_path", "DYLD_INSERT_LIBRARIES=/tmp", "DYLD_INSERT_LIBRARIES=$HOME", "DYLD_INSERT_LIBRARIES=@loader_path", "@executable_path/../Library/Frameworks/inject.dylib"],
            remediation: "Injecting libraries into other processes is used for credential theft and hooking."
        ),
        ScanRule(
            id: "MAL-HASH-MASKING",
            title: "Integrity check immediately before execution",
            severity: .medium,
            category: .heuristic,
            scope: .content,
            regex: #"(shasum|sha256sum|md5|openssl\s+dgst)[^\n|;]{0,60}(-|&&|;)[^\n|]{0,40}(curl|wget|bash|sh\s+-c|python\s+-c)"#,
            remediation: "Hash comparison right before execution hides a tampered payload from the user."
        ),
        ScanRule(
            id: "MAL-HISTORY-TAMPER",
            title: "Shell history manipulation",
            severity: .medium,
            category: .heuristic,
            scope: .content,
            literals: ["unset HISTFILE", "unset HISTSIZE", "export HISTFILE=/dev/null", "shred -u", "history -c &&"],
            remediation: "Anti-forensics behaviour."
        ),
        ScanRule(
            id: "MAL-PRIVILEGE-ESCALATION",
            title: "Privilege escalation / sudoers tampering",
            severity: .high,
            category: .system,
            scope: .content,
            literals: ["chmod u+s ", "chmod 4755 ", "echo 'ALL=(ALL)", "echo \"ALL=(ALL)", "visudo -c -f /etc/sudoers", "authorizationdb write system.privilege"],
            remediation: "Verify no unexpected SUID binaries or sudoers drop-ins were added."
        ),
        ScanRule(
            id: "MAL-BROWSER-CREDENTIALS",
            title: "Direct access to browser profile credential stores",
            severity: .high,
            category: .heuristic,
            scope: .content,
            literals: ["SELECT origin_url, username_value, password_value FROM logins", "SELECT * FROM cookies", "sqlite3 ~/Library/Safari/ Cookies.db", "Chrome\\x00Login Data", "Login Data\\x00"],
            remediation: "Infostealer behaviour targeting saved passwords."
        ),
        ScanRule(
            id: "MAL-PACKER-UPX",
            title: "UPX-style packer signature",
            severity: .medium,
            category: .heuristic,
            scope: .content,
            literals: ["UPX!", "This file is packed with the UPX", "$Info: This file is packed"],
            remediation: "Packed payloads are used to hide real code from static inspection."
        ),
    ]

    static let pathRules: [ScanRule] = [
        ScanRule(
            id: "PATH-TEMP-EXEC",
            title: "Executable living in a temporary directory",
            severity: .high,
            category: .heuristic,
            scope: .path,
            remediation: "Legitimate software does not execute from temp dirs. Quarantine the file.",
            pathPrefixes: ["/tmp/", "/var/tmp/", "/private/tmp/", "/private/var/tmp/", "/Users/Shared/"]
        ),
        ScanRule(
            id: "PATH-HIDDEN-HOME",
            title: "Executable hidden inside a dot-directory",
            severity: .medium,
            category: .heuristic,
            scope: .path,
            regex: #"^/Users/[^/]+/\.[^/]+/"#,
            remediation: "Hidden persistence location. Verify what installed it."
        ),
        ScanRule(
            id: "PATH-LAUNCHAGENT-TARGET",
            title: "Executable referenced from a LaunchAgent/Daemon",
            severity: .info,
            category: .persistence,
            scope: .path,
            regex: #"(LaunchAgents|LaunchDaemons)/"#,
            remediation: "Every launch item should have a known vendor and notarized binary."
        ),
    ]

    static let processRules: [ScanRule] = [
        ScanRule(
            id: "PROC-SHELL-AS-APP",
            title: "Shell binary running as a service instead of a real program",
            severity: .high,
            category: .process,
            scope: .process,
            literals: ["/bin/sh -c", "/bin/bash -c", "/bin/zsh -c", "/bin/sh ", "/usr/bin/env sh", "osascript -e"],
            remediation: "A launch item should exec a signed binary, not shell a script string. Verify the vendor."
        ),
        ScanRule(
            id: "PROC-NET-CAT-LISTENER",
            title: "netcat/socat listener",
            severity: .high,
            category: .network,
            scope: .process,
            regex: #"(^|\s)(nc|ncat|netcat|socat)\s+(-l|-e|--listen)"#,
            remediation: "Reverse-shell listener unless you started it yourself."
        ),
    ]

    static let bundleRules: [ScanRule] = [
        ScanRule(
            id: "BUNDLE-HIDDEN-HELPER",
            title: "App bundle installs helpers without a bundle identifier",
            severity: .medium,
            category: .heuristic,
            scope: .bundleInfo,
            literals: ["com.apple.launchservices"],
            remediation: "Inspect LSBackgroundOnly/LSUIElement agents shipped by this bundle."
        ),
    ]
}

public struct HashSignature: Codable, Sendable {
    public var sha256: String
    public var name: String
    public var severity: Severity
    public var category: ThreatCategory
    public var note: String?
}

public struct SignatureDatabase: Codable, Sendable {
    public var version: Int = 1
    public var updatedAt: Date = Date()
    public var malicious: [HashSignature] = []
    public var trustedVendors: [String: [String]] = [:] // teamID -> known bundle id prefixes
}

public final class SignatureDB: @unchecked Sendable {
    public static let shared = SignatureDB()
    private let lock = NSLock()
    private var db: SignatureDatabase

    private init() {
        let url = (Home.stateDir as NSString).appendingPathComponent("signatures.json")
        if let data = FileManager.default.contents(atPath: url),
           let loaded = try? JSONDecoder().decode(SignatureDatabase.self, from: data) {
            db = loaded
        } else {
            db = SignatureDatabase()
        }
    }

    public var database: SignatureDatabase {
        lock.lock(); defer { lock.unlock() }
        return db
    }

    public func lookup(sha256: String) -> HashSignature? {
        lock.lock(); defer { lock.unlock() }
        let needle = sha256.lowercased()
        return db.malicious.first { $0.sha256.lowercased() == needle }
    }

    public func isTrusted(teamID: String?, bundleID: String?) -> Bool {
        guard let teamID else { return false }
        lock.lock(); defer { lock.unlock() }
        guard let prefixes = db.trustedVendors[teamID], let bundleID else { return false }
        return prefixes.contains { bundleID.hasPrefix($0) }
    }

    public func importSignatures(from url: String) throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: url))
        let incoming = try JSONDecoder().decode(SignatureDatabase.self, from: data)
        lock.lock(); defer { lock.unlock() }
        let known = Set(db.malicious.map { $0.sha256.lowercased() })
        db.malicious.append(contentsOf: incoming.malicious.filter { !known.contains($0.sha256.lowercased()) })
        for (team, prefixes) in incoming.trustedVendors {
            db.trustedVendors[team, default: []].append(contentsOf: prefixes)
        }
        db.updatedAt = Date()
        try persistLocked()
    }

    public func add(_ signature: HashSignature) {
        lock.lock(); defer { lock.unlock() }
        db.malicious.append(signature)
        db.updatedAt = Date()
        try? persistLocked()
    }

    public func addTrustedVendor(teamID: String, bundlePrefixes: [String]) {
        lock.lock(); defer { lock.unlock() }
        db.trustedVendors[teamID, default: []].append(contentsOf: bundlePrefixes)
        try? persistLocked()
    }

    private func persistLocked() throws {
        let url = (Home.stateDir as NSString).appendingPathComponent("signatures.json")
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(db).write(to: URL(fileURLWithPath: url))
    }
}

public enum StringExtractor {
    /// Pulls printable ASCII runs out of a binary. This is how we pattern-match
    /// compiled payloads without a full disassembler.
    public static func asciiStrings(from data: Data, minLength: Int = 6, limit: Int = 4000) -> [String] {
        let bytes = [UInt8](data)
        var out: [String] = []
        var current: [UInt8] = []
        current.reserveCapacity(64)

        for byte in bytes {
            if byte >= 0x20, byte <= 0x7E {
                current.append(byte)
                if current.count > 512 {
                    if current.count >= minLength {
                        out.append(String(decoding: current, as: UTF8.self))
                    }
                    current.removeAll(keepingCapacity: true)
                }
            } else {
                if current.count >= minLength {
                    out.append(String(decoding: current, as: UTF8.self))
                    if out.count >= limit { return out }
                }
                current.removeAll(keepingCapacity: true)
            }
        }
        if current.count >= minLength, out.count < limit {
            out.append(String(decoding: current, as: UTF8.self))
        }
        return out
    }

    public static func head(ofFile path: String, maxBytes: Int) -> Data? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        return (try? handle.read(upToCount: maxBytes)) ?? Data()
    }
}

public enum MachOInspector {
    public enum Kind: String, Sendable {
        case machO64 = "Mach-O 64"
        case machO32 = "Mach-O 32"
        case fat = "Universal (fat)"
        case script = "Script"
        case unknown = "Unknown"
    }

    public struct Info {
        public var kind: Kind
        public var isExecutable = false
        public var hasCodeSignature = false
        public var hasEncryptedSegments = false
        public var cputypes: [String] = []
        public var isAppSigned = false
    }

    public static func inspect(path: String, maxBytes: Int = 4 * 1024 * 1024) -> Info {
        var info = Info(kind: .unknown)
        guard let data = StringExtractor.head(ofFile: path, maxBytes: maxBytes), data.count >= 4 else {
            return info
        }
        let magic = data.prefix(4).map { String(format: "%02x", $0) }.joined()

        if let shebang = String(data: data.prefix(80), encoding: .utf8), shebang.hasPrefix("#!") {
            info.kind = .script
            return info
        }

        switch magic {
        case "feedfacf":
            info.kind = .machO64
            info.isExecutable = true
        case "feedface":
            info.kind = .machO32
            info.isExecutable = true
        case "cafebabe", "bebafeca":
            info.kind = .fat
            info.isExecutable = true
        default:
            return info
        }

        info.hasEncryptedSegments = data.range(of: Data([0x21, 0x00, 0x00, 0x21])) != nil && info.kind != .fat
        info.hasCodeSignature = data.range(of: Data([0xC0, 0xFA, 0xED, 0xFE])) != nil || data.range(of: Data([0xFA, 0xED, 0xFE, 0xC0])) != nil
        return info
    }
}
