import CryptoKit
import Foundation

public enum Digesting {
    public static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// Streaming SHA256 of a file. Reads in 1 MiB chunks so huge binaries stay cheap.
    public static func sha256Hex(ofFile path: String) -> String? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            let chunk: Data?
            if #available(macOS 10.15.4, *) {
                chunk = try? handle.read(upToCount: 1 << 20)
            } else {
                chunk = handle.readData(ofLength: 1 << 20)
            }
            guard let chunk, !chunk.isEmpty else { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

public struct CommandResult {
    public var status: Int32
    public var stdout: String
    public var stderr: String

    public var combined: String { stdout + stderr }
    public var succeeded: Bool { status == 0 }
}

public enum Shell {
    /// Runs an external tool with a timeout; never throws, returns a sentinel result on failure.
    /// Names that must never reach a child process. `DYLD_*` and `LD_*` let an
    /// attacker who controls the environment inject code into every tool we run;
    /// under sudo that would be a local privilege escalation.
    private static let dangerousEnvPrefixes = ["DYLD_", "LD_"]
    private static let dangerousEnvNames: Set<String> = [
        "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "IFS", "CDPATH",
        "PERL5LIB", "PERLLIB", "PYTHONPATH", "PYTHONSTARTUP", "RUBYOPT",
        "GEM_HOME", "GEM_PATH", "NODE_OPTIONS", "NODE_PATH", "SSH_AUTH_SOCK",
    ]

    private static let allowedInheritedEnv: Set<String> = [
        "PATH", "TMPDIR", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM",
    ]

    /// Builds the child environment from scratch. Only a short allowlist of
    /// harmless variables is inherited; everything else is dropped.
    public static func sanitizedEnvironment() -> [String: String] {
        var out: [String: String] = [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "en_US.UTF-8",
        ]
        let source = ProcessInfo.processInfo.environment
        for key in allowedInheritedEnv where key != "PATH" {
            if let value = source[key], !value.isEmpty { out[key] = value }
        }
        for (key, _) in source {
            let upper = key.uppercased()
            if dangerousEnvNames.contains(upper) || dangerousEnvPrefixes.contains(where: { upper.hasPrefix($0) }) {
                out.removeValue(forKey: key)
            }
        }
        return out
    }

    /// When running as root, only execute root-owned binaries in a system
    /// directory. A user-writable `/usr/local/bin/codesign` would otherwise be
    /// executed with root privileges.
    private static func isTrustedWhenPrivileged(_ path: String) -> Bool {
        guard geteuid() == 0 else { return true }
        let trustedPrefixes = ["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/"]
        guard trustedPrefixes.contains(where: { path.hasPrefix($0) }) else { return false }
        return PathUtil.uid(path) == 0 && !PathUtil.isWorldWritable(path)
    }

    @discardableResult
    public static func run(_ launchPath: String, _ args: [String], timeout: TimeInterval = 20) -> CommandResult {
        guard FileManager.default.isExecutableFile(atPath: launchPath) else {
            return CommandResult(status: 127, stdout: "", stderr: "tool not found: \(launchPath)")
        }
        guard isTrustedWhenPrivileged(launchPath) else {
            return CommandResult(status: 126, stdout: "", stderr: "refusing to run untrusted binary as root: \(launchPath)")
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = args
        process.environment = sanitizedEnvironment()
        process.currentDirectoryURL = URL(fileURLWithPath: "/")

        let out = Pipe()
        let err = Pipe()
        process.standardOutput = out
        process.standardError = err

        do {
            try process.run()
        } catch {
            return CommandResult(status: 126, stdout: "", stderr: error.localizedDescription)
        }
        let childPID = process.processIdentifier
        // New process group, so a timeout kills the whole job rather than
        // leaving orphaned grandchildren behind.
        setpgid(childPID, childPID)

        // Drain asynchronously so a full pipe buffer can never deadlock the child.
        var outData = Data()
        var errData = Data()
        let group = DispatchGroup()
        let queue = DispatchQueue(label: "macguard.shell.io", attributes: .concurrent)
        group.enter()
        queue.async {
            outData = out.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        group.enter()
        queue.async {
            errData = err.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }

        let deadline = DispatchTime.now() + timeout
        if group.wait(timeout: deadline) == .timedOut {
            kill(-childPID, SIGTERM)
            _ = group.wait(timeout: .now() + 1)
            kill(-childPID, SIGKILL)
            process.terminate()
            _ = group.wait(timeout: .now() + 1)
            return CommandResult(status: 124, stdout: "", stderr: "timeout after \(Int(timeout))s")
        }
        process.waitUntilExit()
        return CommandResult(
            status: process.terminationStatus,
            stdout: String(decoding: outData, as: UTF8.self),
            stderr: String(decoding: errData, as: UTF8.self)
        )
    }

    /// Locates a system tool, honouring both the normal and sbin paths.
    public static func which(_ tool: String) -> String? {
        let candidates = [
            "/usr/bin/\(tool)", "/bin/\(tool)", "/usr/sbin/\(tool)", "/sbin/\(tool)",
            "/usr/local/bin/\(tool)", "/opt/homebrew/bin/\(tool)",
        ]
        for path in candidates where FileManager.default.isExecutableFile(atPath: path) {
            return path
        }
        return nil
    }
}

public enum PathUtil {
    public static let fm = FileManager.default

    public static func exists(_ path: String) -> Bool {
        fm.fileExists(atPath: path)
    }

    public static func isDirectory(_ path: String) -> Bool {
        var isDir: ObjCBool = false
        let found = fm.fileExists(atPath: path, isDirectory: &isDir)
        return found && isDir.boolValue
    }

    /// Total size of a file, or of every file under a directory. A plain file
    /// reports its own size; the previous version returned 0 for single files
    /// because `enumerator(atPath:)` succeeds but yields no entries.
    public static func size(_ path: String) -> Int {
        guard !isDirectory(path) else {
            var total = 0
            guard let enumerator = fm.enumerator(atPath: path) else {
                return (try? fm.attributesOfItem(atPath: path))?[.size] as? Int ?? 0
            }
            for case let rel as String in enumerator {
                let full = (path as NSString).appendingPathComponent(rel)
                let attrs = try? fm.attributesOfItem(atPath: full)
                total += (attrs?[.size] as? NSNumber)?.intValue ?? 0
            }
            return total
        }
        return (try? fm.attributesOfItem(atPath: path))?[.size] as? Int ?? 0
    }

    public static func mtime(_ path: String) -> Date? {
        let attrs = try? fm.attributesOfItem(atPath: path)
        return attrs?[.modificationDate] as? Date
    }

    /// True when the file (or its parent directory) is writable by the current user.
    public static func isWritableByCurrentUser(_ path: String) -> Bool {
        if fm.isWritableFile(atPath: path) { return true }
        let parent = (path as NSString).deletingLastPathComponent
        return fm.isWritableFile(atPath: parent)
    }

    /// True when the on-disk mode grants group/other write, i.e. anyone can tamper.
    public static func isWorldWritable(_ path: String) -> Bool {
        let attrs = try? fm.attributesOfItem(atPath: path)
        guard let perms = attrs?[.posixPermissions] as? NSNumber else { return false }
        return perms.uint16Value & 0o002 != 0
    }

    public static func posixMode(_ path: String) -> String {
        let attrs = try? fm.attributesOfItem(atPath: path)
        guard let perms = (attrs?[.posixPermissions] as? NSNumber)?.uint16Value else { return "?" }
        return String(format: "%04o", perms)
    }

    /// Owner as "name(uid)" via stat(2), which works on files the user cannot read.
    public static func owner(_ path: String) -> String {
        var info = stat()
        guard stat(path, &info) == 0 else { return "unknown" }
        let uid = info.st_uid
        let name = UserLookup.name(forUID: uid) ?? "uid:\(uid)"
        return "\(name)(\(uid))"
    }

    public static func uid(_ path: String) -> UInt32? {
        var info = stat()
        guard stat(path, &info) == 0 else { return nil }
        return info.st_uid
    }

    public static func gid(_ path: String) -> UInt32? {
        var info = stat()
        guard stat(path, &info) == 0 else { return nil }
        return info.st_gid
    }

    public static func isAppBundle(_ path: String) -> Bool {
        (path as NSString).pathExtension == "app" && isDirectory(path)
    }

    public static func bundleExecutable(_ appPath: String) -> String? {
        let infoPlist = (appPath as NSString).appendingPathComponent("Contents/Info.plist")
        guard let data = fm.contents(atPath: infoPlist) else { return nil }
        let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard let dict = plist as? [String: Any] else { return nil }
        guard let name = dict["CFBundleExecutable"] as? String else { return nil }
        let exe = (appPath as NSString).appendingPathComponent("Contents/MacOS/\(name)")
        return fm.fileExists(atPath: exe) ? exe : nil
    }

    public static func bundleIdentifier(_ appPath: String) -> String? {
        let infoPlist = (appPath as NSString).appendingPathComponent("Contents/Info.plist")
        guard let data = fm.contents(atPath: infoPlist) else { return nil }
        let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        return (plist as? [String: Any])?["CFBundleIdentifier"] as? String
    }

    public static func bundleVersion(_ appPath: String) -> String? {
        let infoPlist = (appPath as NSString).appendingPathComponent("Contents/Info.plist")
        guard let data = fm.contents(atPath: infoPlist) else { return nil }
        let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        guard let dict = plist as? [String: Any] else { return nil }
        let short = dict["CFBundleShortVersionString"] as? String
        let build = dict["CFBundleVersion"] as? String
        return [short, build].compactMap { $0 }.joined(separator: " (")
            .isEmpty ? nil : "\(short ?? "?") (\(build ?? "?"))"
    }

    public static func expand(_ path: String) -> String {
        if path.hasPrefix("~") {
            return (path as NSString).expandingTildeInPath
        }
        return path
    }

    public static func contractHome(_ path: String) -> String {
        let home = Home.current
        if path == home { return "~" }
        if path.hasPrefix(home + "/") { return "~" + path.dropFirst(home.count) }
        return path
    }
}

public enum Home {
    /// True when MacGuard is acting on behalf of a real user account rather than
    /// root itself. Under `sudo` this is true even though `geteuid()` is 0.
    ///
    /// This is the single question that decides where state lives and which key
    /// signs records: the user's own directory, not root's.
    public static var hasUserState: Bool {
        guard let sudoUser = ProcessInfo.processInfo.environment["SUDO_USER"],
              sudoUser != "root"
        else {
            // No sudo: either a plain user run, or a genuine root shell. A root
            // shell has no user state dir to act on behalf of.
            return geteuid() != 0
        }
        return homeDirectory(forUser: sudoUser) != nil
    }

    /// When running under `sudo`, quarantine and reports should belong to the human, not root.
    public static var current: String {
        if let sudoUser = ProcessInfo.processInfo.environment["SUDO_USER"],
           sudoUser != "root",
           let pwd = homeDirectory(forUser: sudoUser) {
            return pwd
        }
        return NSHomeDirectory()
    }

    /// Resolves a user's home directory from the directory service.
    ///
    /// `dscl . -read /Users/x NFSHomeDirectory` prints
    /// `NFSHomeDirectory: /Users/x`, so the value has to be taken from after the
    /// colon. Splitting on newlines instead yields the whole labelled line,
    /// which does not look like a path, and silently falls through to
    /// `NSHomeDirectory()` — which is `/var/root` under sudo. That strands the
    /// user's quarantine in root's home where they cannot see or restore it.
    static func homeDirectory(forUser user: String) -> String? {
        let stdout = Shell.run(
            "/usr/bin/dscl", [".", "-read", "/Users/\(user)", "NFSHomeDirectory"]
        ).stdout
        guard let value = stdout.split(separator: ":", maxSplits: 1).last else {
            return nil
        }
        let path = value.trimmingCharacters(in: .whitespacesAndNewlines)
        // Require an absolute path that is not just a prefix fragment, and make
        // sure it actually names a directory before trusting it.
        guard path.hasPrefix("/"), path.count > 1, !path.contains(" ") else {
            return nil
        }
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory),
              isDirectory.boolValue else {
            return nil
        }
        return path
    }

    /// Owns the directory and locks it to the current user. Under sudo the
    /// directory would otherwise be created by root inside the user's home,
    /// which then blocks the user's own non-privileged runs.
    private static func ensureOwnedDir(_ path: String) -> String {
        if !FileManager.default.fileExists(atPath: path) {
            try? FileManager.default.createDirectory(
                atPath: path,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
        // Ownership follows the *user* this directory belongs to, never the
        // process running it. Under `sudo` those differ: chowning to `geteuid()`
        // handed the user's state dir to root and locked the user out of their
        // own quarantine. When we cannot determine the user (a real root shell
        // with no SUDO_USER) the caller is root and owns it legitimately.
        if let owner = stateOwner {
            if let target = PathUtil.uid(path), target != owner.uid {
                chown(path, owner.uid, owner.gid)
            }
            chmod(path, 0o700)
        }
        return path
    }

    /// The account whose state directory this is. Under `sudo` this is the
    /// invoking user, so the directory stays theirs across privilege levels.
    static var stateOwner: (uid: UInt32, gid: UInt32)? {
        let home = current
        guard let uid = PathUtil.uid(home), let gid = PathUtil.gid(home) else {
            return nil
        }
        return (uid, gid)
    }

    public static var stateDir: String {
        let dir = (current as NSString).appendingPathComponent("Library/Application Support/MacGuard")
        return ensureOwnedDir(dir)
    }

    public static var configDir: String {
        let dir = (current as NSString).appendingPathComponent(".macguard")
        return ensureOwnedDir(dir)
    }

    public static var quarantineDir: String {
        let dir = (stateDir as NSString).appendingPathComponent("Quarantine")
        return ensureOwnedDir(dir)
    }
}

public enum UserLookup {
    private static var cache: [UInt32: String] = [:]
    private static let lock = NSLock()

    public static func name(forUID uid: UInt32) -> String? {
        lock.lock(); defer { lock.unlock() }
        if let cached = cache[uid] { return cached }
        if uid == 0 {
            cache[uid] = "root"
            return "root"
        }
        // dscl prints "<RecordName> something"; take the first token.
        let output = Shell.run("/usr/bin/dscl", [".", "-read", "/Users/ByUID/\(uid)", "RecordName"]).stdout
        let line = output.split(separator: "\n").first { $0.contains("RecordName") }
        let name = line?.split(separator: " ").dropFirst().joined(separator: " ")
            .trimmingCharacters(in: .whitespaces)
        let resolved = (name?.isEmpty == false) ? name : nil
        cache[uid] = resolved
        return resolved
    }
}

public enum Xattr {
    public static func read(_ path: String, _ name: String) -> String? {
        var size = getxattr(path, name, nil, 0, 0, XATTR_NOFOLLOW)
        if size <= 0 {
            // Follow symlinks as a fallback (some launch items are symlinked).
            size = getxattr(path, name, nil, 0, 0, 0)
        }
        guard size > 0 else { return nil }
        var buf = [UInt8](repeating: 0, count: size)
        let read = getxattr(path, name, &buf, size, 0, 0)
        guard read > 0 else { return nil }
        return String(decoding: buf[0..<read], as: UTF8.self)
    }

    public static func list(_ path: String) -> [String] {
        let size = listxattr(path, nil, 0, XATTR_NOFOLLOW)
        guard size > 0 else { return [] }
        var buf = [UInt8](repeating: 0, count: size)
        let read = listxattr(path, &buf, size, XATTR_NOFOLLOW)
        guard read > 0 else { return [] }
        var names: [String] = []
        var current = ""
        for byte in buf[0..<read] {
            if byte == 0 {
                if !current.isEmpty { names.append(current) }
                current = ""
            } else {
                current.append(Character(UnicodeScalar(byte)))
            }
        }
        if !current.isEmpty { names.append(current) }
        return names
    }

    public static func write(_ path: String, _ name: String, _ value: String) -> Bool {
        value.withCString { cstr in
            setxattr(path, name, cstr, strlen(cstr), 0, 0) == 0
        }
    }

    public static func remove(_ path: String, _ name: String) -> Bool {
        removexattr(path, name, 0) == 0
    }
}
