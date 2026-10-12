import Foundation

/// Enumerates the things worth inspecting: app bundles, privileged helpers,
/// user-level persistence targets and anything a launch item points at.
public enum AppScanner {
    public struct Candidate {
        public var path: String
        public var origin: String
    }

    public static func appDirectories() -> [String] {
        [
            "/Applications",
            (Home.current as NSString).appendingPathComponent("Applications"),
            "/Applications/Utilities",
            "/Library/Application Support",
        ]
    }

    /// Directories where an unexpected executable is always suspicious.
    public static func hotDirectories() -> [String] {
        [
            (Home.current as NSString).appendingPathComponent("Library/LaunchAgents"),
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "/Library/PrivilegedHelperTools",
            "/usr/local/bin",
            "/usr/local/sbin",
            "/opt/homebrew/bin",
            "/opt/homebrew/sbin",
            "/tmp",
            "/var/tmp",
            "/private/tmp",
            "/Users/Shared",
            (Home.current as NSString).appendingPathComponent("Downloads"),
        ]
    }

    public static func candidates(includeAppleApps: Bool, followPersistence: Bool) -> [Candidate] {
        var out: [Candidate] = []
        var seen = Set<String>()

        func add(_ path: String, _ origin: String) {
            let resolved = (path as NSString).resolvingSymlinksInPath
            guard !seen.contains(resolved) else { return }
            // MacGuard's detection patterns are compiled into its own binary,
            // so scanning it reports a cryptominer, a dropper and a Gatekeeper
            // bypasser — all false positives, all of them every run.
            guard !ApplePaths.isSelf(resolved) else { return }
            seen.insert(resolved)
            out.append(Candidate(path: resolved, origin: origin))
        }

        for dir in appDirectories() {
            guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries {
                let path = (dir as NSString).appendingPathComponent(entry)
                guard PathUtil.isAppBundle(path) else { continue }
                if !includeAppleApps, path.hasPrefix("/System/") { continue }
                add(path, "app-bundle")
            }
        }

        for dir in hotDirectories() {
            collectExecutables(in: dir, depth: 2, add: add)
        }

        if followPersistence {
            for item in PersistenceScanner.inventory() {
                for exe in item.executables {
                    let expanded = PathUtil.expand(exe)
                    guard expanded.hasPrefix("/") else { continue }
                    if PathUtil.exists(expanded) {
                        add(expanded, "persistence:\(item.kind.rawValue)")
                    } else if let dir = item.plistPath, exe.hasSuffix(".sh") {
                        _ = dir
                    }
                }
                if let plist = item.plistPath, PathUtil.exists(plist),
                   ["Shell profile", "Cron", "SSH authorized_keys", "Sudoers drop-in"].contains(item.kind.rawValue) {
                    add(plist, "persistence:\(item.kind.rawValue)")
                }
            }
        }

        return out
    }

    /// Walks a suspicious directory up to `depth` levels, collecting app bundles,
    /// executable files and any plist that a malware dropper might have written.
    private static func collectExecutables(in dir: String, depth: Int, add: (String, String) -> Void) {
        guard depth >= 0,
              let entries = try? FileManager.default.contentsOfDirectory(atPath: dir)
        else { return }

        for entry in entries where !entry.hasPrefix(".") {
            let path = (dir as NSString).appendingPathComponent(entry)
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir) else { continue }

            if isDir.boolValue {
                if PathUtil.isAppBundle(path) {
                    add(path, "hot-dir:app")
                } else if depth > 0, entry != "Caches" {
                    collectExecutables(in: path, depth: depth - 1, add: add)
                }
                continue
            }
            if entry.hasSuffix(".plist") {
                add(path, "hot-dir:plist")
            }
            guard PathUtil.fm.isExecutableFile(atPath: path) else { continue }
            add(path, "hot-dir:exec")
        }
    }

    /// Names of Apple's own command-line tools, used for masquerade detection.
    public static func appleToolNames() -> Set<String> {
        var names = Set<String>()
        for dir in ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec"] {
            guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries {
                let path = (dir as NSString).appendingPathComponent(entry)
                guard !PathUtil.isDirectory(path), PathUtil.fm.isExecutableFile(atPath: path) else { continue }
                names.insert(entry)
            }
        }
        return names
    }
}
