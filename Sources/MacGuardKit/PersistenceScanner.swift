import Foundation

public struct PersistenceItem {
    public enum Kind: String, Sendable {
        case launchAgent = "LaunchAgent"
        case launchDaemon = "LaunchDaemon"
        case startupItem = "StartupItem"
        case loginItem = "LoginItem"
        case cron = "Cron"
        case sshKeys = "SSH authorized_keys"
        case shellProfile = "Shell profile"
        case sudoers = "Sudoers drop-in"
        case kernelExtension = "System/Kernel Extension"
        case configurationProfile = "Configuration Profile"
    }

    public var kind: Kind
    public var label: String
    public var plistPath: String?
    public var executables: [String]
    public var runAtLoad: Bool
    public var keepAlive: Bool
    public var environment: [String: String]
    public var rawDict: [String: Any]
}

public struct PersistenceScanner {
    public static var launchAgentDirs: [String] {
        [
            (Home.current as NSString).appendingPathComponent("Library/LaunchAgents"),
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "/Users/Shared/LaunchAgents",
            "/System/Library/LaunchAgents",
            "/System/Library/LaunchDaemons",
        ]
    }

    public static func inventory(includeApple: Bool = false) -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        items.append(contentsOf: launchItems(includeApple: includeApple))
        items.append(contentsOf: legacyStartupItems())
        items.append(contentsOf: cronEntries())
        items.append(contentsOf: shellProfiles())
        items.append(contentsOf: sshAuthorizedKeys())
        items.append(contentsOf: sudoersDropIns())
        items.append(contentsOf: systemExtensions())
        items.append(contentsOf: configurationProfiles())
        if includeApple { items.append(contentsOf: backgroundTaskItems()) }
        return items
    }

    // MARK: - Launch agents / daemons

    static func launchItems(includeApple: Bool) -> [PersistenceItem] {
        var out: [PersistenceItem] = []
        for dir in launchAgentDirs {
            let isApple = dir.hasPrefix("/System/")
            guard !isApple || includeApple else { continue }
            guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries where entry.hasSuffix(".plist") {
                let path = (dir as NSString).appendingPathComponent(entry)
                guard let data = FileManager.default.contents(atPath: path),
                      let dict = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]
                else { continue }

                let kind: PersistenceItem.Kind = dir.contains("LaunchDaemons") ? .launchDaemon : .launchAgent
                let label = dict["Label"] as? String ?? entry
                out.append(PersistenceItem(
                    kind: kind,
                    label: label,
                    plistPath: path,
                    executables: programArguments(dict),
                    runAtLoad: dict["RunAtLoad"] as? Bool ?? false,
                    keepAlive: (dict["KeepAlive"] as? Bool ?? false) || dict["KeepAlive"] is [String: Any],
                    environment: dict["EnvironmentVariables"] as? [String: String] ?? [:],
                    rawDict: dict
                ))
            }
        }
        return out
    }

    static func programArguments(_ dict: [String: Any]) -> [String] {
        if let program = dict["Program"] as? String { return [program] }
        if let args = dict["ProgramArguments"] as? [String] { return args }
        return []
    }

    static func legacyStartupItems() -> [PersistenceItem] {
        var out: [PersistenceItem] = []
        for dir in ["/Library/StartupItems", "/System/Library/StartupItems"] {
            guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries {
                let path = (dir as NSString).appendingPathComponent(entry)
                out.append(PersistenceItem(
                    kind: .startupItem,
                    label: entry,
                    plistPath: path,
                    executables: [path],
                    runAtLoad: true,
                    keepAlive: false,
                    environment: [:],
                    rawDict: [:]
                ))
            }
        }
        return out
    }

    // MARK: - Login items

    /// Ventura+ stores login items in the Background Task Management database.
    /// `sfltool dumpbtm` is the only non-TCC way to read it.
    static func backgroundTaskItems() -> [PersistenceItem] {
        guard let sfltool = Shell.which("sfltool") else { return [] }
        let result = Shell.run(sfltool, ["dumpbtm"], timeout: 30)
        guard result.status == 0 || !result.stdout.isEmpty else { return [] }

        var out: [PersistenceItem] = []
        let text = result.stdout
        for match in text.matches(of: #"\"(URL|BundleURL)\"\s*:\s*\"([^\"]+)\""#) {
            let path = match.value(at: 2)
            guard path.hasPrefix("/") else { continue }
            out.append(PersistenceItem(
                kind: .loginItem,
                label: (path as NSString).lastPathComponent,
                plistPath: nil,
                executables: [path],
                runAtLoad: true,
                keepAlive: false,
                environment: [:],
                rawDict: [:]
            ))
        }
        // Legacy Login Items plist, if it still exists.
        let legacy = "/Library/Application Support/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm"
        _ = legacy
        return dedupe(out)
    }

    static func dedupe(_ items: [PersistenceItem]) -> [PersistenceItem] {
        var seen = Set<String>()
        return items.filter { seen.insert($0.label + "|" + ($0.plistPath ?? $0.executables.joined(separator: ","))).inserted }
    }

    // MARK: - Cron

    static func cronEntries() -> [PersistenceItem] {
        var out: [PersistenceItem] = []

        let crontab = Shell.run("/usr/bin/crontab", ["-l"]).stdout
        if !crontab.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            for line in crontab.split(separator: "\n") {
                let text = line.trimmingCharacters(in: .whitespaces)
                guard !text.isEmpty, !text.hasPrefix("#") else { continue }
                out.append(PersistenceItem(
                    kind: .cron,
                    label: "crontab",
                    plistPath: nil,
                    executables: cronCommand(text),
                    runAtLoad: false,
                    keepAlive: false,
                    environment: [:],
                    rawDict: ["line": text]
                ))
            }
        }

        for dir in ["/etc/cron.d", "/usr/lib/cron/tabs"] {
            guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries {
                let path = (dir as NSString).appendingPathComponent(entry)
                guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
                for line in text.split(separator: "\n") {
                    let trimmed = line.trimmingCharacters(in: .whitespaces)
                    guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { continue }
                    out.append(PersistenceItem(
                        kind: .cron,
                        label: entry,
                        plistPath: path,
                        executables: cronCommand(trimmed),
                        runAtLoad: false,
                        keepAlive: false,
                        environment: [:],
                        rawDict: ["line": trimmed]
                    ))
                }
            }
        }
        return out
    }

    static func cronCommand(_ line: String) -> [String] {
        let parts = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        // Skip the five schedule fields plus the user field.
        return parts.count > 6 ? Array(parts[6...]) : parts
    }

    // MARK: - Shell profiles

    static func shellProfiles() -> [PersistenceItem] {
        var out: [PersistenceItem] = []
        let home = Home.current
        let names = [".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile", ".config/fish/config.fish"]
        for name in names {
            let path = (home as NSString).appendingPathComponent(name)
            guard PathUtil.exists(path) else { continue }
            out.append(PersistenceItem(
                kind: .shellProfile,
                label: name,
                plistPath: path,
                executables: [path],
                runAtLoad: true,
                keepAlive: false,
                environment: [:],
                rawDict: [:]
            ))
        }
        return out
    }

    // MARK: - SSH

    static func sshAuthorizedKeys() -> [PersistenceItem] {
        var out: [PersistenceItem] = []
        let homes = [Home.current, "/Users/Shared"].filter { PathUtil.isDirectory($0) }
        for homeDir in homes {
            let path = (homeDir as NSString).appendingPathComponent(".ssh/authorized_keys")
            guard PathUtil.exists(path) else { continue }
            out.append(PersistenceItem(
                kind: .sshKeys,
                label: "authorized_keys (\(PathUtil.contractHome(path)))",
                plistPath: path,
                executables: [],
                runAtLoad: false,
                keepAlive: false,
                environment: [:],
                rawDict: [:]
            ))
        }
        return out
    }

    // MARK: - sudoers

    static func sudoersDropIns() -> [PersistenceItem] {
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: "/etc/sudoers.d") else { return [] }
        return entries.map {
            PersistenceItem(
                kind: .sudoers,
                label: $0,
                plistPath: ("/etc/sudoers.d" as NSString).appendingPathComponent($0),
                executables: [],
                runAtLoad: false,
                keepAlive: false,
                environment: [:],
                rawDict: [:]
            )
        }
    }

    // MARK: - Extensions and profiles

    static func systemExtensions() -> [PersistenceItem] {
        var out: [PersistenceItem] = []
        for dir in ["/Library/Extensions", "/Library/SystemExtensions"] {
            guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries {
                let path = (dir as NSString).appendingPathComponent(entry)
                out.append(PersistenceItem(
                    kind: .kernelExtension,
                    label: entry,
                    plistPath: path,
                    executables: [path],
                    runAtLoad: true,
                    keepAlive: false,
                    environment: [:],
                    rawDict: [:]
                ))
            }
        }
        return out
    }

    static func configurationProfiles() -> [PersistenceItem] {
        var out: [PersistenceItem] = []
        for dir in ["/Library/Managed Preferences", "/Library/Application Support/com.apple.TCC"] {
            guard let entries = try? FileManager.default.contentsOfDirectory(atPath: dir) else { continue }
            for entry in entries {
                out.append(PersistenceItem(
                    kind: .configurationProfile,
                    label: "\((dir as NSString).lastPathComponent)/\(entry)",
                    plistPath: nil,
                    executables: [(dir as NSString).appendingPathComponent(entry)],
                    runAtLoad: false,
                    keepAlive: false,
                    environment: [:],
                    rawDict: [:]
                ))
            }
        }
        return out
    }
}

extension String {
    /// Small helper so command output can be scraped without a regex dependency.
    func matches(of pattern: String) -> [RegexCapture] {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let ns = self as NSString
        var results: [RegexCapture] = []
        var searchRange = NSRange(location: 0, length: ns.length)
        while searchRange.length > 0 {
            guard let match = regex.firstMatch(in: self, options: [], range: searchRange) else { break }
            results.append(RegexCapture(match: match, text: ns))
            let next = match.range.location + match.range.length
            guard next < ns.length else { break }
            searchRange = NSRange(location: next, length: ns.length - next)
        }
        return results
    }
}

public struct RegexCapture {
    private let match: NSTextCheckingResult
    private let text: NSString

    init(match: NSTextCheckingResult, text: NSString) {
        self.match = match
        self.text = text
    }

    public func value(at index: Int) -> String {
        guard index < match.numberOfRanges else { return "" }
        return text.substring(with: match.range(at: index))
    }
}
