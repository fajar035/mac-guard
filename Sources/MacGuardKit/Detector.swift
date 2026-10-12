import Foundation

public enum ScanScope: String, CaseIterable, Sendable {
    case all
    case apps
    case persistence
    case processes
    case network
    case system
}

public final class Detector {
    private let config: ScanConfig
    private let rules: RuleEngine
    private let analyzer: ItemAnalyzer
    private var scannedItems = 0

    public init(config: ScanConfig, rules: RuleEngine, baseline: Baseline = Baseline()) {
        self.config = config
        self.rules = rules
        self.analyzer = ItemAnalyzer(rules: rules, config: config, baseline: baseline)
    }

    public func scan(scopes: [ScanScope], progress: ((String) -> Void)? = nil) -> ThreatReport {
        let start = Date()
        var findings: [Finding] = []
        let requested = scopes.contains(where: { $0 == .all }) ? ScanScope.allCases : scopes

        if requested.contains(.system) {
            progress?("checking system security posture")
            findings.append(contentsOf: systemFindings())
        }
        if requested.contains(.persistence) {
            progress?("auditing persistence locations")
            findings.append(contentsOf: persistenceFindings())
        }
        if requested.contains(.apps) {
            let candidates = AppScanner.candidates(
                includeAppleApps: config.includeAppleBinaries,
                followPersistence: config.followLaunchAgentTargets
            )
            progress?("verifying \(candidates.count) applications & binaries")
            for (index, candidate) in candidates.enumerated() {
                if index % 25 == 0 { progress?("verifying \(index)/\(candidates.count): \(PathUtil.contractHome(candidate.path))") }
                let item = analyzer.analyze(path: candidate.path)
                scannedItems += 1
                findings.append(contentsOf: analyzer.findings(for: item))
            }
        }
        if requested.contains(.processes) {
            progress?("inspecting running processes")
            findings.append(contentsOf: processFindings())
        }
        if requested.contains(.network) {
            progress?("mapping listening sockets")
            findings.append(contentsOf: networkFindings())
        }

        let finish = Date()
        let filtered = dedupe(findings).filter { $0.severity >= config.minSeverity }
        return ThreatReport(
            host: HostInfo.name,
            user: NSUserName(),
            startedAt: start,
            finishedAt: finish,
            durationSeconds: finish.timeIntervalSince(start),
            scopes: requested.map { $0.rawValue },
            findings: filtered,
            scannedItems: scannedItems,
            quarantinedCount: 0,
            baselineApproved: 0
        )
    }

    private func dedupe(_ findings: [Finding]) -> [Finding] {
        var seen = Set<String>()
        var out: [Finding] = []
        for finding in findings {
            let key = finding.id
            guard seen.insert(key).inserted else { continue }
            out.append(finding)
        }
        return out
    }

    // MARK: - Persistence

    public func persistenceFindings() -> [Finding] {
        var out: [Finding] = []
        let items = PersistenceScanner.inventory()
        let appleTools = AppScanner.appleToolNames()

        for item in items {
            let plist = item.plistPath ?? item.executables.first ?? item.label
            let subject = PathUtil.contractHome(plist)

            func add(_ severity: Severity, _ category: ThreatCategory, _ title: String, _ detail: String,
                     _ evidence: [Evidence], _ remediation: String?, ruleID: String = "PERSIST") {
                out.append(Finding(
                    id: Finding.makeID(subject: subject, rule: "\(ruleID)/\(title)"),
                    severity: severity,
                    category: category,
                    title: title,
                    detail: detail,
                    path: item.plistPath,
                    ruleID: ruleID,
                    remediation: remediation,
                    evidence: evidence
                ))
            }

            if let plist = item.plistPath, !ApplePaths.isApplePath(plist) {
                if PathUtil.isWorldWritable(plist) {
                    add(.critical, .system, "Writable launch/persistence item",
                        "\(plist) is group- or world-writable; any local user can repoint it at their own payload.",
                        [Evidence(key: "mode", value: PathUtil.posixMode(plist)), Evidence(key: "owner", value: PathUtil.owner(plist))],
                        "Fix with `sudo chown root:wheel <file> && sudo chmod 644 <file>`.", ruleID: "PERM")
                } else if item.kind == .launchDaemon, PathUtil.uid(plist) != 0 {
                    add(.high, .system, "LaunchDaemon not owned by root",
                        "\(plist) runs as root at boot but is owned by \(PathUtil.owner(plist)).",
                        [Evidence(key: "owner", value: PathUtil.owner(plist))],
                        "Reinstall the vendor package; do not run unknown boot daemons.", ruleID: "PERM")
                }
            }

            if item.kind == .launchAgent, item.label.hasPrefix("com.apple."), !ApplePaths.isApplePath(plist) {
                add(.high, .persistence, "Apple-looking label outside the system domain",
                    "Label \"\(item.label)\" is registered from \(subject), not from /System.",
                    [Evidence(key: "label", value: item.label)],
                    "Apple does not install user-level agents with com.apple labels. Likely masquerade.", ruleID: "LABEL")
            }

            if let env = item.environment.first(where: { $0.key.hasPrefix("DYLD") || $0.key == "LD_PRELOAD" }) {
                add(.critical, .system, "Library injection in a launch item",
                    "\(item.label) sets \(env.key)=\(env.value), which injects code into every child process.",
                    [Evidence(key: env.key, value: env.value)],
                    "Remove the variable. This is a rootkit-class technique.", ruleID: "ENV")
            }

            let program = item.executables.first ?? ""
            let resolved = resolve(exe: program, item: item)

            if !program.isEmpty {
                if program.hasPrefix("/bin/sh") || program.hasSuffix("sh") || program.hasSuffix("bash") || program.hasSuffix("zsh") {
                    let inline = item.executables.dropFirst().joined(separator: " ")
                    let suspicious = ["curl", "wget", "base64", "osascript", "nc ", "eval", "python -c", "ruby -e"]
                    if suspicious.contains(where: { inline.contains($0) }) {
                        add(.high, .persistence, "Shell used as a service wrapper",
                            "\(item.label) launches \(program) with: \(inline.prefix(160))",
                            [Evidence(key: "program", value: program), Evidence(key: "args", value: String(inline.prefix(160)))],
                            "Interpreting inline download/exec as a launch item is a dropper pattern.", ruleID: "SHELL-WRAPPER")
                    } else {
                        add(.low, .persistence, "Shell interpreter as the service program",
                            "\(item.label) runs \(program) instead of a signed binary.",
                            [Evidence(key: "program", value: program)],
                            nil, ruleID: "SHELL-WRAPPER")
                    }
                }

                // `Program` may be a shell while the real payload is a file path in the
                // arguments. Follow those so the actual script still gets analysed.
                for argument in item.executables.dropFirst() {
                    guard argument.hasPrefix("/"), argument.hasPrefix("/bin/") == false else { continue }
                    let expanded = PathUtil.expand(argument)
                    guard PathUtil.exists(expanded), expanded != resolved else { continue }
                    analyzePersistencePayload(
                        path: expanded,
                        label: item.label,
                        appleTools: appleTools,
                        add: add
                    )
                }

                if let resolved, PathUtil.exists(resolved) {
                    let tempDirs = ["/tmp/", "/var/tmp/", "/private/tmp/", "/Users/Shared/"]
                    if tempDirs.contains(where: { resolved.hasPrefix($0) }) {
                        add(.critical, .persistence, "Persistence payload stored in a temp directory",
                            "\(item.label) points at \(resolved), which lives in a temporary directory that macOS periodically clears.",
                            [Evidence(key: "program", value: resolved)],
                            "Quarantine the payload and the launch item.", ruleID: "TEMP-PAYLOAD")
                    }
                    let base = (resolved as NSString).lastPathComponent
                    if appleTools.contains(base), !ApplePaths.isApplePath(resolved) {
                        add(.high, .persistence, "Persistence item shadows an Apple system tool",
                            "\(item.label) runs \(resolved) while a real Apple tool of the same name exists in /usr/bin.",
                            [Evidence(key: "program", value: resolved)],
                            "Classic masquerade: verify where this binary came from.", ruleID: "MASQUERADE")
                    }
                    analyzePersistencePayload(
                        path: resolved,
                        label: item.label,
                        appleTools: appleTools,
                        add: add
                    )
                } else if !program.isEmpty, !program.hasPrefix("/"), !program.hasPrefix("$") {
                    let leaf = (program as NSString).deletingPathExtension
                    let guessed = PathUtil.expand("~/Library/Application Support/\(leaf)/\(program)")
                    if PathUtil.exists(guessed) {
                        add(.medium, .persistence, "Relative program path in a launch item",
                            "\(item.label) uses \"\(program)\", resolved relative to the wrong directory.",
                            [Evidence(key: "program", value: program)],
                            nil, ruleID: "RELATIVE")
                    }
                }
            }

            switch item.kind {
            case .sshKeys:
                if let plist = item.plistPath, let text = try? String(contentsOfFile: plist, encoding: .utf8) {
                    let keys = text.split(separator: "\n").filter { !$0.hasPrefix("#") && !$0.trimmingCharacters(in: .whitespaces).isEmpty }
                    add(keys.count > 1 ? .high : .medium, .persistence, "SSH keys authorised on this Mac",
                        "\(keys.count) key(s) in \(subject). Any of them can log in as you without a password.",
                        [Evidence(key: "keys", value: "\(keys.count)"), Evidence(key: "path", value: subject)],
                        "Review with `cat \(PathUtil.contractHome(plist))` and delete keys you do not recognise.", ruleID: "SSH")
                }
            case .cron:
                if let line = item.rawDict["line"] as? String {
                    let combined = item.executables.joined(separator: " ") + " " + line
                    for match in rules.scanStrings([combined], path: item.plistPath ?? "") {
                        add(match.rule.severity, match.rule.category, match.rule.title,
                            match.rule.detail, [Evidence(key: match.evidenceKey, value: match.evidenceValue)],
                            match.rule.remediation, ruleID: match.rule.id)
                    }
                    let downloaders = ["curl", "wget", "base64", "osascript", "nc ", "nohup", ">/dev/null"]
                    if downloaders.contains(where: { combined.contains($0) }) {
                        add(.high, .persistence, "Scheduled job downloads or executes code",
                            "Cron entry: \(String(line.prefix(200)))",
                            [Evidence(key: "line", value: String(line.prefix(200)))],
                            "Inspect and remove unexpected scheduled jobs.", ruleID: "CRON")
                    }
                }
            case .shellProfile:
                if let plist = item.plistPath, let text = try? String(contentsOfFile: plist, encoding: .utf8) {
                    for match in rules.scanStrings([text], path: plist) {
                        add(match.rule.severity, match.rule.category, match.rule.title,
                            match.rule.detail, [Evidence(key: match.evidenceKey, value: match.evidenceValue)],
                            match.rule.remediation, ruleID: match.rule.id)
                    }
                    let autocmd = text.split(separator: "\n").filter { $0.contains("&") && ($0.contains("curl") || $0.contains("wget")) }
                    if !autocmd.isEmpty {
                        add(.high, .persistence, "Shell profile auto-runs a downloader",
                            "\(subject) runs: \(autocmd.joined(separator: "; ").prefix(200))",
                            [Evidence(key: "line", value: String(autocmd.joined(separator: "; ").prefix(200)))],
                            "Remove the line, then rotate your credentials.", ruleID: "SHELL-RC")
                    }
                }
            case .sudoers:
                if let plist = item.plistPath, let text = try? String(contentsOfFile: plist, encoding: .utf8) {
                    if text.contains("NOPASSWD: ALL") || text.contains("ALL=(ALL) NOPASSWD") {
                        add(.critical, .system, "Passwordless sudo granted",
                            "\(subject) contains an unrestricted NOPASSWD rule.",
                            [Evidence(key: "line", value: text.prefix(200).description)],
                            "Verify this was intended; remove if not.", ruleID: "SUDO")
                    }
                    if PathUtil.isWorldWritable(plist) {
                        add(.critical, .system, "Writable sudoers drop-in",
                            "\(subject) is writable and grants root.",
                            [Evidence(key: "mode", value: PathUtil.posixMode(plist))],
                            "chmod 440 and review with `sudo visudo -c`.", ruleID: "PERM")
                    }
                }
            case .configurationProfile, .kernelExtension, .startupItem, .loginItem, .launchAgent, .launchDaemon:
                break
            }
        }
        return out
    }

    /// Runs the full heuristic set against the file an autorun entry actually executes.
    private func analyzePersistencePayload(
        path: String,
        label: String,
        appleTools: Set<String>,
        add: (Severity, ThreatCategory, String, String, [Evidence], String?, String) -> Void
    ) {
        guard !ApplePaths.isApplePath(path), !ApplePaths.isDevelopmentPath(path) else { return }

        let tempDirs = ["/tmp/", "/var/tmp/", "/private/tmp/", "/Users/Shared/"]
        if tempDirs.contains(where: { path.hasPrefix($0) }) {
            add(.critical, .persistence, "Persistence payload stored in a temp directory",
                "\(label) points at \(path), which lives in a temporary directory that macOS periodically clears.",
                [Evidence(key: "program", value: path)],
                "Quarantine the payload and the launch item.", "TEMP-PAYLOAD")
        }

        let base = (path as NSString).lastPathComponent
        if appleTools.contains(base) {
            add(.high, .persistence, "Persistence item shadows an Apple system tool",
                "\(label) runs \(path) while a real Apple tool of the same name exists in /usr/bin.",
                [Evidence(key: "program", value: path)],
                "Classic masquerade: verify where this binary came from.", "MASQUERADE")
        }

        let head = StringExtractor.head(ofFile: path, maxBytes: 4 << 20) ?? Data()
        for match in rules.scanStrings(StringExtractor.asciiStrings(from: head), path: path) {
            add(match.rule.severity, match.rule.category, match.rule.title,
                "\(label) runs \(path): \(match.rule.detail)",
                [Evidence(key: match.evidenceKey, value: match.evidenceValue)],
                match.rule.remediation, match.rule.id)
        }

        let scriptExtensions: Set<String> = ["sh", "plist", "command", "py", "rb", "zsh", "bash", "zshrc"]
        let isScript = scriptExtensions.contains((path as NSString).pathExtension.lowercased())
        guard !isScript, PathUtil.fm.isExecutableFile(atPath: path) else { return }

        let sig = CodeSignatureVerifier.verify(path: path, checkNotarization: false)
        if sig.verdict == .invalid {
            add(.critical, .signature, "Boot/autorun payload with a broken signature",
                "\(path) fails signature validation: \(sig.errors.joined(separator: "; "))",
                [Evidence(key: "program", value: path)],
                "Tampered system component. Quarantine immediately.", "SIG")
        } else if sig.verdict == .unsigned || sig.verdict == .adHoc {
            add(.high, .signature, "Autorun payload is not vendor-signed",
                "\(path) is \(sig.verdict.rawValue) and starts automatically on every boot/login.",
                [Evidence(key: "program", value: path), Evidence(key: "verdict", value: sig.verdict.rawValue)],
                "Only trust it if you installed it yourself.", "SIG")
        }
    }

    private func resolve(exe: String, item: PersistenceItem) -> String? {
        let candidate = PathUtil.expand(exe)
        guard !candidate.isEmpty else { return nil }
        if candidate.hasPrefix("/") { return candidate }
        // launchd resolves relative Program paths against the plist's own directory.
        if let plist = item.plistPath {
            let dir = (plist as NSString).deletingLastPathComponent
            return (dir as NSString).appendingPathComponent(candidate)
        }
        return nil
    }

    // MARK: - Processes

    public func processFindings() -> [Finding] {
        var out: [Finding] = []
        let processes = ProcessScanner.allProcesses()
        let byPid = Dictionary(processes.map { ($0.pid, $0) }, uniquingKeysWith: { a, _ in a })
        let appleTools = AppScanner.appleToolNames()
        let tempDirs = ["/tmp/", "/var/tmp/", "/private/tmp/", "/Users/Shared/"]

        for proc in processes where proc.pid != getpid() {
            let subject = "pid:\(proc.pid)/\(proc.comm)"
            let path = proc.path ?? ""

            func add(_ severity: Severity, _ category: ThreatCategory, _ title: String, _ detail: String,
                     _ evidence: [Evidence], _ remediation: String?, ruleID: String = "PROC") {
                out.append(Finding(
                    id: Finding.makeID(subject: subject, rule: "\(ruleID)/\(title)"),
                    severity: severity,
                    category: category,
                    title: title,
                    detail: detail,
                    path: proc.path,
                    processName: proc.comm,
                    pid: proc.pid,
                    ruleID: ruleID,
                    remediation: remediation,
                    evidence: evidence
                ))
            }

            for match in rules.scanProcess(name: proc.comm, path: proc.path, args: proc.args) {
                add(match.rule.severity, match.rule.category, match.rule.title, match.rule.detail,
                    [Evidence(key: match.evidenceKey, value: match.evidenceValue)], match.rule.remediation,
                    ruleID: match.rule.id)
            }

            if !path.isEmpty {
                if !PathUtil.exists(path) {
                    add(.medium, .process, "Process running from a deleted image",
                        "The executable backing \(proc.comm) (pid \(proc.pid)) no longer exists on disk — the file was removed while running.",
                        [Evidence(key: "path", value: path)],
                        "Kill the process; malware often removes itself this way.", ruleID: "DELETED-IMAGE")
                }
                if tempDirs.contains(where: { path.hasPrefix($0) }) {
                    add(.critical, .process, "Running process executing from a temp directory",
                        "\(proc.comm) (pid \(proc.pid)) runs from \(path).",
                        [Evidence(key: "path", value: path), Evidence(key: "args", value: proc.args.joined(separator: " ").prefix(200).description)],
                        "Kill and quarantine immediately.", ruleID: "TEMP-EXEC")
                }
                let isDevPath = ApplePaths.isDevelopmentPath(path)
                if !ApplePaths.isApplePath(path) {
                    let base = (path as NSString).lastPathComponent
                    if appleTools.contains(base), !isDevPath {
                        add(.critical, .process, "Process masquerading as an Apple system tool",
                            "\(proc.comm) (pid \(proc.pid)) runs from \(path) while Apple ships \(base) in /usr/bin.",
                            [Evidence(key: "path", value: path)],
                            "Almost certainly malicious. Isolate the host and quarantine.", ruleID: "MASQUERADE")
                    }
                    if proc.uid == 0, PathUtil.uid(path) != 0 {
                        add(.critical, .system, "root process running from a non-root-owned file",
                            "\(proc.comm) (pid \(proc.pid), uid 0) executes \(path) owned by \(PathUtil.owner(path)).",
                            [Evidence(key: "path", value: path), Evidence(key: "owner", value: PathUtil.owner(path))],
                            "Local privilege escalation vector. Quarantine the binary.", ruleID: "PRIVESC")
                    }
                    if proc.cpuPercent > 70, proc.ppid != 1, appleTools.contains(base) == false,
                       let parent = byPid[proc.ppid], parent.pid != 1 {
                        add(.low, .process, "High CPU usage",
                            "\(proc.comm) (pid \(proc.pid)) averages \(Int(proc.cpuPercent))% of one core since launch.",
                            [Evidence(key: "cpu", value: String(format: "%.0f%%", proc.cpuPercent))],
                            nil, ruleID: "CPU")
                    }
                }
            } else if proc.uid == 0 && proc.ppid == 1 {
                add(.medium, .process, "Root process with an unresolvable path",
                    "\(proc.comm) (pid \(proc.pid)) runs as root but its executable cannot be inspected.",
                    [Evidence(key: "comm", value: proc.comm)],
                    "Usually a kernel task; investigate if the name is unfamiliar.", ruleID: "OPAQUE")
            }

            if proc.ppid != 0, proc.ppid != 1, byPid[proc.ppid] == nil {
                add(.low, .process, "Orphaned process",
                    "\(proc.comm) (pid \(proc.pid)) points at parent pid \(proc.ppid), which no longer exists.",
                    [Evidence(key: "ppid", value: "\(proc.ppid)")],
                    nil, ruleID: "ORPHAN")
            }
        }
        return out
    }

    // MARK: - Network

    public func networkFindings() -> [Finding] {
        var out: [Finding] = []
        let sockets = ProcessScanner.listeningSockets()
        let processPaths = Dictionary(
            ProcessScanner.allProcesses().compactMap { proc in proc.path.map { (proc.pid, $0) } },
            uniquingKeysWith: { a, _ in a }
        )
        let suspiciousPorts: Set<Int> = [1337, 31337, 4444, 4445, 5555, 6666, 6667, 9001, 12345]
        let devPorts: Set<Int> = [3000, 5000, 5173, 8000, 8080, 9000, 4200, 27017, 5432, 6379, 11211]

        for socket in sockets {
            let subject = "port:\(socket.port)/\(socket.process)"
            let isWildcard = socket.address == "*" || socket.address == "0.0.0.0" || socket.address == "::"
            let path = socket.pid.flatMap { pid in processPaths[pid] }

            func add(_ severity: Severity, _ title: String, _ detail: String, _ evidence: [Evidence], _ remediation: String?) {
                out.append(Finding(
                    id: Finding.makeID(subject: subject, rule: "NET/\(title)"),
                    severity: severity,
                    category: .network,
                    title: title,
                    detail: detail,
                    path: path,
                    processName: socket.process,
                    pid: socket.pid,
                    ruleID: "NETWORK",
                    remediation: remediation,
                    evidence: evidence
                ))
            }

            if suspiciousPorts.contains(socket.port) {
                add(.high, "Listener on a known backdoor port",
                    "\(socket.process) is listening on \(socket.address):\(socket.port).",
                    [Evidence(key: "port", value: "\(socket.port)"), Evidence(key: "address", value: socket.address)],
                    "Backdoor ports. Kill the process unless you started it deliberately.")
            }
            if socket.isPrivileged, isWildcard, socket.port == 23 || socket.port == 3389 || socket.port == 5900 {
                add(.high, "Remote-access service exposed to the network",
                    "\(socket.process) exposes telnet/VNC/RDP on all interfaces.",
                    [Evidence(key: "port", value: "\(socket.port)")],
                    "Disable it or bind it to localhost.")
            }
            if devPorts.contains(socket.port), isWildcard {
                add(.low, "Development/service port bound to all interfaces",
                    "\(socket.process) listens on \(socket.address):\(socket.port); reachable from the local network.",
                    [Evidence(key: "port", value: "\(socket.port)"), Evidence(key: "address", value: socket.address)],
                    "Bind to 127.0.0.1 if only local access is needed.")
            }
            if isWildcard, let path, !ApplePaths.isApplePath(path) {
                let sig = CodeSignatureVerifier.verify(path: path, checkNotarization: false)
                if sig.verdict == .unsigned || sig.verdict == .adHoc {
                    add(.medium, "Unsigned binary exposing a network port",
                        "\(socket.process) (\(path)) is \(sig.verdict.rawValue) and listening on \(socket.address):\(socket.port).",
                        [Evidence(key: "path", value: path), Evidence(key: "verdict", value: sig.verdict.rawValue)],
                        "Verify the origin before trusting an open network service.")
                }
            }
        }
        return out
    }

    // MARK: - System posture

    public func systemFindings() -> [Finding] {
        var out: [Finding] = []

        func add(_ severity: Severity, _ title: String, _ detail: String, _ evidence: [Evidence], _ remediation: String?) {
            out.append(Finding(
                id: Finding.makeID(subject: "system", rule: "SYS/\(title)"),
                severity: severity,
                category: .system,
                title: title,
                detail: detail,
                ruleID: "SYSTEM",
                remediation: remediation,
                evidence: evidence
            ))
        }

        let csr = Shell.run("/usr/bin/csrutil", ["status"])
        if csr.stdout.contains("disabled") {
            add(.high, "System Integrity Protection is disabled",
                "SIP status: \(csr.stdout.trimmingCharacters(in: .whitespacesAndNewlines))",
                [Evidence(key: "csrutil", value: csr.stdout.trimmingCharacters(in: .whitespacesAndNewlines))],
                "Reboot into Recovery and run `csrutil enable`.")
        }
        let spctl = Shell.run("/usr/sbin/spctl", ["--status"])
        if spctl.stdout.contains("assessments disabled") {
            add(.critical, "Gatekeeper is disabled",
                "`spctl --status` reports: \(spctl.stdout.trimmingCharacters(in: .whitespacesAndNewlines))",
                [Evidence(key: "spctl", value: spctl.stdout.trimmingCharacters(in: .whitespacesAndNewlines))],
                "Run `sudo spctl --master-enable` immediately.")
        }
        // fdesetup lives in /usr/bin on this OS release, not /usr/sbin.
        let filevault = Shell.run("/usr/bin/fdesetup", ["status"])
        if filevault.stdout.contains("FileVault is Off"), filevault.succeeded {
            add(.medium, "FileVault disk encryption is off",
                "Data at rest is readable if the machine is stolen.",
                [Evidence(key: "fdesetup", value: "Off")],
                "Enable with `sudo fdesetup enable -user \"$USER\"`.")
        }
        if geteuid() != 0 {
            add(.info, "Scan ran without root privileges",
                "System-wide launch daemons, other users' processes and SIP/Firewall state could not be fully inspected.",
                [Evidence(key: "euid", value: "\(geteuid())")],
                "Re-run with `sudo macguard scan` for full coverage.")
        }
        return out
    }
}

public enum HostInfo {
    public static var name: String {
        let result = Shell.run("/usr/sbin/scutil", ["--get", "ComputerName"])
        let name = result.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        return name.isEmpty ? ProcessInfo.processInfo.hostName : name
    }
}
