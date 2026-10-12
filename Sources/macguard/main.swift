import CryptoKit
import Foundation
import MacGuardKit

// MARK: - Argument parsing

struct Args {
    private var positional: [String] = []
    private var flags: [String: [String]] = [:]

    init(_ raw: [String]) {
        var i = 0
        while i < raw.count {
            let token = raw[i]
            if token.hasPrefix("--") {
                let name = String(token.dropFirst(2))
                var values: [String] = []
                i += 1
                while i < raw.count, !raw[i].hasPrefix("--") {
                    values.append(raw[i])
                    i += 1
                }
                flags[name] = values
            } else {
                positional.append(token)
                i += 1
            }
        }
    }

    var command: String? { positional.first }
    var arguments: [String] { Array(positional.dropFirst()) }

    func has(_ name: String) -> Bool { flags[name] != nil }
    func value(_ name: String) -> String? { flags[name]?.first }
    func values(_ name: String) -> [String] { flags[name] ?? [] }
    func int(_ name: String, default def: Int) -> Int { flags[name]?.first.flatMap(Int.init) ?? def }
}

let args = Args(Array(CommandLine.arguments.dropFirst()))
let command = args.command ?? "help"

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("macguard: \(message)\n".utf8))
    exit(2)
}

func severityFrom(_ raw: String?) -> Severity? {
    guard let raw else { return nil }
    switch raw.lowercased() {
    case "info": return .info
    case "low": return .low
    case "medium", "med": return .medium
    case "high": return .high
    case "critical", "crit": return .critical
    default: return nil
    }
}

func scopesFrom(_ raw: [String]) -> [ScanScope] {
    if raw.isEmpty { return [.all] }
    var out: [ScanScope] = []
    for value in raw {
        for part in value.split(separator: ",") {
            let token = part.trimmingCharacters(in: .whitespaces).lowercased()
            if token == "all" { return [.all] }
            if let scope = ScanScope(rawValue: token) { out.append(scope) }
        }
    }
    return out.isEmpty ? [.all] : out
}

func printUsage() {
    print("""
    MacGuard \(MacGuardVersion.current) — anomaly scanner & remediation tool for macOS

    USAGE
      macguard <command> [options]

    COMMANDS
      scan            Scan apps, persistence, processes and network for anomalies
      inspect <path>  Deep analysis of a single file or app bundle
      quarantine <p>  Move a suspicious item into quarantine (and stop it running)
      restore <id>    Restore an item from quarantine
      list            List quarantined items
      purge <id>      Permanently delete a quarantined item
       reseal         Re-sign quarantine records that predate integrity digests
      baseline        Approve / revoke / list trusted items
      sig             Manage the local hash & vendor signature database
      watch           Repeat scans on an interval and report new findings
      audit           Show the tamper-evident action log
      rules           List the active detection rules
      config          Show or change persistent scan settings
      doctor          Print environment diagnostics
      selfcheck       Verify the integrity of MacGuard's own state and log

    SCAN OPTIONS
      --scope <list>          all | apps | persistence | processes | network | system
      --min <severity>        info | low | medium | high | critical   (default: low)
      --json <file>           write a JSON report
      --html <file>           write an HTML report
      --evidence              print every piece of evidence
      --quarantine            quarantine findings of --quarantine-at or higher
      --quarantine-at <sev>   threshold for --quarantine (default: high)
      --delete                permanently delete instead of quarantining
      --dry-run               never modify anything
      --no-notarization       skip Gatekeeper/notarization checks (much faster)
      --include-apple         also scan Apple's own apps and launch items
      --progress              print live progress
      --baseline              honour ~/.macguard/baseline.json
      --allow-protected       permit touching SIP-protected paths (dangerous)

    EXAMPLES
      macguard scan
      sudo macguard scan --scope all --quarantine --quarantine-at critical
      macguard scan --scope persistence --json ~/Desktop/scan.json
      macguard inspect /Applications/Some.app
      macguard quarantine ~/Library/LaunchAgents/com.evil.plist
      macguard baseline add /Applications/Firefox.app
      macguard watch --interval 300
      macguard audit --verify
      macguard selfcheck
      macguard restore 20261002-101623-update_helper          # inert, safe
      macguard restore 20261002-101622-com.vendorupdate.agent --reload

    RESTORE OPTIONS
      --reload                re-register a restored launch item with launchd
                             (off by default: it starts the item running again)

    EXIT CODES
      0 clean   1 threats found   2 usage/permission error
    """)
}

func requireRootIfNeeded(_ reason: String) {
    guard geteuid() != 0 else { return }
    FileHandle.standardError.write(Data(
        "macguard: \(reason) needs root. Re-run with: sudo macguard \(command) \(args.arguments.joined(separator: " "))\n".utf8
    ))
    exit(2)
}

func writeTo(_ path: String, _ contents: String) {
    let url = URL(fileURLWithPath: path)
    try? FileManager.default.createDirectory(
        at: url.deletingLastPathComponent(),
        withIntermediateDirectories: true
    )
    do {
        try contents.write(to: url, atomically: true, encoding: .utf8)
        print(Theme.dim("  wrote \(PathUtil.contractHome(path))"))
    } catch {
        FileHandle.standardError.write(Data("macguard: could not write \(path): \(error.localizedDescription)\n".utf8))
    }
}

func loadConfig() -> ScanConfig {
    var config = ConfigStore.shared.load()
    if let min = severityFrom(args.value("min")) { config.minSeverity = min }
    if args.has("no-notarization") { config.checkNotarization = false }
    if args.has("include-apple") { config.includeAppleBinaries = true }
    return config
}

func buildDetector(_ config: ScanConfig) -> Detector {
    let rules = RuleEngine.loadDefault(
        extraRulesFrom: (Home.configDir as NSString).appendingPathComponent("rules.json")
    )
    let baseline = args.has("baseline") ? BaselineStore.shared.load() : Baseline()
    return Detector(config: config, rules: rules, baseline: baseline)
}

// MARK: - Commands

func commandScan() {
    let config = loadConfig()
    let scopes = scopesFrom(args.values("scope"))
    let detector = buildDetector(config)

    let showProgress = args.has("progress")
    let report = detector.scan(scopes: scopes) { message in
        if showProgress {
            FileHandle.standardError.write(Data("\r\u{1B}[2Kmacguard: \(message)".utf8))
        }
    }
    if showProgress { FileHandle.standardError.write(Data("\r\u{1B}[2K".utf8)) }

    print(Reporter.render(report, showEvidence: args.has("evidence")))

    if let json = args.value("json") { writeTo(json, Reporter.json(report)) }
    if let html = args.value("html") { writeTo(html, Reporter.html(report)) }

    // Remediation pass.
    let threshold = severityFrom(args.value("quarantine-at")) ?? .high
    if args.has("quarantine") || args.has("delete") {
        let dryRun = args.has("dry-run")
        var options = QuarantineOptions()
        options.deleteInsteadOfQuarantine = args.has("delete")
        options.dryRun = dryRun
        options.allowProtectedPath = args.has("allow-protected")

        let targets = report.sortedFindings().filter {
            $0.severity >= threshold && $0.path != nil
        }
        guard !targets.isEmpty else {
            print(Theme.dim("\nNothing at or above \(threshold.label) with a file path — no action taken."))
            exit(report.findings.isEmpty ? 0 : 1)
        }

        print("")
        print(Theme.bold(dryRun ? "DRY RUN — planned remediation" : "Remediating \(targets.count) finding(s)"))
        let engine = QuarantineEngine()
        var done = 0

        // Several findings usually point at the same launch item. Group them so the
        // file is only acted on once, and also carry along the payload the item runs.
        var grouped: [String: [Finding]] = [:]
        for finding in targets {
            guard let path = finding.path else { continue }
            grouped[path, default: []].append(finding)
        }

        var plan: [(path: String, findings: [Finding])] = []
        for (path, findings) in grouped {
            plan.append((path, findings))
            // Quarantining the plist alone leaves the payload on disk. Follow the
            // `program` evidence for any severe finding, not a fixed list of rule
            // ids: a payload can be flagged as a miner, a dropper, or anything
            // else, and leaving it behind defeats the quarantine.
            for finding in findings where finding.severity >= .high {
                guard let program = finding.evidence.first(where: { $0.key == "program" })?.value,
                      program.hasPrefix("/"),
                      program != path,
                      PathUtil.exists(program)
                else { continue }
                plan.append((program, [finding]))
            }
        }

        var seen = Set<String>()
        for entry in plan.sorted(by: { $0.path < $1.path }) {
            guard seen.insert(entry.path).inserted else { continue }
            guard PathUtil.exists(entry.path) else {
                print("  \(Theme.yellow("skip"))  \(PathUtil.contractHome(entry.path)) — file no longer exists")
                continue
            }
            let top = entry.findings.max { $0.severity < $1.severity } ?? entry.findings[0]
            let reason = entry.findings
                .map { "\($0.severity.label): \($0.title)" }
                .joined(separator: " | ")
            let verb = options.deleteInsteadOfQuarantine ? "delete" : "quarantine"
            do {
                let record = try engine.quarantine(
                    path: entry.path,
                    reason: reason,
                    findings: entry.findings,
                    options: options
                )
                done += 1
                var detail = "  \(Theme.red("✓")) \(verb)d \(PathUtil.contractHome(entry.path))"
                if !record.killedPIDs.isEmpty {
                    detail += " \(Theme.dim("(killed pids \(record.killedPIDs.map(String.init).joined(separator: ",")))"))"
                }
                print(detail)
                print("      \(Theme.dim(top.title))")
            } catch {
                print("  \(Theme.orange("fail"))  \(PathUtil.contractHome(entry.path)): \(error.localizedDescription)")
            }
        }
        if dryRun {
            print(Theme.dim("\nRe-run without --dry-run to apply. Quarantine lives in \(PathUtil.contractHome(Home.quarantineDir))"))
        } else if done > 0 {
            print(Theme.dim("\nRestore anything with: macguard list  /  macguard restore <id>"))
        }
        AuditLog.shared.record(action: "scan-remediate", target: "n/a", detail: "\(done) item(s), threshold \(threshold.label)")
    }

    exit(report.findings.isEmpty ? 0 : 1)
}

func commandInspect() {
    guard let path = args.arguments.first else { fail("inspect needs a path") }
    let expanded = PathUtil.expand(path)
    guard PathUtil.exists(expanded) else { fail("no such file: \(expanded)") }

    let config = loadConfig()
    let rules = RuleEngine.loadDefault(
        extraRulesFrom: (Home.configDir as NSString).appendingPathComponent("rules.json")
    )
    let analyzer = ItemAnalyzer(rules: rules, config: config)
    let item = analyzer.analyze(path: expanded)
    let findings = analyzer.findings(for: item)

    print(Theme.bold("MacGuard inspect — \(PathUtil.contractHome(expanded))"))
    print(Theme.dim("─" .padding(toLength: 72, withPad: "─", startingAt: 0)))

    let sig = item.signature
    print("type          \(PathUtil.isAppBundle(expanded) ? "app bundle" : (MachOInspector.inspect(path: expanded).kind.rawValue))")
    print("size          \(ByteCountFormatter.string(fromByteCount: Int64(item.sizeBytes), countStyle: .file))")
    print("mode/owner    \(PathUtil.posixMode(expanded))  \(PathUtil.owner(expanded))")
    print("modified      \(PathUtil.mtime(expanded).map { ISO8601DateFormatter().string(from: $0) } ?? "unknown")")
    print("sha256        \(item.sha256 ?? "n/a")")
    print("signature     \(sig.verdict.rawValue)\(sig.errors.isEmpty ? "" : " — \(sig.errors.joined(separator: "; "))")")
    print("identity      \(sig.teamID ?? "none")\(sig.signingIdentifier.map { " (\($0))" } ?? "")")
    print("authority     \(sig.authority ?? "none")")
    print("notarized     \(sig.notarized.map { $0 ? "yes" : "no" } ?? "not checked")")
    if let gate = sig.gatekeeperDetail {
        print("gatekeeper    \(gate.replacingOccurrences(of: "\n", with: " | "))")
    }
    print("hardened rt   \(sig.hasHardenedRuntime ? "yes" : "no")")
    if let bundleID = item.bundleID { print("bundle id     \(bundleID)") }
    let xattrs = Xattr.list(expanded)
    if !xattrs.isEmpty {
        print("xattrs        \(xattrs.joined(separator: ", "))")
    }
    if let process = ProcessScanner.allProcesses().first(where: { $0.path == expanded }) {
        print("running       yes — pid \(process.pid), cpu \(Int(process.cpuPercent))%")
    }

    print("")
    if findings.isEmpty {
        print(Theme.green("No anomalies detected for this item."))
    } else {
        let now = Date()
        let report = ThreatReport(
            host: HostInfo.name,
            user: NSUserName(),
            startedAt: now,
            finishedAt: now,
            durationSeconds: 0,
            scopes: ["inspect"],
            findings: findings,
            scannedItems: 1,
            quarantinedCount: 0,
            baselineApproved: 0
        )
        print(Reporter.render(report, showEvidence: true))
    }
    exit(findings.isEmpty ? 0 : 1)
}

func commandQuarantine() {
    if let id = args.value("id") {
        requireRootIfNeeded("Restoring system items")
        var options = QuarantineOptions()
        options.reloadAfterRestore = args.has("reload")
        options.allowProtectedPath = args.has("allow-protected")
        do {
            let record = try QuarantineEngine().restore(id: id, options: options)
            print(Theme.green("✓ restored \(PathUtil.contractHome(record.originalPath))"))
        } catch {
            fail(error.localizedDescription)
        }
        return
    }
    guard let path = args.arguments.first else { fail("quarantine needs a path or --id <id>") }
    requireRootIfNeeded("Quarantining system items")
    var options = QuarantineOptions()
    options.dryRun = args.has("dry-run")
    options.deleteInsteadOfQuarantine = args.has("delete")
    options.killProcesses = !args.has("no-kill")
    options.allowProtectedPath = args.has("allow-protected")

    let reason = args.value("reason") ?? "manual quarantine by \(NSUserName())"
    do {
        let record = try QuarantineEngine().quarantine(
            path: PathUtil.expand(path),
            reason: reason,
            options: options
        )
        if options.dryRun {
            print(Theme.yellow("DRY RUN: would quarantine \(PathUtil.contractHome(record.originalPath)) → \(PathUtil.contractHome(record.payloadPath))"))
        } else {
            print(Theme.green("✓ quarantined \(PathUtil.contractHome(record.originalPath))"))
            print("  id       \(record.id)")
            print("  payload  \(PathUtil.contractHome(record.payloadPath))")
            if !record.killedPIDs.isEmpty {
                print("  stopped  pids \(record.killedPIDs.map(String.init).joined(separator: ", "))")
            }
            print("  restore  macguard restore \(record.id)")
        }
    } catch {
        fail(error.localizedDescription)
    }
}

func commandRestore() {
    guard let id = args.arguments.first ?? args.value("id") else { fail("restore needs an id") }
    requireRootIfNeeded("Restoring system items")
    var options = QuarantineOptions()
    options.reloadAfterRestore = args.has("reload")
    options.allowProtectedPath = args.has("allow-protected")
    do {
        let record = try QuarantineEngine().restore(id: id, options: options)
        print(Theme.green("✓ restored \(PathUtil.contractHome(record.originalPath))"))
        if QuarantineEngine.isLaunchItem(record.originalPath), !options.reloadAfterRestore {
            print(Theme.yellow("  not re-registered with launchd — pass --reload to start it again"))
        }
    } catch {
        fail(error.localizedDescription)
    }
}

/// Re-signs quarantine records that predate the integrity digest.
///
/// This is only safe where the payload is still present and still hashes to the
/// value the record claims. The signature then attests to what we can actually
/// observe on disk, not to whatever the old record used to say.
func commandReseal() {
    requireRootIfNeeded("Re-sealing quarantine records")
    let engine = QuarantineEngine()
    let records = engine.list()
    guard !records.isEmpty else {
        print("Quarantine is empty.")
        return
    }

    // Re-signing must not weaken a record that already verifies.
    guard IntegrityKey.isRootBacked() else {
        print(Theme.red("Refusing to re-seal without root."))
        print(Theme.dim(
            "The signing key would land in \(IntegrityKey.keyURL()), which a user can replace."))
        print(Theme.dim("Re-run with sudo so the key is root-owned."))
        exit(1)
    }

    // The key the re-sealed records must be readable by the account that owns
    // the state directory. `validate` succeeding is not the same test: under
    // `sudo` the root key is readable, so a record signed with it looks healthy
    // here while staying unverifiable for the user who owns it. Compare key IDs
    // instead, which is what the user's own run will do.
    let targetKey: SymmetricKey
    do {
        targetKey = try IntegrityKey.load()
    } catch {
        print(Theme.red("Cannot load the signing key: \(error.localizedDescription)"))
        exit(2)
    }
    let targetKeyID = IntegrityKey.keyID(targetKey)

    var sealed = 0
    var refused = 0
    for record in records {
        if record.integrityKeyID == targetKeyID,
           (try? QuarantineEngine.validate(record)) != nil {
            print("  \(Theme.dim("ok   ")) \(record.id) already verifies")
            continue
        }
        // Signed by a key we can no longer read (or by this same key but with a
        // broken digest). Re-attest below once the payload is confirmed.
        let stale = record.integrityKeyID
        if !stale.isEmpty, stale != targetKeyID {
            print("  \(Theme.dim("stale")) \(record.id) — signed with key \(stale), re-signing with \(targetKeyID)")
        }

        guard PathUtil.exists(record.payloadPath) else {
            print("  \(Theme.yellow("skip"))  \(record.id) — payload is gone, nothing to attest to")
            refused += 1
            continue
        }
        guard let data = FileManager.default.contents(atPath: record.payloadPath),
              !record.isDirectory
        else {
            print("  \(Theme.yellow("skip"))  \(record.id) — cannot read payload")
            refused += 1
            continue
        }
        guard Digesting.sha256Hex(data) == record.sha256 else {
            print("  \(Theme.red("fail")) \(record.id) — payload no longer matches its recorded hash")
            refused += 1
            continue
        }

        var resealed = record
        do {
            try QuarantineEngine.seal(&resealed)
            try QuarantineEngine.saveRecord(resealed)
            try QuarantineEngine.validate(resealed)
            print("  \(Theme.green("sealed")) \(record.id)")
            AuditLog.shared.record(
                action: "reseal", target: record.originalPath,
                detail: "signed legacy record \(record.id), payload hash confirmed")
            sealed += 1
        } catch {
            print("  \(Theme.red("fail")) \(record.id) — \(error.localizedDescription)")
            refused += 1
        }
    }

    print("")
    print("\(sealed) re-sealed, \(refused) left alone.")
    if sealed > 0 {
        print(Theme.dim("Re-sealed records are signed with a key in \(IntegrityKey.keyURL())."))
    }
}

func commandList() {
    let records = QuarantineEngine().list()
    guard !records.isEmpty else {
        print(Theme.green("Quarantine is empty."))
        return
    }
    print(Theme.bold("Quarantined items (\(records.count))"))
    for record in records {
        let when = ISO8601DateFormatter().string(from: record.quarantinedAt).prefix(19)
        let state = record.restoredAt != nil ? Theme.green("restored") : Theme.red("active")
        print("")
        print("  \(Theme.bold(record.id))  \(state)")
        print("    original  \(PathUtil.contractHome(record.originalPath))")
        print("    reason    \(record.reason)")
        print("    size      \(ByteCountFormatter.string(fromByteCount: Int64(record.sizeBytes), countStyle: .file))")
        print("    sha256    \(record.sha256)")
        print("    at        \(when)")
        if !record.killedPIDs.isEmpty {
            print("    stopped   \(record.killedPIDs.map(String.init).joined(separator: ", "))")
        }
        // Flag records that will be refused on restore now, instead of letting
        // the failure surface later at the moment the file is actually needed.
        do {
            try QuarantineEngine.validate(record)
        } catch {
            print("    \(Theme.red("UNVERIFIED"))  \(Theme.dim(error.localizedDescription))")
        }
    }
}

func commandPurge() {
    guard let id = args.arguments.first else { fail("purge needs an id") }
    requireRootIfNeeded("Deleting system files")
    guard args.has("yes") || args.has("force") else {
        fail("refusing to permanently delete without --yes")
    }
    do {
        try QuarantineEngine().purge(id: id)
        print(Theme.green("✓ purged \(id)"))
    } catch {
        fail(error.localizedDescription)
    }
}

func commandBaseline() {
    let store = BaselineStore.shared
    let action = args.arguments.first ?? "list"
    switch action {
    case "list":
        let baseline = store.load()
        guard !baseline.entries.isEmpty else {
            print("No approved items yet. Add one with: macguard baseline add /Applications/App.app")
            return
        }
        print(Theme.bold("Approved items (\(baseline.entries.count))"))
        for entry in baseline.entries {
            print("  \(PathUtil.contractHome(entry.path))")
            if let team = entry.teamID { print("    team \(team)\(entry.bundleID.map { " · \($0)" } ?? "")") }
        }
    case "add":
        guard let path = args.arguments.dropFirst().first ?? nil else { fail("baseline add needs a path") }
        do {
            let entry = try store.approve(PathUtil.expand(path), note: args.value("note"))
            print(Theme.green("✓ approved \(PathUtil.contractHome(entry.path))"))
            print(Theme.dim("  scanned with --baseline to suppress this item"))
        } catch {
            fail(error.localizedDescription)
        }
    case "remove", "revoke":
        guard let path = args.arguments.dropFirst().first ?? nil else { fail("baseline remove needs a path") }
        do {
            try store.revoke(PathUtil.expand(path))
            print(Theme.green("✓ revoked \(PathUtil.contractHome(path))"))
        } catch {
            fail(error.localizedDescription)
        }
    default:
        fail("unknown baseline action '\(action)' (list|add|remove)")
    }
}

func commandSig() {
    let db = SignatureDB.shared
    let action = args.arguments.first ?? "list"
    switch action {
    case "list":
        let database = db.database
        print(Theme.bold("Malicious hashes: \(database.malicious.count)"))
        for entry in database.malicious.prefix(50) {
            print("  \(entry.sha256.prefix(16))…  \(entry.severity.label)  \(entry.name)")
        }
        print(Theme.bold("Trusted vendor team IDs: \(database.trustedVendors.count)"))
        for (team, prefixes) in database.trustedVendors.sorted(by: { $0.key < $1.key }) {
            print("  \(team)  \(prefixes.joined(separator: ", "))")
        }
    case "import":
        guard let path = args.arguments.dropFirst().first else { fail("sig import needs a JSON file") }
        do {
            try db.importSignatures(from: PathUtil.expand(path))
            print(Theme.green("✓ imported signature database from \(path)"))
        } catch {
            fail("could not import \(path): \(error.localizedDescription)")
        }
    case "trust":
        guard let team = args.arguments.dropFirst().first else { fail("sig trust needs a team id") }
        let prefixes = args.values("bundle").isEmpty ? ["*"] : args.values("bundle")
        db.addTrustedVendor(teamID: team, bundlePrefixes: prefixes)
        print(Theme.green("✓ trusting \(team) for \(prefixes.joined(separator: ", "))"))
    default:
        fail("unknown sig action '\(action)' (list|import|trust)")
    }
}

func commandWatch() {
    let interval = args.int("interval", default: 300)
    let scopes = scopesFrom(args.values("scope"))
    var seen = Set<String>()
    var firstRun = true

    print(Theme.bold("MacGuard watch — every \(interval)s, Ctrl-C to stop"))
    while true {
        let report = buildDetector(loadConfig()).scan(scopes: scopes)
        let fresh = report.sortedFindings().filter { !seen.contains($0.id) }
        if firstRun {
            seen = Set(report.findings.map(\.id))
            print(Theme.dim("\(ISO8601DateFormatter().string(from: report.finishedAt)) baseline: \(seen.count) findings"))
            if report.findings.isEmpty {
                print(Theme.green("  clean"))
            } else {
                print(Reporter.render(report))
            }
            firstRun = false
        } else if !fresh.isEmpty {
            print("")
            print(Theme.red("\(ISO8601DateFormatter().string(from: report.finishedAt)) \(fresh.count) NEW finding(s)"))
            for finding in fresh {
                print("  \(Theme.severityBadge(finding.severity)) \(finding.title) — \(finding.path.map(PathUtil.contractHome) ?? "pid:\(finding.pid.map(String.init) ?? "–")")")
            }
            seen.formUnion(fresh.map(\.id))
        } else {
            print(Theme.dim("\(ISO8601DateFormatter().string(from: report.finishedAt)) no new findings"))
        }
        fflush(stdout)
        Thread.sleep(forTimeInterval: Double(interval))
    }
}

func commandAudit() {
    if args.has("verify") {
        let result = AuditLog.shared.verify()
        if result.ok {
            print(Theme.green("✓ audit chain intact — \(result.checked) entries verified"))
        } else {
            let line = AuditLog.shared.lineCount()
            // Distinguish "a line is corrupt/legacy" from "a decoded entry was
            // edited", because they need different fixes.
            if result.checked < line {
                print(Theme.red("✗ \(line - result.checked) of \(line) audit lines could not be decoded"))
                print(Theme.dim("  These lines predate the hash chain or were corrupted."))
                print(Theme.dim("  The next action that writes to the log archives them aside."))
            } else if let why = AuditLog.shared.lastVerificationFailure() {
                print(Theme.red("✗ audit chain not trustworthy — \(why)"))
                switch why {
                case "undecodable line":
                    print(Theme.dim("  Entries at or after that point were edited, reordered or deleted."))
                case "unsigned entry":
                    print(Theme.dim("  These entries predate signing and cannot be attested to."))
                    print(Theme.dim("  The next action that writes to the log archives them aside."))
                case "signed with a key we do not hold":
                    print(Theme.dim("  The signing key is missing or was replaced."))
                default:
                    print(Theme.dim("  An entry's signature does not match its contents."))
                }
            } else {
                print(Theme.red("✗ audit chain broken at entry \(result.brokenAt.map(String.init) ?? "?") of \(result.checked)"))
                print(Theme.dim("  Entries at or after that point were edited, reordered or deleted."))
            }
            exit(1)
        }
        return
    }
    let lines = args.int("lines", default: 25)
    let entries = AuditLog.shared.tail(lines)
    guard !entries.isEmpty else {
        print("Audit log is empty.")
        return
    }
    for line in entries {
        print(Theme.dim(line))
    }
}

func commandRules() {
    let rules = RuleEngine.loadDefault(
        extraRulesFrom: (Home.configDir as NSString).appendingPathComponent("rules.json")
    ).rules
    print(Theme.bold("Active rules (\(rules.count))"))
    for rule in rules.map(\.rule) {
        let pattern = rule.regex ?? rule.literals?.joined(separator: " | ") ?? ""
        print("")
        print("  \(Theme.severity(rule.severity, String(format: "%-6s", (rule.severity.label as NSString).utf8String!))) \(Theme.bold(rule.id))  \(Theme.dim(rule.scope.rawValue))")
        print("      \(rule.title)")
        print("      \(Theme.dim(String(pattern.prefix(150))))")
    }
    print("")
    print(Theme.dim("Add your own rules to ~/.macguard/rules.json (JSON array of ScanRule)."))
}

func commandConfig() {
    let store = ConfigStore.shared
    guard args.arguments.first != "set" else {
        var config = store.load()
        if let min = severityFrom(args.value("min")) { config.minSeverity = min }
        if args.has("no-notarization") { config.checkNotarization = false }
        if args.has("include-apple") { config.includeAppleBinaries = true }
        store.save(config)
        print(Theme.green("✓ config updated"))
        commandConfig()
        return
    }
    let config = store.load()
    print(Theme.bold("MacGuard configuration"))
    print("  config file        \(PathUtil.contractHome((Home.configDir as NSString).appendingPathComponent("config.json")))")
    print("  min severity       \(config.minSeverity.label)")
    print("  notarization       \(config.checkNotarization ? "on" : "off")")
    print("  Apple apps         \(config.includeAppleBinaries ? "included" : "skipped")")
    print("  quarantine dir     \(PathUtil.contractHome(Home.quarantineDir))")
    print("  euid               \(geteuid()) \(geteuid() == 0 ? "(root)" : "(user)")")
    print(Theme.dim("\nChange with: macguard config set --min high"))
}

func commandDoctor() {
    print(Theme.bold("MacGuard environment"))
    let tools = ["spctl", "lsof", "codesign", "sfltool", "crontab", "dscl"]
    for tool in tools {
        let path = Shell.which(tool)
        print("  \(path == nil ? Theme.red("missing") : Theme.green("ok"))      \(tool.padding(toLength: 10, withPad: " ", startingAt: 0)) \(path ?? "-")")
    }
    print("")
    print("  euid        \(geteuid()) \(geteuid() == 0 ? "(root — full coverage)" : "(user — run with sudo for full coverage)")")
    print("  home        \(Home.current)")
    print("  quarantine  \(Home.quarantineDir)")
    print("  config      \(Home.configDir)")
    print("  baseline    \(BaselineStore.shared.load().entries.count) approved item(s)")
    print("  sig db      \(SignatureDB.shared.database.malicious.count) hash(es), \(SignatureDB.shared.database.trustedVendors.count) trusted vendor(s)")
    print("  rules       \(DefaultRules.rules.count) built-in")
    print("  processes   \(ProcessScanner.allProcesses().count) visible")
    print("  sockets     \(ProcessScanner.listeningSockets().count) listening")
}

func commandSelfCheck() {
    print(Theme.bold("MacGuard self-check"))
    var problems = 0

    func check(_ label: String, _ ok: Bool, _ detail: String) {
        if ok {
            print("  \(Theme.green("ok"))      \(label.padding(toLength: 22, withPad: " ", startingAt: 0)) \(Theme.dim(detail))")
        } else {
            problems += 1
            print("  \(Theme.red("FAIL"))    \(label)  \(Theme.orange(detail))")
        }
    }

    let audit = AuditLog.shared.verify()
    check("audit chain", audit.ok, audit.ok
        ? "\(audit.checked) entries verified"
        : "broken at entry \(audit.brokenAt.map(String.init) ?? "?"): "
            + (AuditLog.shared.lastVerificationFailure() ?? "unknown reason"))

    let state = Home.stateDir
    let quarantine = Home.quarantineDir
    for (label, dir) in [("state dir", state), ("quarantine dir", quarantine)] {
        let owner = PathUtil.uid(dir)
        check(label, owner == nil || owner == geteuid(),
            owner.map { "owned by uid \($0)" } ?? "missing")
        check("\(label) mode", PathUtil.posixMode(dir) == "0700", PathUtil.posixMode(dir))
    }

    // Any quarantined payload the current user could still execute defeats the
    // point of quarantining it.
    for record in QuarantineEngine().list() where !record.deleted {
        do {
            try QuarantineEngine.validate(record)
        } catch {
            problems += 1
            print("  \(Theme.red("FAIL"))    record \(record.id)  \(Theme.orange(error.localizedDescription))")
            continue
        }
        guard !record.payloadPath.isEmpty, PathUtil.exists(record.payloadPath) else { continue }
        let owner = PathUtil.uid(record.payloadPath)
        let mode = PathUtil.posixMode(record.payloadPath)
        let locked = mode == "0000" && (owner == nil || owner == 0 || owner == geteuid())
        check("payload \(record.id)", locked, "mode \(mode) owner \(owner.map(String.init) ?? "?")")
    }

    // Executables on MacGuard's own PATH must not be user-writable when the
    // scanner runs privileged.
    let tools = ["spctl", "codesign", "launchctl", "crontab", "lsof", "dscl"]
    for tool in tools {
        guard let path = Shell.which(tool) else { continue }
        let trusted = PathUtil.uid(path) == 0 && !PathUtil.isWorldWritable(path)
        check("tool \(tool)", trusted, "\(path) \(PathUtil.posixMode(path)) \(PathUtil.owner(path))")
    }

    print("")
    if problems == 0 {
        print(Theme.green("Self-check passed."))
    } else {
        print(Theme.red("\(problems) problem(s) found."))
        exit(1)
    }
}

// MARK: - Dispatch

switch command {
case "scan": commandScan()
case "inspect": commandInspect()
case "quarantine": commandQuarantine()
case "restore": commandRestore()
case "list", "quarantine-list": commandList()
case "purge": commandPurge()
case "reseal": commandReseal()
case "baseline": commandBaseline()
case "sig", "signatures": commandSig()
case "watch": commandWatch()
case "audit": commandAudit()
case "rules": commandRules()
case "config": commandConfig()
case "doctor": commandDoctor()
case "selfcheck", "self-check": commandSelfCheck()
case "help", "--help", "-h": printUsage()
case "version", "--version":
    print("macguard \(MacGuardVersion.current)")
default:
    printUsage()
    exit(2)
}
