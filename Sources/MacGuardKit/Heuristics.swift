import Foundation

public struct AnalyzedItem {
    public var path: String
    public var isBundle: Bool
    public var executablePath: String?
    public var bundleID: String?
    public var teamID: String?
    public var sha256: String?
    public var sizeBytes: Int
    public var signature: SignatureInfo
    public var notarized: Bool?
}

public final class ItemAnalyzer {
    private let rules: RuleEngine
    private let config: ScanConfig
    private let sigDB: SignatureDB
    private let baseline: Baseline

    public init(rules: RuleEngine, config: ScanConfig, sigDB: SignatureDB = .shared, baseline: Baseline = Baseline()) {
        self.rules = rules
        self.config = config
        self.sigDB = sigDB
        self.baseline = baseline
    }

    public func isBaselineApproved(_ item: AnalyzedItem) -> Bool {
        guard !baseline.entries.isEmpty else { return false }
        for entry in baseline.entries {
            if entry.path == item.path {
                if let sha = entry.sha256, let itemSha = item.sha256, sha != itemSha { continue }
                return true
            }
            if let bundle = entry.bundleID, bundle == item.bundleID,
               let team = entry.teamID, team == item.teamID {
                return true
            }
        }
        return false
    }

    /// Full analysis of a file, binary or app bundle.
    public func analyze(path: String) -> AnalyzedItem {
        // Self-exclusion belongs here as well as in `findings(for:)`: `analyze`
        // shells out to `codesign` and hashes the binary, which is wasted work on
        // a file we are about to discard.
        let isSelf = ApplePaths.isSelf(path)
        let isBundle = PathUtil.isAppBundle(path)
        let executable = isBundle ? PathUtil.bundleExecutable(path) : path
        let size = PathUtil.size(path)
        let sha = executable.flatMap { Digesting.sha256Hex(ofFile: $0) }

        var info = SignatureInfo()
        if let executable, !isSelf {
            info = CodeSignatureVerifier.verify(path: executable, checkNotarization: false)
        }

        var item = AnalyzedItem(
            path: path,
            isBundle: isBundle,
            executablePath: executable,
            bundleID: isBundle ? PathUtil.bundleIdentifier(path) : nil,
            teamID: info.teamID,
            sha256: sha,
            sizeBytes: size,
            signature: info,
            notarized: info.notarized
        )

        if config.checkNotarization, let executable, !isSelf,
           info.verdict == .valid, !info.isPlatformBinary, info.notarized == nil {
            let full = CodeSignatureVerifier.verify(path: executable, checkNotarization: true)
            item.signature = full
            item.notarized = full.notarized
            item.teamID = full.teamID ?? item.teamID
        }
        return item
    }

    /// Produces all findings for a single item.
    public func findings(for item: AnalyzedItem) -> [Finding] {
        // Scanning MacGuard's own binary matches every content rule, because the
        // patterns live in it as string literals. Skip it outright rather than
        // filtering findings after the fact — cheaper, and it cannot be fooled by
        // a rule that gains a new pattern later.
        guard !ApplePaths.isSelf(item.path) else { return [] }
        var out: [Finding] = []
        let subject = PathUtil.contractHome(item.path)

        if isBaselineApproved(item) { return [] }

        // 1. Known-bad hash match.
        if let sha = item.sha256, let sig = sigDB.lookup(sha256: sha) {
            out.append(Finding(
                id: Finding.makeID(subject: subject, rule: sig.name),
                severity: .critical,
                category: .signatureDB,
                title: "Known-bad file hash: \(sig.name)",
                detail: sig.note ?? "SHA-256 of this file is present in the MacGuard malicious signature database.",
                path: item.path,
                ruleID: "SIGDB",
                remediation: "Quarantine immediately and change passwords used on this Mac.",
                evidence: [Evidence(key: "sha256", value: sha)],
                sha256: sha
            ))
        }

        // 2. Content / path / bundle rules.
        for match in rules.scanPath(item.path) {
            out.append(ruleFinding(match, subject: subject, path: item.path))
        }
        if let exe = item.executablePath {
            for match in rules.scanPath(exe) {
                out.append(ruleFinding(match, subject: subject, path: item.path))
            }
            let head = StringExtractor.head(ofFile: exe, maxBytes: config.maxBytesPerBinary)
            if let head, !head.isEmpty {
                let strings = StringExtractor.asciiStrings(from: head)
                for match in rules.scanStrings(strings, path: item.path) {
                    out.append(ruleFinding(match, subject: subject, path: item.path, sha256: item.sha256))
                }
            }
        }
        if item.isBundle, let dict = infoPlist(item.path) {
            for match in rules.scanBundleInfo(dict, path: item.path) {
                out.append(ruleFinding(match, subject: subject, path: item.path))
            }
        }

        // 3. Code signature findings.
        out.append(contentsOf: signatureFindings(item))

        // 4. Structural heuristics.
        out.append(contentsOf: structuralFindings(item))
        return out
    }

    private func ruleFinding(
        _ match: RuleMatch,
        subject: String,
        path: String,
        sha256: String? = nil
    ) -> Finding {
        Finding(
            id: Finding.makeID(subject: subject, rule: match.rule.id),
            severity: match.rule.severity,
            category: match.rule.category,
            title: match.rule.title,
            detail: "Rule \(match.rule.id) matched during \(match.rule.scope.rawValue) analysis.",
            path: path,
            ruleID: match.rule.id,
            remediation: match.rule.remediation,
            evidence: [Evidence(key: match.evidenceKey, value: match.evidenceValue)],
            sha256: sha256
        )
    }

    private func signatureFindings(_ item: AnalyzedItem) -> [Finding] {
        var out: [Finding] = []
        let subject = PathUtil.contractHome(item.path)
        let sig = item.signature
        let inApple = ApplePaths.isApplePath(item.path)
        let trusted = sigDB.isTrusted(teamID: item.teamID, bundleID: item.bundleID)
        let escalates = !inApple && PathUtil.isWritableByCurrentUser(item.path)

        func add(_ severity: Severity, _ category: ThreatCategory, _ title: String, _ detail: String, _ evidence: [Evidence], _ remediation: String?) {
            out.append(Finding(
                id: Finding.makeID(subject: subject, rule: "SIG/\(title)"),
                severity: severity,
                category: category,
                title: title,
                detail: detail,
                path: item.path,
                ruleID: "SIGNATURE",
                remediation: remediation,
                evidence: evidence,
                sha256: item.sha256
            ))
        }

        // Homebrew/local builds are signed ad-hoc by design; not a security signal.
        let isDev = ApplePaths.isDevelopmentPath(item.path)
        let isBundle = item.isBundle
        let isToolchainBinary = !isBundle && !isDev

        switch sig.verdict {
        case .invalid:
            // A broken signature on a shipped app is serious; on a source-built
            // tool in a package-manager prefix it is usually a linking artefact.
            if isBundle || (isToolchainBinary && escalates) {
                add(
                    isBundle ? .critical : .high,
                    .signature,
                    "Broken or tampered code signature",
                    "The code signature on \(item.executablePath ?? item.path) does not validate: \(sig.errors.joined(separator: "; ")).",
                    [Evidence(key: "errors", value: sig.errors.joined(separator: "; "))],
                    "Do not run. Reinstall from the official source; if the file was never yours, quarantine it."
                )
            } else {
                add(
                    .low,
                    .signature,
                    "Signature does not validate on a locally built binary",
                    "\(item.executablePath ?? item.path): \(sig.errors.joined(separator: "; ")).",
                    [Evidence(key: "errors", value: sig.errors.joined(separator: "; "))],
                    nil
                )
            }
        case .unsigned:
            if isBundle && !trusted {
                add(
                    .high,
                    .signature,
                    "App bundle is not code signed",
                    "\(item.path) has no Developer ID signature, so its origin cannot be verified.",
                    [Evidence(key: "path", value: item.path)],
                    "Only run unsigned apps you built or obtained from a source you trust."
                )
            } else if isToolchainBinary, !trusted, escalates {
                add(
                    .high,
                    .signature,
                    "Unsigned executable in a user-writable location",
                    "\(item.executablePath ?? item.path) is unsigned and lives in a directory you can write to.",
                    [Evidence(key: "path", value: item.path)],
                    "Quarantine unless you compiled it yourself."
                )
            }
        case .adHoc:
            if isBundle && !trusted {
                add(
                    .medium,
                    .signature,
                    "App bundle signed ad-hoc, no vendor identity",
                    "\(item.path) is signed without a Developer ID certificate.",
                    [Evidence(key: "path", value: item.path)],
                    "Verify the developer identity before running."
                )
            }
        case .notCode, .valid, .unchecked:
            break
        }

        if let notarized = item.notarized, !notarized, !inApple, !trusted, sig.verdict == .valid, isBundle {
            add(
                .medium,
                .notarization,
                "Signed but not notarized",
                "Apple notarization ticket missing (Gatekeeper: \(sig.gatekeeperDetail ?? "unknown")).",
                [Evidence(key: "gatekeeper", value: sig.gatekeeperDetail ?? "unknown")],
                "Genuine vendors notarize their releases. Treat as higher risk."
            )
        }

        if sig.verdict == .valid, sig.isPlatformBinary == false, sig.hasHardenedRuntime == false, !inApple, isBundle {
            add(
                .low,
                .signature,
                "Hardened runtime not enabled",
                "The binary is signed but does not enable the hardened runtime.",
                [Evidence(key: "path", value: item.path)],
                nil
            )
        }
        return out
    }

    private func structuralFindings(_ item: AnalyzedItem) -> [Finding] {
        var out: [Finding] = []
        let subject = PathUtil.contractHome(item.path)
        let exe = item.executablePath ?? item.path
        let macho = MachOInspector.inspect(path: exe, maxBytes: min(config.maxBytesPerBinary, 4 << 20))

        func add(_ severity: Severity, _ category: ThreatCategory, _ title: String, _ detail: String, _ evidence: [Evidence], _ remediation: String?, ruleID: String = "HEURISTIC") {
            out.append(Finding(
                id: Finding.makeID(subject: subject, rule: "\(ruleID)/\(title)"),
                severity: severity,
                category: category,
                title: title,
                detail: detail,
                path: item.path,
                ruleID: ruleID,
                remediation: remediation,
                evidence: evidence,
                sha256: item.sha256
            ))
        }

        if item.sizeBytes > 200_000,
           item.signature.verdict == .unsigned || item.signature.verdict == .adHoc,
           !ApplePaths.isApplePath(item.path),
           !ApplePaths.isDevelopmentPath(item.path) {
            if let head = StringExtractor.head(ofFile: exe, maxBytes: 1 << 20) {
                let entropy = Shannon.entropy(head)
                if entropy > 7.5 {
                    add(
                        .medium,
                        .heuristic,
                        "High-entropy unsigned payload",
                        String(format: "Shannon entropy %.2f with no valid signature suggests a packed or encrypted payload.", entropy),
                        [Evidence(key: "entropy", value: String(format: "%.3f", entropy))],
                        "Packed unsigned code is a classic malware delivery shape.",
                        ruleID: "ENTROPY"
                    )
                }
            }
        }

        if macho.hasEncryptedSegments {
            add(
                .medium,
                .heuristic,
                "Encrypted Mach-O segments",
                "Contains LC_ENCRYPTION_INFO; the real code is decrypted only at runtime.",
                [Evidence(key: "macho", value: macho.kind.rawValue)],
                "Legitimate App Store binaries use this; unexpected elsewhere.",
                ruleID: "MACHO-CRYPTO"
            )
        }

        if PathUtil.isWorldWritable(item.path) {
            add(
                .high,
                .system,
                "World-writable executable",
                "Mode \(PathUtil.posixMode(item.path)) lets any local user replace this binary.",
                [Evidence(key: "mode", value: PathUtil.posixMode(item.path))],
                "Remove group/other write bits.",
                ruleID: "PERM"
            )
        }

        // Only meaningful for freshly-downloaded items. Installed apps in
        // /Applications legitimately have the flag stripped after first launch.
        let quarantine = Xattr.read(item.path, "com.apple.quarantine")
        if quarantine == nil, !ApplePaths.isApplePath(item.path) {
            let downloads = (Home.current as NSString).appendingPathComponent("Downloads")
            let inDownloads = item.path.hasPrefix(downloads)
            let createdAt = (try? FileManager.default.attributesOfItem(atPath: item.path))?[.creationDate] as? Date
            let recentlyCreated = createdAt.map { Date().timeIntervalSince($0) < 14 * 86_400 } ?? false
            if inDownloads && recentlyCreated {
                add(
                    .medium,
                    .heuristic,
                    "Downloaded item with the quarantine flag stripped",
                    "This item is still in ~/Downloads and was created recently, but the Gatekeeper quarantine attribute is gone — normally it is only removed after a successful first launch.",
                    [Evidence(key: "path", value: PathUtil.contractHome(item.path))],
                    "Stripping the quarantine flag bypasses Gatekeeper's first-run check.",
                    ruleID: "XATTR"
                )
            }
        }

        if item.isBundle, item.executablePath == nil {
            add(
                .medium,
                .heuristic,
                "App bundle without a main executable",
                "Contents/MacOS entry declared by Info.plist is missing — the bundle is corrupt or was tampered with.",
                [Evidence(key: "path", value: item.path)],
                "Delete and reinstall the app.",
                ruleID: "BUNDLE"
            )
        }

        return out
    }

    private func infoPlist(_ appPath: String) -> [String: Any]? {
        let plistPath = (appPath as NSString).appendingPathComponent("Contents/Info.plist")
        guard let data = FileManager.default.contents(atPath: plistPath) else { return nil }
        return try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]
    }
}

public enum Shannon {
    public static func entropy(_ data: Data) -> Double {
        guard !data.isEmpty else { return 0 }
        var counts = [UInt8: Int]()
        for byte in data { counts[byte, default: 0] += 1 }
        var result = 0.0
        let total = Double(data.count)
        for count in counts.values {
            let p = Double(count) / total
            if p > 0 { result -= p * log2(p) }
        }
        return result
    }
}
