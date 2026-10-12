import Foundation

public enum Theme {
    public static let colorsEnabled: Bool = isatty(STDOUT_FILENO) == 1 && ProcessInfo.processInfo.environment["NO_COLOR"] == nil

    static func wrap(_ text: String, _ code: String) -> String {
        colorsEnabled ? "\u{1B}[\(code)m\(text)\u{1B}[0m" : text
    }

    public static func red(_ s: String) -> String { wrap(s, "1;31") }
    public static func orange(_ s: String) -> String { wrap(s, "1;33") }
    public static func yellow(_ s: String) -> String { wrap(s, "0;33") }
    public static func blue(_ s: String) -> String { wrap(s, "0;36") }
    public static func green(_ s: String) -> String { wrap(s, "0;32") }
    public static func bold(_ s: String) -> String { wrap(s, "1") }
    public static func dim(_ s: String) -> String { wrap(s, "2") }

    public static func severity(_ s: Severity, _ text: String) -> String {
        switch s {
        case .critical: return red(text)
        case .high: return orange(text)
        case .medium: return yellow(text)
        case .low: return blue(text)
        case .info: return dim(text)
        }
    }

    public static func severityBadge(_ s: Severity) -> String {
        severity(s, String(format: "[%-4s]", (s.label as NSString).utf8String!))
    }
}

public enum Reporter {
    public static func render(_ report: ThreatReport, showEvidence: Bool = false) -> String {
        var out: [String] = []
        out.append(Theme.bold("MacGuard \(MacGuardVersion.current) — \(report.host) as \(report.user)"))
        out.append(Theme.dim("scopes: \(report.scopes.joined(separator: ", ")) · items: \(report.scannedItems) · \(String(format: "%.1f", report.durationSeconds))s"))

        let findings = report.sortedFindings()
        if findings.isEmpty {
            out.append("")
            out.append(Theme.green("No anomalies found. Nothing needed cleaning up."))
            return out.joined(separator: "\n")
        }

        var current: Severity?
        for finding in findings {
            if finding.severity != current {
                current = finding.severity
                out.append("")
                out.append(Theme.severity(finding.severity, "── \(finding.severity.label.uppercased()) ──"))
            }
            let subject = finding.path.map(PathUtil.contractHome)
                ?? (finding.pid.map { "pid:\($0)/\(finding.processName ?? "?")" } ?? "system")
            out.append("\(Theme.severityBadge(finding.severity)) \(finding.title)")
            out.append("     \(Theme.dim(subject))  \(Theme.dim("[\(finding.category.label)]"))")
            if showEvidence || finding.evidence.count > 0 {
                out.append("     \(Theme.dim(finding.detail))")
                for evidence in finding.evidence.prefix(showEvidence ? 20 : 3) {
                    out.append("       \(Theme.dim("\(evidence.key): \(evidence.value)"))")
                }
                if finding.evidence.count > 3, !showEvidence {
                    out.append("       \(Theme.dim("… \(finding.evidence.count - 3) more (use --evidence)"))")
                }
            }
            if let remediation = finding.remediation {
                out.append("       \(Theme.yellow("→ " + remediation))")
            }
        }

        out.append("")
        out.append(summary(report))
        return out.joined(separator: "\n")
    }

    public static func summary(_ report: ThreatReport) -> String {
        let counts = report.counts
        let parts = Severity.allCases.reversed().compactMap { severity -> String? in
            guard let count = counts[severity], count > 0 else { return nil }
            return "\(severity.label.lowercased()):\(count)"
        }
        let head = parts.isEmpty ? "clean" : parts.joined(separator: " ")
        return "\(Theme.bold("Summary")) \(head) · \(report.findings.count) finding(s)"
    }

    public static func json(_ report: ThreatReport) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(report) else { return "{}" }
        return String(decoding: data, as: UTF8.self)
    }

    public static func html(_ report: ThreatReport) -> String {
        let findings = report.sortedFindings()
        var rows = ""
        for finding in findings {
            let subject = finding.path.map(PathUtil.contractHome) ?? "pid:\(finding.pid.map(String.init) ?? "–")"
            rows += """
            <tr class="sev-\(finding.severity.rawValue)">
              <td><span class="badge b\(finding.severity.rawValue)">\(finding.severity.label)</span></td>
              <td>\(escape(finding.title))</td>
              <td><code>\(escape(subject))</code></td>
              <td>\(escape(finding.category.label))</td>
              <td>\(escape(finding.detail))</td>
              <td>\(escape(finding.remediation ?? ""))</td>
            </tr>
            """
        }
        let formatter = ISO8601DateFormatter()
        return """
        <!DOCTYPE html><html><head><meta charset="utf-8">
        <title>MacGuard report — \(escape(report.host))</title>
        <style>
          body{font:14px/1.5 -apple-system,BlinkMacSystemFont,sans-serif;margin:32px;background:#0f1115;color:#e6e6e6}
          h1{font-size:20px} .meta{color:#8b93a1;margin-bottom:20px}
          table{border-collapse:collapse;width:100%} th,td{border:1px solid #262b33;padding:8px;text-align:left;vertical-align:top}
          th{background:#171b22} code{font:12px ui-monospace,Menlo,monospace;word-break:break-all}
          .badge{font-weight:700;padding:2px 8px;border-radius:4px;color:#0f1115}
          .b4{background:#ff3b30}.b3{background:#ff9f0a}.b2{background:#ffd60a}.b1{background:#64d2ff}.b0{background:#8e8e93}
        </style></head><body>
        <h1>MacGuard \(escape(MacGuardVersion.current))</h1>
        <div class="meta">host \(escape(report.host)) · user \(escape(report.user)) ·
        \(formatter.string(from: report.startedAt)) · scopes \(escape(report.scopes.joined(separator: ", "))) ·
        \(report.findings.count) findings · \(summaryPlain(report))</div>
        <table><thead><tr><th>Sev</th><th>Finding</th><th>Subject</th><th>Category</th><th>Detail</th><th>Remediation</th></tr></thead>
        <tbody>\(rows)</tbody></table>
        </body></html>
        """
    }

    private static func summaryPlain(_ report: ThreatReport) -> String {
        let counts = report.counts
        return Severity.allCases.reversed().compactMap { s in
            counts[s].map { "\(s.label.lowercased()) \($0)" }
        }.joined(separator: ", ")
    }

    private static func escape(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
    }
}

public final class BaselineStore {
    public static let shared = BaselineStore()

    private var url: String {
        (Home.configDir as NSString).appendingPathComponent("baseline.json")
    }

    private let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        e.dateEncodingStrategy = .iso8601
        return e
    }()

    private let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()

    public func load() -> Baseline {
        guard let data = FileManager.default.contents(atPath: url),
              let baseline = try? decoder.decode(Baseline.self, from: data)
        else { return Baseline() }
        return baseline
    }

    public func save(_ baseline: Baseline) throws {
        try encoder.encode(baseline).write(to: URL(fileURLWithPath: url))
    }

    /// Approves an item so future scans stay quiet about it.
    @discardableResult
    public func approve(_ path: String, note: String? = nil) throws -> BaselineEntry {
        var baseline = load()
        let expanded = PathUtil.expand(path)
        let isBundle = PathUtil.isAppBundle(expanded)
        let exe = isBundle ? PathUtil.bundleExecutable(expanded) : expanded
        let sig = exe.map { CodeSignatureVerifier.verify(path: $0, checkNotarization: false) }
        let entry = BaselineEntry(
            path: expanded,
            sha256: exe.flatMap { Digesting.sha256Hex(ofFile: $0) },
            teamID: sig?.teamID,
            bundleID: isBundle ? PathUtil.bundleIdentifier(expanded) : nil,
            addedAt: Date(),
            note: note
        )
        baseline.entries.removeAll { $0.path == entry.path }
        baseline.entries.append(entry)
        try save(baseline)
        return entry
    }

    public func revoke(_ path: String) throws {
        var baseline = load()
        let expanded = PathUtil.expand(path)
        baseline.entries.removeAll { $0.path == expanded || $0.bundleID == expanded }
        try save(baseline)
    }
}
