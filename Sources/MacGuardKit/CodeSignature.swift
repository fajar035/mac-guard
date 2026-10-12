import CoreFoundation
import Foundation
import Security

public struct SignatureInfo: Sendable {
    public enum Verdict: String, Sendable {
        case valid
        case invalid
        case unsigned
        case adHoc
        /// The item is not signed code at all (shell script, text file, plist).
        case notCode
        case unchecked
    }

    public var verdict: Verdict = .unchecked
    public var teamID: String?
    public var signingIdentifier: String?
    public var source: String?
    public var authority: String?
    public var isPlatformBinary = false
    public var hasHardenedRuntime = false
    public var notarized: Bool?
    public var gatekeeperDetail: String?
    public var errors: [String] = []

    public var isThirdPartySigned: Bool { teamID != nil && !isPlatformBinary }
}

public enum CodeSignatureVerifier {
    /// `CS_RUNTIME` — the hardened runtime bit in `kSecCodeInfoFlags`.
    ///
    /// Exposed for tests: the value is the whole point of the fix, so it should
    /// be asserted rather than trusted.
    public static let codeDirectoryRuntimeMask: UInt32 = 0x10000

    private static let cacheLock = NSLock()
    private static var cache: [String: SignatureInfo] = [:]

    /// Verifies a file or app bundle using the Security framework, then optionally asks
    /// Gatekeeper (via spctl) whether the code carries a valid notarization ticket.
    public static func verify(path: String, checkNotarization: Bool = true) -> SignatureInfo {
        cacheLock.lock()
        if let hit = cache[path] {
            cacheLock.unlock()
            return hit
        }
        cacheLock.unlock()

        let info = inspect(path: path, checkNotarization: checkNotarization)

        cacheLock.lock()
        cache[path] = info
        cacheLock.unlock()
        return info
    }

    private static func inspect(path: String, checkNotarization: Bool) -> SignatureInfo {
        var info = SignatureInfo()

        // Gatekeeper only governs code. Asking the Security framework to validate a
        // shell script or a .zshrc produces a misleading "broken signature" verdict.
        let macho = MachOInspector.inspect(path: path)
        let looksLikeCode = macho.isExecutable
            || PathUtil.isAppBundle(path)
            || PathUtil.isDirectory(path) == false && macho.kind == .script && false
        guard looksLikeCode else {
            info.verdict = .notCode
            return info
        }

        let url = URL(fileURLWithPath: path) as CFURL

        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(url, [], &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            info.verdict = .unchecked
            info.errors = ["SecStaticCodeCreateWithPath failed (\(createStatus))"]
            return info
        }

        var flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures)
        flags.insert(SecCSFlags(rawValue: kSecCSCheckNestedCode))

        var validationError: Unmanaged<CFError>?
        let valid = SecStaticCodeCheckValidityWithErrors(code, flags, nil, &validationError)
        if valid == errSecSuccess {
            info.verdict = .valid
        } else {
            info.verdict = .invalid
            if let cfError = validationError?.takeRetainedValue() {
                info.errors.append(describe(validationError: cfError))
            } else {
                info.errors.append("signature validation failed (OSStatus \(valid))")
            }
        }

        // No embedded signature at all means "unsigned", not "tampered".
        // This distinction is what keeps scripts and unsigned tools from being
        // reported as "tampered".
        guard hasSignature(staticCode: code) else {
            info.verdict = .unsigned
            info.errors = []
            return info
        }

        var signingInfo: CFDictionary?
        let copyStatus = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &signingInfo)
        if copyStatus == errSecSuccess, let dict = signingInfo as? [String: Any] {
            info.teamID = dict[kSecCodeInfoTeamIdentifier as String] as? String
            info.signingIdentifier = dict[kSecCodeInfoIdentifier as String] as? String
            info.source = dict[kSecCodeInfoSource as String] as? String
            // Platform identifier is an NSNumber (the OS build), not a string.
            info.isPlatformBinary = dict[kSecCodeInfoPlatformIdentifier as String] != nil
            if let flagsNumber = dict[kSecCodeInfoFlags as String] as? NSNumber {
                // Hardened runtime is the `runtime` bit in the CodeDirectory
                // flags (0x10000), reported by `codesign` as
                // `flags=0x10000(runtime)`. It is *not* `SecCodeStatus.hard`
                // (0x100), which is a status bit describing whether validation
                // had to treat the code as hard-linked. Comparing against that
                // reported every signed notarized app as lacking hardened
                // runtime.
                info.hasHardenedRuntime = (flagsNumber.uint32Value & codeDirectoryRuntimeMask) != 0
            }
            if let certs = dict[kSecCodeInfoCertificates as String] as? [SecCertificate],
               let leaf = certs.first {
                info.authority = SecCertificateCopySubjectSummary(leaf) as String?
            }
            if let statusNumber = dict[kSecCodeInfoStatus as String] as? NSNumber {
                let raw = statusNumber.uint32Value
                if (raw & SecCodeStatus.valid.rawValue) != 0 { info.verdict = .valid }
                if (raw & SecCodeStatus.platform.rawValue) != 0 { info.isPlatformBinary = true }
                if (raw & SecCodeStatus.debugged.rawValue) != 0 { info.hasHardenedRuntime = false }
            }
        } else {
            info.verdict = .unsigned
            if info.verdict == .valid { info.verdict = .valid }
        }

        if info.teamID == nil, info.verdict == .valid, !info.isPlatformBinary {
            // A valid signature without a Developer ID team is an ad-hoc signature.
            info.verdict = .adHoc
        }

        if info.source?.lowercased().contains("notarized") == true {
            info.notarized = !info.source!.lowercased().contains("unnotarized")
        }

        if checkNotarization, info.verdict == .valid, info.notarized == nil {
            applyGatekeeperVerdict(path: path, to: &info)
        }

        return info
    }

    /// `spctl` is the only supported way to learn the Gatekeeper/notarization verdict.
    private static func applyGatekeeperVerdict(path: String, to info: inout SignatureInfo) {
        guard let spctl = Shell.which("spctl") else {
            info.gatekeeperDetail = "spctl unavailable"
            return
        }
        let result = Shell.run(spctl, ["-a", "-vvv", "-t", "exec", path], timeout: 30)
        let text = result.combined.trimmingCharacters(in: .whitespacesAndNewlines)
        info.gatekeeperDetail = text

        let lower = text.lowercased()
        if lower.contains("origin=macos software signing") {
            info.isPlatformBinary = true
        }
        if lower.contains("source=notarized") {
            info.notarized = true
        } else if lower.contains("unnotarized") {
            info.notarized = false
        } else if result.status == 0 {
            info.notarized = true
        } else {
            info.notarized = false
        }
    }

    private static func describe(validationError error: CFError) -> String {
        let code = CFErrorGetCode(error)
        let domain = CFErrorGetDomain(error) as String
        let description: String = CFErrorCopyDescription(error) as String? ?? "unknown"
        // Validation errors usually carry the real reason in the description payload.
        return "\(domain)[\(code)]: \(description)"
    }

    /// Checks for the presence of an embedded signature without validating it.
    private static func hasSignature(staticCode: SecStaticCode) -> Bool {
        let status = SecStaticCodeCheckValidity(
            staticCode,
            SecCSFlags(rawValue: kSecCSBasicValidateOnly),
            nil
        )
        return status != errSecCSUnsigned && status != errSecCSStaticCodeNotFound
    }

    /// Whether the item carries an embedded code signature at all.
    /// Distinguishing "unsigned" from "tampered" is what keeps false positives away.
    public static func hasSignature(path: String) -> Bool {
        var staticCode: SecStaticCode?
        let url = URL(fileURLWithPath: path) as CFURL
        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else { return false }
        let status = SecStaticCodeCheckValidity(
            code,
            SecCSFlags(rawValue: kSecCSBasicValidateOnly),
            nil
        )
        return status != errSecCSUnsigned
    }

    /// Reads embedded entitlements that grant capabilities we treat as risk amplifiers.
    /// Entitlements live inside the signature blob, so codesign is the reliable extractor.
    public static func entitlements(path: String) -> [String: Any] {
        guard let codesign = Shell.which("codesign") else { return [:] }
        let result = Shell.run(codesign, ["-d", "--entitlements", "-", path], timeout: 20)
        let combined = result.combined
        guard let range = combined.range(of: "<?xml") else { return [:] }
        let xml = String(combined[range.lowerBound...])
        guard let xmlData = xml.data(using: .utf8),
              let plist = try? PropertyListSerialization.propertyList(from: xmlData, options: [], format: nil)
        else { return [:] }
        return plist as? [String: Any] ?? [:]
    }
}
