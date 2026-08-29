import Darwin
import Foundation
import Security

/// A single signing snapshot collected from the live process image.  The
/// registry's designated requirement pins this exact image; these fields make
/// publisher provenance visible to the person approving a session.
public struct LiveCodeIdentity: Sendable, Equatable {
    public let canonicalPath: String
    public let identifier: String
    public let teamID: String?
    public let signingAuthority: String?
    public let cdHash: String?
    public let signatureFlags: UInt32
    public let hasTrustedPublisher: Bool
    public let disablesLibraryValidation: Bool
    // Stable cs_blobs ABI flags used by Apple's codesign and Security.framework.
    public static let hardenedRuntimeFlag: UInt32 = 0x0001_0000 // CS_RUNTIME
    public static let libraryValidationFlag: UInt32 = 0x0000_2000 // CS_REQUIRE_LV
    public init(
        canonicalPath: String,
        identifier: String,
        teamID: String?,
        signingAuthority: String?,
        cdHash: String?,
        signatureFlags: UInt32 = 0,
        hasTrustedPublisher: Bool,
        disablesLibraryValidation: Bool = false
    ) {
        self.canonicalPath = canonicalPath
        self.identifier = identifier
        self.teamID = teamID
        self.signingAuthority = signingAuthority
        self.cdHash = cdHash
        self.signatureFlags = signatureFlags
        self.hasTrustedPublisher = hasTrustedPublisher
        self.disablesLibraryValidation = disablesLibraryValidation
    }

    public var enforcesHardenedRuntimeLibraryValidation: Bool {
        self.signatureFlags & Self.hardenedRuntimeFlag != 0 && !self.disablesLibraryValidation
    }

    public var requiresLibraryValidation: Bool {
        self.signatureFlags & Self.libraryValidationFlag != 0 && !self.disablesLibraryValidation
    }

    public var provenanceSummary: String {
        if self.hasTrustedPublisher, let teamID, let signingAuthority {
            return "trusted signature (team \(teamID); \(signingAuthority)); exact image pinned"
        }
        return "exact image pinned; publisher unverified"
    }

    public var signatureSummary: String {
        let kind = self.teamID == nil && self.signingAuthority == nil ? "ad-hoc/unanchored" : "certificate-backed"
        return self.signingAuthority.map { "\(kind); \($0)" } ?? "\(kind); authority unavailable"
    }
}

public struct LiveCodeInspection: Sendable, Equatable {
    public let identity: LiveCodeIdentity
    public let codeRequirement: String

    public init(identity: LiveCodeIdentity, codeRequirement: String) {
        self.identity = identity
        self.codeRequirement = codeRequirement
    }
}

public enum LiveCodeIdentityInspector {
    public static func inspect(pid: Int32, expectedPath: String? = nil) throws -> LiveCodeInspection {
        guard pid > 0 else { throw AgentProtocolError.denied }
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &code) ==
            errSecSuccess,
            let code else { throw AgentProtocolError.denied }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            throw AgentProtocolError.denied
        }
        let candidate = try self.snapshot(
            staticCode: staticCode, expectedPath: expectedPath, staticallyValidated: false
        )
        return try self.validateLiveCandidate(code: code, candidate: candidate)
    }

    /// Deterministic race seam: even if metadata changes between the candidate
    /// read and validation, the forged identifier/team/cdhash requirement must
    /// fail against the original live SecCode before the snapshot is returned.
    public static func validateCandidateForTesting(
        pid: Int32,
        expectedPath: String,
        candidate: LiveCodeIdentity
    ) throws -> LiveCodeInspection {
        guard pid > 0,
              self.matchesExpectedPath(actual: candidate.canonicalPath, expected: expectedPath)
        else { throw AgentProtocolError.denied }
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &code) ==
            errSecSuccess,
            let code else { throw AgentProtocolError.denied }
        return try self.validateLiveCandidate(code: code, candidate: candidate)
    }

    public static func inspectTrusted(
        pid: Int32,
        expectedPath: String,
        identifier: String,
        teamID: String
    ) throws -> LiveCodeInspection {
        guard pid > 0, !identifier.isEmpty, !teamID.isEmpty
        else { throw AgentProtocolError.denied }
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &code) ==
            errSecSuccess,
            let code else { throw AgentProtocolError.denied }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            throw AgentProtocolError.denied
        }
        let candidate = try self.snapshot(
            staticCode: staticCode, expectedPath: expectedPath, staticallyValidated: false
        )
        guard candidate.identifier == identifier, candidate.teamID == teamID, candidate.hasTrustedPublisher,
              candidate.enforcesHardenedRuntimeLibraryValidation
        else {
            throw AgentProtocolError.denied
        }
        return try self.validateLiveCandidate(code: code, candidate: candidate)
    }

    /// Requires Apple's platform Git identity before it is launched. Xcode's
    /// Git uses the platform `anchor apple` requirement and CS_REQUIRE_LV,
    /// rather than the third-party hardened-runtime contract used by macop.
    public static func inspectExpectedAppleGitStatic(path: String) throws -> LiveCodeIdentity {
        let canonical = self.canonicalPath(path)
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: canonical) as CFURL, [], &staticCode) == errSecSuccess,
              let staticCode
        else { throw AgentProtocolError.denied }
        let candidate = try self.snapshot(
            staticCode: staticCode, expectedPath: canonical, staticallyValidated: true
        )
        let requirement = try self.expectedAppleGitRequirement()
        guard candidate.identifier == self.appleGitIdentifier, candidate.requiresLibraryValidation,
              SecStaticCodeCheckValidity(
                  staticCode, SecCSFlags(rawValue: kSecCSStrictValidate), requirement
              ) == errSecSuccess
        else { throw AgentProtocolError.denied }
        return candidate
    }

    /// Rechecks the same Apple requirement against the suspended live Git
    /// image, then pins its exact cdhash for the verified session.
    public static func inspectExpectedAppleGit(pid: Int32, expectedPath: String) throws -> LiveCodeInspection {
        guard pid > 0 else { throw AgentProtocolError.denied }
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &code) ==
            errSecSuccess,
            let code
        else { throw AgentProtocolError.denied }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            throw AgentProtocolError.denied
        }
        let candidate = try self.snapshot(
            staticCode: staticCode, expectedPath: expectedPath, staticallyValidated: false
        )
        let requirement = try self.expectedAppleGitRequirement()
        guard candidate.identifier == self.appleGitIdentifier, candidate.requiresLibraryValidation,
              SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess
        else { throw AgentProtocolError.denied }
        return try self.validateLiveCandidate(code: code, candidate: candidate)
    }

    public static func inspectStatic(path: String) throws -> LiveCodeIdentity {
        let canonical = self.canonicalPath(path)
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: canonical) as CFURL, [], &staticCode) == errSecSuccess,
              let staticCode else { throw AgentProtocolError.denied }
        return try self.snapshot(staticCode: staticCode, expectedPath: canonical, staticallyValidated: true)
    }

    public static func canonicalPath(_ path: String) -> String {
        URL(fileURLWithPath: path).resolvingSymlinksInPath().standardizedFileURL.path
    }

    public static func matchesExpectedPath(actual: String, expected: String) -> Bool {
        self.canonicalPath(actual) == self.canonicalPath(expected)
    }

    private static func snapshot(
        staticCode: SecStaticCode,
        expectedPath: String?,
        staticallyValidated: Bool
    ) throws -> LiveCodeIdentity {
        var raw: CFDictionary?
        let staticStatus = SecStaticCodeCheckValidity(staticCode, SecCSFlags(rawValue: kSecCSStrictValidate), nil)
        if staticallyValidated, staticStatus != errSecSuccess {
            throw AgentProtocolError.denied
        }
        let informationFlags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation)
        guard SecCodeCopySigningInformation(staticCode, informationFlags, &raw) ==
            errSecSuccess,
            let info = raw as? [CFString: Any],
            let identifier = info[kSecCodeInfoIdentifier] as? String, !identifier.isEmpty,
            let mainExecutable = info[kSecCodeInfoMainExecutable] as? URL
        else { throw AgentProtocolError.denied }
        let canonicalPath = self.canonicalPath(mainExecutable.path)
        guard expectedPath.map({ self.matchesExpectedPath(actual: canonicalPath, expected: $0) }) ?? true else {
            throw AgentProtocolError.denied
        }
        let teamID = info[kSecCodeInfoTeamIdentifier] as? String
        let authority = (info[kSecCodeInfoCertificates] as? [SecCertificate])?.first.flatMap {
            SecCertificateCopySubjectSummary($0) as String?
        }
        let cdHash = (info[kSecCodeInfoUnique] as? Data)?.map { String(format: "%02x", $0) }.joined()
        let flags = (info[kSecCodeInfoFlags] as? NSNumber)?.uint32Value ?? 0
        let entitlements = info[kSecCodeInfoEntitlementsDict] as? [String: Any]
        let disablesLibraryValidation = entitlements?["com.apple.security.cs.disable-library-validation"] as? Bool
            ?? false
        // Team IDs are assigned only to a certificate-backed identity.  Still
        // require Apple anchoring below before treating it as publisher proof.
        let trusted = teamID.map { self.isAppleAnchored(staticCode, teamID: $0, identifier: identifier) } ?? false
        return LiveCodeIdentity(
            canonicalPath: canonicalPath, identifier: identifier, teamID: teamID,
            signingAuthority: authority, cdHash: cdHash, signatureFlags: flags, hasTrustedPublisher: trusted,
            disablesLibraryValidation: disablesLibraryValidation
        )
    }

    private static func validateLiveCandidate(
        code: SecCode,
        candidate: LiveCodeIdentity
    ) throws -> LiveCodeInspection {
        let text = try self.finalRequirementText(for: candidate)
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement,
              SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess
        else { throw AgentProtocolError.denied }
        return LiveCodeInspection(identity: candidate, codeRequirement: text)
    }

    static func finalRequirementText(for candidate: LiveCodeIdentity) throws -> String {
        guard self.safeIdentifier(candidate.identifier), let cdHash = candidate.cdHash,
              self.safeCDHash(cdHash)
        else { throw AgentProtocolError.denied }
        let image = "identifier \"\(candidate.identifier)\" and cdhash H\"\(cdHash)\""
        guard candidate.hasTrustedPublisher else { return image }
        guard let teamID = candidate.teamID, self.safeTeamID(teamID) else { throw AgentProtocolError.denied }
        return "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\" and \(image)"
    }

    private static func safeIdentifier(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.allSatisfy { byte in
            byte >= 48 && byte <= 57 || byte >= 65 && byte <= 90 || byte >= 97 && byte <= 122
                || byte == 45 || byte == 46 || byte == 95
        }
    }

    private static func safeTeamID(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.allSatisfy { byte in
            byte >= 48 && byte <= 57 || byte >= 65 && byte <= 90
        }
    }

    private static func safeCDHash(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.allSatisfy { byte in
            byte >= 48 && byte <= 57 || byte >= 65 && byte <= 70 || byte >= 97 && byte <= 102
        }
    }

    private static func trustedRequirement(identifier: String, teamID: String) throws -> SecRequirement {
        guard self.safeIdentifier(identifier), self.safeTeamID(teamID) else { throw AgentProtocolError.denied }
        var requirement: SecRequirement?
        let text = "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\" and identifier \"\(identifier)\""
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement
        else {
            throw AgentProtocolError.denied
        }
        return requirement
    }

    private static let appleGitIdentifier = "com.apple.git"

    private static func expectedAppleGitRequirement() throws -> SecRequirement {
        var requirement: SecRequirement?
        let text = "anchor apple and identifier \"\(self.appleGitIdentifier)\""
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement
        else { throw AgentProtocolError.denied }
        return requirement
    }

    fileprivate static func isAppleAnchored(_ code: SecStaticCode, teamID: String, identifier: String) -> Bool {
        guard let requirement = try? self.trustedRequirement(identifier: identifier, teamID: teamID) else {
            return false
        }
        return SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) ==
            errSecSuccess
    }
}

/// Production verified-agent launches require a certificate-backed macop pair
/// from one Apple developer team. Ad-hoc source builds deliberately fail
/// closed: a same-UID user can replace either ad-hoc executable between checks.
public struct TrustedAgentLaunchPolicy: Sendable, Equatable {
    public let executablePath: String
    public let teamID: String
    public let identifier: String
    public init(executablePath: String, teamID: String, identifier: String) {
        self.executablePath = executablePath
        self.teamID = teamID
        self.identifier = identifier
    }

    public func validateRunningProcess(_ pid: Int32) throws {
        _ = try LiveCodeIdentityInspector.inspectTrusted(
            pid: pid,
            expectedPath: self.executablePath,
            identifier: self.identifier,
            teamID: self.teamID
        )
    }
}

public enum TrustedAgentHelperVerifier {
    public static let mainIdentifier = "macop"
    public static let helperIdentifier = "macop-agent"

    public static func resolveTrustedSibling(of mainExecutable: String) throws -> String {
        try self.resolveTrustedLaunch(of: mainExecutable).executablePath
    }

    public static func resolveTrustedLaunch(of mainExecutable: String) throws -> TrustedAgentLaunchPolicy {
        do {
            // Bind policy to the code actually executing this invocation,
            // rather than only the mutable pathname from which it was loaded.
            let main = try LiveCodeIdentityInspector.inspect(pid: getpid(), expectedPath: mainExecutable).identity
            guard main.identifier == self.mainIdentifier, main.hasTrustedPublisher, let teamID = main.teamID,
                  !teamID.isEmpty else { throw self.unavailable() }
            let helper = URL(fileURLWithPath: main.canonicalPath).deletingLastPathComponent()
                .appendingPathComponent("macop-agent").path
            var details = stat()
            guard lstat(helper, &details) == 0, details.st_mode & S_IFMT == S_IFREG,
                  details.st_uid == getuid(), details.st_mode & 0o022 == 0,
                  FileManager.default.isExecutableFile(atPath: helper)
            else { throw self.unavailable() }
            let identity = try LiveCodeIdentityInspector.inspectStatic(path: helper)
            guard self.isTrustedPair(main: main, helper: identity) else { throw self.unavailable() }
            return TrustedAgentLaunchPolicy(
                executablePath: identity.canonicalPath,
                teamID: teamID,
                identifier: self.helperIdentifier
            )
        } catch is CLIError {
            throw self.unavailable()
        } catch {
            // Security.framework errors must not escape as a generic runtime
            // error; unavailable provenance is an authorization denial.
            throw self.unavailable()
        }
    }

    /// Pure policy seam for deterministic tests. Callers must still obtain
    /// both inputs from strict Security.framework validation, as above.
    public static func isTrustedPair(main: LiveCodeIdentity, helper: LiveCodeIdentity) -> Bool {
        guard let mainTeam = main.teamID, !mainTeam.isEmpty,
              let helperTeam = helper.teamID, !helperTeam.isEmpty
        else { return false }
        return main.identifier == self.mainIdentifier && helper.identifier == self.helperIdentifier
            && main.hasTrustedPublisher && helper.hasTrustedPublisher
            && main.enforcesHardenedRuntimeLibraryValidation
            && helper.enforcesHardenedRuntimeLibraryValidation
            && mainTeam == helperTeam
    }

    /// Called by the helper after exec. This closes the validation-to-exec
    /// window: its *running* code must itself be trusted, not merely the path
    /// the parent checked before launching it.
    public static func requireTrustedRunningHelper() throws {
        let path = try RunningExecutable.path()
        let identity = try LiveCodeIdentityInspector.inspect(pid: getpid(), expectedPath: path).identity
        guard identity.identifier == self.helperIdentifier,
              identity.hasTrustedPublisher,
              identity.enforcesHardenedRuntimeLibraryValidation
        else { throw self.unavailable() }
    }

    private static func unavailable() -> CLIError {
        .unsupportedCommand(
            command: "ssh agent",
            reason: "Verified SSH sessions require a trusted team-signed, hardened-runtime macop and "
                + "macop-agent package with library validation enabled; ad-hoc source builds are not eligible."
        )
    }
}
