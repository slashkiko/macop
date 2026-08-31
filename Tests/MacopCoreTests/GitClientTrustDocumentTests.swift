import Darwin
@testable import MacopCore
import Security
import XCTest

// swiftlint:disable file_length

private struct GitClientTrustFixtureFailure: Error {}

private struct GitClientTrustFixtureInspector: GitClientTrustInspecting {
    let identity: LiveCodeIdentity

    func inspectSelector(_: String) throws -> LiveCodeIdentity {
        self.identity
    }
}

private struct GitClientTrustFixtureExecutor: CommandExecuting {
    func execute(path _: String, arguments _: [String], environment _: CommandEnvironment) throws -> CommandResult {
        CommandResult(exitCode: 0)
    }
}

private final class GitClientTrustSnapshotFixture: @unchecked Sendable {
    private let lock = NSLock()
    private var calls = 0
    private let stable: ProcessSnapshot
    private let mutated: ProcessSnapshot?
    private let mutationCall: Int

    init(stable: ProcessSnapshot, mutated: ProcessSnapshot? = nil, mutationCall: Int = .max) {
        self.stable = stable
        self.mutated = mutated
        self.mutationCall = mutationCall
    }

    func snapshot(_: Int32) -> ProcessSnapshot? {
        self.lock.lock(); defer { self.lock.unlock() }
        self.calls += 1
        if self.calls >= self.mutationCall {
            return self.mutated
        }
        return self.stable
    }
}

// swiftlint:disable:next type_body_length
final class GitClientTrustDocumentTests: XCTestCase {
    private func entry(selector: String = "/opt/git") -> GitClientTrustEntry {
        GitClientTrustEntry(
            selectorPath: selector, resolvedPath: "/opt/git-real", identifier: "com.example.git",
            cdHash: "aabbccdd", codeRequirement: "identifier \"com.example.git\" and cdhash H\"aabbccdd\"",
            teamID: "", publisherVerified: false, signatureKind: "exact image pinned", version: "1.0"
        )
    }

    func testCanonicalDocumentIsStableAndCoversEveryEntryField() throws {
        let first = GitClientTrustDocument(
            generation: 7,
            clients: [self.entry(selector: "/z"), self.entry(selector: "/a")]
        )
        let reordered = GitClientTrustDocument(
            generation: 7,
            clients: [self.entry(selector: "/a"), self.entry(selector: "/z")]
        )
        XCTAssertEqual(try first.canonicalBytes(), try reordered.canonicalBytes())
        XCTAssertEqual(try first.digest(), try reordered.digest())
        var changed = self.entry(); changed = GitClientTrustEntry(
            selectorPath: changed.selectorPath, resolvedPath: changed.resolvedPath, identifier: changed.identifier,
            cdHash: changed.cdHash, codeRequirement: changed.codeRequirement, teamID: changed.teamID,
            publisherVerified: changed.publisherVerified, signatureKind: changed.signatureKind, version: "2.0"
        )
        XCTAssertNotEqual(try GitClientTrustDocument(generation: 7, clients: [changed]).digest(),
                          try GitClientTrustDocument(generation: 7, clients: [self.entry()]).digest())
    }

    func testEveryTrustEntryFieldChangesCanonicalDigest() throws {
        let original = self.entry()
        let baseline = try GitClientTrustDocument(generation: 1, clients: [original]).digest()
        let variants = [
            GitClientTrustEntry(
                selectorPath: "/opt/other",
                resolvedPath: original.resolvedPath,
                identifier: original.identifier,
                cdHash: original.cdHash,
                codeRequirement: original.codeRequirement,
                teamID: original.teamID,
                publisherVerified: original.publisherVerified,
                signatureKind: original.signatureKind,
                version: original.version
            ),
            GitClientTrustEntry(
                selectorPath: original.selectorPath,
                resolvedPath: "/opt/other-real",
                identifier: original.identifier,
                cdHash: original.cdHash,
                codeRequirement: original.codeRequirement,
                teamID: original.teamID,
                publisherVerified: original.publisherVerified,
                signatureKind: original.signatureKind,
                version: original.version
            ),
            GitClientTrustEntry(
                selectorPath: original.selectorPath,
                resolvedPath: original.resolvedPath,
                identifier: "com.example.other",
                cdHash: original.cdHash,
                codeRequirement: "identifier \"com.example.other\" and cdhash H\"aabbccdd\"",
                teamID: "",
                publisherVerified: false,
                signatureKind: original.signatureKind,
                version: original.version
            ),
            GitClientTrustEntry(
                selectorPath: original.selectorPath,
                resolvedPath: original.resolvedPath,
                identifier: original.identifier,
                cdHash: "bbccddeeff",
                codeRequirement: "identifier \"com.example.git\" and cdhash H\"bbccddeeff\"",
                teamID: "",
                publisherVerified: false,
                signatureKind: original.signatureKind,
                version: original.version
            ),
            GitClientTrustEntry(
                selectorPath: original.selectorPath,
                resolvedPath: original.resolvedPath,
                identifier: original.identifier,
                cdHash: original.cdHash,
                codeRequirement: original.codeRequirement,
                teamID: original.teamID,
                publisherVerified: original.publisherVerified,
                signatureKind: "other display",
                version: original.version
            ),
            GitClientTrustEntry(
                selectorPath: original.selectorPath,
                resolvedPath: original.resolvedPath,
                identifier: original.identifier,
                cdHash: original.cdHash,
                codeRequirement: original.codeRequirement,
                teamID: original.teamID,
                publisherVerified: original.publisherVerified,
                signatureKind: original.signatureKind,
                version: "2.0"
            )
        ]
        for variant in variants {
            XCTAssertNotEqual(baseline, try GitClientTrustDocument(generation: 1, clients: [variant]).digest())
        }
        let publisher = GitClientTrustEntry(
            selectorPath: original.selectorPath,
            resolvedPath: original.resolvedPath,
            identifier: original.identifier,
            cdHash: original.cdHash,
            codeRequirement: "anchor apple generic and certificate leaf[subject.OU] = \"EXAMPLE1234\" "
                + "and identifier \"com.example.git\" and cdhash H\"aabbccdd\"",
            teamID: "EXAMPLE1234",
            publisherVerified: true,
            signatureKind: original.signatureKind,
            version: original.version
        )
        XCTAssertNotEqual(baseline, try GitClientTrustDocument(generation: 1, clients: [publisher]).digest())
    }

    func testKeychainQueryBuilderPinsPrivateGroupDataProtectionAndAccessibility() throws {
        let builder = GitClientTrustKeychainQueryBuilder(accessGroup: "TEAM.io.github.slashkiko.macop.auth")
        for query in [
            builder.add(), builder.read(), builder.update(generation: Data(repeating: 0, count: 8)), builder.delete()
        ] {
            XCTAssertEqual(query[kSecAttrAccessGroup] as? String, "TEAM.io.github.slashkiko.macop.auth")
            XCTAssertEqual(query[kSecUseDataProtectionKeychain] as? Bool, true)
            XCTAssertEqual(
                try String(describing: XCTUnwrap(query[kSecAttrAccessible])),
                String(describing: kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
            )
        }
    }

    func testCanonicalDecoderRejectsUnknownAndDuplicateKeys() throws {
        XCTAssertThrowsError(try GitClientTrustDocument
            .decodeCanonical(Data("{\"schema_version\":2,\"generation\":1,\"clients\":[],\"extra\":true}".utf8)))
        XCTAssertThrowsError(try GitClientTrustDocument
            .decodeCanonical(Data("{\"schema_version\":2,\"generation\":1,\"generation\":1,\"clients\":[]}".utf8)))
    }

    func testAuthorityRejectsTamperReplayRemovalAndGenerationRollback() throws {
        let authority = InMemoryGitClientTrustAuthority()
        let initial = GitClientTrustDocument(generation: 1, clients: [self.entry()])
        try authority.authorizeMutation(operation: .enroll, expectedGeneration: 0, nextDocument: initial,
                                        canonicalDocument: initial.canonicalBytes(), digest: initial.digest())
        try authority.verify(document: initial, canonicalDocument: initial.canonicalBytes(), digest: initial.digest())
        let removed = GitClientTrustDocument(generation: 2, clients: [])
        try authority.authorizeMutation(operation: .remove, expectedGeneration: 1, nextDocument: removed,
                                        canonicalDocument: removed.canonicalBytes(), digest: removed.digest())
        XCTAssertThrowsError(try authority.verify(
            document: initial,
            canonicalDocument: initial.canonicalBytes(),
            digest: initial.digest()
        ))
        XCTAssertThrowsError(try authority.authorizeMutation(
            operation: .enroll,
            expectedGeneration: 1,
            nextDocument: initial,
            canonicalDocument: initial.canonicalBytes(),
            digest: initial.digest()
        ))
    }

    func testStateStoreCASRejectsExpectedGenerationRace() throws {
        let store = InMemoryGitClientTrustStateStore()
        let one = GitClientTrustProtectedState(generation: 1, documentDigest: Data(repeating: 1, count: 32))
        XCTAssertTrue(try store.compareAndSwap(expectedGeneration: nil, next: one))
        XCTAssertFalse(try store.compareAndSwap(
            expectedGeneration: 0,
            next: GitClientTrustProtectedState(generation: 1, documentDigest: Data(repeating: 2, count: 32))
        ))
        XCTAssertTrue(try store.compareAndSwap(
            expectedGeneration: 1,
            next: GitClientTrustProtectedState(generation: 2, documentDigest: Data(repeating: 2, count: 32))
        ))
    }

    func testTrustWireBindsRequestDigestGenerationAndMessageType() throws {
        let document = GitClientTrustDocument(generation: 9, clients: [self.entry()])
        let digest = try document.digest()
        let request = try AuthBrokerGitClientTrustVerifyRequest(
            requestID: UUID(),
            canonicalDocument: document.canonicalBytes(),
            digest: digest
        )
        var frame = try AuthBrokerWire.frame(.gitClientTrustVerifyRequest(request))
        XCTAssertEqual(try AuthBrokerWire.takeFrame(from: &frame), .gitClientTrustVerifyRequest(request))
        let response = AuthBrokerGitClientTrustVerifyResponse(
            requestID: request.requestID,
            digest: digest,
            generation: 9,
            status: .trusted
        )
        frame = try AuthBrokerWire.frame(.gitClientTrustVerifyResponse(response))
        XCTAssertEqual(try AuthBrokerWire.takeFrame(from: &frame), .gitClientTrustVerifyResponse(response))
    }

    func testTrustResponseClassificationKeepsBrokerAndBusinessFailuresDistinct() throws {
        let requestID = UUID()
        let authorizationID = UUID()
        let digest = Data(repeating: 9, count: 32)
        let generation: UInt64 = 4

        try AuthBrokerGitClientTrustVerifier.validateVerifyResponse(
            .gitClientTrustVerifyResponse(AuthBrokerGitClientTrustVerifyResponse(
                requestID: requestID, digest: digest, generation: generation, status: .trusted
            )),
            requestID: requestID,
            digest: digest,
            generation: generation
        )
        self.assertBrokerFailure(.protocolMismatch) {
            try AuthBrokerGitClientTrustVerifier.validateVerifyResponse(
                .gitClientTrustVerifyResponse(AuthBrokerGitClientTrustVerifyResponse(
                    requestID: UUID(), digest: digest, generation: generation, status: .trusted
                )), requestID: requestID, digest: digest, generation: generation
            )
        }
        self.assertBrokerFailure(.protocolMismatch) {
            try AuthBrokerGitClientTrustVerifier.validateVerifyResponse(
                .gitClientTrustStateResponse(AuthBrokerGitClientTrustStateResponse(
                    requestID: requestID, generation: generation, status: .trusted
                )), requestID: requestID, digest: digest, generation: generation
            )
        }
        XCTAssertThrowsError(try AuthBrokerGitClientTrustVerifier.validateVerifyResponse(
            .gitClientTrustVerifyResponse(AuthBrokerGitClientTrustVerifyResponse(
                requestID: requestID, digest: digest, generation: generation, status: .mismatch
            )), requestID: requestID, digest: digest, generation: generation
        )) { error in
            XCTAssertEqual(error as? GitClientTrustFailure, .stateMismatch)
        }
        XCTAssertThrowsError(try AuthBrokerGitClientTrustVerifier.validateVerifyResponse(
            .gitClientTrustVerifyResponse(AuthBrokerGitClientTrustVerifyResponse(
                requestID: requestID, digest: digest, generation: generation, status: .unavailable
            )), requestID: requestID, digest: digest, generation: generation
        )) { error in
            XCTAssertEqual(error as? GitClientTrustFailure, .stateUnavailable)
        }

        self.assertBrokerFailure(.userDenied) {
            try AuthBrokerGitClientTrustVerifier.validateMutationResponse(
                .gitClientTrustMutationResponse(AuthBrokerGitClientTrustMutationResponse(
                    authorizationID: authorizationID, digest: digest, generation: generation, status: .rejected
                )), authorizationID: authorizationID, digest: digest, generation: generation
            )
        }
        XCTAssertThrowsError(try AuthBrokerGitClientTrustVerifier.validateMutationResponse(
            .gitClientTrustMutationResponse(AuthBrokerGitClientTrustMutationResponse(
                authorizationID: authorizationID, digest: digest, generation: generation, status: .generationConflict
            )), authorizationID: authorizationID, digest: digest, generation: generation
        )) { error in
            XCTAssertEqual(error as? GitClientTrustFailure, .generationConflict)
        }
        self.assertBrokerFailure(.protocolMismatch) {
            try AuthBrokerGitClientTrustVerifier.validateMutationResponse(
                .gitClientTrustMutationResponse(AuthBrokerGitClientTrustMutationResponse(
                    authorizationID: UUID(), digest: digest, generation: generation, status: .approved
                )), authorizationID: authorizationID, digest: digest, generation: generation
            )
        }

        let brokerRendering = ErrorRenderer.render(
            error: AuthBrokerFailure(.userDenied).cliError,
            format: .json
        )
        XCTAssertTrue(brokerRendering.stderr.contains("user_denied"))
        let conflictRendering = ErrorRenderer.render(
            error: GitClientTrustFailure.generationConflict.cliError,
            format: .json
        )
        XCTAssertFalse(conflictRendering.stderr.contains("broker_failure"))
        XCTAssertTrue(conflictRendering.stderr.contains("Git client trust state changed concurrently"))
    }

    func testLockedRegistryTransactionStaysBoundToOriginalDirectoryAndClosesDescriptors() throws {
        let fileManager = FileManager.default
        let root = fileManager.temporaryDirectory.appendingPathComponent("macop-registry-fd-\(UUID().uuidString)")
        defer { try? fileManager.removeItem(at: root) }
        let registryLeaf = "custom-registry.json"
        let originalDirectory = root.appendingPathComponent("registry")
        let replacementDirectory = root.appendingPathComponent("replacement")
        let movedDirectory = root.appendingPathComponent("moved")
        try fileManager.createDirectory(at: originalDirectory, withIntermediateDirectories: true)
        try fileManager.createDirectory(at: replacementDirectory, withIntermediateDirectories: true)
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: originalDirectory.path)
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: replacementDirectory.path)

        let original = GitClientTrustDocument(generation: 1, clients: [self.entry()])
        let replacement = GitClientTrustDocument(generation: 44, clients: [])
        let updated = GitClientTrustDocument(generation: 2, clients: [])
        let originalFile = originalDirectory.appendingPathComponent(registryLeaf)
        let replacementFile = replacementDirectory.appendingPathComponent(registryLeaf)
        try original.canonicalBytes().write(to: originalFile)
        try replacement.canonicalBytes().write(to: replacementFile)
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: originalFile.path)
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: replacementFile.path)

        let originalRegistryPath = try GitClientRegistryFilesystem.validatedPath(for: originalFile)
        try GitClientRegistryFilesystem.withExclusiveLock(registryPath: originalRegistryPath) { directory in
            XCTAssertEqual(rename(originalDirectory.path, movedDirectory.path), 0)
            XCTAssertEqual(rename(replacementDirectory.path, originalDirectory.path), 0)
            XCTAssertEqual(try directory.readRegistry(), try original.canonicalBytes())
            try directory.writeRegistry(updated)
        }
        XCTAssertEqual(
            try Data(contentsOf: movedDirectory.appendingPathComponent(registryLeaf)),
            try updated.canonicalBytes()
        )
        XCTAssertEqual(
            try Data(contentsOf: originalDirectory.appendingPathComponent(registryLeaf)),
            try replacement.canonicalBytes()
        )
        XCTAssertFalse(fileManager.fileExists(
            atPath: movedDirectory.appendingPathComponent(GitClientRegistryFilesystem.registryFileName).path
        ))
        XCTAssertFalse(fileManager.fileExists(
            atPath: originalDirectory.appendingPathComponent(GitClientRegistryFilesystem.registryFileName).path
        ))

        let protectedTemporary = movedDirectory.appendingPathComponent(".git-clients.tmp")
        try Data("must-not-be-deleted".utf8).write(to: protectedTemporary)
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: protectedTemporary.path)
        let movedRegistryPath = try GitClientRegistryFilesystem.validatedPath(
            for: movedDirectory.appendingPathComponent(registryLeaf)
        )
        try GitClientRegistryFilesystem.withExclusiveLock(registryPath: movedRegistryPath) { directory in
            try directory.writeRegistry(updated)
        }
        XCTAssertEqual(try Data(contentsOf: protectedTemporary), Data("must-not-be-deleted".utf8))

        let descriptorCount = try fileManager.contentsOfDirectory(atPath: "/dev/fd").count
        for _ in 0 ..< 10 {
            XCTAssertThrowsError(
                try GitClientRegistryFilesystem.withExclusiveLock(registryPath: movedRegistryPath) { directory in
                    _ = try directory.readRegistry()
                    throw GitClientTrustFixtureFailure()
                }
            )
        }
        XCTAssertEqual(try fileManager.contentsOfDirectory(atPath: "/dev/fd").count, descriptorCount)
    }

    func testCustomRegistryLeafIsUsedForListAndMutationsWithoutDefaultSibling() throws {
        let fileManager = FileManager.default
        let root = fileManager.temporaryDirectory.appendingPathComponent("macop-custom-registry-\(UUID().uuidString)")
        defer { try? fileManager.removeItem(at: root) }
        let customURL = root.appendingPathComponent("custom.json")
        let defaultURL = root.appendingPathComponent(GitClientRegistryFilesystem.registryFileName)
        let identity = LiveCodeIdentity(
            canonicalPath: "/opt/git-real", identifier: "com.example.git", teamID: nil, signingAuthority: nil,
            cdHash: "aabbccdd", hasTrustedPublisher: false
        )
        let authority = InMemoryGitClientTrustAuthority()
        let registry = GitClientTrustRegistry(
            fileURL: customURL, inspector: GitClientTrustFixtureInspector(identity: identity), verifier: authority,
            mutator: authority
        )

        XCTAssertEqual(try registry.list(), [])
        XCTAssertFalse(fileManager.fileExists(atPath: defaultURL.path))
        try registry.reset()
        XCTAssertTrue(fileManager.fileExists(atPath: customURL.path))
        XCTAssertFalse(fileManager.fileExists(atPath: defaultURL.path))
        XCTAssertEqual(try registry.list(), [])

        let trusted = try registry.trust(selectorPath: "/opt/git", version: "1.0")
        XCTAssertEqual(try registry.list(), [trusted])
        XCTAssertFalse(fileManager.fileExists(atPath: defaultURL.path))
        XCTAssertEqual(try registry.remove(selectorPath: trusted.selectorPath), trusted)
        XCTAssertEqual(try registry.list(), [])
        XCTAssertFalse(fileManager.fileExists(atPath: defaultURL.path))
    }

    func testMissingRegistryIsRejectedWhenProtectedStateExists() throws {
        let fileManager = FileManager.default
        let root = fileManager.temporaryDirectory.appendingPathComponent("macop-missing-registry-\(UUID().uuidString)")
        defer { try? fileManager.removeItem(at: root) }
        let registryURL = root.appendingPathComponent(GitClientRegistryFilesystem.registryFileName)
        let identity = LiveCodeIdentity(
            canonicalPath: "/opt/git-real", identifier: "com.example.git", teamID: nil, signingAuthority: nil,
            cdHash: "aabbccdd", hasTrustedPublisher: false
        )
        let authority = InMemoryGitClientTrustAuthority()
        let registry = GitClientTrustRegistry(
            fileURL: registryURL, inspector: GitClientTrustFixtureInspector(identity: identity), verifier: authority,
            mutator: authority
        )

        _ = try registry.trust(selectorPath: "/opt/git", version: "1.0")
        try fileManager.removeItem(at: registryURL)

        XCTAssertThrowsError(try registry.list()) { error in
            XCTAssertTrue(String(describing: error).contains("protected trust state still exists"))
        }
    }

    func testMissingReservedRegistryLeafIsRejectedBeforeListShortcut() throws {
        let fileManager = FileManager.default
        let root = fileManager.temporaryDirectory.appendingPathComponent("macop-reserved-registry-\(UUID().uuidString)")
        defer { try? fileManager.removeItem(at: root) }
        let identity = LiveCodeIdentity(
            canonicalPath: "/opt/git-real", identifier: "com.example.git", teamID: nil, signingAuthority: nil,
            cdHash: "aabbccdd", hasTrustedPublisher: false
        )
        let authority = InMemoryGitClientTrustAuthority()
        let registry = GitClientTrustRegistry(
            fileURL: root.appendingPathComponent(".git-clients.lock"),
            inspector: GitClientTrustFixtureInspector(identity: identity), verifier: authority, mutator: authority
        )

        XCTAssertThrowsError(try registry.list())
        XCTAssertFalse(fileManager.fileExists(atPath: root.path))
    }

    func testNonAppleGitRequesterValidationBuildsPinnedApprovalRequest() throws {
        let snapshot = ProcessSnapshot(pid: 71, parentPID: 1, startTime: 9)
        let identity = self.signedNonAppleGitIdentity()
        let entry = self.signedNonAppleGitEntry(identity: identity)
        let inspection = LiveCodeInspection(identity: identity, codeRequirement: entry.codeRequirement)
        let environment = GitClientRequesterValidationEnvironment(
            snapshot: { _ in snapshot },
            executablePath: { _ in identity.canonicalPath },
            inspectAppleGit: { _, _ in throw AgentProtocolError.denied },
            inspectSelector: { _ in identity },
            inspectLiveCode: { _, _ in inspection },
            loadRegistry: { [entry] }
        )

        let request = try AuthBrokerRequester.gitSSHSigningApprovalRequest(
            credentialLabel: "fixture", credentialFingerprint: "SHA256:fixture", rootPID: snapshot.pid,
            requesterEnvironment: environment
        )
        var frame = try AuthBrokerWire.frame(.approvalRequest(request))
        XCTAssertEqual(try AuthBrokerWire.takeFrame(from: &frame), .approvalRequest(request))
        XCTAssertEqual(request.rootPID, snapshot.pid)
        XCTAssertEqual(request.rootStartTime, snapshot.startTime)
        XCTAssertEqual(request.rootIdentifier, identity.identifier)
        XCTAssertEqual(request.rootExecutablePath, identity.canonicalPath)
        XCTAssertEqual(request.rootCodeRequirement, entry.codeRequirement)
    }

    func testNonAppleGitRequesterValidationRejectsUnregisteredAndPinBypass() throws {
        let snapshot = ProcessSnapshot(pid: 72, parentPID: 1, startTime: 10)
        let identity = self.signedNonAppleGitIdentity()
        let entry = self.signedNonAppleGitEntry(identity: identity)
        let unregistered = GitClientRequesterValidationEnvironment(
            snapshot: { _ in snapshot }, executablePath: { _ in identity.canonicalPath },
            inspectAppleGit: { _, _ in throw AgentProtocolError.denied }, inspectSelector: { _ in identity },
            inspectLiveCode: { _, _ in LiveCodeInspection(identity: identity, codeRequirement: entry.codeRequirement) },
            loadRegistry: { [] }
        )
        XCTAssertThrowsError(try GitClientRequesterTrust.validate(pid: snapshot.pid, environment: unregistered))

        let changedIdentity = LiveCodeIdentity(
            canonicalPath: identity.canonicalPath, identifier: identity.identifier, teamID: identity.teamID,
            signingAuthority: identity.signingAuthority, cdHash: "00112233", hasTrustedPublisher: true
        )
        let pinBypass = GitClientRequesterValidationEnvironment(
            snapshot: { _ in snapshot }, executablePath: { _ in identity.canonicalPath },
            inspectAppleGit: { _, _ in throw AgentProtocolError.denied }, inspectSelector: { _ in changedIdentity },
            inspectLiveCode: { _, _ in LiveCodeInspection(identity: identity, codeRequirement: entry.codeRequirement) },
            loadRegistry: { [entry] }
        )
        XCTAssertThrowsError(try GitClientRequesterTrust.validate(pid: snapshot.pid, environment: pinBypass))
    }

    func testNonAppleGitRequesterValidationRejectsRootAttributionMutation() throws {
        let stable = ProcessSnapshot(pid: 73, parentPID: 1, startTime: 11)
        let changed = ProcessSnapshot(pid: 73, parentPID: 1, startTime: 12)
        let snapshots = GitClientTrustSnapshotFixture(stable: stable, mutated: changed, mutationCall: 4)
        let identity = self.signedNonAppleGitIdentity()
        let entry = self.signedNonAppleGitEntry(identity: identity)
        let environment = GitClientRequesterValidationEnvironment(
            snapshot: { snapshots.snapshot($0) }, executablePath: { _ in identity.canonicalPath },
            inspectAppleGit: { _, _ in throw AgentProtocolError.denied }, inspectSelector: { _ in identity },
            inspectLiveCode: { _, _ in LiveCodeInspection(identity: identity, codeRequirement: entry.codeRequirement) },
            loadRegistry: { [entry] }
        )
        XCTAssertThrowsError(try AuthBrokerRequester.gitSSHSigningApprovalRequest(
            credentialLabel: "fixture", credentialFingerprint: "SHA256:fixture", rootPID: stable.pid,
            requesterEnvironment: environment
        ))
    }

    func testSSHGitClientDispatcherUsesInjectedRegistryAndMatchesAdvertisedActions() throws {
        let fileManager = FileManager.default
        let root = fileManager.temporaryDirectory.appendingPathComponent("macop-git-dispatch-\(UUID().uuidString)")
        defer { try? fileManager.removeItem(at: root) }
        let identity = LiveCodeIdentity(
            canonicalPath: "/opt/git-real", identifier: "com.example.git", teamID: nil, signingAuthority: nil,
            cdHash: "aabbccdd", hasTrustedPublisher: false
        )
        let authority = InMemoryGitClientTrustAuthority()
        let registry = GitClientTrustRegistry(
            fileURL: root.appendingPathComponent(GitClientRegistryFilesystem.registryFileName),
            inspector: GitClientTrustFixtureInspector(identity: identity), verifier: authority, mutator: authority
        )
        let run: ([String]) throws -> CommandResult = { args in
            try SSHCommand.run(
                args: args, options: GlobalOptions(), env: ["HOME": root.path],
                executor: GitClientTrustFixtureExecutor(),
                gitClientRegistry: registry, gitClientVersionProbe: GitClientTrustDocumentTests.VersionProbe()
            )
        }
        XCTAssertTrue(try run(["git-client", "trust", "/opt/git"]).stdout.contains("trusted: /opt/git"))
        XCTAssertTrue(try run(["git-client", "list"]).stdout.contains("/opt/git"))
        XCTAssertTrue(try run(["git-client", "remove", "/opt/git"]).stdout.contains("removed: /opt/git"))
        XCTAssertThrowsError(try run(["git-client", "unknown"]))
        XCTAssertThrowsError(try run(["remove", "/opt/git"]))
        XCTAssertEqual(try registry.list(), [])
        let gitClientAdvertisingTexts = [
            HelpText.main, CompletionText.render(shell: "zsh"), CompletionText.render(shell: "bash"),
            CompletionText.render(shell: "fish")
        ]
        let actions = ["trust", "list", "remove", "migrate", "reset"]
        for action in actions {
            XCTAssertTrue(HelpText.main.contains("ssh git-client \(action)"))
        }
        for text in gitClientAdvertisingTexts.dropFirst() {
            XCTAssertTrue(actions.allSatisfy(text.contains))
        }
    }

    private struct VersionProbe: GitClientVersionProbing {
        func version(executablePath _: String) -> String {
            "git version fixture"
        }
    }

    private func signedNonAppleGitIdentity() -> LiveCodeIdentity {
        LiveCodeIdentity(
            canonicalPath: "/opt/homebrew/Cellar/git/2.50/bin/git", identifier: "com.example.git",
            teamID: "EXAMPLE1234", signingAuthority: "Example Developer", cdHash: "aabbccdd",
            hasTrustedPublisher: true
        )
    }

    private func signedNonAppleGitEntry(identity: LiveCodeIdentity) -> GitClientTrustEntry {
        GitClientTrustEntry(
            selectorPath: "/opt/homebrew/bin/git", resolvedPath: identity.canonicalPath,
            identifier: identity.identifier,
            cdHash: "aabbccdd",
            codeRequirement: "anchor apple generic and certificate leaf[subject.OU] = \"EXAMPLE1234\" and "
                + "identifier \"com.example.git\" and cdhash H\"aabbccdd\"",
            teamID: "EXAMPLE1234", publisherVerified: true, signatureKind: "certificate-backed", version: "2.50"
        )
    }

    private func assertBrokerFailure(
        _ expected: AuthBrokerFailureCategory,
        operation: () throws -> Any
    ) {
        XCTAssertThrowsError(try operation()) { error in
            XCTAssertEqual((error as? AuthBrokerFailure)?.category, expected)
        }
    }
}
