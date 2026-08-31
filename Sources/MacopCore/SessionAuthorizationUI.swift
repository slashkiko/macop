import AppKit
import Foundation
import LocalAuthentication

public struct SessionAuthorizationPresentation: Sendable, Equatable {
    public let identityLabel: String
    public let application: String
    public let verification: String
    public let signingAuthority: String
    public let cdHash: String
    public let fingerprint: String
    public let rootPID: Int32
    public let rootStartTime: UInt64
    public let rootIdentifier: String
    public let rootCodeRequirement: String
    public let rootExecutablePath: String
    public let sessionID: UUID
    public let expiresAt: Date

    public init(
        identityLabel: String,
        application: String,
        verification: String,
        signingAuthority: String,
        cdHash: String,
        fingerprint: String,
        rootPID: Int32,
        rootStartTime: UInt64,
        rootIdentifier: String,
        rootCodeRequirement: String,
        sessionID: UUID,
        expiresAt: Date,
        rootExecutablePath: String? = nil
    ) {
        self.identityLabel = identityLabel
        self.application = application
        self.verification = verification
        self.signingAuthority = signingAuthority
        self.cdHash = cdHash
        self.fingerprint = fingerprint
        self.rootPID = rootPID
        self.rootStartTime = rootStartTime
        self.rootIdentifier = rootIdentifier
        self.rootCodeRequirement = rootCodeRequirement
        self.rootExecutablePath = rootExecutablePath ?? application
        self.sessionID = sessionID
        self.expiresAt = expiresAt
    }
}

public protocol SessionAuthorizationResultPrompting: Sendable {
    func authorizeResult(
        _ presentation: SessionAuthorizationPresentation,
        completion: @escaping @Sendable (SessionAuthorizationResult) -> Void
    )
}

/// A successful result owns the same LAContext that must be supplied to
/// `CTKIdentitySigner`; callers must not replace it with a fresh context.
public final class SessionAuthorizationResult: @unchecked Sendable {
    public let approved: Bool
    public let authenticationContext: LAContext?
    public let signer: (any AgentKeySigning)?
    /// A safe broker category is retained for the agent's public boundary;
    /// `approved == false` alone is reserved for an ordinary user refusal.
    public let brokerFailure: AuthBrokerFailure?

    public init(
        approved: Bool,
        authenticationContext: LAContext?,
        signer: (any AgentKeySigning)? = nil,
        brokerFailure: AuthBrokerFailure? = nil
    ) {
        self.approved = approved
        self.authenticationContext = authenticationContext
        self.signer = signer
        self.brokerFailure = brokerFailure
    }
}

/// The prompt intentionally describes the boundary: it grants only a registry
/// session and cannot govern direct use of Apple's PKCS#11 provider.
public struct LocalAuthenticationSessionPrompt: SessionAuthorizationResultPrompting {
    public init() {}

    public func authorizeResult(
        _ presentation: SessionAuthorizationPresentation,
        completion: @escaping @Sendable (SessionAuthorizationResult) -> Void
    ) {
        // The runtime can be entered on the app main thread. Do not enqueue a
        // MainActor task and then make that same thread wait on its completion.
        if Thread.isMainThread {
            MainActor.assumeIsolated {
                Self.authorizeOnMain(presentation, completion: completion)
            }
            return
        }
        Task { @MainActor in
            Self.authorizeOnMain(presentation, completion: completion)
        }
    }

    @MainActor private static func authorizeOnMain(
        _ presentation: SessionAuthorizationPresentation,
        completion: @escaping @Sendable (SessionAuthorizationResult) -> Void
    ) {
        guard self.present(presentation) else {
            completion(SessionAuthorizationResult(approved: false, authenticationContext: nil)); return
        }
        let context = AuthenticationContextBox(LAContext())
        let expiry = ISO8601DateFormatter().string(from: presentation.expiresAt)
        let reason = "Identity: \(presentation.identityLabel); application: \(presentation.application); "
            + "signature: \(presentation.signingAuthority); cdhash: \(presentation.cdHash); "
            + "verification: \(presentation.verification); key: \(presentation.fingerprint); "
            + "session: \(presentation.sessionID.uuidString); expiry: \(expiry). "
            + "Direct CTK access outside macop-agent is not controlled."
        context.value.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, _ in
            completion(SessionAuthorizationResult(
                approved: success, authenticationContext: success ? context.value : nil
            ))
        }
    }

    @MainActor private static func present(_ presentation: SessionAuthorizationPresentation) -> Bool {
        let body = """
        Identity: \(presentation.identityLabel)
        Application: \(presentation.application)
        Signature: \(presentation.signingAuthority)
        CDHash: \(presentation.cdHash)
        Verification: \(presentation.verification)
        Key: \(presentation.fingerprint)
        Session: \(presentation.sessionID.uuidString)
        Expires: \(ISO8601DateFormatter().string(from: presentation.expiresAt))

        This authorization applies only through macop-agent. Direct CTK access outside it is not controlled.
        """
        var approved = false
        let show = {
            let alert = NSAlert()
            alert.messageText = "Authorize verified SSH session"
            alert.informativeText = body
            alert.addButton(withTitle: "Continue with Touch ID")
            alert.addButton(withTitle: "Cancel")
            approved = alert.runModal() == .alertFirstButtonReturn
        }
        show()
        return approved
    }
}

private final class AuthenticationContextBox: @unchecked Sendable {
    let value: LAContext
    init(_ value: LAContext) {
        self.value = value
    }
}
