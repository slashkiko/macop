import Foundation

/// Boundary between the CLI launcher and the resident agent service. The
/// launcher never treats a socket path or nonce as proof of caller identity.
public protocol VerifiedSessionServing: Sendable {
    func reserveSession(keyFingerprint: String, expiresAt: Date) throws -> VerifiedSessionReservation
    func activateSession(reservation: VerifiedSessionReservation, request: VerifiedSessionLaunchRequest) throws
        -> VerifiedSession
}

public struct VerifiedSessionLaunchRequest: Sendable {
    public let rootPID: Int32
    public let rootStartTime: UInt64
    public let bundleID: String
    public let codeRequirement: String

    public init(rootPID: Int32, rootStartTime: UInt64, bundleID: String, codeRequirement: String) {
        self.rootPID = rootPID
        self.rootStartTime = rootStartTime
        self.bundleID = bundleID
        self.codeRequirement = codeRequirement
    }
}

public struct RegistrySessionService: VerifiedSessionServing {
    public let registry: SessionRegistry
    public init(registry: SessionRegistry) {
        self.registry = registry
    }

    public func reserveSession(keyFingerprint: String, expiresAt: Date) throws -> VerifiedSessionReservation {
        try self.registry.reserve(keyFingerprint: keyFingerprint, expiresAt: expiresAt)
    }

    // swiftlint:disable opening_brace
    public func activateSession(reservation: VerifiedSessionReservation,
                                request: VerifiedSessionLaunchRequest) throws -> VerifiedSession
    {
        try self.registry.activate(
            reservation: reservation,
            rootPID: request.rootPID,
            rootStartTime: request.rootStartTime,
            bundleID: request.bundleID,
            codeRequirement: request.codeRequirement,
            inspector: SystemRequesterInspector()
        )
    }
    // swiftlint:enable opening_brace
}

public enum VerifiedSessionLauncher {
    public static func environment(for reservation: VerifiedSessionReservation) -> [String: String] {
        // KERN_PROCARGS2 cannot reliably be read for another process on
        // current macOS (including a same-UID process), so an environment
        // value cannot be observed back from the launched root. Keep the
        // nonce as an opaque launcher-to-registry reservation capability
        // instead of leaking an unauthenticated value to the child.
        ["SSH_AUTH_SOCK": reservation.socketPath.path]
    }

    public static func environment(for session: VerifiedSession) -> [String: String] {
        ["SSH_AUTH_SOCK": session.socketPath.path]
    }

    public static func notice(for session: VerifiedSession) -> String {
        "Verified session \(session.id.uuidString) expires \(ISO8601DateFormatter().string(from: session.expiresAt)). "
            + "Approval applies only through macop-agent; direct Apple provider use is not controlled."
    }
}
