import Darwin
import Foundation

public struct AuthBrokerVerifiedPeer: Sendable, Equatable {
    public let peer: RequesterPeer
    public let peerSnapshot: ProcessSnapshot
    public let peerIdentity: LiveCodeIdentity
    public let requestingApplication: LiveCodeIdentity?

    public init(
        peer: RequesterPeer,
        peerSnapshot: ProcessSnapshot,
        peerIdentity: LiveCodeIdentity,
        requestingApplication: LiveCodeIdentity?
    ) {
        self.peer = peer
        self.peerSnapshot = peerSnapshot
        self.peerIdentity = peerIdentity
        self.requestingApplication = requestingApplication
    }
}

public struct AuthBrokerPeerVerifier: Sendable {
    public let expectedTeamID: String
    public let allowedIdentifiers: Set<String>
    public let currentUID: Int32
    public let maximumAncestryDepth: Int

    public init(
        expectedTeamID: String,
        allowedIdentifiers: Set<String> = ["macop", "macop-agent"],
        currentUID: Int32 = Int32(getuid()),
        maximumAncestryDepth: Int = 64
    ) {
        self.expectedTeamID = expectedTeamID
        self.allowedIdentifiers = allowedIdentifiers
        self.currentUID = currentUID
        self.maximumAncestryDepth = max(0, maximumAncestryDepth)
    }

    public func verify(
        peer: RequesterPeer,
        inspector: any RequesterInspecting = SystemRequesterInspector(),
        identityInspector: @Sendable (Int32) throws -> LiveCodeIdentity = { pid in
            try LiveCodeIdentityInspector.inspect(pid: pid).identity
        }
    ) throws -> AuthBrokerVerifiedPeer {
        guard self.maximumAncestryDepth > 0,
              peer.uid == self.currentUID, !self.expectedTeamID.isEmpty,
              let before = inspector.snapshot(of: peer.pid)
        else { throw AgentProtocolError.denied }
        let identity = try identityInspector(peer.pid)
        guard self.acceptsPeerIdentity(identity), inspector.snapshot(of: peer.pid) == before else {
            throw AgentProtocolError.denied
        }
        let requester = self.resolveRequestingApplication(
            startingAt: before.parentPID,
            inspector: inspector,
            identityInspector: identityInspector
        )
        guard inspector.snapshot(of: peer.pid) == before else { throw AgentProtocolError.denied }
        return AuthBrokerVerifiedPeer(
            peer: peer,
            peerSnapshot: before,
            peerIdentity: identity,
            requestingApplication: requester
        )
    }

    public func acceptsPeerIdentity(_ identity: LiveCodeIdentity) -> Bool {
        identity.hasTrustedPublisher && identity.teamID == self.expectedTeamID
            && self.allowedIdentifiers.contains(identity.identifier)
    }

    private func resolveRequestingApplication(
        startingAt pid: Int32,
        inspector: any RequesterInspecting,
        identityInspector: @Sendable (Int32) throws -> LiveCodeIdentity
    ) -> LiveCodeIdentity? {
        var currentPID = pid
        var seen = Set<Int32>()
        for _ in 0 ..< self.maximumAncestryDepth {
            guard currentPID > 1, seen.insert(currentPID).inserted,
                  let before = inspector.snapshot(of: currentPID)
            else { return nil }
            if let identity = try? identityInspector(currentPID),
               inspector.snapshot(of: currentPID) == before,
               Self.isApplicationExecutable(identity.canonicalPath)
            // swiftlint:disable:next opening_brace
            {
                return identity
            }
            currentPID = before.parentPID
        }
        return nil
    }

    private static func isApplicationExecutable(_ path: String) -> Bool {
        path.contains(".app/Contents/MacOS/")
    }
}
