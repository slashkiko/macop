import Foundation

public enum MacopAuthEntitlementPolicy {
    public struct Resolved: Sendable, Equatable {
        public let applicationIdentifier: String
        public let teamIdentifier: String
        public let managedKeychainAccessGroup: String
        public let sshKeyAccessGroup: String?

        public init(
            applicationIdentifier: String,
            teamIdentifier: String,
            managedKeychainAccessGroup: String,
            sshKeyAccessGroup: String?
        ) {
            self.applicationIdentifier = applicationIdentifier
            self.teamIdentifier = teamIdentifier
            self.managedKeychainAccessGroup = managedKeychainAccessGroup
            self.sshKeyAccessGroup = sshKeyAccessGroup
        }
    }

    public static let bundleIdentifier = "io.github.slashkiko.macop.auth"

    /// Accept only the two exact groups embedded in MacopAuth. A wildcard in a
    /// provisioning profile may authorize signing, but a wildcard entitlement
    /// at runtime must not expand the process's effective key ownership.
    public static func resolve(
        applicationIdentifier: String?,
        keychainAccessGroups: [String]?
    ) -> Resolved? {
        guard let applicationIdentifier,
              let keychainAccessGroups,
              let separator = applicationIdentifier.firstIndex(of: ".")
        else { return nil }
        let teamIdentifier = String(applicationIdentifier[..<separator])
        guard !teamIdentifier.isEmpty,
              applicationIdentifier == "\(teamIdentifier).\(self.bundleIdentifier)"
        else { return nil }
        let managedGroup = applicationIdentifier
        let sshGroup = "\(applicationIdentifier).ssh"
        guard keychainAccessGroups.contains(managedGroup) else { return nil }
        return Resolved(
            applicationIdentifier: applicationIdentifier,
            teamIdentifier: teamIdentifier,
            managedKeychainAccessGroup: managedGroup,
            sshKeyAccessGroup: keychainAccessGroups.contains(sshGroup) ? sshGroup : nil
        )
    }
}
