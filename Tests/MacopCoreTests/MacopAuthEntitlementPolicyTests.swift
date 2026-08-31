@testable import MacopCore
import XCTest

final class MacopAuthEntitlementPolicyTests: XCTestCase {
    func testResolvesOnlyExactManagedAndSSHGroups() {
        let applicationIdentifier = "TEAM123.io.github.slashkiko.macop.auth"
        XCTAssertEqual(
            MacopAuthEntitlementPolicy.resolve(
                applicationIdentifier: applicationIdentifier,
                keychainAccessGroups: [applicationIdentifier, "\(applicationIdentifier).ssh"]
            ),
            .init(
                applicationIdentifier: applicationIdentifier,
                teamIdentifier: "TEAM123",
                managedKeychainAccessGroup: applicationIdentifier,
                sshKeyAccessGroup: "\(applicationIdentifier).ssh"
            )
        )
    }

    func testPreservesManagedGroupWhenSSHGroupIsMissing() {
        let applicationIdentifier = "TEAM123.io.github.slashkiko.macop.auth"
        XCTAssertEqual(MacopAuthEntitlementPolicy.resolve(
            applicationIdentifier: applicationIdentifier,
            keychainAccessGroups: [applicationIdentifier]
        ), .init(
            applicationIdentifier: applicationIdentifier,
            teamIdentifier: "TEAM123",
            managedKeychainAccessGroup: applicationIdentifier,
            sshKeyAccessGroup: nil
        ))
    }

    func testRejectsWildcardRuntimeEntitlement() {
        XCTAssertNil(MacopAuthEntitlementPolicy.resolve(
            applicationIdentifier: "TEAM123.io.github.slashkiko.macop.auth",
            keychainAccessGroups: ["TEAM123.*"]
        ))
    }

    func testRejectsUnexpectedApplicationIdentifier() {
        XCTAssertNil(MacopAuthEntitlementPolicy.resolve(
            applicationIdentifier: "TEAM123.example.auth",
            keychainAccessGroups: ["TEAM123.example.auth", "TEAM123.example.auth.ssh"]
        ))
    }
}
