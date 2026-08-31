import LocalAuthentication
@testable import MacopCore
import Security
import XCTest

final class DirectSecureEnclaveKeyStoreTests: XCTestCase {
    private let rawID = "01234567-89ab-cdef-0123-456789abcdef"

    func testKeyIDRequiresCanonicalUUIDAndRoundTripsApplicationTag() throws {
        let id = try XCTUnwrap(DirectSecureEnclaveKeyID(rawValue: self.rawID))
        XCTAssertEqual(DirectSecureEnclaveKeyID.parse(applicationTag: id.applicationTag), id)
        XCTAssertNil(DirectSecureEnclaveKeyID(rawValue: self.rawID.uppercased()))
        XCTAssertNil(DirectSecureEnclaveKeyID(rawValue: "not-a-key-id"))
        XCTAssertNil(DirectSecureEnclaveKeyID.parse(applicationTag: Data("foreign".utf8)))
    }

    func testQueryBuilderPinsEveryLookupToPrivateAccessGroupAndSecureEnclave() throws {
        let group = "TEAM.io.github.slashkiko.macop.auth.ssh"
        let builder = try DirectSecureEnclaveKeyQueryBuilder(accessGroup: group)
        let id = try XCTUnwrap(DirectSecureEnclaveKeyID(rawValue: self.rawID))
        let query = builder.resolve(id)
        XCTAssertEqual(query[kSecClass] as? String, kSecClassKey as String)
        XCTAssertEqual(query[kSecAttrKeyClass] as? String, kSecAttrKeyClassPrivate as String)
        XCTAssertEqual(query[kSecAttrKeyType] as? String, kSecAttrKeyTypeECSECPrimeRandom as String)
        XCTAssertEqual(query[kSecAttrTokenID] as? String, kSecAttrTokenIDSecureEnclave as String)
        XCTAssertEqual(query[kSecAttrAccessGroup] as? String, group)
        XCTAssertEqual(query[kSecAttrApplicationTag] as? Data, id.applicationTag)
        XCTAssertEqual(query[kSecUseDataProtectionKeychain] as? Bool, true)
        XCTAssertEqual(query[kSecMatchLimit] as? String, kSecMatchLimitAll as String)
        XCTAssertEqual(query[kSecReturnRef] as? Bool, true)
    }

    func testEnumerationCannotFallBackToDefaultKeychain() throws {
        let group = "TEAM.io.github.slashkiko.macop.auth.ssh"
        let query = try DirectSecureEnclaveKeyQueryBuilder(accessGroup: group).enumerate()
        XCTAssertEqual(query[kSecAttrAccessGroup] as? String, group)
        XCTAssertEqual(query[kSecUseDataProtectionKeychain] as? Bool, true)
        XCTAssertEqual(query[kSecMatchLimit] as? String, kSecMatchLimitAll as String)
        XCTAssertEqual(query[kSecReturnAttributes] as? Bool, true)
    }

    func testResolveQueryCarriesTheExactAuthenticationContext() throws {
        let group = "TEAM.io.github.slashkiko.macop.auth.ssh"
        let id = try XCTUnwrap(DirectSecureEnclaveKeyID(rawValue: self.rawID))
        let context = LAContext()

        let query = try DirectSecureEnclaveKeyQueryBuilder(accessGroup: group).resolve(
            id,
            authenticationContext: context
        )

        XCTAssertTrue(query[kSecUseAuthenticationContext] as? LAContext === context)
    }

    func testRejectsEmptyWildcardAndNonSSHAccessGroups() {
        for group in ["", "TEAM.*", "TEAM.io.github.slashkiko.macop.auth"] {
            XCTAssertThrowsError(try DirectSecureEnclaveKeyQueryBuilder(accessGroup: group)) { error in
                XCTAssertEqual(error as? DirectSecureEnclaveKeyStoreError, .invalidAccessGroup)
            }
        }
    }

    func testRecordFingerprintIsDerivedFromPublicKeyBlob() throws {
        let id = try XCTUnwrap(DirectSecureEnclaveKeyID(rawValue: self.rawID))
        let blob = Data("public-key".utf8)
        let record = DirectSecureEnclaveKeyRecord(id: id, label: "github", publicKeyBlob: blob)
        XCTAssertEqual(record.fingerprint, sshFingerprint(for: blob))
    }
}
