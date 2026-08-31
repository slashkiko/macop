import Foundation
@testable import MacopCore
import XCTest

final class AuthEffectPipelineTests: XCTestCase {
    func testPostAuthenticationRequesterFailureDiscardsSignature() {
        var deliveredOutcome: AuthBrokerSSHSignOutcome?
        var deliveredSignature = Data([9])
        let presentation = AuthEffectPipeline.signing(
            operation: .sshSession,
            prepare: {},
            sign: { Data([1, 2, 3]) },
            revalidate: { throw AgentProtocolError.denied },
            deliver: { outcome, signature in
                deliveredOutcome = outcome
                deliveredSignature = signature
            }
        )

        XCTAssertEqual(deliveredOutcome, .requesterInvalid)
        XCTAssertTrue(deliveredSignature.isEmpty)
        XCTAssertFalse(presentation.isSuccess)
    }

    func testSignatureIsDeliveredOnlyAfterSecondValidation() {
        var order: [String] = []
        let presentation = AuthEffectPipeline.signing(
            operation: .sshSession,
            prepare: { order.append("before") },
            sign: { order.append("sign"); return Data([1]) },
            revalidate: { order.append("after") },
            deliver: { outcome, signature in
                XCTAssertEqual(outcome, .signed)
                XCTAssertEqual(signature, Data([1]))
                order.append("deliver")
            }
        )

        XCTAssertEqual(order, ["before", "sign", "after", "deliver"])
        XCTAssertTrue(presentation.isSuccess)
    }
}
