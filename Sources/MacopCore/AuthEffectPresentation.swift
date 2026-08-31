import Foundation

public enum AuthEffectResponseDelivery: Sendable, Equatable {
    case notAttempted
    case delivered
    case unknown
}

public enum ManagedKeychainEffectOutcome: Sendable, Equatable {
    case notStarted
    case committed
    case failed
    case indeterminate
}

public struct ManagedKeychainEffectPresentation: Sendable, Equatable {
    public let message: String
    public let isSuccess: Bool

    public init(
        updating: Bool,
        outcome: ManagedKeychainEffectOutcome,
        delivery: AuthEffectResponseDelivery
    ) {
        let action = updating
            ? PresentationLocalization.text("managed.action.update", fallback: "更新")
            : PresentationLocalization.text("managed.action.add", fallback: "登録")
        self.isSuccess = outcome == .committed && delivery == .delivered
        self.message = switch (outcome, delivery) {
        case (.notStarted, _):
            PresentationLocalization.format(
                "result.keychain.mutation_not_received",
                fallback: "Keychain項目の%@要求を受信できませんでした。Keychainは変更していません",
                action
            )
        case (.committed, .delivered):
            PresentationLocalization.format(
                "result.keychain.mutation_completed",
                fallback: "Keychain項目を%@しました",
                action
            )
        case (.committed, .unknown):
            PresentationLocalization.format(
                "result.keychain.mutation_completed_delivery_indeterminate",
                fallback: "Keychain項目を%@しました。要求元への結果通知は確認できません",
                action
            )
        case (.failed, .delivered):
            PresentationLocalization.format(
                "result.keychain.mutation_failed",
                fallback: "Keychain項目の%@に失敗しました",
                action
            )
        case (.failed, .unknown):
            PresentationLocalization.format(
                "result.keychain.mutation_failed_delivery_indeterminate",
                fallback: "Keychain項目の%@に失敗しました。要求元への結果通知は確認できません",
                action
            )
        case (.indeterminate, .delivered):
            PresentationLocalization.format(
                "result.keychain.mutation_indeterminate",
                fallback: "Keychain項目の%@結果を確認できません",
                action
            )
        case (.indeterminate, .unknown):
            PresentationLocalization.format(
                "result.keychain.mutation_and_delivery_indeterminate",
                fallback: "Keychain項目の%@結果と、要求元への結果通知を確認できません",
                action
            )
        case (_, .notAttempted):
            PresentationLocalization.format(
                "result.keychain.mutation_delivery_failed",
                fallback: "Keychain項目の%@結果を要求元へ通知できませんでした",
                action
            )
        }
    }
}

public enum SSHSigningEffectOutcome: Sendable, Equatable {
    case noSignatureRequested
    case requesterInvalid
    case signerUnavailable
    case identityMismatch
    case signatureFailed
    case signed
}

public enum SSHSigningEffectFailure: Sendable, Equatable {
    case requesterInvalid
    case signerUnavailable
    case identityMismatch
    case signatureFailed
}

public struct SSHSigningEffectPresentation: Sendable, Equatable {
    public let message: String
    public let isSuccess: Bool

    public init(
        operation: AuthBrokerOperation,
        outcome: SSHSigningEffectOutcome,
        delivery: AuthEffectResponseDelivery
    ) {
        let subject = operation == .gitSSHSign
            ? PresentationLocalization.text("purpose.git_ssh_signing", fallback: "Git SSH署名")
            : PresentationLocalization.text("purpose.ssh_signing", fallback: "SSH署名")
        self.isSuccess = outcome == .signed && delivery == .delivered
        self.message = switch (outcome, delivery) {
        case (.noSignatureRequested, _):
            PresentationLocalization.text(
                "result.signing.no_request_received",
                fallback: "SSH鍵の使用を許可しましたが、署名要求は受信しませんでした"
            )
        case (.requesterInvalid, .delivered):
            PresentationLocalization.format(
                "result.signing.requester_invalid",
                fallback: "%@の要求元を再検証できませんでした。署名は実行していません",
                subject
            )
        case (.requesterInvalid, .unknown):
            PresentationLocalization.format(
                "result.signing.requester_invalid_delivery_indeterminate",
                fallback: "%@の要求元を再検証できませんでした。署名は実行していません。要求元への結果通知は確認できません",
                subject
            )
        case (.requesterInvalid, .notAttempted):
            PresentationLocalization.format(
                "result.signing.requester_invalid_not_returned",
                fallback: "%@の要求元を再検証できませんでした。署名は実行していません。結果は返していません",
                subject
            )
        case (.signerUnavailable, .delivered):
            PresentationLocalization.format(
                "result.signing.key_unavailable",
                fallback: "%@のSecure Enclave署名鍵を準備できませんでした。署名は実行していません",
                subject
            )
        case (.signerUnavailable, .unknown):
            PresentationLocalization.format(
                "result.signing.key_unavailable_delivery_indeterminate",
                fallback: "%@のSecure Enclave署名鍵を準備できませんでした。署名は実行していません。要求元への結果通知は確認できません",
                subject
            )
        case (.signerUnavailable, .notAttempted):
            PresentationLocalization.format(
                "result.signing.key_unavailable_not_returned",
                fallback: "%@のSecure Enclave署名鍵を準備できませんでした。署名は実行していません。結果は返していません",
                subject
            )
        case (.identityMismatch, .delivered):
            PresentationLocalization.format(
                "result.signing.identity_mismatch",
                fallback: "%@の承認済み署名鍵が一致しませんでした。署名は実行していません",
                subject
            )
        case (.identityMismatch, .unknown):
            PresentationLocalization.format(
                "result.signing.identity_mismatch_delivery_indeterminate",
                fallback: "%@の承認済み署名鍵が一致しませんでした。署名は実行していません。要求元への結果通知は確認できません",
                subject
            )
        case (.identityMismatch, .notAttempted):
            PresentationLocalization.format(
                "result.signing.identity_mismatch_not_returned",
                fallback: "%@の承認済み署名鍵が一致しませんでした。署名は実行していません。結果は返していません",
                subject
            )
        case (.signatureFailed, .delivered):
            PresentationLocalization.format(
                "result.signing.failed",
                fallback: "%@のSecure Enclave署名処理に失敗しました。署名結果は返していません",
                subject
            )
        case (.signatureFailed, .unknown):
            PresentationLocalization.format(
                "result.signing.failed_delivery_indeterminate",
                fallback: "%@のSecure Enclave署名処理に失敗しました。署名結果は返していません。要求元への結果通知は確認できません",
                subject
            )
        case (.signatureFailed, .notAttempted):
            PresentationLocalization.format(
                "result.signing.failed",
                fallback: "%@のSecure Enclave署名処理に失敗しました。署名結果は返していません",
                subject
            )
        case (.signed, .delivered):
            PresentationLocalization.format("result.signing.completed", fallback: "%@を完了しました", subject)
        case (.signed, .unknown):
            PresentationLocalization.format(
                "result.signing.completed_delivery_indeterminate",
                fallback: "%@は完了しましたが、要求元への署名結果の受け渡しは確認できません",
                subject
            )
        case (.signed, .notAttempted):
            PresentationLocalization.format(
                "result.signing.completed_not_returned",
                fallback: "%@は完了しましたが、署名結果は返していません",
                subject
            )
        }
    }
}

public enum AuthEffectPipeline {
    public static func managedMutation(
        updating: Bool,
        outcome: ManagedKeychainEffectOutcome,
        deliver: () throws -> Void
    ) -> ManagedKeychainEffectPresentation {
        let delivery: AuthEffectResponseDelivery
        do {
            try deliver()
            delivery = .delivered
        } catch {
            delivery = .unknown
        }
        return ManagedKeychainEffectPresentation(
            updating: updating,
            outcome: outcome,
            delivery: delivery
        )
    }

    public static func signing(
        operation: AuthBrokerOperation,
        prepare: () throws -> Void = {},
        sign: () throws -> Data,
        revalidate: () throws -> Void = {},
        deliver: (AuthBrokerSSHSignOutcome, Data) throws -> Void
    ) -> SSHSigningEffectPresentation {
        do {
            try prepare()
        } catch {
            return self.signingFailure(
                operation: operation,
                failure: .requesterInvalid,
                deliver: deliver
            )
        }
        let signature: Data
        do {
            signature = try sign()
        } catch {
            return self.signingFailure(
                operation: operation,
                failure: .signatureFailed,
                deliver: deliver
            )
        }
        do {
            try revalidate()
        } catch {
            return self.signingFailure(
                operation: operation,
                failure: .requesterInvalid,
                deliver: deliver
            )
        }
        do {
            try deliver(.signed, signature)
            return SSHSigningEffectPresentation(
                operation: operation,
                outcome: .signed,
                delivery: .delivered
            )
        } catch {
            return SSHSigningEffectPresentation(
                operation: operation,
                outcome: .signed,
                delivery: .unknown
            )
        }
    }

    public static func signingFailure(
        operation: AuthBrokerOperation,
        failure: SSHSigningEffectFailure,
        deliver: (AuthBrokerSSHSignOutcome, Data) throws -> Void
    ) -> SSHSigningEffectPresentation {
        let (brokerOutcome, outcome): (AuthBrokerSSHSignOutcome, SSHSigningEffectOutcome) = switch failure {
        case .requesterInvalid:
            (.requesterInvalid, .requesterInvalid)
        case .signerUnavailable:
            (.signerUnavailable, .signerUnavailable)
        case .identityMismatch:
            (.identityMismatch, .identityMismatch)
        case .signatureFailed:
            (.signatureFailed, .signatureFailed)
        }
        let delivery: AuthEffectResponseDelivery
        do {
            try deliver(brokerOutcome, Data())
            delivery = .delivered
        } catch {
            delivery = .unknown
        }
        return SSHSigningEffectPresentation(
            operation: operation,
            outcome: outcome,
            delivery: delivery
        )
    }
}

public enum AuthApprovalDeliveredRoute: Sendable, Equatable {
    case passwordAutoFill
    case approvedPhaseTwo
    case approvedImmediate
    case rejected(AuthBrokerApprovalStatus)
}

public enum AuthApprovalOrchestration {
    public static func deliveredRoute(
        operation: AuthBrokerOperation,
        status: AuthBrokerApprovalStatus,
        hasSigner: Bool
    ) -> AuthApprovalDeliveredRoute {
        guard status == .approved else { return .rejected(status) }
        if operation == .passwordAutoFill {
            return .passwordAutoFill
        }
        if hasSigner || operation.phaseTwoKind != .none {
            return .approvedPhaseTwo
        }
        return .approvedImmediate
    }
}
