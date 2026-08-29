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
        let action = updating ? "更新" : "登録"
        self.isSuccess = outcome == .committed && delivery == .delivered
        self.message = switch (outcome, delivery) {
        case (.notStarted, _):
            "Keychain項目の\(action)要求を受信できませんでした。Keychainは変更していません"
        case (.committed, .delivered):
            "Keychain項目を\(action)しました"
        case (.committed, .unknown):
            "Keychain項目を\(action)しました。要求元への結果通知は確認できません"
        case (.failed, .delivered):
            "Keychain項目の\(action)に失敗しました"
        case (.failed, .unknown):
            "Keychain項目の\(action)に失敗しました。要求元への結果通知は確認できません"
        case (.indeterminate, .delivered):
            "Keychain項目の\(action)結果を確認できません"
        case (.indeterminate, .unknown):
            "Keychain項目の\(action)結果と、要求元への結果通知を確認できません"
        case (_, .notAttempted):
            "Keychain項目の\(action)結果を要求元へ通知できませんでした"
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
        let subject = operation == .gitSSHSign ? "Git SSH署名" : "SSH署名"
        self.isSuccess = outcome == .signed && delivery == .delivered
        self.message = switch (outcome, delivery) {
        case (.noSignatureRequested, _):
            "SSH鍵の使用を許可しましたが、署名要求は受信しませんでした"
        case (.requesterInvalid, .delivered):
            "\(subject)の要求元を再検証できませんでした。署名は実行していません"
        case (.requesterInvalid, .unknown):
            "\(subject)の要求元を再検証できませんでした。署名は実行していません。要求元への結果通知は確認できません"
        case (.requesterInvalid, .notAttempted):
            "\(subject)の要求元を再検証できませんでした。署名は実行していません。結果は返していません"
        case (.signerUnavailable, .delivered):
            "\(subject)のSecure Enclave署名鍵を準備できませんでした。署名は実行していません"
        case (.signerUnavailable, .unknown):
            "\(subject)のSecure Enclave署名鍵を準備できませんでした。署名は実行していません。要求元への結果通知は確認できません"
        case (.signerUnavailable, .notAttempted):
            "\(subject)のSecure Enclave署名鍵を準備できませんでした。署名は実行していません。結果は返していません"
        case (.identityMismatch, .delivered):
            "\(subject)の承認済み署名鍵が一致しませんでした。署名は実行していません"
        case (.identityMismatch, .unknown):
            "\(subject)の承認済み署名鍵が一致しませんでした。署名は実行していません。要求元への結果通知は確認できません"
        case (.identityMismatch, .notAttempted):
            "\(subject)の承認済み署名鍵が一致しませんでした。署名は実行していません。結果は返していません"
        case (.signatureFailed, .delivered):
            "\(subject)のSecure Enclave署名処理に失敗しました。署名結果は返していません"
        case (.signatureFailed, .unknown):
            "\(subject)のSecure Enclave署名処理に失敗しました。署名結果は返していません。要求元への結果通知は確認できません"
        case (.signatureFailed, .notAttempted):
            "\(subject)のSecure Enclave署名処理に失敗しました。署名結果は返していません"
        case (.signed, .delivered):
            "\(subject)を完了しました"
        case (.signed, .unknown):
            "\(subject)は完了しましたが、要求元への署名結果の受け渡しは確認できません"
        case (.signed, .notAttempted):
            "\(subject)は完了しましたが、署名結果は返していません"
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
        if hasSigner || operation == .managedKeychainImport || operation == .managedKeychainUpdate {
            return .approvedPhaseTwo
        }
        return .approvedImmediate
    }
}
