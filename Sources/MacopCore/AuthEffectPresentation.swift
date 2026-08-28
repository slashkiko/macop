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
    case preparationFailed
    case signatureFailed
    case signed
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
        case (.preparationFailed, _):
            "\(subject)の要求元または署名鍵を検証できませんでした。署名は実行していません"
        case (.signatureFailed, _):
            "\(subject)に失敗しました。署名結果は返していません"
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
        deliver: (Data) throws -> Void
    ) -> SSHSigningEffectPresentation {
        do {
            try prepare()
        } catch {
            return SSHSigningEffectPresentation(
                operation: operation,
                outcome: .preparationFailed,
                delivery: .notAttempted
            )
        }
        let signature: Data
        do {
            signature = try sign()
        } catch {
            return SSHSigningEffectPresentation(
                operation: operation,
                outcome: .signatureFailed,
                delivery: .notAttempted
            )
        }
        do {
            try deliver(signature)
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
