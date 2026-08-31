import Foundation

public struct GitClientTrustMutationPresentation: Sendable, Equatable {
    public let title: String
    public let changeDescription: String
    public let resultDescription: String
    public let listIntroduction: String
    public let confirmationTitle: String
    public let authenticationReason: String

    public init(operation: GitClientTrustMutationOperation, trustedClientCount: Int) {
        let count = max(0, trustedClientCount)
        self.resultDescription = "変更後に信頼する Git クライアント: \(count) 件"
        self.listIntroduction = count == 0
            ? "変更後、信頼する Git クライアントはありません。"
            : "以下の \(count) 件だけを信頼します。"
        switch operation {
        case .enroll:
            self.title = "Git クライアントの信頼設定を更新します"
            self.changeDescription = "信頼する Git クライアントを追加または更新します。"
            self.confirmationTitle = "この内容で更新"
        case .remove:
            self.title = "Git クライアントの信頼設定を変更します"
            self.changeDescription = "選択した Git クライアントを信頼対象から外します。"
            self.confirmationTitle = "この内容で削除"
        case .migrate:
            self.title = "Git クライアントの信頼設定を移行します"
            self.changeDescription = "既存の信頼情報を、改ざんと巻き戻しを検出できる形式へ移行します。"
            self.confirmationTitle = "この内容で移行"
        case .reset:
            self.title = "Git クライアントの信頼設定をリセットします"
            self.changeDescription = "現在の Git クライアント信頼設定をすべて解除します。"
            self.confirmationTitle = "すべて解除"
        }
        self.authenticationReason = "表示された Git クライアント信頼設定を macop に保存します。"
    }
}
