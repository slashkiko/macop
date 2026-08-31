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
        self.resultDescription = PresentationLocalization.format(
            "trust.result.count",
            fallback: "変更後に信頼する Git クライアント: %d 件",
            count
        )
        self.listIntroduction = count == 0
            ? PresentationLocalization.text(
                "trust.result.none",
                fallback: "変更後、信頼する Git クライアントはありません。"
            )
            : PresentationLocalization.format(
                "trust.result.only_count",
                fallback: "以下の %d 件だけを信頼します。",
                count
            )
        switch operation {
        case .enroll:
            self.title = PresentationLocalization.text("trust.enroll.title", fallback: "Git クライアントの信頼設定を更新します")
            self.changeDescription = PresentationLocalization.text(
                "trust.enroll.description",
                fallback: "信頼する Git クライアントを追加または更新します。"
            )
            self.confirmationTitle = PresentationLocalization.text("trust.enroll.action", fallback: "この内容で更新")
        case .remove:
            self.title = PresentationLocalization.text("trust.remove.title", fallback: "Git クライアントの信頼設定を変更します")
            self.changeDescription = PresentationLocalization.text(
                "trust.remove.description",
                fallback: "選択した Git クライアントを信頼対象から外します。"
            )
            self.confirmationTitle = PresentationLocalization.text("trust.remove.action", fallback: "この内容で削除")
        case .migrate:
            self.title = PresentationLocalization.text("trust.migrate.title", fallback: "Git クライアントの信頼設定を移行します")
            self.changeDescription = PresentationLocalization.text(
                "trust.migrate.description",
                fallback: "既存の信頼情報を、改ざんと巻き戻しを検出できる形式へ移行します。"
            )
            self.confirmationTitle = PresentationLocalization.text("trust.migrate.action", fallback: "この内容で移行")
        case .reset:
            self.title = PresentationLocalization.text("trust.reset.title", fallback: "Git クライアントの信頼設定をリセットします")
            self.changeDescription = PresentationLocalization.text(
                "trust.reset.description",
                fallback: "現在の Git クライアント信頼設定をすべて解除します。"
            )
            self.confirmationTitle = PresentationLocalization.text("trust.reset.action", fallback: "すべて解除")
        }
        self.authenticationReason = PresentationLocalization.text(
            "trust.authentication_reason",
            fallback: "表示された Git クライアント信頼設定を macop に保存します。"
        )
    }
}
