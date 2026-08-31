@testable import MacopCore
import XCTest

final class GitClientTrustMutationPresentationTests: XCTestCase {
    func testPresentationUsesHumanReadableChangeDescriptionInsteadOfGeneration() {
        let presentation = GitClientTrustMutationPresentation(operation: .enroll, trustedClientCount: 2)

        XCTAssertEqual(presentation.title, "Git クライアントの信頼設定を更新します")
        XCTAssertEqual(presentation.changeDescription, "信頼する Git クライアントを追加または更新します。")
        XCTAssertEqual(presentation.resultDescription, "変更後に信頼する Git クライアント: 2 件")
        XCTAssertEqual(presentation.listIntroduction, "以下の 2 件だけを信頼します。")
        XCTAssertEqual(presentation.confirmationTitle, "この内容で更新")
        XCTAssertFalse(String(describing: presentation).contains("世代"))
    }

    func testDestructivePresentationsStateTheirEffect() {
        let removal = GitClientTrustMutationPresentation(operation: .remove, trustedClientCount: 1)
        XCTAssertEqual(removal.confirmationTitle, "この内容で削除")
        XCTAssertTrue(removal.changeDescription.contains("信頼対象から外します"))

        let reset = GitClientTrustMutationPresentation(operation: .reset, trustedClientCount: 0)
        XCTAssertEqual(reset.confirmationTitle, "すべて解除")
        XCTAssertEqual(reset.resultDescription, "変更後に信頼する Git クライアント: 0 件")
        XCTAssertEqual(reset.listIntroduction, "変更後、信頼する Git クライアントはありません。")
    }

    func testMigrationExplainsSecurityOutcomeWithoutInternalCounter() {
        let migration = GitClientTrustMutationPresentation(operation: .migrate, trustedClientCount: 3)

        XCTAssertEqual(migration.title, "Git クライアントの信頼設定を移行します")
        XCTAssertTrue(migration.changeDescription.contains("改ざんと巻き戻しを検出"))
        XCTAssertEqual(migration.confirmationTitle, "この内容で移行")
    }
}
