import AppKit
@testable import MacopAuth
import SwiftUI
import XCTest

@MainActor
final class PairedAppKitPasswordAutoFillFieldsTests: XCTestCase {
    private final class CredentialState {
        var username = ""
        var password = ""
    }

    private final class HostedFormState: ObservableObject {
        @Published var credentials = PasswordAutoFillCredentialState()
    }

    private struct HostedCredentialFields: View {
        @ObservedObject var state: HostedFormState
        let presentation: PasswordAutoFillFieldPresentation

        var body: some View {
            PasswordAutoFillCredentialFields(
                credentials: self.$state.credentials,
                presentation: self.presentation
            )
        }
    }

    private struct Subject {
        let fields: PairedAppKitPasswordAutoFillFields
        let coordinator: PairedAppKitPasswordAutoFillFields.Coordinator
        let state: CredentialState
    }

    func testProductionCompositionKeepsPairedAdapterUntilSignedProbePasses() {
        XCTAssertEqual(
            ObjectIdentifier(ActivePasswordAutoFillFieldAdapter.self),
            ObjectIdentifier(PairedAppKitPasswordAutoFillFieldAdapter.self)
        )
    }

    func testConstructsSiblingSystemFieldsWithForwardKeyTraversal() {
        let subject = self.makeSubject()
        let stack = self.makeStack(fields: subject.fields, coordinator: subject.coordinator)

        XCTAssertEqual(ObjectIdentifier(type(of: stack.usernameField)), ObjectIdentifier(NSTextField.self))
        XCTAssertEqual(ObjectIdentifier(type(of: stack.passwordField)), ObjectIdentifier(NSSecureTextField.self))
        XCTAssertTrue(stack.arrangedSubviews[1] === stack.usernameField)
        XCTAssertTrue(stack.arrangedSubviews[3] === stack.passwordField)
        XCTAssertEqual(stack.usernameField.contentType, .username)
        XCTAssertEqual(stack.passwordField.contentType, .password)
        XCTAssertTrue(stack.usernameField.delegate === subject.coordinator)
        XCTAssertTrue(stack.passwordField.delegate === subject.coordinator)
        XCTAssertTrue(stack.usernameField.nextKeyView === stack.passwordField)
        XCTAssertFalse(stack.passwordField.nextKeyView === stack.usernameField)
    }

    func testForwardsBothChangesWithoutApplyingAStaleBindingValue() {
        let subject = self.makeSubject()
        let stack = self.makeStack(fields: subject.fields, coordinator: subject.coordinator)

        stack.usernameField.stringValue = "alice@example.com"
        subject.coordinator.controlTextDidChange(Notification(
            name: NSControl.textDidChangeNotification,
            object: stack.usernameField
        ))
        stack.passwordField.stringValue = "example-secret"
        subject.coordinator.controlTextDidChange(Notification(
            name: NSControl.textDidChangeNotification,
            object: stack.passwordField
        ))

        XCTAssertEqual(subject.state.username, "alice@example.com")
        XCTAssertEqual(subject.state.password, "example-secret")

        subject.coordinator.update(
            username: "",
            password: "",
            resetGeneration: subject.fields.resetGeneration,
            presentation: self.presentation
        )
        XCTAssertEqual(stack.usernameField.stringValue, "alice@example.com")
        XCTAssertEqual(stack.passwordField.stringValue, "example-secret")

        subject.coordinator.update(
            username: subject.state.username,
            password: subject.state.password,
            resetGeneration: subject.fields.resetGeneration,
            presentation: self.presentation
        )
        subject.coordinator.update(
            username: "bob@example.com",
            password: "replacement",
            resetGeneration: subject.fields.resetGeneration,
            presentation: self.presentation
        )
        XCTAssertEqual(stack.usernameField.stringValue, "bob@example.com")
        XCTAssertEqual(stack.passwordField.stringValue, "replacement")
    }

    func testProductionResetRouteOverridesStaleRenderProtection() throws {
        let state = HostedFormState()
        let host = NSHostingView(rootView: HostedCredentialFields(
            state: state,
            presentation: self.presentation
        ))
        host.frame = NSRect(x: 0, y: 0, width: 420, height: 180)
        host.layoutSubtreeIfNeeded()
        let stack = try XCTUnwrap(self.findFieldStack(in: host))

        // Model a filled form, then reset it before the next reconciliation.
        // The state assertions prove both values clear; the native assertions
        // prove the explicit generation crosses the representable lifecycle.
        stack.usernameField.stringValue = "alice@example.com"
        stack.passwordField.stringValue = "example-secret"
        state.credentials.username = "alice@example.com"
        state.credentials.password = "example-secret"

        state.credentials.reset()
        XCTAssertEqual(state.credentials.username, "")
        XCTAssertEqual(state.credentials.password, "")
        RunLoop.main.run(until: Date(timeIntervalSinceNow: 0.05))
        host.layoutSubtreeIfNeeded()

        XCTAssertEqual(state.credentials.resetGeneration, 1)
        XCTAssertEqual(stack.usernameField.stringValue, "")
        XCTAssertEqual(stack.passwordField.stringValue, "")
    }

    private func findFieldStack(
        in view: NSView
    ) -> PairedAppKitPasswordAutoFillFields.FieldStack? {
        if let stack = view as? PairedAppKitPasswordAutoFillFields.FieldStack {
            return stack
        }
        for subview in view.subviews {
            if let stack = self.findFieldStack(in: subview) {
                return stack
            }
        }
        return nil
    }

    private var presentation: PasswordAutoFillFieldPresentation {
        PasswordAutoFillFieldPresentation(
            usernameLabel: "Username",
            usernamePlaceholder: "name@example.com",
            passwordLabel: "Password",
            passwordPlaceholder: "Choose from Passwords"
        )
    }

    private func makeSubject() -> Subject {
        let state = CredentialState()
        let fields = PairedAppKitPasswordAutoFillFields(
            username: Binding(get: { state.username }, set: { state.username = $0 }),
            password: Binding(get: { state.password }, set: { state.password = $0 }),
            resetGeneration: 0,
            presentation: self.presentation
        )
        return Subject(fields: fields, coordinator: fields.makeCoordinator(), state: state)
    }

    private func makeStack(
        fields: PairedAppKitPasswordAutoFillFields,
        coordinator: PairedAppKitPasswordAutoFillFields.Coordinator
    ) -> PairedAppKitPasswordAutoFillFields.FieldStack {
        PairedAppKitPasswordAutoFillFields.FieldStack(
            presentation: self.presentation,
            username: fields.username,
            password: fields.password,
            resetGeneration: fields.resetGeneration,
            coordinator: coordinator
        )
    }
}
