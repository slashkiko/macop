import AppKit
import SwiftUI

struct PasswordAutoFillFieldPresentation {
    let usernameLabel: String
    let usernamePlaceholder: String
    let passwordLabel: String
    let passwordPlaceholder: String
}

struct PasswordAutoFillCredentialState {
    var username = ""
    var password = ""
    private(set) var resetGeneration: UInt64 = 0

    mutating func reset() {
        self.username = ""
        self.password = ""
        // WHY: the native adapter needs an explicit command because a stale
        // render and an intentional clear otherwise contain identical values.
        self.resetGeneration &+= 1
    }
}

/// The UI port used by the Password AutoFill request screen.
///
/// WHY: form recognition belongs to macOS and can change independently of the
/// request screen. Keeping that system-specific choice behind an adapter lets a
/// future native SwiftUI implementation replace the AppKit workaround without
/// touching account validation, authorization, or the rest of the screen.
@MainActor
protocol PasswordAutoFillFieldAdapter {
    associatedtype Content: View

    @ViewBuilder
    func makeFields(
        username: Binding<String>,
        password: Binding<String>,
        resetGeneration: UInt64,
        presentation: PasswordAutoFillFieldPresentation
    ) -> Content
}

/// This is the composition root for the credential-field UI.
///
/// WHY: change only `ActivePasswordAutoFillFieldAdapter` when a simpler native
/// implementation becomes reliable. Callers continue to depend on this stable
/// view and never need to know which framework renders the fields. Keep the
/// alias internal so a regression test can lock this deliberate production
/// choice until the signed native-adapter probe passes.
typealias ActivePasswordAutoFillFieldAdapter = PairedAppKitPasswordAutoFillFieldAdapter

@MainActor
struct PasswordAutoFillCredentialFields: View {
    @Binding var credentials: PasswordAutoFillCredentialState
    let presentation: PasswordAutoFillFieldPresentation

    var body: some View {
        ActivePasswordAutoFillFieldAdapter().makeFields(
            username: self.$credentials.username,
            password: self.$credentials.password,
            resetGeneration: self.credentials.resetGeneration,
            presentation: self.presentation
        )
    }
}

@MainActor
struct PairedAppKitPasswordAutoFillFieldAdapter: PasswordAutoFillFieldAdapter {
    func makeFields(
        username: Binding<String>,
        password: Binding<String>,
        resetGeneration: UInt64,
        presentation: PasswordAutoFillFieldPresentation
    ) -> some View {
        PairedAppKitPasswordAutoFillFields(
            username: username,
            password: password,
            resetGeneration: resetGeneration,
            presentation: presentation
        )
    }
}

/// Compile-tested replacement candidate for a future macOS release.
///
/// WHY: keep the simple native implementation ready, but inactive, so switching
/// back is a one-line composition-root change. Activate it only after a signed
/// integration probe proves that one chooser action fills both bindings.
@MainActor
struct NativePasswordAutoFillFieldAdapter: PasswordAutoFillFieldAdapter {
    func makeFields(
        username: Binding<String>,
        password: Binding<String>,
        resetGeneration _: UInt64,
        presentation: PasswordAutoFillFieldPresentation
    ) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 5) {
                Text(presentation.usernameLabel)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                TextField(
                    presentation.usernameLabel,
                    text: username,
                    prompt: Text(presentation.usernamePlaceholder)
                )
                .textContentType(.username)
                .controlSize(.large)
            }
            VStack(alignment: .leading, spacing: 5) {
                Text(presentation.passwordLabel)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                SecureField(
                    presentation.passwordLabel,
                    text: password,
                    prompt: Text(presentation.passwordPlaceholder)
                )
                .textContentType(.password)
                .controlSize(.large)
            }
        }
    }
}

/// AppKit adapter for macOS Password AutoFill form recognition.
///
/// WHY: macOS recognizes the credential pair from one native view hierarchy.
/// Two independent representables look like two unrelated forms, so the system
/// can fill the secure value without associating its account name. This adapter
/// deliberately owns both unmodified standard controls as direct siblings.
struct PairedAppKitPasswordAutoFillFields: NSViewRepresentable {
    struct FieldViews {
        let usernameField: NSTextField
        let passwordField: NSTextField
        let usernameLabel: NSTextField
        let passwordLabel: NSTextField
    }

    @MainActor
    final class FieldStack: NSStackView {
        let usernameField: NSTextField
        let passwordField: NSTextField
        let usernameLabel: NSTextField
        let passwordLabel: NSTextField

        init(
            presentation: PasswordAutoFillFieldPresentation,
            username: String,
            password: String,
            resetGeneration: UInt64,
            coordinator: Coordinator
        ) {
            self.usernameLabel = Self.makeLabel(presentation.usernameLabel)
            // WHY: use the standard concrete AppKit classes. The system-owned
            // classifier is undocumented, so custom observer subclasses add an
            // avoidable difference from controls known to work in the signed PoC.
            self.usernameField = NSTextField()
            self.passwordLabel = Self.makeLabel(presentation.passwordLabel)
            self.passwordField = NSSecureTextField()
            super.init(frame: .zero)
            [
                self.usernameLabel,
                self.usernameField,
                self.passwordLabel,
                self.passwordField
            ].forEach(self.addArrangedSubview)

            Self.configure(
                field: self.usernameField,
                placeholder: presentation.usernamePlaceholder,
                accessibilityLabel: presentation.usernameLabel,
                contentType: .username,
                coordinator: coordinator
            )
            Self.configure(
                field: self.passwordField,
                placeholder: presentation.passwordPlaceholder,
                accessibilityLabel: presentation.passwordLabel,
                contentType: .password,
                coordinator: coordinator
            )
            // WHY: keep the expected first-to-second field order, but do not
            // point back to the first field or keyboard users become trapped.
            self.usernameField.nextKeyView = self.passwordField
            self.usernameField.stringValue = username
            self.passwordField.stringValue = password

            self.orientation = .vertical
            self.alignment = .leading
            self.spacing = 5
            self.setCustomSpacing(12, after: self.usernameField)
            self.usernameField.widthAnchor.constraint(equalTo: self.widthAnchor).isActive = true
            self.passwordField.widthAnchor.constraint(equalTo: self.widthAnchor).isActive = true

            coordinator.connect(
                views: FieldViews(
                    usernameField: self.usernameField,
                    passwordField: self.passwordField,
                    usernameLabel: self.usernameLabel,
                    passwordLabel: self.passwordLabel
                ),
                username: username,
                password: password,
                resetGeneration: resetGeneration
            )
        }

        @available(*, unavailable)
        required init?(coder _: NSCoder) {
            fatalError("init(coder:) is unavailable")
        }

        private static func makeLabel(_ value: String) -> NSTextField {
            let label = NSTextField(labelWithString: value)
            label.font = .systemFont(ofSize: NSFont.smallSystemFontSize)
            label.textColor = .secondaryLabelColor
            return label
        }

        private static func configure(
            field: NSTextField,
            placeholder: String,
            accessibilityLabel: String,
            contentType: NSTextContentType,
            coordinator: Coordinator
        ) {
            field.placeholderString = placeholder
            field.setAccessibilityLabel(accessibilityLabel)
            field.contentType = contentType
            field.delegate = coordinator
            field.isEditable = true
            field.isSelectable = true
            field.bezelStyle = .roundedBezel
            field.controlSize = .large
            field.font = .systemFont(ofSize: NSFont.systemFontSize(for: .large))
        }
    }

    @Binding var username: String
    @Binding var password: String
    let resetGeneration: UInt64
    let presentation: PasswordAutoFillFieldPresentation

    func makeCoordinator() -> Coordinator {
        Coordinator(username: self.$username, password: self.$password)
    }

    func makeNSView(context: Context) -> FieldStack {
        FieldStack(
            presentation: self.presentation,
            username: self.username,
            password: self.password,
            resetGeneration: self.resetGeneration,
            coordinator: context.coordinator
        )
    }

    func updateNSView(_: FieldStack, context: Context) {
        context.coordinator.update(
            username: self.username,
            password: self.password,
            resetGeneration: self.resetGeneration,
            presentation: self.presentation
        )
    }

    @MainActor
    final class Coordinator: NSObject, NSTextFieldDelegate {
        @Binding private var username: String
        @Binding private var password: String
        private var usernameField: NSTextField?
        private var passwordField: NSTextField?
        private var usernameLabel: NSTextField?
        private var passwordLabel: NSTextField?
        private var lastAppliedUsername: String?
        private var lastAppliedPassword: String?
        private var lastResetGeneration: UInt64?

        init(username: Binding<String>, password: Binding<String>) {
            self._username = username
            self._password = password
        }

        func connect(
            views: FieldViews,
            username: String,
            password: String,
            resetGeneration: UInt64
        ) {
            self.usernameField = views.usernameField
            self.passwordField = views.passwordField
            self.usernameLabel = views.usernameLabel
            self.passwordLabel = views.passwordLabel
            self.lastAppliedUsername = username
            self.lastAppliedPassword = password
            self.lastResetGeneration = resetGeneration
        }

        func update(
            username: String,
            password: String,
            resetGeneration: UInt64,
            presentation: PasswordAutoFillFieldPresentation
        ) {
            self.usernameLabel?.stringValue = presentation.usernameLabel
            self.passwordLabel?.stringValue = presentation.passwordLabel
            self.usernameField?.placeholderString = presentation.usernamePlaceholder
            self.usernameField?.setAccessibilityLabel(presentation.usernameLabel)
            self.passwordField?.placeholderString = presentation.passwordPlaceholder
            self.passwordField?.setAccessibilityLabel(presentation.passwordLabel)
            if self.lastResetGeneration != resetGeneration {
                // WHY: an old empty SwiftUI render and an intentional post-submit
                // clear carry the same strings. The explicit generation makes the
                // security-sensitive clear unambiguous instead of guessing from
                // event timing.
                self.lastResetGeneration = resetGeneration
                self.lastAppliedUsername = username
                self.lastAppliedPassword = password
                self.usernameField?.stringValue = username
                self.passwordField?.stringValue = password
                return
            }
            if self.lastAppliedUsername != username {
                self.lastAppliedUsername = username
                self.usernameField?.stringValue = username
            }
            if self.lastAppliedPassword != password {
                self.lastAppliedPassword = password
                self.passwordField?.stringValue = password
            }
        }

        func controlTextDidChange(_ notification: Notification) {
            guard let field = notification.object as? NSTextField else { return }
            if field === self.usernameField {
                // WHY: do not update lastAppliedUsername here. A stale SwiftUI
                // render may still carry the old empty value; remembering only
                // values applied from SwiftUI prevents that render from erasing
                // the account name that Password AutoFill just inserted.
                if self.username != field.stringValue {
                    self.username = field.stringValue
                }
            } else if field === self.passwordField {
                // WHY: the same ordering rule protects the other half of the
                // credential pair while SwiftUI processes the delegate change.
                if self.password != field.stringValue {
                    self.password = field.stringValue
                }
            }
        }
    }
}
