import Foundation

enum PresentationLocalization {
    static func text(_ key: String, fallback: String) -> String {
        Bundle.main.localizedString(forKey: key, value: fallback, table: nil)
    }

    static func format(_ key: String, fallback: String, _ arguments: CVarArg...) -> String {
        String(format: self.text(key, fallback: fallback), locale: Locale.current, arguments: arguments)
    }
}
