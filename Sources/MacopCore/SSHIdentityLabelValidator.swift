import Foundation

enum SSHIdentityLabelValidator {
    static func validate(_ label: String) throws {
        guard !label.isEmpty,
              label == label.trimmingCharacters(in: .whitespacesAndNewlines),
              label.utf8.count <= 128,
              !label.unicodeScalars.contains(where: {
                  $0.value == 0 || CharacterSet.controlCharacters.contains($0)
                      || CharacterSet.newlines.contains($0) || $0.properties.generalCategory == .format
              })
        else {
            throw CLIError.invalidArguments(
                message: "SSH identity label must be printable, trimmed, and at most 128 UTF-8 bytes."
            )
        }
    }
}
