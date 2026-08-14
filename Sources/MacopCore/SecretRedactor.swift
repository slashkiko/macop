import Foundation

/// Replaces complete UTF-8 secret byte sequences while retaining enough trailing
/// bytes to recognize a secret split between two reads. Bytes are scanned once
/// from the source cursor: replacement bytes are never passed through matching.
public final class SecretRedactor: @unchecked Sendable {
    private let secrets: [[UInt8]]
    private var pending = [UInt8]()
    private let replacement = Array("<concealed by macop>".utf8)
    private let longestSecret: Int

    public init(secrets: [String]) {
        self.secrets = Array(Set(secrets.filter { !$0.isEmpty })).map { Array($0.utf8) }
            .sorted { lhs, rhs in lhs.count > rhs.count }
        self.longestSecret = self.secrets.map(\.count).max() ?? 0
    }

    public func process(_ chunk: Data, final: Bool = false) -> Data {
        guard !self.secrets.isEmpty else { return chunk }
        self.pending += chunk
        let stableEnd = final ? self.pending.count : max(0, self.pending.count - self.longestSecret + 1)
        var cursor = 0
        var output = [UInt8]()

        while cursor < stableEnd {
            if let secret = self.secrets.first(where: { secret in
                cursor + secret.count <= self.pending.count
                    && self.pending[cursor ..< cursor + secret.count].elementsEqual(secret)
            }) {
                // Do not emit a candidate that could extend into the retained
                // suffix; wait for another read (or final flush) instead.
                guard cursor + secret.count <= stableEnd || final else { break }
                output += self.replacement
                cursor += secret.count
            } else {
                output.append(self.pending[cursor])
                cursor += 1
            }
        }
        self.pending = Array(self.pending.dropFirst(cursor))
        return Data(output)
    }
}
