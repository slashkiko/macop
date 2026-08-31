import Foundation
@testable import MacopCore
import XCTest

final class SecretRedactorTests: XCTestCase {
    private let replacement = "<concealed by macop>"

    func testChunkBoundariesMatchTheFullInputContract() {
        let source = Data("xaba秘密🦀tokenba".utf8)
        let secrets = ["aba", "ba", "秘密", "密", "🦀token", "token"]
        let expected = self.redact(source, secrets: secrets, chunks: [source.count])

        // Every possible set of boundaries for this compact adversarial input
        // must produce the same leftmost-longest result as a single chunk.
        let boundarySource = Data("ababa秘密".utf8)
        let boundaryExpected = self.redact(
            boundarySource,
            secrets: secrets,
            chunks: [boundarySource.count]
        )
        for mask in 0 ..< (1 << (boundarySource.count - 1)) {
            var chunks = [Int]()
            var start = 0
            for index in 0 ..< boundarySource.count - 1 where mask & (1 << index) != 0 {
                chunks.append(index + 1 - start)
                start = index + 1
            }
            chunks.append(boundarySource.count - start)
            XCTAssertEqual(
                self.redact(boundarySource, secrets: secrets, chunks: chunks),
                boundaryExpected,
                "boundary mask \(mask) changed the result"
            )
        }

        var generator = SeededGenerator(seed: 0x5EED4B)
        var repeated = Data()
        for _ in 0 ..< 128 {
            repeated.append(source)
        }
        for _ in 0 ..< 64 {
            var remaining = repeated.count
            var chunks = [Int]()
            while remaining > 0 {
                let length = min(remaining, 1 + generator.nextInt(upperBound: 31))
                chunks.append(length)
                remaining -= length
            }
            XCTAssertEqual(
                self.redact(repeated, secrets: secrets, chunks: chunks),
                String(repeating: expected, count: 128)
            )
        }
    }

    func testDuplicatesContainedOverlapsAndUTF8UseLeftmostLongestSourceMatches() {
        let source = Data("xaba秘密🦀tokenba<concealed by macop>".utf8)
        let output = self.redact(
            source,
            secrets: ["", "aba", "aba", "ba", "秘密", "密", "🦀token", "token", self.replacement],
            chunks: Array(repeating: 1, count: source.count)
        )
        XCTAssertEqual(output, "x" + String(repeating: self.replacement, count: 5))
    }

    func testSuffixOutputSurvivesAnEarlierAcceptedOverlapForEveryChunkSplit() {
        let source = Data("abcde".utf8)
        let secrets = ["ab", "bcde", "de"]
        let expected = self.replacement + "c" + self.replacement

        XCTAssertEqual(self.redact(source, secrets: secrets, chunks: [source.count]), expected)
        for mask in 0 ..< (1 << (source.count - 1)) {
            XCTAssertEqual(
                self.redact(source, secrets: secrets, chunks: self.chunks(for: mask, byteCount: source.count)),
                expected,
                "boundary mask \(mask) lost a suffix secret"
            )
        }
    }

    func testNestedOverlapChunkingMatchesReferenceOracle() {
        let secrets = ["ab", "abc", "bcde", "bcd", "cde", "de", "e"]
        for input in ["abcde", "zabcde", "abcdeabcde", "ababcde"] {
            let source = Data(input.utf8)
            let expected = String(
                bytes: self.referenceRedact(source, secrets: secrets),
                encoding: .utf8
            )
            XCTAssertNotNil(expected)
            for mask in 0 ..< (1 << (source.count - 1)) {
                XCTAssertEqual(
                    self.redact(source, secrets: secrets, chunks: self.chunks(for: mask, byteCount: source.count)),
                    expected,
                    "nested-overlap boundary mask \(mask) changed \(input)"
                )
            }
        }
    }

    func testEmptySecretsPassThroughAndFinalFlushStartsANewStream() {
        let noSecrets = SecretRedactor(secrets: ["", ""])
        XCTAssertEqual(noSecrets.process(Data("first".utf8)), Data("first".utf8))
        XCTAssertEqual(noSecrets.process(Data(" second".utf8), final: true), Data(" second".utf8))

        let redactor = SecretRedactor(secrets: ["secret"])
        XCTAssertEqual(redactor.process(Data("secret".utf8), final: true), Data(self.replacement.utf8))
        XCTAssertEqual(redactor.process(Data("secret".utf8), final: true), Data(self.replacement.utf8))
    }

    func testCommonPrefixAdversaryUsesLinearTransitionWork() {
        let prefix = String(repeating: "a", count: 64 * 1024)
        let secrets = [prefix + "x", prefix + "y", prefix + "z"]
        let source = Data((prefix + "q" + prefix + "y").utf8)
        let redactor = SecretRedactor(secrets: secrets)

        let midpoint = source.count / 2
        let output = redactor.process(Data(source.prefix(midpoint)))
            + redactor.process(Data(source.dropFirst(midpoint)), final: true)

        XCTAssertEqual(output, Data((prefix + "q" + self.replacement).utf8))
        XCTAssertLessThanOrEqual(redactor.transitionLookupCount, source.count * 8)
    }

    func testLargeChunkRetentionIsBoundedByTheLongestSecret() {
        let source = Data(repeating: 120, count: 1_000_000)
        let redactor = SecretRedactor(secrets: ["xy", "y"])

        XCTAssertEqual(redactor.process(source, final: true), source)
        XCTAssertLessThanOrEqual(redactor.maximumRetainedByteCount, 3)
        XCTAssertEqual(redactor.retainedByteCount, 0)
        XCTAssertLessThanOrEqual(redactor.pendingStorageCapacity, 16)
    }

    private func redact(_ source: Data, secrets: [String], chunks: [Int]) -> String {
        let redactor = SecretRedactor(secrets: secrets)
        var output = Data()
        var offset = 0
        for (index, length) in chunks.enumerated() {
            let end = offset + length
            output.append(redactor.process(Data(source[offset ..< end]), final: index == chunks.indices.last))
            offset = end
        }
        XCTAssertEqual(offset, source.count)
        return String(bytes: output, encoding: .utf8) ?? ""
    }

    private func chunks(for mask: Int, byteCount: Int) -> [Int] {
        var chunks = [Int]()
        var start = 0
        for index in 0 ..< byteCount - 1 where mask & (1 << index) != 0 {
            chunks.append(index + 1 - start)
            start = index + 1
        }
        chunks.append(byteCount - start)
        return chunks
    }

    private func referenceRedact(_ source: Data, secrets: [String]) -> Data {
        let sourceBytes = Array(source)
        let patterns = Array(Set(secrets.filter { !$0.isEmpty })).map { Array($0.utf8) }
        var output = [UInt8]()
        var cursor = 0
        while cursor < sourceBytes.count {
            let longest = patterns.filter { pattern in
                cursor + pattern.count <= sourceBytes.count
                    && sourceBytes[cursor ..< cursor + pattern.count].elementsEqual(pattern)
            }.map(\.count).max() ?? 0
            if longest > 0 {
                output += self.replacement.utf8
                cursor += longest
            } else {
                output.append(sourceBytes[cursor])
                cursor += 1
            }
        }
        return Data(output)
    }
}

private struct SeededGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        self.state = seed
    }

    mutating func nextInt(upperBound: Int) -> Int {
        self.state = self.state &* 6_364_136_223_846_793_005 &+ 1
        return Int(self.state % UInt64(upperBound))
    }
}
