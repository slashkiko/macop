import Foundation

/// Replaces complete UTF-8 secret byte sequences with a deterministic,
/// leftmost-longest result from the complete input stream.
///
/// The reverse byte Aho-Corasick automaton identifies every source start's
/// longest match directly. This is important for suffix overlaps: if an
/// earlier chosen secret skips a longer overlap, a shorter suffix secret is
/// still available at its own source start. Processing fixed windows of
/// `2 * longestSecret - 1` bytes keeps retained state independent of caller
/// chunk size. The first ordinary output can be delayed by up to
/// `2 * (longestSecret - 1)` bytes while the first complete window fills.
///
/// Adjacent windows overlap by at most `longestSecret - 1` bytes, so every
/// source byte is scanned at most twice. Each scan is linear because failure
/// links only move to shorter prefixes; replacement bytes are never scanned.
public final class SecretRedactor: @unchecked Sendable {
    private struct Node {
        var children = [UInt8: Int]()
        var failure = 0
        var longestOutput = 0
    }

    /// A ring prevents `removeFirst` from turning many small streaming chunks
    /// into quadratic copying. Its capacity depends only on the longest secret,
    /// never on the size of a caller-provided chunk.
    private struct PendingWindow {
        private var storage = [UInt8?]()
        private var head = 0
        private var entryCount = 0

        var isEmpty: Bool {
            self.entryCount == 0
        }

        var count: Int {
            self.entryCount
        }

        var capacity: Int {
            self.storage.count
        }

        mutating func append(_ byte: UInt8) {
            self.ensureCapacity(for: self.entryCount + 1)
            let index = (head + self.entryCount) % self.storage.count
            self.storage[index] = byte
            self.entryCount += 1
        }

        func bytes() -> [UInt8] {
            var result = [UInt8]()
            result.reserveCapacity(self.entryCount)
            for offset in 0 ..< self.entryCount {
                guard let byte = storage[(head + offset) % storage.count] else {
                    preconditionFailure("pending redactor byte is unexpectedly absent")
                }
                result.append(byte)
            }
            return result
        }

        mutating func discardFirst(_ amount: Int) {
            precondition(amount >= 0 && amount <= self.entryCount)
            guard amount > 0 else { return }
            for offset in 0 ..< amount {
                self.storage[(self.head + offset) % self.storage.count] = nil
            }
            self.head = (self.head + amount) % self.storage.count
            self.entryCount -= amount
            if self.isEmpty {
                self.head = 0
            }
        }

        private mutating func ensureCapacity(for required: Int) {
            guard self.storage.count < required else { return }
            let newCapacity = max(16, required, storage.count * 2)
            var expanded = [UInt8?](repeating: nil, count: newCapacity)
            for offset in 0 ..< self.entryCount {
                expanded[offset] = self.storage[(self.head + offset) % self.storage.count]
            }
            self.storage = expanded
            self.head = 0
        }
    }

    private let nodes: [Node]
    private let longestSecret: Int
    private let processingWindowSize: Int
    private let replacement = Array("<concealed by macop>".utf8)
    private var pending = PendingWindow()

    /// Internal test seams for deterministic bounds without a flaky benchmark.
    private(set) var transitionLookupCount = 0
    private(set) var maximumRetainedByteCount = 0

    var retainedByteCount: Int {
        self.pending.count
    }

    var pendingStorageCapacity: Int {
        self.pending.capacity
    }

    public init(secrets: [String]) {
        let patterns = Array(Set(secrets.filter { !$0.isEmpty }))
            .map { Array($0.utf8.reversed()) }
            .sorted { $0.lexicographicallyPrecedes($1) }
        self.longestSecret = patterns.map(\.count).max() ?? 0
        let maximumWindowSecretLength = Int.max / 2 + 1
        self.processingWindowSize = self.longestSecret == 0
            ? 0
            : self.longestSecret > maximumWindowSecretLength ? Int.max : self.longestSecret * 2 - 1
        self.nodes = Self.makeAutomaton(patterns: patterns)
    }

    public func process(_ chunk: Data, final: Bool = false) -> Data {
        guard self.longestSecret > 0 else { return chunk }

        var output = [UInt8]()
        for byte in chunk {
            self.pending.append(byte)
            self.maximumRetainedByteCount = max(self.maximumRetainedByteCount, self.pending.count)
            self.flushReady(into: &output)
        }
        if final {
            self.flushFinal(into: &output)
        }
        return Data(output)
    }

    private func flushReady(into output: inout [UInt8]) {
        while self.pending.count >= self.processingWindowSize {
            self.resolve(
                self.pending.bytes(),
                decisionCount: self.longestSecret,
                into: &output
            )
        }
    }

    private func flushFinal(into output: inout [UInt8]) {
        while !self.pending.isEmpty {
            let window = self.pending.bytes()
            self.resolve(window, decisionCount: window.count, into: &output)
        }
    }

    private func resolve(_ window: [UInt8], decisionCount: Int, into output: inout [UInt8]) {
        let matches = self.longestMatchesBySourceStart(in: window)
        var cursor = 0
        while cursor < decisionCount {
            let matchLength = matches[cursor]
            if matchLength > 0 {
                output += self.replacement
                cursor += matchLength
            } else {
                output.append(window[cursor])
                cursor += 1
            }
        }
        self.pending.discardFirst(cursor)
    }

    private func longestMatchesBySourceStart(in window: [UInt8]) -> [Int] {
        var matches = [Int](repeating: 0, count: window.count)
        var matcherState = 0
        for index in window.indices.reversed() {
            let byte = window[index]
            while matcherState != 0, self.nodes[matcherState].children[byte] == nil {
                self.transitionLookupCount += 1
                matcherState = self.nodes[matcherState].failure
            }
            self.transitionLookupCount += 1
            matcherState = self.nodes[matcherState].children[byte] ?? 0
            matches[index] = self.nodes[matcherState].longestOutput
        }
        return matches
    }

    private static func makeAutomaton(patterns: [[UInt8]]) -> [Node] {
        guard !patterns.isEmpty else { return [Node()] }
        var nodes = [Node]()
        nodes.append(Node())

        for pattern in patterns {
            var state = 0
            for byte in pattern {
                if let next = nodes[state].children[byte] {
                    state = next
                } else {
                    let next = nodes.count
                    nodes.append(Node())
                    nodes[state].children[byte] = next
                    state = next
                }
            }
            nodes[state].longestOutput = max(nodes[state].longestOutput, pattern.count)
        }

        var queue = Array(nodes[0].children.values)
        var cursor = 0
        while cursor < queue.count {
            let state = queue[cursor]
            cursor += 1
            for (byte, child) in nodes[state].children {
                var fallback = nodes[state].failure
                while fallback != 0, nodes[fallback].children[byte] == nil {
                    fallback = nodes[fallback].failure
                }
                if let next = nodes[fallback].children[byte] {
                    nodes[child].failure = next
                }
                nodes[child].longestOutput = max(
                    nodes[child].longestOutput,
                    nodes[nodes[child].failure].longestOutput
                )
                queue.append(child)
            }
        }
        return nodes
    }
}
