import Foundation

enum StrictJSONDuplicateKeyScanner {
    static func containsDuplicateObjectKey(in data: Data) -> Bool {
        guard let text = String(data: data, encoding: .utf8) else { return false }
        var stack: [Set<String>] = []
        var index = text.startIndex
        var expectingKey = false
        while index < text.endIndex {
            let character = text[index]
            if character == "\"" {
                let start = text.index(after: index)
                var cursor = start
                var escaped = false
                while cursor < text.endIndex {
                    let current = text[cursor]
                    if current == "\"", !escaped {
                        break
                    }
                    if current == "\\", !escaped {
                        escaped = true
                    } else {
                        escaped = false
                    }
                    cursor = text.index(after: cursor)
                }
                guard cursor < text.endIndex else { return false }
                guard let string = self.decodeString(String(text[start ..< cursor])) else {
                    return false
                }
                var after = text.index(after: cursor)
                while after < text.endIndex, text[after].isWhitespace {
                    after = text.index(after: after)
                }
                if expectingKey, after < text.endIndex, text[after] == ":" {
                    if stack.last?.contains(string) == true {
                        return true
                    }
                    stack[stack.count - 1].insert(string)
                    expectingKey = false
                }
                index = text.index(after: cursor)
                continue
            }
            if character == "{" {
                stack.append([]); expectingKey = true
            }
            if character == "}" {
                _ = stack.popLast(); expectingKey = false
            }
            if character == ",", !stack.isEmpty {
                expectingKey = true
            }
            index = text.index(after: index)
        }
        return false
    }

    private static func decodeString(_ rawValue: String) -> String? {
        let data = Data("[\"\(rawValue)\"]".utf8)
        return try? JSONDecoder().decode([String].self, from: data).first
    }
}
