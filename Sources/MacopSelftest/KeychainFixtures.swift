import Foundation
import MacopCore

@inline(__always)
func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() {
        throw SelftestFailure(message: message)
    }
}

struct FakeKeychainClient: KeychainClient {
    let response: Result<Data, KeychainFailure>

    func read(_: KeychainQuery) -> Result<Data, KeychainFailure> {
        self.response
    }
}

final class RecordingKeychainClient: KeychainClient, @unchecked Sendable {
    var queries: [KeychainQuery] = []
    let response: Result<Data, KeychainFailure>

    init(_ response: Result<Data, KeychainFailure>) {
        self.response = response
    }

    func read(_ query: KeychainQuery) -> Result<Data, KeychainFailure> {
        self.queries.append(query)
        return self.response
    }
}

final class QuerySensitiveKeychainClient: KeychainClient, @unchecked Sendable {
    var queries = [KeychainQuery]()

    func read(_ query: KeychainQuery) -> Result<Data, KeychainFailure> {
        self.queries.append(query)
        switch query {
        case .generic(service: "service", account: "account"):
            return .success(Data("keychain://generic/other/account".utf8))
        default:
            return .success(Data("unexpected-second-resolution".utf8))
        }
    }
}
