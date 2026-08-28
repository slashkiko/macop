import Foundation
import Security

/// Resolves each selector at most once for a single command. Only a genuinely
/// missing managed item may open Passwords; cancellation and other Keychain
/// failures remain failures instead of triggering a surprising second prompt.
final class PasswordFallbackKeychainClient: KeychainClient, @unchecked Sendable {
    private let primary: any KeychainClient
    private let passwordAutoFillProvider: any PasswordAutoFillProviding
    private let command: String
    private let lock = NSLock()
    private var cache = [KeychainQuery: Data]()

    init(
        primary: any KeychainClient,
        passwordAutoFillProvider: any PasswordAutoFillProviding,
        command: String
    ) {
        self.primary = primary
        self.passwordAutoFillProvider = passwordAutoFillProvider
        self.command = command
    }

    func read(_ query: KeychainQuery) -> Result<Data, KeychainFailure> {
        self.lock.lock()
        defer { self.lock.unlock() }
        if let cached = cache[query] {
            return .success(cached)
        }
        switch self.primary.read(query) {
        case let .success(secret):
            self.cache[query] = secret
            return .success(secret)
        case let .failure(failure):
            guard failure.status == errSecItemNotFound,
                  case let .managed(service, account) = query
            else { return .failure(failure) }
            do {
                let credential = try self.passwordAutoFillProvider.acquire(
                    service: service,
                    account: account,
                    command: self.command
                )
                guard !credential.secret.isEmpty,
                      credential.secret.count <= ManagedKeychainStore.maximumSecretLength
                else { return .failure(KeychainFailure(errSecDecode)) }
                self.cache[query] = credential.secret
                return .success(credential.secret)
            } catch let error as CLIError {
                return .failure(KeychainFailure(self.status(for: error)))
            } catch {
                return .failure(KeychainFailure(errSecInternalComponent))
            }
        }
    }

    private func status(for error: CLIError) -> OSStatus {
        switch error {
        case .denied:
            errSecUserCanceled
        case .providerUnavailable:
            errSecNotAvailable
        case .notFound:
            errSecItemNotFound
        default:
            errSecInternalComponent
        }
    }
}
