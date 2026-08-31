import Darwin
import Foundation
@testable import MacopCore
import XCTest

final class ConfigStoreDurabilityTests: XCTestCase {
    func testNewDirectorySyncsParentBeforeFileAndConfigDirectoryAfterRename() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("new-config")
        let file = directory.appendingPathComponent("config.json")
        var fileExistedAtSync = [Bool]()

        _ = try ConfigStore.initialize(configDirectory: directory.path) { _ in
            fileExistedAtSync.append(FileManager.default.fileExists(atPath: file.path))
            return 0
        }

        XCTAssertEqual(fileExistedAtSync, [false, false, true])
    }

    func testExistingDirectoryDoesNotSyncItsParent() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("existing-config")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var syncCount = 0

        _ = try ConfigStore.initialize(configDirectory: directory.path) { _ in
            syncCount += 1
            return 0
        }

        XCTAssertEqual(syncCount, 2)
    }

    func testPostRenameDirectorySyncFailureLeavesPublishedConfigAndThrows() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("new-config")
        let file = directory.appendingPathComponent("config.json")
        var syncCount = 0

        XCTAssertThrowsError(try ConfigStore.initialize(configDirectory: directory.path) { _ in
            syncCount += 1
            if syncCount == 3 {
                errno = EIO
                return -1
            }
            return 0
        })
        XCTAssertEqual(syncCount, 3)
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path))
    }
}
