import AppKit
import Darwin
import Foundation
import MacopCore

func snapshot(_ pid: Int32) -> ProcessSnapshot? {
    SystemRequesterInspector().snapshot(of: pid)
}

func spawn(_ argv: [String], environment: [String: String], isolatedProcessGroup: Bool) throws -> Int32 {
    guard let program = argv.first, !argv.isEmpty else { throw AgentProtocolError.denied }
    var arguments = argv.map { strdup($0) } + [nil]
    var variables = environment.map { strdup("\($0.key)=\($0.value)") } + [nil]
    defer { arguments.compactMap(\.self).forEach { free($0) }; variables.compactMap(\.self).forEach { free($0) } }
    var pid: pid_t = 0
    var attributes: posix_spawnattr_t?
    guard posix_spawnattr_init(&attributes) == 0 else { throw AgentProtocolError.denied }
    defer { posix_spawnattr_destroy(&attributes) }
    var flags: Int16 = 0
    var childSignalMask = sigset_t()
    sigemptyset(&childSignalMask)
    var childSignalDefaults = sigset_t()
    sigemptyset(&childSignalDefaults)
    sigaddset(&childSignalDefaults, SIGINT)
    sigaddset(&childSignalDefaults, SIGTERM)
    guard posix_spawnattr_setsigmask(&attributes, &childSignalMask) == 0,
          posix_spawnattr_setsigdefault(&attributes, &childSignalDefaults) == 0,
          posix_spawnattr_getflags(&attributes, &flags) == 0
    else { throw AgentProtocolError.denied }
    flags |= Int16(POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF)
    if isolatedProcessGroup {
        guard posix_spawnattr_setflags(&attributes, flags | Int16(POSIX_SPAWN_SETPGROUP)) == 0,
              // A zero process-group argument asks posix_spawn to establish a
              // new group with the child's PID. This is used only when no
              // interactive terminal is attached.
              posix_spawnattr_setpgroup(&attributes, 0) == 0
        else { throw AgentProtocolError.denied }
    } else if posix_spawnattr_setflags(&attributes, flags) != 0 {
        throw AgentProtocolError.denied
    }
    let result = arguments.withUnsafeMutableBufferPointer { argvBuffer in
        variables.withUnsafeMutableBufferPointer { environmentBuffer in
            posix_spawnp(&pid, program, nil, &attributes, argvBuffer.baseAddress, environmentBuffer.baseAddress)
        }
    }
    guard result == 0 else { throw AgentProtocolError.denied }
    return Int32(pid)
}

final class ApplicationLaunchBox: @unchecked Sendable {
    private let lock = NSLock()
    private var application: NSRunningApplication?

    func store(_ application: NSRunningApplication?) {
        self.lock.lock(); self.application = application; self.lock.unlock()
    }

    func read() -> NSRunningApplication? {
        self.lock.lock(); defer { self.lock.unlock() }
        return self.application
    }
}

func launchApplication(_ path: String, environment: [String: String]) throws -> NSRunningApplication {
    let launched = ApplicationLaunchBox()
    let config = NSWorkspace.OpenConfiguration()
    config.createsNewApplicationInstance = true
    config.environment = environment
    NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: path), configuration: config) { application, _ in
        launched.store(application)
    }
    let deadline = DispatchTime.now().uptimeNanoseconds + 15_000_000_000
    while launched.read() == nil, DispatchTime.now().uptimeNanoseconds < deadline {
        _ = RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.05))
    }
    guard let application = launched.read() else { throw AgentProtocolError.denied }
    return application
}

struct OwnedProcess {
    let pid: Int32
    let startTime: UInt64
    let mode: String
    let application: NSRunningApplication?
    let processGroup: Int32?
    let descendants: [Int32: UInt64]
}

private func childPIDs(of pid: Int32) -> [Int32] {
    // libproc does not promise a useful sizing result for a NULL buffer on
    // every supported macOS release. A bounded fixed buffer avoids treating a
    // zero sizing probe as “no descendants”.
    var storage = [pid_t](repeating: 0, count: 1024)
    let filled = storage.withUnsafeMutableBytes { buffer in
        proc_listchildpids(pid_t(pid), buffer.baseAddress, Int32(buffer.count))
    }
    guard filled > 0 else { return [] }
    // Unlike the list APIs that return a byte count, proc_listchildpids
    // returns a count of pid_t entries on macOS.
    let childCount = min(Int(filled), storage.count)
    return storage.enumerated().compactMap { index, child in index < childCount ? Int32(child) : nil }
}

private func descendantSnapshot(rootPID: Int32) -> [Int32: UInt64] {
    var result: [Int32: UInt64] = [:]
    var pending = [rootPID]
    while let parent = pending.popLast() {
        for child in childPIDs(of: parent) where result[child] == nil {
            guard let current = snapshot(child) else { continue }
            result[child] = current.startTime
            pending.append(child)
        }
    }
    return result
}

func capture(_ pid: Int32, mode: String, app: NSRunningApplication? = nil) throws -> OwnedProcess {
    guard let root = snapshot(pid) else { throw AgentProtocolError.denied }
    let group: Int32? = if mode == "shell", getpgid(pid_t(pid)) == pid_t(pid) {
        pid
    } else {
        nil
    }
    return OwnedProcess(
        pid: pid, startTime: root.startTime, mode: mode, application: app,
        processGroup: group, descendants: mode == "application" ? descendantSnapshot(rootPID: pid) : [:]
    )
}

func abandon(_ pid: Int32, mode: String, app: NSRunningApplication? = nil, isolated: Bool = false) {
    if let app {
        app.terminate()
        return
    }
    guard mode == "shell" else { return }
    let target = isolated ? -pid_t(pid) : pid_t(pid)
    _ = kill(target, SIGTERM)
    var status: Int32 = 0
    let deadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
    var rootExited = false
    while DispatchTime.now().uptimeNanoseconds < deadline {
        let waited = waitpid(pid_t(pid), &status, WNOHANG)
        rootExited = rootExited || waited == pid_t(pid) || (waited == -1 && errno == ECHILD)
        if rootExited, !isolated || !groupIsAlive(pid) {
            return
        }
        usleep(20000)
    }
    _ = kill(target, SIGKILL)
    if !rootExited {
        while waitpid(pid_t(pid), &status, 0) == -1, errno == EINTR {}
    }
    if isolated {
        let killDeadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
        while groupIsAlive(pid), DispatchTime.now().uptimeNanoseconds < killDeadline {
            usleep(20000)
        }
    }
}

func waitForShellExit(_ pid: Int32, interrupted: @escaping @Sendable () -> Bool = { false }) throws -> Int32 {
    var status: Int32 = 0
    while true {
        let waited = waitpid(pid_t(pid), &status, WNOHANG)
        if waited == pid_t(pid) {
            break
        }
        if waited == -1, errno != EINTR {
            throw AgentProtocolError.denied
        }
        if interrupted() {
            throw AgentProtocolError.denied
        }
        usleep(20000)
    }
    return status & 0x7F == 0 ? (status >> 8) & 0xFF : 128 + (status & 0x7F)
}

/// Poll application ownership and drain the signal self-pipe on each bounded tick.
func waitForApplicationExit(
    _ owned: OwnedProcess,
    interrupted: @escaping @Sendable () -> Bool = { false }
) throws -> Int32 {
    while rootIsStillOwned(owned) {
        if interrupted() {
            throw AgentProtocolError.denied
        }
        _ = RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.25))
    }
    return ExitCode.success.rawValue
}

private func isStillOwned(_ pid: Int32, _ startTime: UInt64) -> Bool {
    snapshot(pid)?.startTime == startTime
}

func rootIsStillOwned(_ owned: OwnedProcess) -> Bool {
    isStillOwned(owned.pid, owned.startTime)
}

func captureDescendants(for owned: OwnedProcess) -> [Int32: UInt64] {
    var result = owned.descendants
    // The root is pinned before this traversal. New children observed before
    // termination are included; children that fork afterwards are an
    // unavoidable NSWorkspace/process-tree race.
    if isStillOwned(owned.pid, owned.startTime) {
        result.merge(descendantSnapshot(rootPID: owned.pid)) { old, _ in old }
    }
    return result
}

func forwardSignal(_ signal: Int32, owned: OwnedProcess, descendants: [Int32: UInt64]) {
    if isStillOwned(owned.pid, owned.startTime) {
        if let group = owned.processGroup, getpgid(pid_t(owned.pid)) == pid_t(group) {
            _ = kill(-pid_t(group), signal)
        } else {
            _ = kill(pid_t(owned.pid), signal)
        }
    }
    for (pid, startTime) in descendants where isStillOwned(pid, startTime) {
        _ = kill(pid_t(pid), signal)
    }
}

private func groupIsAlive(_ group: Int32?) -> Bool {
    guard let group else { return false }
    if kill(-pid_t(group), 0) == 0 {
        return true
    }
    return errno == EPERM
}

private func descendantsAreAlive(_ descendants: [Int32: UInt64]) -> Bool {
    descendants.contains { pid, startTime in isStillOwned(pid, startTime) }
}

private func cleanupStillRunning(_ owned: OwnedProcess, descendants: [Int32: UInt64], deadline: UInt64) -> Bool {
    (groupIsAlive(owned.processGroup) || descendantsAreAlive(descendants))
        && DispatchTime.now().uptimeNanoseconds < deadline
}

private func shellRootExited(_ pid: Int32, status: inout Int32) -> Bool {
    let waited = waitpid(pid_t(pid), &status, WNOHANG)
    return waited == pid_t(pid) || (waited == -1 && errno == ECHILD)
}

private func appRootExited(_ application: NSRunningApplication?, owned: OwnedProcess) -> Bool {
    application?.isTerminated == true || !isStillOwned(owned.pid, owned.startTime)
}

func terminateOwnedRoot(
    _ owned: OwnedProcess,
    additionalDescendants: [Int32: UInt64] = [:],
    reapRoot: Bool = true,
    gracefulShutdownNanoseconds: UInt64 = 2_000_000_000
) {
    let application = owned.application
    var descendants = captureDescendants(for: owned)
    descendants.merge(additionalDescendants) { current, _ in current }
    if let application {
        application.terminate()
        for (pid, startTime) in descendants where isStillOwned(pid, startTime) {
            _ = kill(pid_t(pid), SIGTERM)
        }
    } else {
        forwardSignal(SIGTERM, owned: owned, descendants: descendants)
    }
    let deadline = DispatchTime.now().uptimeNanoseconds + gracefulShutdownNanoseconds
    var status: Int32 = 0
    var rootExited = false
    while DispatchTime.now().uptimeNanoseconds < deadline {
        if owned.mode == "shell" {
            rootExited = rootExited ||
                (reapRoot ? shellRootExited(owned.pid, status: &status) : !rootIsStillOwned(owned))
            if rootExited, !groupIsAlive(owned.processGroup), !descendantsAreAlive(descendants) {
                return
            }
        } else if appRootExited(application, owned: owned), !descendantsAreAlive(descendants) {
            return
        }
        usleep(20000)
    }
    if owned.mode == "shell", rootExited || isStillOwned(owned.pid, owned.startTime) {
        forwardSignal(SIGKILL, owned: owned, descendants: descendants)
        if !rootExited, reapRoot {
            _ = try? waitForShellExit(owned.pid)
        }
        if !reapRoot {
            let killDeadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
            while cleanupStillRunning(owned, descendants: descendants, deadline: killDeadline) {
                usleep(20000)
            }
        }
        return
    }
    if !appRootExited(application, owned: owned), isStillOwned(owned.pid, owned.startTime) {
        application?.forceTerminate()
    }
    forwardSignal(SIGKILL, owned: owned, descendants: descendants)
    let killDeadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
    while !appRootExited(application, owned: owned), DispatchTime.now().uptimeNanoseconds < killDeadline {
        usleep(20000)
    }
}

private func waitForFile(_ url: URL) -> Bool {
    let deadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
    while DispatchTime.now().uptimeNanoseconds < deadline {
        if FileManager.default.fileExists(atPath: url.path) {
            return true
        }
        usleep(20000)
    }
    return false
}

private func processExists(_ pid: Int32) -> Bool {
    kill(pid_t(pid), 0) == 0 || errno == EPERM
}

private func waitForProcessExit(_ pid: Int32) -> Bool {
    let deadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
    while DispatchTime.now().uptimeNanoseconds < deadline {
        if !processExists(pid) {
            return true
        }
        usleep(20000)
    }
    return !processExists(pid)
}

private func fixtureFailure(_ stage: String) -> Bool {
    if ProcessInfo.processInfo.environment["MACOP_AGENT_LIFECYCLE_DEBUG"] == "1" {
        FileHandle.standardError.write(Data("lifecycle fixture failed: \(stage)\n".utf8))
    }
    return false
}

/// Hidden, CTK-independent process fixtures used by the agent helper test.
/// They exercise the actual spawn/ownership/termination path, including a
/// TERM-ignoring forked child. A pseudo-terminal wrapper invokes this binary
/// separately to confirm interactive children retain its foreground group.
func runLifecycleFixtures() -> Bool {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("macop-agent-lifecycle-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: root) }
    do {
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let childFile = root.appendingPathComponent("child")
        let script = "trap '' TERM; (trap '' TERM; exec /bin/sleep 1000) & echo $! > '\(childFile.path)'; while :; do sleep 1; done"
        let pid = try spawn(["/bin/sh", "-c", script], environment: ProcessInfo.processInfo.environment,
                            isolatedProcessGroup: true)
        let owned = try capture(pid, mode: "shell")
        guard waitForFile(childFile),
              let child = try Int32(String(contentsOf: childFile).trimmingCharacters(in: .whitespacesAndNewlines))
        else { abandon(pid, mode: "shell", isolated: true); return fixtureFailure("shell-ready") }
        terminateOwnedRoot(owned)
        guard waitForProcessExit(pid), waitForProcessExit(child) else { return fixtureFailure("shell-cleanup") }

        let failedChildFile = root.appendingPathComponent("capture-failure-child")
        let failedScript = "(trap '' TERM; exec /bin/sleep 1000) & echo $! > '\(failedChildFile.path)'; while :; do sleep 1; done"
        let failedPID = try spawn(["/bin/sh", "-c", failedScript], environment: ProcessInfo.processInfo.environment,
                                  isolatedProcessGroup: true)
        guard waitForFile(failedChildFile),
              let failedChild = try Int32(String(contentsOf: failedChildFile)
                  .trimmingCharacters(in: .whitespacesAndNewlines))
        else { abandon(failedPID, mode: "shell", isolated: true); return fixtureFailure("capture-failure-ready") }
        abandon(failedPID, mode: "shell", isolated: true)
        guard waitForProcessExit(failedPID), waitForProcessExit(failedChild)
        else { return fixtureFailure("capture-failure-cleanup") }

        let appChildFile = root.appendingPathComponent("app-child")
        let appScript = "trap '' TERM; (trap '' TERM; exec /bin/sleep 1000) & echo $! > '\(appChildFile.path)'; while :; do sleep 1; done"
        let appPID = try spawn(["/bin/sh", "-c", appScript], environment: ProcessInfo.processInfo.environment,
                               isolatedProcessGroup: true)
        let appOwned = try capture(appPID, mode: "application")
        guard waitForFile(appChildFile),
              let appChild = try Int32(String(contentsOf: appChildFile).trimmingCharacters(in: .whitespacesAndNewlines))
        else { abandon(appPID, mode: "shell", isolated: true); return fixtureFailure("app-ready") }
        terminateOwnedRoot(appOwned)
        _ = try? waitForShellExit(appPID)
        guard waitForProcessExit(appPID) else { return fixtureFailure("app-root-cleanup") }
        guard waitForProcessExit(appChild) else { return fixtureFailure("app-child-cleanup") }

        if isatty(STDIN_FILENO) == 1, isatty(STDOUT_FILENO) == 1 {
            let interactivePID = try spawn(["/bin/sh", "-c", "trap 'exit 130' INT; read -r _ </dev/tty"],
                                           environment: ProcessInfo.processInfo.environment,
                                           isolatedProcessGroup: false)
            guard getpgid(pid_t(interactivePID)) == getpgrp() else {
                abandon(interactivePID, mode: "shell"); return fixtureFailure("interactive-pgrp")
            }
            _ = kill(pid_t(interactivePID), SIGINT)
            guard (try? waitForShellExit(interactivePID)) == 130 else { return fixtureFailure("interactive-sigint") }
        }
        return true
    } catch {
        return fixtureFailure("threw")
    }
}
