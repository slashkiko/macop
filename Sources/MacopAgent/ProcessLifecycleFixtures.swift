import Darwin
import Foundation

#if DEBUG
    func runLifecycleFixtures() -> Bool {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("macop-agent-lifecycle-' $ \(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        do {
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            let sentinel = open("/dev/null", O_RDONLY)
            guard sentinel >= 3 else { return false }
            defer { _ = close(sentinel) }
            let sentinelFlags = fcntl(sentinel, F_GETFD)
            guard sentinelFlags >= 0, fcntl(sentinel, F_SETFD, sentinelFlags & ~FD_CLOEXEC) == 0 else { return false }
            var sentinelEnvironment = ProcessInfo.processInfo.environment
            sentinelEnvironment["MACOP_SENTINEL_FD"] = "\(sentinel)"
            let sentinelPID = try spawn(
                [
                    "/bin/sh", "-c",
                    "test -e /dev/fd/0 && test -e /dev/fd/1 && test -e /dev/fd/2 && test ! -e /dev/fd/$MACOP_SENTINEL_FD"
                ],
                environment: sentinelEnvironment, isolatedProcessGroup: true
            )
            guard try waitForShellExit(sentinelPID) == 0 else { return false }
            let childFile = root.appendingPathComponent("child")
            let script = "trap '' TERM; (trap '' TERM; exec /bin/sleep 1000) & echo $! > \"$MACOP_AGENT_CHILD_FILE\"; while :; do sleep 1; done"
            var childEnvironment = ProcessInfo.processInfo.environment
            childEnvironment["MACOP_AGENT_CHILD_FILE"] = childFile.path
            let pid = try spawn(
                ["/bin/sh", "-c", script],
                environment: childEnvironment,
                isolatedProcessGroup: true
            )
            let owned = try capture(pid, mode: "shell")
            guard waitForFile(childFile),
                  let child = try Int32(String(contentsOf: childFile).trimmingCharacters(in: .whitespacesAndNewlines))
            else { abandon(
                pid,
                mode: "shell",
                isolated: true
            ); return false }
            terminateOwnedRoot(owned)
            guard waitForProcessExit(pid), waitForProcessExit(child) else { return false }

            let failedChildFile = root.appendingPathComponent("capture-failure-child")
            let failedScript = "(trap '' TERM; exec /bin/sleep 1000) & echo $! > \"$MACOP_AGENT_CHILD_FILE\"; while :; do sleep 1; done"
            var failedEnvironment = ProcessInfo.processInfo.environment
            failedEnvironment["MACOP_AGENT_CHILD_FILE"] = failedChildFile.path
            let failedPID = try spawn(["/bin/sh", "-c", failedScript], environment: failedEnvironment,
                                      isolatedProcessGroup: true)
            guard waitForFile(failedChildFile),
                  let failedChild = try Int32(String(contentsOf: failedChildFile)
                      .trimmingCharacters(in: .whitespacesAndNewlines))
            else { abandon(failedPID, mode: "shell", isolated: true); return false }
            abandon(failedPID, mode: "shell", isolated: true)
            guard waitForProcessExit(failedPID), waitForProcessExit(failedChild) else { return false }

            let appChildFile = root.appendingPathComponent("app-child")
            let appScript = "trap '' TERM; (trap '' TERM; exec /bin/sleep 1000) & echo $! > \"$MACOP_AGENT_CHILD_FILE\"; while :; do sleep 1; done"
            var appEnvironment = ProcessInfo.processInfo.environment
            appEnvironment["MACOP_AGENT_CHILD_FILE"] = appChildFile.path
            let appPID = try spawn(["/bin/sh", "-c", appScript], environment: appEnvironment,
                                   isolatedProcessGroup: true)
            let appOwned = try capture(appPID, mode: "application")
            guard waitForFile(appChildFile),
                  let appChild = try Int32(String(contentsOf: appChildFile)
                      .trimmingCharacters(in: .whitespacesAndNewlines))
            else { abandon(appPID, mode: "shell", isolated: true); return false }
            terminateOwnedRoot(appOwned)
            _ = try? waitForShellExit(appPID)
            guard waitForProcessExit(appPID), waitForProcessExit(appChild) else { return false }

            if isatty(STDIN_FILENO) == 1, isatty(STDOUT_FILENO) == 1 {
                let interactivePID = try spawn(["/bin/sh", "-c", "trap 'exit 130' INT; read -r _ </dev/tty"],
                                               environment: ProcessInfo.processInfo.environment,
                                               isolatedProcessGroup: false)
                guard getpgid(pid_t(interactivePID)) == getpgrp()
                else { abandon(interactivePID, mode: "shell"); return false }
                _ = kill(pid_t(interactivePID), SIGINT)
                guard (try? waitForShellExit(interactivePID)) == 130 else { return false }
            }
            return true
        } catch { return false }
    }
#endif
