import Darwin
import Dispatch
import Foundation

public protocol GitClientVersionProbing: Sendable {
    func version(executablePath: String) -> String
}

public struct SystemGitClientVersionProbe: GitClientVersionProbing {
    private static let outputLimit = 4096
    private static let timeoutNanoseconds: UInt64 = 2_000_000_000

    public init() {}

    public func version(executablePath: String) -> String {
        guard executablePath.hasPrefix("/"), !executablePath.contains("\0") else { return "unknown" }
        var outputPipe = [Int32](repeating: -1, count: 2)
        guard pipe(&outputPipe) == 0 else { return "unknown" }
        let readDescriptor = outputPipe[0]
        var writeDescriptor = outputPipe[1]
        defer {
            close(readDescriptor); if writeDescriptor >= 0 {
                close(writeDescriptor)
            }
        }
        _ = fcntl(readDescriptor, F_SETFL, fcntl(readDescriptor, F_GETFL) | O_NONBLOCK)
        _ = fcntl(readDescriptor, F_SETFD, FD_CLOEXEC)
        _ = fcntl(writeDescriptor, F_SETFD, FD_CLOEXEC)

        var attributes: posix_spawnattr_t?
        var actions: posix_spawn_file_actions_t?
        guard posix_spawnattr_init(&attributes) == 0 else { return "unknown" }
        defer { posix_spawnattr_destroy(&attributes) }
        guard posix_spawn_file_actions_init(&actions) == 0 else { return "unknown" }
        defer { posix_spawn_file_actions_destroy(&actions) }
        let flags = Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETPGROUP)
        guard posix_spawnattr_setflags(&attributes, flags) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0,
              posix_spawn_file_actions_adddup2(&actions, writeDescriptor, STDOUT_FILENO) == 0,
              posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) == 0,
              posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0,
              posix_spawn_file_actions_addclose(&actions, readDescriptor) == 0,
              posix_spawn_file_actions_addclose(&actions, writeDescriptor) == 0
        else { return "unknown" }

        var arguments: [UnsafeMutablePointer<CChar>?] = [strdup(executablePath), strdup("--version"), nil]
        var environment: [UnsafeMutablePointer<CChar>?] = [strdup("PATH=/usr/bin:/bin"), nil]
        defer {
            arguments.compactMap(\.self).forEach { free($0) }
            environment.compactMap(\.self).forEach { free($0) }
        }
        var processID: pid_t = 0
        let spawnStatus = arguments.withUnsafeMutableBufferPointer { argumentBuffer in
            environment.withUnsafeMutableBufferPointer { environmentBuffer in
                posix_spawn(
                    &processID, executablePath, &actions, &attributes,
                    argumentBuffer.baseAddress, environmentBuffer.baseAddress
                )
            }
        }
        guard spawnStatus == 0, processID > 1 else { return "unknown" }
        close(writeDescriptor)
        writeDescriptor = -1

        var output = Data()
        var status: Int32 = 0
        var reaped = false
        let deadline = DispatchTime.now().uptimeNanoseconds + Self.timeoutNanoseconds
        while DispatchTime.now().uptimeNanoseconds < deadline {
            self.drain(readDescriptor, into: &output)
            let waited = waitpid(processID, &status, WNOHANG)
            if waited == processID {
                reaped = true; break
            }
            if waited == -1, errno != EINTR {
                break
            }
            var descriptor = pollfd(fd: readDescriptor, events: Int16(POLLIN), revents: 0)
            _ = poll(&descriptor, 1, 20)
        }
        if !reaped {
            _ = kill(-processID, SIGTERM)
            reaped = self.waitForExit(processID, status: &status, milliseconds: 200)
        }
        _ = kill(-processID, SIGKILL)
        if !reaped {
            reaped = self.waitForExit(processID, status: &status, milliseconds: 500)
        }
        self.drain(readDescriptor, into: &output)
        guard reaped, self.exitCode(status) == 0,
              let text = String(data: output, encoding: .utf8)
        else { return "unknown" }
        return text
    }

    private func drain(_ descriptor: Int32, into output: inout Data) {
        var buffer = [UInt8](repeating: 0, count: 1024)
        while true {
            let bufferSize = buffer.count
            let count = buffer.withUnsafeMutableBytes { read(descriptor, $0.baseAddress, bufferSize) }
            guard count > 0 else { return }
            if output.count < Self.outputLimit {
                output.append(buffer, count: min(count, Self.outputLimit - output.count))
            }
        }
    }

    private func waitForExit(_ processID: pid_t, status: inout Int32, milliseconds: Int32) -> Bool {
        let deadline = DispatchTime.now().uptimeNanoseconds + UInt64(milliseconds) * 1_000_000
        while DispatchTime.now().uptimeNanoseconds < deadline {
            let waited = waitpid(processID, &status, WNOHANG)
            if waited == processID {
                return true
            }
            if waited == -1, errno != EINTR {
                return false
            }
            usleep(10000)
        }
        return false
    }

    private func exitCode(_ status: Int32) -> Int32 {
        status & 0x7F != 0 ? 128 + (status & 0x7F) : (status >> 8) & 0xFF
    }
}
