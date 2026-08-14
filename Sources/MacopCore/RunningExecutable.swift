import Foundation

/// Resolves the Mach-O image currently executing this process.  `argv[0]` is
/// intentionally not used: callers may invoke macop through PATH or a symlink.
public enum RunningExecutable {
    public static func path() throws -> String {
        var byteCount: UInt32 = 0
        _ = _NSGetExecutablePath(nil, &byteCount)
        guard byteCount > 0 else {
            throw CLIError.notFound(message: "Could not resolve the running macop executable.")
        }
        let buffer = UnsafeMutablePointer<CChar>.allocate(capacity: Int(byteCount))
        defer { buffer.deallocate() }
        guard _NSGetExecutablePath(buffer, &byteCount) == 0 else {
            throw CLIError.notFound(message: "Could not resolve the running macop executable.")
        }
        return URL(fileURLWithPath: String(cString: buffer)).resolvingSymlinksInPath().path
    }
}
