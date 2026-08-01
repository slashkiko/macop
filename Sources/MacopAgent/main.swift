import Foundation

FileHandle.standardError.write(Data("macop-agent: not implemented yet\n".utf8))
exit(ExitCode.unsupported.rawValue)

private enum ExitCode: Int32 {
    case unsupported = 3
}

