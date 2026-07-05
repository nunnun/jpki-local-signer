import Foundation

public struct APDUResponse: Equatable, Sendable {
    public let data: [UInt8]
    public let sw1: UInt8
    public let sw2: UInt8

    public init(data: [UInt8], sw1: UInt8, sw2: UInt8) {
        self.data = data
        self.sw1 = sw1
        self.sw2 = sw2
    }

    public init(encoded bytes: [UInt8]) throws {
        guard bytes.count >= 2 else {
            throw APDUResponseError.missingStatusWord
        }

        self.data = Array(bytes.dropLast(2))
        self.sw1 = bytes[bytes.count - 2]
        self.sw2 = bytes[bytes.count - 1]
    }

    public var statusWord: UInt16 {
        UInt16(sw1) << 8 | UInt16(sw2)
    }

    public var isSuccess: Bool {
        statusWord == 0x9000
    }

    public var pinRetryCount: Int? {
        guard sw1 == 0x63, (sw2 & 0xF0) == 0xC0 else {
            return nil
        }
        return Int(sw2 & 0x0F)
    }

    public var status: APDUStatus {
        if isSuccess {
            return .success
        }
        if let pinRetryCount {
            return .pinVerificationFailed(retriesRemaining: pinRetryCount)
        }
        if statusWord == 0x6983 {
            return .authenticationMethodBlocked
        }
        if statusWord == 0x6A82 {
            return .fileNotFound
        }
        if statusWord == 0x6700 {
            return .wrongLength
        }
        return .unknown(statusWord)
    }
}

public enum APDUStatus: Equatable, Sendable {
    case success
    case pinVerificationFailed(retriesRemaining: Int)
    case authenticationMethodBlocked
    case fileNotFound
    case wrongLength
    case unknown(UInt16)
}

public enum APDUResponseError: Error, Equatable, Sendable {
    case missingStatusWord
}
