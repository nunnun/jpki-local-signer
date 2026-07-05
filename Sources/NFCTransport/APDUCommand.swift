import Foundation

public struct APDUCommand: Equatable, Sendable {
    public let cla: UInt8
    public let ins: UInt8
    public let p1: UInt8
    public let p2: UInt8
    public let data: [UInt8]
    public let expectedResponseLength: ExpectedResponseLength?

    public enum ExpectedResponseLength: Equatable, Sendable {
        case exact(UInt8)
        case extended(UInt16)
        case maximum
    }

    public init(
        cla: UInt8,
        ins: UInt8,
        p1: UInt8,
        p2: UInt8,
        data: [UInt8] = [],
        expectedResponseLength: ExpectedResponseLength? = nil
    ) {
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = data
        self.expectedResponseLength = expectedResponseLength
    }

    public var encoded: [UInt8] {
        precondition(data.count <= UInt8.max, "Extended APDU command data is not implemented yet")

        var bytes = [cla, ins, p1, p2]
        if !data.isEmpty {
            bytes.append(UInt8(data.count))
            bytes.append(contentsOf: data)
        }

        switch expectedResponseLength {
        case nil:
            break
        case .exact(let le):
            bytes.append(le)
        case .extended(let le):
            bytes.append(0x00)
            bytes.append(UInt8((le >> 8) & 0xff))
            bytes.append(UInt8(le & 0xff))
        case .maximum:
            bytes.append(0x00)
        }

        return bytes
    }

    public static func selectFile(identifier: [UInt8]) -> APDUCommand {
        APDUCommand(
            cla: 0x00,
            ins: 0xA4,
            p1: 0x04,
            p2: 0x0C,
            data: identifier,
            expectedResponseLength: nil
        )
    }

    public static func selectEF(identifier: [UInt8]) -> APDUCommand {
        APDUCommand(
            cla: 0x00,
            ins: 0xA4,
            p1: 0x02,
            p2: 0x0C,
            data: identifier,
            expectedResponseLength: nil
        )
    }

    /// READ BINARY with a 15-bit offset (P1 bit 8 must stay clear so P1/P2 are
    /// interpreted as an offset, not a short EF identifier).
    public static func readBinary(offset: Int, expectedLength: Int) -> APDUCommand {
        precondition((0..<0x8000).contains(offset), "READ BINARY offset must fit in 15 bits")
        precondition((1...256).contains(expectedLength), "READ BINARY expected length must be 1...256")

        return APDUCommand(
            cla: 0x00,
            ins: 0xB0,
            p1: UInt8((offset >> 8) & 0x7F),
            p2: UInt8(offset & 0xFF),
            expectedResponseLength: expectedLength == 256 ? .maximum : .exact(UInt8(expectedLength))
        )
    }

    /// VERIFY with no command data: returns 63Cx carrying the remaining retry
    /// count without consuming an attempt.
    public static func verifyRetryQuery() -> APDUCommand {
        APDUCommand(
            cla: 0x00,
            ins: 0x20,
            p1: 0x00,
            p2: 0x80,
            expectedResponseLength: nil
        )
    }

    public static func verify(pin: String) -> APDUCommand {
        APDUCommand(
            cla: 0x00,
            ins: 0x20,
            p1: 0x00,
            p2: 0x80,
            data: Array(pin.utf8),
            expectedResponseLength: nil
        )
    }

    public static func computeDigitalSignature(digestInfo: [UInt8]) -> APDUCommand {
        APDUCommand(
            cla: 0x80,
            ins: 0x2A,
            p1: 0x00,
            p2: 0x80,
            data: digestInfo,
            expectedResponseLength: .maximum
        )
    }
}
