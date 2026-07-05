import Foundation

struct DEREncodedTLV: Equatable, Sendable {
    let tag: UInt8
    let contentRange: Range<Int>
    let totalRange: Range<Int>
}

enum DEREncodingError: Error, Equatable, Sendable {
    case invalidLength
    case invalidOID(String)
    case unexpectedEnd
    case unexpectedTag(expected: UInt8, actual: UInt8)
}

enum DEREncoding {
    static func sequence(_ children: [[UInt8]]) -> [UInt8] {
        tlv(tag: 0x30, content: children.flatMap { $0 })
    }

    static func set(_ children: [[UInt8]]) -> [UInt8] {
        tlv(tag: 0x31, content: children.flatMap { $0 })
    }

    static func setOf(_ children: [[UInt8]]) -> [UInt8] {
        set(children.sorted(by: lexicographicallyPrecedes))
    }

    static func contextConstructed(_ tagNumber: UInt8, content: [UInt8]) -> [UInt8] {
        tlv(tag: 0xA0 + tagNumber, content: content)
    }

    static func integer(_ value: Int) -> [UInt8] {
        precondition(value >= 0)

        var remaining = value
        var bytes: [UInt8] = []
        repeat {
            bytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        } while remaining > 0

        if let first = bytes.first, first & 0x80 != 0 {
            bytes.insert(0x00, at: 0)
        }

        return tlv(tag: 0x02, content: bytes)
    }

    static func octetString(_ bytes: [UInt8]) -> [UInt8] {
        tlv(tag: 0x04, content: bytes)
    }

    static func null() -> [UInt8] {
        [0x05, 0x00]
    }

    static func objectIdentifier(_ dotted: String) throws -> [UInt8] {
        let parts = try dotted.split(separator: ".", omittingEmptySubsequences: false).map { part -> UInt in
            guard let value = UInt(part) else {
                throw DEREncodingError.invalidOID(dotted)
            }
            return value
        }

        guard parts.count >= 2, parts[0] <= 2, parts[1] <= 39 || parts[0] == 2 else {
            throw DEREncodingError.invalidOID(dotted)
        }

        var content: [UInt8] = []
        appendBase128(parts[0] * 40 + parts[1], to: &content)
        for part in parts.dropFirst(2) {
            appendBase128(part, to: &content)
        }

        return tlv(tag: 0x06, content: content)
    }

    static func utcTime(_ date: Date) -> [UInt8] {
        let text = timeString(date, format: "%02d%02d%02d%02d%02d%02dZ", twoDigitYear: true)
        return tlv(tag: 0x17, content: Array(text.utf8))
    }

    static func generalizedTime(_ date: Date) -> [UInt8] {
        let text = timeString(date, format: "%04d%02d%02d%02d%02d%02dZ", twoDigitYear: false)
        return tlv(tag: 0x18, content: Array(text.utf8))
    }

    static func time(_ date: Date) -> [UInt8] {
        let year = utcCalendar.component(.year, from: date)
        if (1950..<2050).contains(year) {
            return utcTime(date)
        }
        return generalizedTime(date)
    }

    static func tlv(tag: UInt8, content: [UInt8]) -> [UInt8] {
        [tag] + length(content.count) + content
    }

    /// Reads a TLV. Supports BER indefinite lengths (`tag 0x80 ... 00 00`)
    /// because RFC 5652 permits BER for CMS ContentInfo and real-world
    /// signers (e.g. Apple's CMS encoder) emit it. For indefinite TLVs the
    /// `contentRange` excludes and `totalRange` includes the end-of-contents
    /// octets, so walking siblings via `totalRange.upperBound` stays correct.
    static func readTLV(_ bytes: [UInt8], at offset: Int) throws -> DEREncodedTLV {
        guard offset < bytes.count else {
            throw DEREncodingError.unexpectedEnd
        }

        let tag = bytes[offset]
        let lengthOffset = offset + 1
        guard lengthOffset < bytes.count else {
            throw DEREncodingError.unexpectedEnd
        }

        let firstLengthByte = bytes[lengthOffset]
        let contentStart: Int
        let contentLength: Int

        if firstLengthByte == 0x80 {
            guard tag & 0x20 != 0 else {
                throw DEREncodingError.invalidLength // indefinite on primitive
            }
            let start = lengthOffset + 1
            var cursor = start
            while true {
                guard cursor + 2 <= bytes.count else {
                    throw DEREncodingError.unexpectedEnd
                }
                if bytes[cursor] == 0x00, bytes[cursor + 1] == 0x00 {
                    return DEREncodedTLV(
                        tag: tag,
                        contentRange: start..<cursor,
                        totalRange: offset..<(cursor + 2)
                    )
                }
                cursor = try readTLV(bytes, at: cursor).totalRange.upperBound
            }
        } else if firstLengthByte & 0x80 == 0 {
            contentStart = lengthOffset + 1
            contentLength = Int(firstLengthByte)
        } else {
            let lengthByteCount = Int(firstLengthByte & 0x7F)
            guard lengthByteCount > 0, lengthByteCount <= MemoryLayout<Int>.size else {
                throw DEREncodingError.invalidLength
            }
            guard lengthOffset + lengthByteCount < bytes.count else {
                throw DEREncodingError.unexpectedEnd
            }

            var length = 0
            for byte in bytes[(lengthOffset + 1)...(lengthOffset + lengthByteCount)] {
                length = (length << 8) | Int(byte)
            }
            contentStart = lengthOffset + 1 + lengthByteCount
            contentLength = length
        }

        let contentEnd = contentStart + contentLength
        guard contentEnd <= bytes.count else {
            throw DEREncodingError.unexpectedEnd
        }

        return DEREncodedTLV(
            tag: tag,
            contentRange: contentStart..<contentEnd,
            totalRange: offset..<contentEnd
        )
    }

    static func requireTLV(_ bytes: [UInt8], at offset: Int, tag expectedTag: UInt8) throws -> DEREncodedTLV {
        let tlv = try readTLV(bytes, at: offset)
        guard tlv.tag == expectedTag else {
            throw DEREncodingError.unexpectedTag(expected: expectedTag, actual: tlv.tag)
        }
        return tlv
    }

    static func contentBytes(of encodedTLV: [UInt8], expectedTag: UInt8) throws -> [UInt8] {
        let tlv = try requireTLV(encodedTLV, at: 0, tag: expectedTag)
        guard tlv.totalRange.upperBound == encodedTLV.count else {
            throw DEREncodingError.invalidLength
        }
        return Array(encodedTLV[tlv.contentRange])
    }

    private static func length(_ value: Int) -> [UInt8] {
        precondition(value >= 0)

        if value < 128 {
            return [UInt8(value)]
        }

        var remaining = value
        var bytes: [UInt8] = []
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        }

        return [0x80 | UInt8(bytes.count)] + bytes
    }

    private static func appendBase128(_ value: UInt, to bytes: inout [UInt8]) {
        var encoded = [UInt8(value & 0x7F)]
        var remaining = value >> 7
        while remaining > 0 {
            encoded.insert(UInt8(remaining & 0x7F) | 0x80, at: 0)
            remaining >>= 7
        }
        bytes.append(contentsOf: encoded)
    }

    private static func lexicographicallyPrecedes(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        for (left, right) in zip(lhs, rhs) {
            if left != right {
                return left < right
            }
        }
        return lhs.count < rhs.count
    }

    private static func timeString(_ date: Date, format: String, twoDigitYear: Bool) -> String {
        let components = utcCalendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        let year = components.year ?? 1970
        let renderedYear = twoDigitYear ? year % 100 : year
        return String(
            format: format,
            locale: Locale(identifier: "en_US_POSIX"),
            renderedYear,
            components.month ?? 1,
            components.day ?? 1,
            components.hour ?? 0,
            components.minute ?? 0,
            components.second ?? 0
        )
    }

    private static var utcCalendar: Calendar {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0) ?? .gmt
        return calendar
    }
}
