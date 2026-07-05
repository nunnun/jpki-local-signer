import Foundation

/// Raw view of one signature dictionary, for conformance checking (the
/// values the MOJ requirement constrains: Type / Filter / SubFilter /
/// Name / M / ByteRange / Contents).
public struct PDFSignatureDictionaryInfo: Sendable {
    public let type: String?
    public let filter: String?
    public let subFilter: String?
    /// /Name decoded (literal string or UTF-16BE hex text string).
    public let name: String?
    /// /M exactly as written (e.g. "D:20260704120000Z").
    public let modificationDate: String?
    public let byteRange: [Int]?
}

public enum PDFSignatureDictionaries {
    /// Enumerates signature dictionaries in file order by locating each
    /// `/ByteRange` and parsing its enclosing direct object's dictionary.
    /// Only top-level dictionary entries are read (a /Prop_Build sub-
    /// dictionary legitimately contains its own /Name, which must not
    /// shadow the signature's). Lenient: unparseable entries yield `nil`
    /// fields, never errors.
    public static func enumerate(in pdf: Data) -> [PDFSignatureDictionaryInfo] {
        let bytes = [UInt8](pdf)
        let marker = [UInt8]("/ByteRange".utf8)
        var results: [PDFSignatureDictionaryInfo] = []
        var searchIndex = 0

        while let markerStart = find(marker, in: bytes, from: searchIndex) {
            searchIndex = markerStart + marker.count

            // ByteRange value (skip unsigned placeholders).
            var cursor = markerStart + marker.count
            let byteRange = parseIntegerArray(bytes, from: &cursor)
            if byteRange == [0, 0, 0, 0] {
                continue
            }

            // Enclosing dictionary: the signature dictionary is a direct
            // object, so walk back to its `... obj` header and parse the
            // balanced `<< ... >>` that follows.
            guard let objectKeyword = findLast([UInt8]("obj".utf8), in: bytes, before: markerStart),
                  let dictionaryStart = find([UInt8]("<<".utf8), in: bytes, from: objectKeyword + 3),
                  dictionaryStart < markerStart,
                  let dictionaryBytes = try? PDFLexer.balancedDictionary(bytes, at: dictionaryStart) else {
                results.append(PDFSignatureDictionaryInfo(
                    type: nil, filter: nil, subFilter: nil, name: nil,
                    modificationDate: nil, byteRange: byteRange
                ))
                continue
            }

            let entries = topLevelEntries(dictionaryBytes)
            results.append(PDFSignatureDictionaryInfo(
                type: entries["Type"].flatMap { nameValue(dictionaryBytes, $0) },
                filter: entries["Filter"].flatMap { nameValue(dictionaryBytes, $0) },
                subFilter: entries["SubFilter"].flatMap { nameValue(dictionaryBytes, $0) },
                name: entries["Name"].flatMap { stringValue(dictionaryBytes, $0) },
                modificationDate: entries["M"].flatMap { stringValue(dictionaryBytes, $0) },
                byteRange: byteRange
            ))
        }

        return results
    }

    // MARK: - Top-level dictionary tokenization

    /// Key → value start offset for the OUTER dictionary only. Nested
    /// dictionaries, arrays, and strings are skipped as opaque values.
    static func topLevelEntries(_ dictionary: [UInt8]) -> [String: Int] {
        var entries: [String: Int] = [:]
        var cursor = 2 // after "<<"
        let end = dictionary.count - 2 // before ">>"

        while cursor < end {
            skipWhitespace(dictionary, &cursor, limit: end)
            guard cursor < end else { break }

            guard dictionary[cursor] == UInt8(ascii: "/") else {
                // Stray token (e.g. the "0 R" tail of a reference value):
                // resynchronize at the next top-level name.
                skipValue(dictionary, &cursor, limit: end)
                continue
            }

            cursor += 1
            let key = readName(dictionary, &cursor, limit: end)
            skipWhitespace(dictionary, &cursor, limit: end)
            guard cursor < end else { break }

            if entries[key] == nil {
                entries[key] = cursor
            }
            skipValue(dictionary, &cursor, limit: end)
        }

        return entries
    }

    private static func skipValue(_ bytes: [UInt8], _ cursor: inout Int, limit: Int) {
        guard cursor < limit else { return }
        switch bytes[cursor] {
        case UInt8(ascii: "<"):
            if cursor + 1 < limit, bytes[cursor + 1] == UInt8(ascii: "<") {
                if let nested = try? PDFLexer.balancedDictionary(bytes, at: cursor) {
                    cursor += nested.count
                } else {
                    cursor = limit
                }
            } else {
                cursor += 1
                while cursor < limit, bytes[cursor] != UInt8(ascii: ">") { cursor += 1 }
                cursor += 1
            }
        case UInt8(ascii: "("):
            cursor = PDFLexer.skipLiteralString(bytes, from: cursor)
        case UInt8(ascii: "["):
            var depth = 0
            while cursor < limit {
                if bytes[cursor] == UInt8(ascii: "[") { depth += 1 }
                if bytes[cursor] == UInt8(ascii: "]") {
                    depth -= 1
                    if depth == 0 { cursor += 1; break }
                }
                if bytes[cursor] == UInt8(ascii: "(") {
                    cursor = PDFLexer.skipLiteralString(bytes, from: cursor)
                    continue
                }
                cursor += 1
            }
        case UInt8(ascii: "/"):
            cursor += 1
            _ = readName(bytes, &cursor, limit: limit)
        default:
            while cursor < limit, !PDFLexer.isWhitespace(bytes[cursor]), !isDelimiter(bytes[cursor]) {
                cursor += 1
            }
            if cursor < limit, PDFLexer.isWhitespace(bytes[cursor]) { cursor += 1 }
        }
    }

    /// PDF name token, decoding #XX escapes.
    private static func readName(_ bytes: [UInt8], _ cursor: inout Int, limit: Int) -> String {
        var name: [UInt8] = []
        while cursor < limit, !PDFLexer.isWhitespace(bytes[cursor]), !isDelimiter(bytes[cursor]) {
            if bytes[cursor] == UInt8(ascii: "#"), cursor + 2 < limit,
               let high = hexNibble(bytes[cursor + 1]), let low = hexNibble(bytes[cursor + 2]) {
                name.append(high << 4 | low)
                cursor += 3
            } else {
                name.append(bytes[cursor])
                cursor += 1
            }
        }
        return String(latin1: name)
    }

    private static func isDelimiter(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "/"), UInt8(ascii: "<"), UInt8(ascii: ">"),
             UInt8(ascii: "["), UInt8(ascii: "]"), UInt8(ascii: "("),
             UInt8(ascii: ")"), UInt8(ascii: "%"):
            return true
        default:
            return false
        }
    }

    private static func skipWhitespace(_ bytes: [UInt8], _ cursor: inout Int, limit: Int) {
        while cursor < limit, PDFLexer.isWhitespace(bytes[cursor]) {
            cursor += 1
        }
    }

    private static func hexNibble(_ byte: UInt8) -> UInt8? {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return byte - UInt8(ascii: "0")
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return byte - UInt8(ascii: "A") + 10
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return byte - UInt8(ascii: "a") + 10
        default: return nil
        }
    }

    // MARK: - Value decoding

    private static func nameValue(_ bytes: [UInt8], _ start: Int) -> String? {
        guard start < bytes.count, bytes[start] == UInt8(ascii: "/") else { return nil }
        var cursor = start + 1
        let name = readName(bytes, &cursor, limit: bytes.count)
        return name.isEmpty ? nil : name
    }

    /// PDF text string: `(literal)` with escapes or `<hex>`; UTF-16BE with
    /// BOM is decoded, otherwise bytes are read as Latin-1 (close enough to
    /// PDFDocEncoding for display).
    private static func stringValue(_ bytes: [UInt8], _ start: Int) -> String? {
        guard start < bytes.count else { return nil }

        if bytes[start] == UInt8(ascii: "(") {
            var text: [UInt8] = []
            var cursor = start + 1
            var depth = 1
            while cursor < bytes.count {
                let byte = bytes[cursor]
                if byte == UInt8(ascii: "\\"), cursor + 1 < bytes.count {
                    let escaped = bytes[cursor + 1]
                    switch escaped {
                    case UInt8(ascii: "n"): text.append(0x0A)
                    case UInt8(ascii: "r"): text.append(0x0D)
                    case UInt8(ascii: "t"): text.append(0x09)
                    default: text.append(escaped)
                    }
                    cursor += 2
                    continue
                }
                if byte == UInt8(ascii: "(") { depth += 1 }
                if byte == UInt8(ascii: ")") {
                    depth -= 1
                    if depth == 0 {
                        return decodeTextStringBytes(text)
                    }
                }
                text.append(byte)
                cursor += 1
            }
            return nil
        }

        if bytes[start] == UInt8(ascii: "<"),
           start + 1 >= bytes.count || bytes[start + 1] != UInt8(ascii: "<") {
            var nibbles: [UInt8] = []
            var cursor = start + 1
            while cursor < bytes.count, bytes[cursor] != UInt8(ascii: ">") {
                if let nibble = hexNibble(bytes[cursor]) {
                    nibbles.append(nibble)
                } else if !PDFLexer.isWhitespace(bytes[cursor]) {
                    return nil
                }
                cursor += 1
            }
            guard cursor < bytes.count else { return nil }
            if !nibbles.count.isMultiple(of: 2) { nibbles.append(0) }
            var decoded: [UInt8] = []
            for pair in stride(from: 0, to: nibbles.count, by: 2) {
                decoded.append(nibbles[pair] << 4 | nibbles[pair + 1])
            }
            return decodeTextStringBytes(decoded)
        }

        return nil
    }

    private static func decodeTextStringBytes(_ bytes: [UInt8]) -> String {
        if bytes.count >= 2, bytes[0] == 0xFE, bytes[1] == 0xFF {
            var units: [UInt16] = []
            var index = 2
            while index + 1 < bytes.count {
                units.append(UInt16(bytes[index]) << 8 | UInt16(bytes[index + 1]))
                index += 2
            }
            return String(decoding: units, as: UTF16.self)
        }
        return String(latin1: bytes)
    }

    private static func parseIntegerArray(_ bytes: [UInt8], from cursor: inout Int) -> [Int]? {
        while cursor < bytes.count, PDFLexer.isWhitespace(bytes[cursor]) {
            cursor += 1
        }
        guard cursor < bytes.count, bytes[cursor] == UInt8(ascii: "[") else {
            return nil
        }
        cursor += 1
        var values: [Int] = []
        while cursor < bytes.count, bytes[cursor] != UInt8(ascii: "]") {
            if let value = PDFLexer.parseInteger(bytes, &cursor) {
                values.append(value)
            } else {
                cursor += 1
            }
        }
        return values.count == 4 ? values : nil
    }

    private static func find(_ needle: [UInt8], in haystack: [UInt8], from start: Int) -> Int? {
        guard needle.count <= haystack.count, start <= haystack.count - needle.count else { return nil }
        let first = needle[0]
        var index = start
        outer: while index <= haystack.count - needle.count {
            if haystack[index] != first {
                index += 1
                continue
            }
            for offset in 1..<needle.count where haystack[index + offset] != needle[offset] {
                index += 1
                continue outer
            }
            return index
        }
        return nil
    }

    private static func findLast(_ needle: [UInt8], in haystack: [UInt8], before end: Int) -> Int? {
        guard needle.count <= end else { return nil }
        var index = end - needle.count
        while index >= 0 {
            if Array(haystack[index..<index + needle.count]) == needle {
                return index
            }
            index -= 1
        }
        return nil
    }
}
