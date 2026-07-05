import Foundation

#if canImport(Compression)
import Compression
#endif

/// Byte-level index of a PDF file: object locations resolved through the
/// classic xref table and/or cross-reference stream chain, plus the trailer
/// entries needed for an incremental update.
///
/// Bodies are exposed as ISO Latin-1 strings so every byte round-trips
/// losslessly (UTF-8 decoding would corrupt binary bytes inside dictionaries).
struct PDFDocumentIndex {
    enum ObjectLocation: Equatable {
        case direct(offset: Int)
        case inObjectStream(streamObjectNumber: Int, indexInStream: Int)
    }

    let data: [UInt8]
    let objectLocations: [Int: ObjectLocation]
    let generations: [Int: Int]
    let rootReference: (number: Int, generation: Int)
    let size: Int
    /// Value for /Prev in the incremental update (the file's last startxref).
    let lastXrefOffset: Int
    /// Whether the newest xref section is a cross-reference stream. The
    /// incremental update must use the same kind.
    let usesXrefStream: Bool

    var nextObjectNumber: Int {
        max(size, (objectLocations.keys.max() ?? 0) + 1)
    }

    static func parse(_ pdf: Data) throws -> PDFDocumentIndex {
        let bytes = [UInt8](pdf)
        let lastXrefOffset = try parseStartXref(bytes)

        var objectLocations: [Int: ObjectLocation] = [:]
        var generations: [Int: Int] = [:]
        var rootReference: (Int, Int)?
        var size = 0
        var usesXrefStream: Bool?

        var nextOffset: Int? = lastXrefOffset
        var visited = Set<Int>()
        while let offset = nextOffset {
            guard offset >= 0, offset < bytes.count, visited.insert(offset).inserted else {
                throw PDFSignaturePreparerError.invalidPDF
            }

            let section = try parseXrefSection(bytes, at: offset)
            if usesXrefStream == nil {
                usesXrefStream = section.isStream
            }
            // Newer sections win; only fill entries not already present.
            for (number, entry) in section.entries where objectLocations[number] == nil {
                objectLocations[number] = entry.location
                generations[number] = entry.generation
            }
            if rootReference == nil {
                rootReference = section.rootReference
            }
            size = max(size, section.size)
            nextOffset = section.previousOffset

            // Hybrid-reference files: a classic trailer may point at an extra
            // xref stream carrying the compressed-object entries.
            if let hybridOffset = section.xrefStmOffset,
               visited.insert(hybridOffset).inserted,
               hybridOffset >= 0, hybridOffset < bytes.count {
                let hybrid = try parseXrefSection(bytes, at: hybridOffset)
                for (number, entry) in hybrid.entries where objectLocations[number] == nil {
                    objectLocations[number] = entry.location
                    generations[number] = entry.generation
                }
                size = max(size, hybrid.size)
            }
        }

        guard let rootReference else {
            throw PDFSignaturePreparerError.rootObjectNotFound
        }

        return PDFDocumentIndex(
            data: bytes,
            objectLocations: objectLocations,
            generations: generations,
            rootReference: rootReference,
            size: size,
            lastXrefOffset: lastXrefOffset,
            usesXrefStream: usesXrefStream ?? false
        )
    }

    /// Loads an object's body (the tokens between `N G obj` and
    /// `endobj`/`stream`) as a Latin-1 string. Objects inside object streams
    /// are extracted after FlateDecode.
    func objectBody(_ number: Int) throws -> String {
        guard let location = objectLocations[number] else {
            throw PDFSignaturePreparerError.objectNotFound(number)
        }

        switch location {
        case .direct(let offset):
            return try Self.directObjectBody(bytes: data, offset: offset, expectedNumber: number)
        case .inObjectStream(let streamObjectNumber, let indexInStream):
            let stream = try loadStreamObject(streamObjectNumber)
            return try Self.objectStreamEntry(
                streamDictionary: stream.dictionary,
                payload: stream.payload,
                index: indexInStream
            )
        }
    }

    func generation(of number: Int) -> Int {
        generations[number] ?? 0
    }

    // MARK: - startxref / xref sections

    private static func parseStartXref(_ bytes: [UInt8]) throws -> Int {
        let marker = [UInt8]("startxref".utf8)
        guard let markerStart = lastRange(of: marker, in: bytes) else {
            throw PDFSignaturePreparerError.invalidPDF
        }
        var cursor = markerStart + marker.count
        PDFLexer.skipWhitespaceAndComments(bytes, &cursor)
        guard let value = PDFLexer.parseInteger(bytes, &cursor) else {
            throw PDFSignaturePreparerError.invalidPDF
        }
        return value
    }

    private struct XrefEntry {
        let location: ObjectLocation
        let generation: Int
    }

    private struct XrefSection {
        let entries: [Int: XrefEntry]
        let rootReference: (number: Int, generation: Int)?
        let size: Int
        let previousOffset: Int?
        let xrefStmOffset: Int?
        let isStream: Bool
    }

    private static func parseXrefSection(_ bytes: [UInt8], at offset: Int) throws -> XrefSection {
        var cursor = offset
        PDFLexer.skipWhitespaceAndComments(bytes, &cursor)
        if PDFLexer.matches(bytes, at: cursor, keyword: "xref") {
            return try parseClassicXref(bytes, at: cursor + 4)
        }
        return try parseXrefStream(bytes, at: cursor)
    }

    private static func parseClassicXref(_ bytes: [UInt8], at start: Int) throws -> XrefSection {
        var cursor = start
        var entries: [Int: XrefEntry] = [:]

        while true {
            PDFLexer.skipWhitespaceAndComments(bytes, &cursor)
            if PDFLexer.matches(bytes, at: cursor, keyword: "trailer") {
                cursor += 7
                break
            }
            guard let firstNumber = PDFLexer.parseInteger(bytes, &cursor) else {
                throw PDFSignaturePreparerError.invalidPDF
            }
            PDFLexer.skipWhitespaceAndComments(bytes, &cursor)
            guard let count = PDFLexer.parseInteger(bytes, &cursor) else {
                throw PDFSignaturePreparerError.invalidPDF
            }
            PDFLexer.skipWhitespaceAndComments(bytes, &cursor)

            // Token-based parsing tolerates both 19- and 20-byte records.
            for index in 0..<count {
                PDFLexer.skipWhitespaceAndComments(bytes, &cursor)
                guard let entryOffset = PDFLexer.parseInteger(bytes, &cursor) else {
                    throw PDFSignaturePreparerError.invalidPDF
                }
                PDFLexer.skipWhitespaceAndComments(bytes, &cursor)
                guard let generation = PDFLexer.parseInteger(bytes, &cursor) else {
                    throw PDFSignaturePreparerError.invalidPDF
                }
                PDFLexer.skipWhitespaceAndComments(bytes, &cursor)
                guard cursor < bytes.count else {
                    throw PDFSignaturePreparerError.invalidPDF
                }
                let kind = bytes[cursor]
                cursor += 1
                if kind == UInt8(ascii: "n") {
                    entries[firstNumber + index] = XrefEntry(
                        location: .direct(offset: entryOffset),
                        generation: generation
                    )
                } else if kind != UInt8(ascii: "f") {
                    throw PDFSignaturePreparerError.invalidPDF
                }
            }
        }

        PDFLexer.skipWhitespaceAndComments(bytes, &cursor)
        let trailerBody = try PDFLexer.balancedDictionary(bytes, at: cursor)
        let trailer = String(latin1: trailerBody)

        return XrefSection(
            entries: entries,
            rootReference: PDFDictionaryScanner.reference(named: "Root", in: trailer),
            size: PDFDictionaryScanner.integer(named: "Size", in: trailer) ?? 0,
            previousOffset: PDFDictionaryScanner.integer(named: "Prev", in: trailer),
            xrefStmOffset: PDFDictionaryScanner.integer(named: "XRefStm", in: trailer),
            isStream: false
        )
    }

    private static func parseXrefStream(_ bytes: [UInt8], at start: Int) throws -> XrefSection {
        let object = try parseStreamObjectHeader(bytes, at: start)
        let dictionary = object.dictionary

        guard PDFDictionaryScanner.name(named: "Type", in: dictionary) == "XRef" else {
            throw PDFSignaturePreparerError.invalidPDF
        }
        guard let size = PDFDictionaryScanner.integer(named: "Size", in: dictionary),
              let widths = PDFDictionaryScanner.integerArray(named: "W", in: dictionary),
              widths.count >= 3 else {
            throw PDFSignaturePreparerError.invalidPDF
        }

        let payload = try decodeStreamPayload(dictionary: dictionary, raw: object.payload)
        let rowWidth = widths.reduce(0, +)
        guard rowWidth > 0 else {
            throw PDFSignaturePreparerError.invalidPDF
        }

        let index = PDFDictionaryScanner.integerArray(named: "Index", in: dictionary) ?? [0, size]
        guard index.count.isMultiple(of: 2) else {
            throw PDFSignaturePreparerError.invalidPDF
        }

        var entries: [Int: XrefEntry] = [:]
        var rowStart = 0
        for pair in stride(from: 0, to: index.count, by: 2) {
            let firstNumber = index[pair]
            let count = index[pair + 1]
            for row in 0..<count {
                guard rowStart + rowWidth <= payload.count else {
                    throw PDFSignaturePreparerError.invalidPDF
                }
                var fields: [Int] = []
                var cursor = rowStart
                for width in widths {
                    var value = 0
                    for _ in 0..<width {
                        value = value << 8 | Int(payload[cursor])
                        cursor += 1
                    }
                    fields.append(value)
                }
                rowStart += rowWidth

                // Default type when W[0] == 0 is 1 (in-use).
                let type = widths[0] == 0 ? 1 : fields[0]
                let number = firstNumber + row
                switch type {
                case 1:
                    entries[number] = XrefEntry(
                        location: .direct(offset: fields[1]),
                        generation: fields[2]
                    )
                case 2:
                    entries[number] = XrefEntry(
                        location: .inObjectStream(streamObjectNumber: fields[1], indexInStream: fields[2]),
                        generation: 0
                    )
                default:
                    break // type 0: free
                }
            }
        }

        return XrefSection(
            entries: entries,
            rootReference: PDFDictionaryScanner.reference(named: "Root", in: dictionary),
            size: size,
            previousOffset: PDFDictionaryScanner.integer(named: "Prev", in: dictionary),
            xrefStmOffset: nil,
            isStream: true
        )
    }

    // MARK: - Objects

    private static func directObjectBody(bytes: [UInt8], offset: Int, expectedNumber: Int) throws -> String {
        var cursor = offset
        guard let header = PDFLexer.parseObjectHeader(bytes, &cursor), header.number == expectedNumber else {
            throw PDFSignaturePreparerError.objectNotFound(expectedNumber)
        }
        PDFLexer.skipWhitespaceAndComments(bytes, &cursor)

        if cursor + 1 < bytes.count, bytes[cursor] == UInt8(ascii: "<"), bytes[cursor + 1] == UInt8(ascii: "<") {
            let dictionary = try PDFLexer.balancedDictionary(bytes, at: cursor)
            return String(latin1: dictionary)
        }

        // Non-dictionary object (e.g. an /Annots array stored indirectly).
        guard let endRange = firstRange(of: [UInt8]("endobj".utf8), in: bytes, from: cursor) else {
            throw PDFSignaturePreparerError.objectNotFound(expectedNumber)
        }
        let body = Array(bytes[cursor..<endRange])
        return String(latin1: body).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private struct StreamObject {
        let dictionary: String
        let payload: [UInt8]
    }

    private func loadStreamObject(_ number: Int) throws -> StreamObject {
        guard let location = objectLocations[number], case .direct(let offset) = location else {
            throw PDFSignaturePreparerError.objectNotFound(number)
        }
        var cursor = offset
        guard let header = PDFLexer.parseObjectHeader(data, &cursor), header.number == number else {
            throw PDFSignaturePreparerError.objectNotFound(number)
        }
        PDFLexer.skipWhitespaceAndComments(data, &cursor)
        let object = try Self.parseStreamObjectHeader(data, at: cursor, dictionaryStart: true)
        let payload = try Self.decodeStreamPayload(dictionary: object.dictionary, raw: object.payload)
        return StreamObject(dictionary: object.dictionary, payload: payload)
    }

    private struct RawStreamObject {
        let dictionary: String
        let payload: [UInt8]
    }

    /// Parses `N G obj << ... >> stream ... endstream` starting either at the
    /// object header (`dictionaryStart == false`) or at `<<`.
    private static func parseStreamObjectHeader(
        _ bytes: [UInt8],
        at start: Int,
        dictionaryStart: Bool = false
    ) throws -> RawStreamObject {
        var cursor = start
        if !dictionaryStart {
            guard PDFLexer.parseObjectHeader(bytes, &cursor) != nil else {
                throw PDFSignaturePreparerError.invalidPDF
            }
            PDFLexer.skipWhitespaceAndComments(bytes, &cursor)
        }

        let dictionaryBytes = try PDFLexer.balancedDictionary(bytes, at: cursor)
        let dictionary = String(latin1: dictionaryBytes)
        cursor += dictionaryBytes.count
        PDFLexer.skipWhitespaceAndComments(bytes, &cursor)

        guard PDFLexer.matches(bytes, at: cursor, keyword: "stream") else {
            throw PDFSignaturePreparerError.invalidPDF
        }
        cursor += 6
        // Per spec: keyword `stream` is followed by CRLF or LF.
        if cursor < bytes.count, bytes[cursor] == 0x0D { cursor += 1 }
        if cursor < bytes.count, bytes[cursor] == 0x0A { cursor += 1 }

        guard let length = PDFDictionaryScanner.integer(named: "Length", in: dictionary),
              cursor + length <= bytes.count else {
            // Indirect /Length values are rare; unsupported for now.
            throw PDFSignaturePreparerError.unsupportedStreamLength
        }

        return RawStreamObject(dictionary: dictionary, payload: Array(bytes[cursor..<cursor + length]))
    }

    private static func decodeStreamPayload(dictionary: String, raw: [UInt8]) throws -> [UInt8] {
        let filter = PDFDictionaryScanner.name(named: "Filter", in: dictionary)
        var payload: [UInt8]
        switch filter {
        case nil:
            payload = raw
        case "FlateDecode":
            payload = try FlateDecoder.inflate(raw)
        default:
            throw PDFSignaturePreparerError.unsupportedStreamFilter(filter ?? "?")
        }

        if let decodeParms = PDFDictionaryScanner.dictionary(named: "DecodeParms", in: dictionary),
           let predictor = PDFDictionaryScanner.integer(named: "Predictor", in: decodeParms),
           predictor >= 2 {
            let columns = PDFDictionaryScanner.integer(named: "Columns", in: decodeParms) ?? 1
            let colors = PDFDictionaryScanner.integer(named: "Colors", in: decodeParms) ?? 1
            let bitsPerComponent = PDFDictionaryScanner.integer(named: "BitsPerComponent", in: decodeParms) ?? 8
            payload = try FlateDecoder.applyPNGPredictor(
                payload,
                columns: columns,
                colors: colors,
                bitsPerComponent: bitsPerComponent
            )
        }

        return payload
    }

    private static func objectStreamEntry(streamDictionary: String, payload: [UInt8], index: Int) throws -> String {
        guard PDFDictionaryScanner.name(named: "Type", in: streamDictionary) == "ObjStm",
              let count = PDFDictionaryScanner.integer(named: "N", in: streamDictionary),
              let first = PDFDictionaryScanner.integer(named: "First", in: streamDictionary),
              index < count else {
            throw PDFSignaturePreparerError.invalidPDF
        }

        // Header: N pairs of "objectNumber offset" relative to /First.
        var cursor = 0
        var offsets: [Int] = []
        for _ in 0..<count {
            PDFLexer.skipWhitespaceAndComments(payload, &cursor)
            guard PDFLexer.parseInteger(payload, &cursor) != nil else {
                throw PDFSignaturePreparerError.invalidPDF
            }
            PDFLexer.skipWhitespaceAndComments(payload, &cursor)
            guard let offset = PDFLexer.parseInteger(payload, &cursor) else {
                throw PDFSignaturePreparerError.invalidPDF
            }
            offsets.append(offset)
        }

        let start = first + offsets[index]
        let end = index + 1 < count ? first + offsets[index + 1] : payload.count
        guard start <= end, end <= payload.count else {
            throw PDFSignaturePreparerError.invalidPDF
        }
        return String(latin1: Array(payload[start..<end])).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    // MARK: - Byte search helpers

    private static func lastRange(of needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard needle.count <= haystack.count else { return nil }
        for start in stride(from: haystack.count - needle.count, through: 0, by: -1)
        where Array(haystack[start..<start + needle.count]) == needle {
            return start
        }
        return nil
    }

    private static func firstRange(of needle: [UInt8], in haystack: [UInt8], from start: Int) -> Int? {
        guard needle.count <= haystack.count, start <= haystack.count - needle.count else { return nil }
        for index in start...(haystack.count - needle.count)
        where Array(haystack[index..<index + needle.count]) == needle {
            return index
        }
        return nil
    }
}

// MARK: - Lexer

enum PDFLexer {
    static func isWhitespace(_ byte: UInt8) -> Bool {
        byte == 0x00 || byte == 0x09 || byte == 0x0A || byte == 0x0C || byte == 0x0D || byte == 0x20
    }

    static func skipWhitespaceAndComments(_ bytes: [UInt8], _ cursor: inout Int) {
        while cursor < bytes.count {
            if isWhitespace(bytes[cursor]) {
                cursor += 1
            } else if bytes[cursor] == UInt8(ascii: "%") {
                while cursor < bytes.count, bytes[cursor] != 0x0A, bytes[cursor] != 0x0D {
                    cursor += 1
                }
            } else {
                break
            }
        }
    }

    static func parseInteger(_ bytes: [UInt8], _ cursor: inout Int) -> Int? {
        var value = 0
        var digits = 0
        while cursor < bytes.count, (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(bytes[cursor]) {
            value = value * 10 + Int(bytes[cursor] - UInt8(ascii: "0"))
            digits += 1
            cursor += 1
        }
        return digits > 0 ? value : nil
    }

    static func matches(_ bytes: [UInt8], at cursor: Int, keyword: String) -> Bool {
        let keywordBytes = [UInt8](keyword.utf8)
        guard cursor + keywordBytes.count <= bytes.count else { return false }
        return Array(bytes[cursor..<cursor + keywordBytes.count]) == keywordBytes
    }

    /// Parses `N G obj`, advancing the cursor past the keyword.
    static func parseObjectHeader(_ bytes: [UInt8], _ cursor: inout Int) -> (number: Int, generation: Int)? {
        var probe = cursor
        skipWhitespaceAndComments(bytes, &probe)
        guard let number = parseInteger(bytes, &probe) else { return nil }
        skipWhitespaceAndComments(bytes, &probe)
        guard let generation = parseInteger(bytes, &probe) else { return nil }
        skipWhitespaceAndComments(bytes, &probe)
        guard matches(bytes, at: probe, keyword: "obj") else { return nil }
        cursor = probe + 3
        return (number, generation)
    }

    /// Returns the bytes of a balanced `<< ... >>` dictionary starting at
    /// `start`. Skips string and hex-string contents so binary bytes cannot
    /// unbalance the scan.
    static func balancedDictionary(_ bytes: [UInt8], at start: Int) throws -> [UInt8] {
        guard start + 1 < bytes.count,
              bytes[start] == UInt8(ascii: "<"), bytes[start + 1] == UInt8(ascii: "<") else {
            throw PDFSignaturePreparerError.invalidObjectDictionary
        }

        var cursor = start
        var depth = 0
        while cursor < bytes.count {
            let byte = bytes[cursor]
            if byte == UInt8(ascii: "<") {
                if cursor + 1 < bytes.count, bytes[cursor + 1] == UInt8(ascii: "<") {
                    depth += 1
                    cursor += 2
                } else {
                    // Hex string: skip to the closing '>'.
                    cursor += 1
                    while cursor < bytes.count, bytes[cursor] != UInt8(ascii: ">") {
                        cursor += 1
                    }
                    cursor += 1
                }
            } else if byte == UInt8(ascii: ">") {
                if cursor + 1 < bytes.count, bytes[cursor + 1] == UInt8(ascii: ">") {
                    depth -= 1
                    cursor += 2
                    if depth == 0 {
                        return Array(bytes[start..<cursor])
                    }
                } else {
                    cursor += 1
                }
            } else if byte == UInt8(ascii: "(") {
                cursor = skipLiteralString(bytes, from: cursor)
            } else {
                cursor += 1
            }
        }

        throw PDFSignaturePreparerError.invalidObjectDictionary
    }

    /// Advances past a `(...)` literal string starting at `start`, honoring
    /// escapes and nested parentheses.
    static func skipLiteralString(_ bytes: [UInt8], from start: Int) -> Int {
        var cursor = start + 1
        var depth = 1
        while cursor < bytes.count, depth > 0 {
            switch bytes[cursor] {
            case UInt8(ascii: "\\"):
                cursor += 2
                continue
            case UInt8(ascii: "("):
                depth += 1
            case UInt8(ascii: ")"):
                depth -= 1
            default:
                break
            }
            cursor += 1
        }
        return cursor
    }
}

// MARK: - Dictionary scanning on Latin-1 bodies

/// Minimal key/value extraction from dictionary bodies kept as Latin-1
/// strings. Keys are matched as whole names (a following delimiter is
/// required) so `/Root` never matches `/RootX`.
enum PDFDictionaryScanner {
    static func valueRange(named name: String, in body: String) -> Range<String.Index>? {
        guard let nameRange = range(ofName: name, in: body) else { return nil }
        var cursor = nameRange.upperBound
        skipWhitespace(body, &cursor)
        guard cursor < body.endIndex else { return nil }
        return cursor..<body.endIndex
    }

    static func integer(named name: String, in body: String) -> Int? {
        guard let range = valueRange(named: name, in: body) else { return nil }
        var digits = ""
        for character in body[range] {
            if character.isNumber {
                digits.append(character)
            } else {
                break
            }
        }
        return Int(digits)
    }

    static func name(named key: String, in body: String) -> String? {
        guard let range = valueRange(named: key, in: body) else { return nil }
        let text = body[range]
        guard text.hasPrefix("/") else { return nil }
        var value = ""
        for character in text.dropFirst() {
            if character.isLetter || character.isNumber {
                value.append(character)
            } else {
                break
            }
        }
        return value.isEmpty ? nil : value
    }

    /// `N G R` reference value.
    static func reference(named name: String, in body: String) -> (number: Int, generation: Int)? {
        guard let range = valueRange(named: name, in: body) else { return nil }
        return parseReference(body[range])
    }

    static func parseReference(_ text: Substring) -> (number: Int, generation: Int)? {
        var cursor = text.startIndex
        guard let number = parseInteger(text, &cursor) else { return nil }
        skipWhitespace(text.base, &cursor)
        guard let generation = parseInteger(text, &cursor) else { return nil }
        skipWhitespace(text.base, &cursor)
        guard cursor < text.endIndex, text.base[cursor] == "R" else { return nil }
        return (number, generation)
    }

    /// `[N G R N G R ...]` array of references.
    static func referenceArray(named name: String, in body: String) -> [(number: Int, generation: Int)]? {
        guard let range = valueRange(named: name, in: body), body[range].hasPrefix("[") else { return nil }
        var references: [(number: Int, generation: Int)] = []
        var numbers: [Int] = []
        var current = ""

        func flushNumber() {
            if let value = Int(current) { numbers.append(value) }
            current = ""
        }

        for character in body[range].dropFirst() {
            if character == "]" {
                return references
            } else if character.isNumber {
                current.append(character)
            } else if character == "R" {
                flushNumber()
                if numbers.count >= 2 {
                    references.append((numbers[numbers.count - 2], numbers[numbers.count - 1]))
                }
                numbers.removeAll()
            } else {
                flushNumber()
            }
        }
        return nil
    }

    static func integerArray(named name: String, in body: String) -> [Int]? {
        guard let range = valueRange(named: name, in: body), body[range].hasPrefix("[") else { return nil }
        var values: [Int] = []
        var current = ""
        for character in body[range].dropFirst() {
            if character == "]" {
                if let value = Int(current) { values.append(value) }
                return values
            }
            if character.isNumber {
                current.append(character)
            } else {
                if let value = Int(current) { values.append(value) }
                current = ""
            }
        }
        return nil
    }

    static func dictionary(named name: String, in body: String) -> String? {
        guard let range = valueRange(named: name, in: body), body[range].hasPrefix("<<") else { return nil }
        let bytes = [UInt8](body[range].unicodeScalars.map { UInt8($0.value & 0xFF) })
        guard let dictionary = try? PDFLexer.balancedDictionary(bytes, at: 0) else { return nil }
        return String(latin1: dictionary)
    }

    /// Matches `/name` only when followed by a delimiter, searching from the
    /// end so the newest entry in the body wins.
    static func range(ofName name: String, in body: String) -> Range<String.Index>? {
        var searchRange: Range<String.Index> = body.startIndex..<body.endIndex
        var lastMatch: Range<String.Index>?
        while let match = body.range(of: "/\(name)", range: searchRange) {
            if match.upperBound == body.endIndex || isDelimiter(body[match.upperBound]) {
                lastMatch = match
            }
            searchRange = match.upperBound..<body.endIndex
        }
        return lastMatch
    }

    static func isDelimiter(_ character: Character) -> Bool {
        character.isWhitespace || "/[]<>()%".contains(character)
    }

    private static func skipWhitespace(_ text: String, _ cursor: inout String.Index) {
        while cursor < text.endIndex, text[cursor].isWhitespace {
            cursor = text.index(after: cursor)
        }
    }

    private static func parseInteger(_ text: Substring, _ cursor: inout String.Index) -> Int? {
        var digits = ""
        while cursor < text.endIndex, text.base[cursor].isNumber {
            digits.append(text.base[cursor])
            cursor = text.base.index(after: cursor)
        }
        return Int(digits)
    }
}

// MARK: - Flate

enum FlateDecoder {
    /// Inflates a zlib-wrapped (RFC 1950) DEFLATE stream, as used by
    /// /FlateDecode.
    static func inflate(_ input: [UInt8]) throws -> [UInt8] {
        #if canImport(Compression)
        // Strip the 2-byte zlib header; Compression's ZLIB is raw DEFLATE.
        guard input.count > 6 else {
            throw PDFSignaturePreparerError.streamDecodeFailed
        }
        let raw = Array(input.dropFirst(2))

        var capacity = max(input.count * 8, 1 << 16)
        for _ in 0..<8 {
            var output = [UInt8](repeating: 0, count: capacity)
            let written = output.withUnsafeMutableBufferPointer { outputBuffer in
                raw.withUnsafeBufferPointer { inputBuffer in
                    compression_decode_buffer(
                        outputBuffer.baseAddress!,
                        capacity,
                        inputBuffer.baseAddress!,
                        raw.count,
                        nil,
                        COMPRESSION_ZLIB
                    )
                }
            }
            if written == 0 {
                throw PDFSignaturePreparerError.streamDecodeFailed
            }
            if written < capacity {
                return Array(output.prefix(written))
            }
            // Output may have been truncated exactly at capacity; retry larger.
            capacity *= 4
        }
        throw PDFSignaturePreparerError.streamDecodeFailed
        #else
        throw PDFSignaturePreparerError.unsupportedStreamFilter("FlateDecode")
        #endif
    }

    /// Reverses PNG row predictors (Predictor >= 10). TIFF Predictor 2 is not
    /// supported.
    static func applyPNGPredictor(
        _ input: [UInt8],
        columns: Int,
        colors: Int,
        bitsPerComponent: Int
    ) throws -> [UInt8] {
        guard columns > 0, colors > 0, bitsPerComponent > 0 else {
            throw PDFSignaturePreparerError.streamDecodeFailed
        }
        let bytesPerPixel = max(1, colors * bitsPerComponent / 8)
        let rowLength = (columns * colors * bitsPerComponent + 7) / 8
        let stride = rowLength + 1
        guard input.count.isMultiple(of: stride) else {
            throw PDFSignaturePreparerError.streamDecodeFailed
        }

        var output: [UInt8] = []
        output.reserveCapacity(input.count)
        var previousRow = [UInt8](repeating: 0, count: rowLength)

        for rowStart in Swift.stride(from: 0, to: input.count, by: stride) {
            let filterType = input[rowStart]
            var row = Array(input[(rowStart + 1)..<(rowStart + stride)])
            switch filterType {
            case 0:
                break
            case 1: // Sub
                for index in bytesPerPixel..<rowLength {
                    row[index] = row[index] &+ row[index - bytesPerPixel]
                }
            case 2: // Up
                for index in 0..<rowLength {
                    row[index] = row[index] &+ previousRow[index]
                }
            case 3: // Average
                for index in 0..<rowLength {
                    let left = index >= bytesPerPixel ? Int(row[index - bytesPerPixel]) : 0
                    row[index] = row[index] &+ UInt8((left + Int(previousRow[index])) / 2)
                }
            case 4: // Paeth
                for index in 0..<rowLength {
                    let left = index >= bytesPerPixel ? Int(row[index - bytesPerPixel]) : 0
                    let up = Int(previousRow[index])
                    let upLeft = index >= bytesPerPixel ? Int(previousRow[index - bytesPerPixel]) : 0
                    let estimate = left + up - upLeft
                    let distances = (abs(estimate - left), abs(estimate - up), abs(estimate - upLeft))
                    let predictor: Int
                    if distances.0 <= distances.1 && distances.0 <= distances.2 {
                        predictor = left
                    } else if distances.1 <= distances.2 {
                        predictor = up
                    } else {
                        predictor = upLeft
                    }
                    row[index] = row[index] &+ UInt8(predictor)
                }
            default:
                throw PDFSignaturePreparerError.streamDecodeFailed
            }
            output.append(contentsOf: row)
            previousRow = row
        }

        return output
    }
}

// MARK: - Latin-1 helpers (lossless byte <-> String round trip)

extension String {
    init(latin1 bytes: [UInt8]) {
        self.init(bytes.map { Character(UnicodeScalar($0)) })
    }

    var latin1Bytes: [UInt8] {
        unicodeScalars.map { UInt8($0.value & 0xFF) }
    }
}
