import Foundation
import PDFSigning

public struct PDFSignatureStructure: Equatable, Sendable {
    public let byteRange: PDFByteRange
    public let contentsHexRange: Range<Int>
    public let contentsLength: Int

    public init(byteRange: PDFByteRange, contentsHexRange: Range<Int>, contentsLength: Int) {
        self.byteRange = byteRange
        self.contentsHexRange = contentsHexRange
        self.contentsLength = contentsLength
    }
}

/// Lenient, per-signature view used by the verification viewer: a structural
/// problem in one signature must not hide the others.
public struct PDFSignatureCandidate: Sendable {
    public let byteRange: PDFByteRange
    /// `nil` when the candidate is structurally broken (see `problem`).
    public let structure: PDFSignatureStructure?
    public let problem: String?
    public let coversWholeFile: Bool
    /// Prior signatures of an incrementally updated file end at a `%%EOF`
    /// revision boundary.
    public let endsAtRevisionBoundary: Bool
}

public enum SignatureStructureVerifier {
    /// Lenient enumeration for viewers: never throws; reports structural
    /// problems per signature. General PDFs may carry incremental updates
    /// after the newest signature (Acrobat-style "changed after signing") —
    /// callers can detect that via `coversWholeFile` of the widest entry.
    public static func enumerateSignatureCandidates(in pdf: Data) -> [PDFSignatureCandidate] {
        let bytes = [UInt8](pdf)
        var candidates: [PDFSignatureCandidate] = []
        let marker = Array("/ByteRange".utf8)
        var searchIndex = 0

        while let markerRange = range(of: marker, in: bytes, from: searchIndex) {
            searchIndex = markerRange.upperBound
            guard let byteRange = try? parseByteRangeValue(in: bytes, from: markerRange.upperBound) else {
                continue
            }
            if byteRange.values == [0, 0, 0, 0] {
                continue // unsigned placeholder
            }

            let b = byteRange.firstLength
            let c = byteRange.secondOffset
            let coverage = byteRange.secondOffset + byteRange.secondLength

            var problem: String?
            var structure: PDFSignatureStructure?
            if byteRange.firstOffset != 0 {
                problem = "ByteRange が 0 から始まっていない"
            } else if !(b >= 1 && c > b && c <= bytes.count && byteRange.secondLength >= 0 && coverage <= bytes.count) {
                problem = "ByteRange がファイル範囲と整合しない"
            } else if bytes[b] != UInt8(ascii: "<") || bytes[c - 1] != UInt8(ascii: ">") {
                problem = "除外区間が /Contents の <...> と一致しない"
            } else {
                let contentsHexRange = (b + 1)..<(c - 1)
                if contentsHexRange.isEmpty || !contentsHexRange.count.isMultiple(of: 2)
                    || bytes[contentsHexRange].contains(where: { !isHexDigit($0) }) {
                    problem = "/Contents が16進文字列でない"
                } else {
                    structure = PDFSignatureStructure(
                        byteRange: byteRange,
                        contentsHexRange: contentsHexRange,
                        contentsLength: contentsHexRange.count / 2
                    )
                }
            }

            let boundary: Bool
            if coverage == bytes.count {
                boundary = true
            } else if coverage < bytes.count, coverage > 5 {
                let tail = Array(bytes[max(0, coverage - 12)..<coverage])
                boundary = trimTrailingPDFWhitespace(tail).hasSuffix(Array("%%EOF".utf8))
            } else {
                boundary = false
            }
            if structure != nil, problem == nil, !boundary {
                problem = "被覆範囲がリビジョン境界(%%EOF)で終わっていない"
            }

            candidates.append(PDFSignatureCandidate(
                byteRange: byteRange,
                structure: problem == nil ? structure : nil,
                problem: problem,
                coversWholeFile: coverage == bytes.count,
                endsAtRevisionBoundary: boundary
            ))
        }

        return candidates
    }

    /// Extracts every signature in the document, in file order.
    ///
    /// Each `/ByteRange [0 b c d]` must exclude exactly its own
    /// `<hex>` Contents object. The widest signature must cover the whole
    /// file; earlier signatures (from previous revisions of a co-signed
    /// document) must end at a `%%EOF` revision boundary.
    public static func extractSignatureStructures(from pdf: Data) throws -> [PDFSignatureStructure] {
        let bytes = [UInt8](pdf)
        var structures: [PDFSignatureStructure] = []
        let marker = Array("/ByteRange".utf8)
        var searchIndex = 0

        while let markerRange = range(of: marker, in: bytes, from: searchIndex) {
            searchIndex = markerRange.upperBound
            guard let byteRange = try? parseByteRangeValue(in: bytes, from: markerRange.upperBound) else {
                continue
            }
            if byteRange.values == [0, 0, 0, 0] {
                continue // unsigned placeholder
            }

            let b = byteRange.firstLength
            let c = byteRange.secondOffset
            guard byteRange.firstOffset == 0,
                  b >= 1, c > b, c <= bytes.count,
                  byteRange.secondLength >= 0,
                  c + byteRange.secondLength <= bytes.count,
                  bytes[b] == UInt8(ascii: "<"),
                  bytes[c - 1] == UInt8(ascii: ">") else {
                throw SignatureStructureVerifierError.byteRangeDoesNotExcludeContents(
                    byteRange,
                    contentsHexRange: (b + 1)..<(c - 1)
                )
            }

            let contentsHexRange = (b + 1)..<(c - 1)
            guard contentsHexRange.count > 0, contentsHexRange.count.isMultiple(of: 2) else {
                throw SignatureStructureVerifierError.invalidContentsHexLength(contentsHexRange.count)
            }
            for byte in bytes[contentsHexRange] where !isHexDigit(byte) {
                throw SignatureStructureVerifierError.invalidContentsHexByte(byte)
            }

            structures.append(PDFSignatureStructure(
                byteRange: byteRange,
                contentsHexRange: contentsHexRange,
                contentsLength: contentsHexRange.count / 2
            ))
        }

        guard !structures.isEmpty else {
            throw SignatureStructureVerifierError.byteRangeNotFound
        }

        let coverages = structures.map { $0.byteRange.secondOffset + $0.byteRange.secondLength }
        guard let widest = coverages.max(), widest == pdf.count else {
            throw SignatureStructureVerifierError.noSignatureCoversWholeFile(fileLength: pdf.count)
        }
        for (structure, coverage) in zip(structures, coverages) where coverage != pdf.count {
            // Prior signature: must end exactly at a revision boundary.
            let tailStart = max(0, coverage - 12)
            let tail = Array(bytes[tailStart..<coverage])
            guard trimTrailingPDFWhitespace(tail).hasSuffix(Array("%%EOF".utf8)) else {
                throw SignatureStructureVerifierError.priorSignatureNotAtRevisionBoundary(structure.byteRange)
            }
        }

        return structures
    }

    public static func extractSignatureStructure(from pdf: Data) throws -> PDFSignatureStructure {
        let bytes = Array(pdf)
        let byteRange = try extractByteRange(from: bytes)
        let contentsHexRange = try extractContentsHexRange(from: bytes)

        try validate(byteRange: byteRange, fileLength: pdf.count)
        guard contentsHexRange.count.isMultiple(of: 2) else {
            throw SignatureStructureVerifierError.invalidContentsHexLength(contentsHexRange.count)
        }
        // The unsigned gap must be exactly the /Contents hex-string object,
        // including its `<` `>` delimiters.
        guard byteRange.firstLength == contentsHexRange.lowerBound - 1,
              byteRange.secondOffset == contentsHexRange.upperBound + 1 else {
            throw SignatureStructureVerifierError.byteRangeDoesNotExcludeContents(
                byteRange,
                contentsHexRange: contentsHexRange
            )
        }

        return PDFSignatureStructure(
            byteRange: byteRange,
            contentsHexRange: contentsHexRange,
            contentsLength: contentsHexRange.count / 2
        )
    }

    public static func validate(byteRange: PDFByteRange, fileLength: Int) throws {
        guard byteRange.firstOffset == 0,
              byteRange.firstLength >= 0,
              byteRange.secondOffset >= byteRange.firstLength,
              byteRange.secondLength >= 0,
              byteRange.secondOffset + byteRange.secondLength == fileLength else {
            throw SignatureStructureVerifierError.invalidByteRange(byteRange, fileLength: fileLength)
        }
    }

    private static func extractByteRange(from bytes: [UInt8]) throws -> PDFByteRange {
        let marker = Array("/ByteRange".utf8)
        guard let markerRange = range(of: marker, in: bytes, from: 0) else {
            throw SignatureStructureVerifierError.byteRangeNotFound
        }
        return try parseByteRangeValue(in: bytes, from: markerRange.upperBound)
    }

    /// Parses the `[a b c d]` array immediately after a `/ByteRange` name.
    private static func parseByteRangeValue(in bytes: [UInt8], from start: Int) throws -> PDFByteRange {
        var cursor = start
        skipPDFWhitespace(in: bytes, from: &cursor)
        guard cursor < bytes.count, bytes[cursor] == UInt8(ascii: "[") else {
            throw SignatureStructureVerifierError.invalidByteRangeSyntax
        }
        cursor += 1

        var values: [Int] = []
        while cursor < bytes.count {
            skipPDFWhitespace(in: bytes, from: &cursor)
            guard cursor < bytes.count else {
                break
            }
            if bytes[cursor] == UInt8(ascii: "]") {
                cursor += 1
                break
            }

            let start = cursor
            while cursor < bytes.count, (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(bytes[cursor]) {
                cursor += 1
            }
            guard cursor > start,
                  let value = Int(String(decoding: bytes[start..<cursor], as: UTF8.self)) else {
                throw SignatureStructureVerifierError.invalidByteRangeSyntax
            }
            values.append(value)
        }

        guard values.count == 4 else {
            throw SignatureStructureVerifierError.invalidByteRangeValueCount(values.count)
        }
        return PDFByteRange(
            firstOffset: values[0],
            firstLength: values[1],
            secondOffset: values[2],
            secondLength: values[3]
        )
    }

    private static func extractContentsHexRange(from bytes: [UInt8]) throws -> Range<Int> {
        let marker = Array("/Contents".utf8)
        var matches: [Range<Int>] = []
        var searchIndex = 0

        while let markerRange = range(of: marker, in: bytes, from: searchIndex) {
            var cursor = markerRange.upperBound
            skipPDFWhitespace(in: bytes, from: &cursor)
            guard cursor < bytes.count, bytes[cursor] == UInt8(ascii: "<") else {
                searchIndex = markerRange.upperBound
                continue
            }

            let hexStart = cursor + 1
            cursor = hexStart
            while cursor < bytes.count, bytes[cursor] != UInt8(ascii: ">") {
                cursor += 1
            }
            guard cursor < bytes.count else {
                throw SignatureStructureVerifierError.unterminatedContentsHex
            }
            matches.append(hexStart..<cursor)
            searchIndex = cursor + 1
        }

        guard matches.count == 1, let contentsHexRange = matches.first else {
            if matches.isEmpty {
                throw SignatureStructureVerifierError.contentsNotFound
            }
            throw SignatureStructureVerifierError.multipleContentsFound(matches.count)
        }
        return contentsHexRange
    }

    private static func range(of needle: [UInt8], in haystack: [UInt8], from startIndex: Int) -> Range<Int>? {
        guard !needle.isEmpty, startIndex <= haystack.count, needle.count <= haystack.count else {
            return nil
        }

        let lastStart = haystack.count - needle.count
        guard startIndex <= lastStart else {
            return nil
        }

        for index in startIndex...lastStart where Array(haystack[index..<index + needle.count]) == needle {
            return index..<index + needle.count
        }
        return nil
    }

    private static func skipPDFWhitespace(in bytes: [UInt8], from cursor: inout Int) {
        while cursor < bytes.count, isPDFWhitespace(bytes[cursor]) {
            cursor += 1
        }
    }

    private static func isPDFWhitespace(_ byte: UInt8) -> Bool {
        byte == 0x00 || byte == 0x09 || byte == 0x0A || byte == 0x0C || byte == 0x0D || byte == 0x20
    }

    private static func isHexDigit(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
            || (UInt8(ascii: "A")...UInt8(ascii: "F")).contains(byte)
            || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(byte)
    }

    private static func trimTrailingPDFWhitespace(_ bytes: [UInt8]) -> [UInt8] {
        var end = bytes.count
        while end > 0, isPDFWhitespace(bytes[end - 1]) {
            end -= 1
        }
        return Array(bytes[..<end])
    }
}

private extension [UInt8] {
    func hasSuffix(_ suffix: [UInt8]) -> Bool {
        count >= suffix.count && Array(self[(count - suffix.count)...]) == suffix
    }
}

public enum SignatureStructureVerifierError: Error, Equatable, Sendable {
    case invalidByteRange(PDFByteRange, fileLength: Int)
    case byteRangeNotFound
    case invalidByteRangeSyntax
    case invalidByteRangeValueCount(Int)
    case contentsNotFound
    case multipleContentsFound(Int)
    case unterminatedContentsHex
    case invalidContentsHexLength(Int)
    case byteRangeDoesNotExcludeContents(PDFByteRange, contentsHexRange: Range<Int>)
    case invalidContentsHexByte(UInt8)
    case noSignatureCoversWholeFile(fileLength: Int)
    case priorSignatureNotAtRevisionBoundary(PDFByteRange)
}
