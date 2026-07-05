import Crypto
import Foundation

public struct PDFByteRange: Equatable, Sendable {
    public let firstOffset: Int
    public let firstLength: Int
    public let secondOffset: Int
    public let secondLength: Int

    public init(firstOffset: Int, firstLength: Int, secondOffset: Int, secondLength: Int) {
        self.firstOffset = firstOffset
        self.firstLength = firstLength
        self.secondOffset = secondOffset
        self.secondLength = secondLength
    }

    public var values: [Int] {
        [firstOffset, firstLength, secondOffset, secondLength]
    }
}

public enum ByteRangeCalculator {
    /// ByteRange excluding the whole /Contents hex-string object — the hex
    /// characters AND the `<` `>` delimiters around them (PDF 32000-1
    /// §12.8.1: the gap is exactly the Contents value). `contentsRange` is
    /// the range of the hex characters; the delimiters sit just outside it.
    public static func byteRange(excludingContentsHexRange contentsRange: Range<Int>, fileLength: Int) throws -> PDFByteRange {
        guard fileLength >= 0 else {
            throw ByteRangeError.invalidFileLength(fileLength)
        }
        guard contentsRange.lowerBound >= 1,
              contentsRange.upperBound + 1 <= fileLength,
              contentsRange.lowerBound <= contentsRange.upperBound else {
            throw ByteRangeError.invalidContentsRange(contentsRange, fileLength: fileLength)
        }

        return PDFByteRange(
            firstOffset: 0,
            firstLength: contentsRange.lowerBound - 1,
            secondOffset: contentsRange.upperBound + 1,
            secondLength: fileLength - contentsRange.upperBound - 1
        )
    }

    public static func signedBytes(from pdf: Data, byteRange: PDFByteRange) throws -> Data {
        let fileLength = pdf.count
        guard byteRange.firstOffset == 0,
              byteRange.firstLength >= 0,
              byteRange.secondOffset >= byteRange.firstLength,
              byteRange.secondLength >= 0,
              byteRange.secondOffset + byteRange.secondLength <= fileLength else {
            throw ByteRangeError.invalidByteRange(byteRange, fileLength: fileLength)
        }

        var result = Data()
        result.append(pdf[byteRange.firstOffset..<byteRange.firstOffset + byteRange.firstLength])
        result.append(pdf[byteRange.secondOffset..<byteRange.secondOffset + byteRange.secondLength])
        return result
    }

    public static func sha256Digest(from pdf: Data, byteRange: PDFByteRange) throws -> [UInt8] {
        let signedBytes = try signedBytes(from: pdf, byteRange: byteRange)
        return Array(SHA256.hash(data: signedBytes))
    }
}

public enum ByteRangeError: Error, Equatable, Sendable {
    case invalidFileLength(Int)
    case invalidContentsRange(Range<Int>, fileLength: Int)
    case invalidByteRange(PDFByteRange, fileLength: Int)
}
