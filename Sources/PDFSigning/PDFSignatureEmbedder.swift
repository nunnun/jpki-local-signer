import Foundation

public enum PDFSignatureEmbedder {
    public static func hexEncodedCMS(_ cms: [UInt8], capacityInBytes: Int) throws -> String {
        guard cms.count <= capacityInBytes else {
            throw PDFSignatureEmbedderError.cmsExceedsPlaceholder(cmsLength: cms.count, capacity: capacityInBytes)
        }

        let hex = cms.map { String(format: "%02X", $0) }.joined()
        let paddingLength = (capacityInBytes - cms.count) * 2
        return hex + String(repeating: "0", count: paddingLength)
    }

    public static func embedCMS(_ cms: [UInt8], into pdf: Data, placeholder: PDFSignaturePlaceholder) throws -> Data {
        guard placeholder.contentsHexRange.lowerBound >= 0,
              placeholder.contentsHexRange.upperBound <= pdf.count,
              placeholder.contentsHexRange.count.isMultiple(of: 2) else {
            throw PDFSignatureEmbedderError.invalidPlaceholderRange(placeholder.contentsHexRange, fileLength: pdf.count)
        }

        let hex = try hexEncodedCMS(cms, capacityInBytes: placeholder.contentsByteCapacity)
        guard let replacement = hex.data(using: .ascii) else {
            throw PDFSignatureEmbedderError.invalidHexEncoding
        }

        var signedPDF = pdf
        signedPDF.replaceSubrange(placeholder.contentsHexRange, with: replacement)
        return signedPDF
    }
}

public enum PDFSignatureEmbedderError: Error, Equatable, Sendable {
    case cmsExceedsPlaceholder(cmsLength: Int, capacity: Int)
    case invalidPlaceholderRange(Range<Int>, fileLength: Int)
    case invalidHexEncoding
}
