import Foundation
import PDFSigning
import SelfVerify
import Testing

@Suite("Signature structure verifier")
struct SignatureStructureVerifierTests {
    @Test("Prepared PDF signature structure matches ByteRange and Contents")
    func preparedPDFStructure() throws {
        let prepared = try PDFSignaturePreparer.prepareForSignature(
            pdf: Self.minimalUnsignedPDF(),
            options: PDFSignaturePreparationOptions(
                signerName: "Taro Yamada",
                signingDate: Date(timeIntervalSince1970: 1_782_048_000),
                contentsByteCapacity: 8
            )
        )

        let structure = try SignatureStructureVerifier.extractSignatureStructure(from: prepared.pdf)

        #expect(structure.byteRange == prepared.placeholder.byteRange)
        #expect(structure.contentsHexRange == prepared.placeholder.contentsHexRange)
        #expect(structure.contentsLength == 8)
    }

    @Test("Embedded CMS keeps signature structure valid")
    func embeddedCMSStructure() throws {
        let prepared = try PDFSignaturePreparer.prepareForSignature(
            pdf: Self.minimalUnsignedPDF(),
            options: PDFSignaturePreparationOptions(
                signerName: "Taro Yamada",
                signingDate: Date(timeIntervalSince1970: 1_782_048_000),
                contentsByteCapacity: 8
            )
        )
        let signed = try PDFSignatureEmbedder.embedCMS([0xCA, 0xFE], into: prepared.pdf, placeholder: prepared.placeholder)

        let structure = try SignatureStructureVerifier.extractSignatureStructure(from: signed)

        #expect(structure.byteRange == prepared.placeholder.byteRange)
        #expect(structure.contentsLength == 8)
    }

    @Test("Verifier rejects ByteRange that does not exclude Contents")
    func byteRangeMismatch() {
        let pdf = Data("/ByteRange [0 31 35 4] /Contents <0000>".utf8)

        #expect(throws: SignatureStructureVerifierError.byteRangeDoesNotExcludeContents(
            PDFByteRange(firstOffset: 0, firstLength: 31, secondOffset: 35, secondLength: 4),
            contentsHexRange: 34..<38
        )) {
            try SignatureStructureVerifier.extractSignatureStructure(from: pdf)
        }
    }

    private static func minimalUnsignedPDF() -> Data {
        var pdf = Data()
        var offsets: [Int] = [0]
        pdf.appendASCII("%PDF-1.7\n")
        appendObject(1, "<< /Type /Catalog /Pages 2 0 R >>", to: &pdf, offsets: &offsets)
        appendObject(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", to: &pdf, offsets: &offsets)
        appendObject(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> /Contents 4 0 R >>", to: &pdf, offsets: &offsets)
        appendObject(4, "<< /Length 0 >>\nstream\n\nendstream", to: &pdf, offsets: &offsets)
        let xrefOffset = pdf.count
        pdf.appendASCII("xref\n0 5\n")
        pdf.appendASCII("0000000000 65535 f \n")
        for offset in offsets.dropFirst() {
            pdf.appendASCII(String(format: "%010d 00000 n \n", offset))
        }
        pdf.appendASCII("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n\(xrefOffset)\n%%EOF\n")
        return pdf
    }

    private static func appendObject(_ number: Int, _ body: String, to pdf: inout Data, offsets: inout [Int]) {
        offsets.append(pdf.count)
        pdf.appendASCII("\(number) 0 obj\n\(body)\nendobj\n")
    }
}

private extension Data {
    mutating func appendASCII(_ string: String) {
        append(contentsOf: string.utf8)
    }
}
