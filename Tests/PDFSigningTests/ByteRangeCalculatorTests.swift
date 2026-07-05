import Foundation
import PDFSigning
import Testing

@Suite("PDF ByteRange")
struct ByteRangeCalculatorTests {
    @Test("ByteRange excludes Contents hex payload")
    func byteRangeExcludesContents() throws {
        let byteRange = try ByteRangeCalculator.byteRange(excludingContentsHexRange: 10..<18, fileLength: 30)

        // The gap covers the hex characters plus the `<` `>` delimiters.
        #expect(byteRange.values == [0, 9, 19, 11])
    }

    @Test("Signed bytes concatenate both ByteRange segments")
    func signedBytes() throws {
        let pdf = Data(Array(0..<20).map(UInt8.init))
        let byteRange = PDFByteRange(firstOffset: 0, firstLength: 5, secondOffset: 10, secondLength: 10)

        let signed = try ByteRangeCalculator.signedBytes(from: pdf, byteRange: byteRange)

        #expect(Array(signed) == [0, 1, 2, 3, 4, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19])
    }

    @Test("CMS hex is padded to placeholder capacity")
    func cmsHexPadding() throws {
        let hex = try PDFSignatureEmbedder.hexEncodedCMS([0xDE, 0xAD], capacityInBytes: 4)

        #expect(hex == "DEAD0000")
    }

    @Test("Signature placeholder is found from Contents hex string")
    func findSignaturePlaceholder() throws {
        let pdf = Data("<< /Type /Sig /ByteRange [0 0 0 0] /Contents <00000000> >>".utf8)

        let placeholder = try PDFSignaturePreparer.findSignaturePlaceholder(in: pdf)

        #expect(placeholder.contentsHexRange == 46..<54)
        #expect(placeholder.contentsByteCapacity == 4)
        #expect(placeholder.byteRange.values == [0, 45, 55, 3])
    }

    @Test("CMS is embedded into the Contents placeholder without changing file length")
    func embedCMSIntoPlaceholder() throws {
        let pdf = Data("prefix /Contents <00000000> suffix".utf8)
        let placeholder = try PDFSignaturePreparer.findSignaturePlaceholder(in: pdf)

        let signedPDF = try PDFSignatureEmbedder.embedCMS([0xDE, 0xAD], into: pdf, placeholder: placeholder)

        #expect(signedPDF.count == pdf.count)
        #expect(String(decoding: signedPDF, as: UTF8.self) == "prefix /Contents <DEAD0000> suffix")
    }

    @Test("Signature placeholder detection rejects ambiguous Contents entries")
    func multipleContentsPlaceholders() {
        let pdf = Data("/Contents <0000> /Contents <0000>".utf8)

        #expect(throws: PDFSignaturePreparerError.multipleContentsPlaceholdersFound(2)) {
            try PDFSignaturePreparer.findSignaturePlaceholder(in: pdf)
        }
    }

    @Test("Signature placeholder detection rejects invalid hex")
    func invalidContentsHex() {
        let pdf = Data("/Contents <000X>".utf8)

        #expect(throws: PDFSignaturePreparerError.invalidContentsHexByte(UInt8(ascii: "X"))) {
            try PDFSignaturePreparer.findSignaturePlaceholder(in: pdf)
        }
    }

    @Test("Preparing a classic PDF appends signature objects and fills ByteRange")
    func prepareClassicPDFForSignature() throws {
        let prepared = try PDFSignaturePreparer.prepareForSignature(
            pdf: Self.minimalUnsignedPDF(),
            options: PDFSignaturePreparationOptions(
                signerName: "Taro Yamada",
                signingDate: Date(timeIntervalSince1970: 1_782_048_000),
                contentsByteCapacity: 8
            )
        )
        let text = String(decoding: prepared.pdf, as: UTF8.self)

        #expect(text.contains("/Type /Sig"))
        #expect(text.contains("/SubFilter /adbe.pkcs7.detached"))
        #expect(text.contains("/AcroForm << /Fields [6 0 R] /SigFlags 3 >>"))
        #expect(text.contains("/Annots [6 0 R]"))
        #expect(text.contains("/Prev "))
        #expect(!text.contains("[0000000000 0000000000 0000000000 0000000000]"))
        #expect(prepared.placeholder.contentsByteCapacity == 8)
        #expect(prepared.placeholder.byteRange.secondOffset + prepared.placeholder.byteRange.secondLength == prepared.pdf.count)
    }

    @Test("Prepared PDF accepts CMS embedding without changing ByteRange")
    func embedCMSIntoPreparedPDF() throws {
        let prepared = try PDFSignaturePreparer.prepareForSignature(
            pdf: Self.minimalUnsignedPDF(),
            options: PDFSignaturePreparationOptions(
                signerName: "Taro Yamada",
                signingDate: Date(timeIntervalSince1970: 1_782_048_000),
                contentsByteCapacity: 8
            )
        )

        let signed = try PDFSignatureEmbedder.embedCMS([0xCA, 0xFE], into: prepared.pdf, placeholder: prepared.placeholder)
        let signedPlaceholder = try PDFSignaturePreparer.findSignaturePlaceholder(in: signed)

        #expect(signed.count == prepared.pdf.count)
        #expect(signedPlaceholder.byteRange == prepared.placeholder.byteRange)
        #expect(String(decoding: signed, as: UTF8.self).contains("<CAFE000000000000>"))
    }

    @Test("Preparing appends to direct AcroForm fields and page annotations")
    func preparePDFWithExistingDirectAcroFormAndAnnots() throws {
        let prepared = try PDFSignaturePreparer.prepareForSignature(
            pdf: Self.minimalUnsignedPDF(
                rootBody: "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [9 0 R] >> >>",
                pageBody: "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> /Contents 4 0 R /Annots [8 0 R] >>"
            ),
            options: PDFSignaturePreparationOptions(
                signerName: "Taro Yamada",
                signingDate: Date(timeIntervalSince1970: 1_782_048_000),
                contentsByteCapacity: 8
            )
        )
        let text = String(decoding: prepared.pdf, as: UTF8.self)

        #expect(text.contains("/Fields [9 0 R 6 0 R]"))
        #expect(text.contains("/SigFlags 3"))
        #expect(text.contains("/Annots [8 0 R 6 0 R]"))
    }

    @Test("Preparing updates indirect AcroForm object and indirect Annots array")
    func preparePDFWithIndirectAcroFormAndAnnots() throws {
        let prepared = try PDFSignaturePreparer.prepareForSignature(
            pdf: Self.minimalUnsignedPDF(
                rootBody: "<< /Type /Catalog /Pages 2 0 R /AcroForm 5 0 R >>",
                pageBody: "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> /Contents 4 0 R /Annots 6 0 R >>",
                extraObjects: [
                    (5, "<< /Fields [20 0 R] >>"),
                    (6, "[21 0 R]")
                ]
            ),
            options: PDFSignaturePreparationOptions(
                signerName: "Taro Yamada",
                signingDate: Date(timeIntervalSince1970: 1_782_048_000),
                contentsByteCapacity: 8
            )
        )
        let text = String(decoding: prepared.pdf, as: UTF8.self)

        // New objects are 7 (signature) and 8 (field); the AcroForm object and
        // Annots array are rewritten in place, so Root and Page stay untouched.
        #expect(text.contains("5 0 obj\n<< /Fields [20 0 R 8 0 R]"))
        #expect(text.contains("/SigFlags 3"))
        #expect(text.contains("6 0 obj\n[21 0 R 8 0 R]"))
        #expect(prepared.placeholder.byteRange.secondOffset + prepared.placeholder.byteRange.secondLength == prepared.pdf.count)
    }

    @Test("Preparing updates an indirect Fields array inside an inline AcroForm")
    func preparePDFWithIndirectFieldsArray() throws {
        let prepared = try PDFSignaturePreparer.prepareForSignature(
            pdf: Self.minimalUnsignedPDF(
                rootBody: "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields 5 0 R /SigFlags 3 >> >>",
                extraObjects: [(5, "[20 0 R]")]
            ),
            options: PDFSignaturePreparationOptions(
                signerName: "Taro Yamada",
                signingDate: Date(timeIntervalSince1970: 1_782_048_000),
                contentsByteCapacity: 8
            )
        )
        let text = String(decoding: prepared.pdf, as: UTF8.self)

        #expect(text.contains("5 0 obj\n[20 0 R 7 0 R]"))
    }

    @Test("Preparing an xref-stream PDF with object streams emits an xref stream increment")
    func prepareXrefStreamPDF() throws {
        let pdf = Self.xrefStreamPDF(compressed: false)

        let prepared = try PDFSignaturePreparer.prepareForSignature(
            pdf: pdf,
            options: PDFSignaturePreparationOptions(
                signerName: "Taro Yamada",
                signingDate: Date(timeIntervalSince1970: 1_782_048_000),
                contentsByteCapacity: 8
            )
        )
        let incrementText = String(decoding: prepared.pdf.dropFirst(pdf.count), as: UTF8.self)

        // Objects run 0-6 in the fixture, so the signature is 7 and the field
        // widget is 8. Root (from the object stream) gains an AcroForm; the
        // page gains the widget annotation; the increment closes with an xref
        // stream, not a classic trailer.
        #expect(incrementText.contains("/AcroForm << /Fields [8 0 R] /SigFlags 3 >>"))
        #expect(incrementText.contains("/Annots [8 0 R]"))
        #expect(incrementText.contains("/Type /XRef"))
        #expect(!incrementText.contains("trailer"))
        #expect(prepared.placeholder.byteRange.secondOffset + prepared.placeholder.byteRange.secondLength == prepared.pdf.count)
    }

    @Test("Preparing decodes FlateDecode object streams and predictor-coded xref streams")
    func prepareCompressedXrefStreamPDF() throws {
        let pdf = Self.xrefStreamPDF(compressed: true)

        let prepared = try PDFSignaturePreparer.prepareForSignature(
            pdf: pdf,
            options: PDFSignaturePreparationOptions(
                signerName: "Taro Yamada",
                signingDate: Date(timeIntervalSince1970: 1_782_048_000),
                contentsByteCapacity: 8
            )
        )
        let incrementText = String(decoding: prepared.pdf.dropFirst(pdf.count), as: UTF8.self)

        #expect(incrementText.contains("/AcroForm << /Fields [8 0 R] /SigFlags 3 >>"))
        #expect(incrementText.contains("/Annots [8 0 R]"))
    }

    @Test("Non-ASCII signer names are encoded as UTF-16BE hex text strings")
    func japaneseSignerName() throws {
        let prepared = try PDFSignaturePreparer.prepareForSignature(
            pdf: Self.minimalUnsignedPDF(),
            options: PDFSignaturePreparationOptions(
                signerName: "山田太郎",
                signingDate: Date(timeIntervalSince1970: 1_782_048_000),
                contentsByteCapacity: 8
            )
        )
        let text = String(decoding: prepared.pdf, as: UTF8.self)

        #expect(text.contains("/Name <FEFF5C717530592A90CE>"))
    }

    private static func minimalUnsignedPDF(
        rootBody: String = "<< /Type /Catalog /Pages 2 0 R >>",
        pageBody: String = "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> /Contents 4 0 R >>",
        extraObjects: [(number: Int, body: String)] = []
    ) -> Data {
        var pdf = Data()
        var offsets: [Int] = [0]
        pdf.appendASCII("%PDF-1.7\n")
        appendObject(1, rootBody, to: &pdf, offsets: &offsets)
        appendObject(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", to: &pdf, offsets: &offsets)
        appendObject(3, pageBody, to: &pdf, offsets: &offsets)
        appendObject(4, "<< /Length 0 >>\nstream\n\nendstream", to: &pdf, offsets: &offsets)
        for object in extraObjects {
            appendObject(object.number, object.body, to: &pdf, offsets: &offsets)
        }
        let objectCount = 5 + extraObjects.count
        let xrefOffset = pdf.count
        pdf.appendASCII("xref\n0 \(objectCount)\n")
        pdf.appendASCII("0000000000 65535 f \n")
        for offset in offsets.dropFirst() {
            pdf.appendASCII(String(format: "%010d 00000 n \n", offset))
        }
        pdf.appendASCII("trailer\n<< /Size \(objectCount) /Root 1 0 R >>\nstartxref\n\(xrefOffset)\n%%EOF\n")
        return pdf
    }

    private static func appendObject(_ number: Int, _ body: String, to pdf: inout Data, offsets: inout [Int]) {
        offsets.append(pdf.count)
        pdf.appendASCII("\(number) 0 obj\n\(body)\nendobj\n")
    }

    /// PDF 1.6-style fixture: Catalog(1) / Pages(2) / Page(3) live inside an
    /// object stream (5); content stream (4) and the xref stream (6) are
    /// direct. `compressed` FlateDecodes the object stream and PNG-predicts
    /// the xref stream, mirroring real-world generator output.
    private static func xrefStreamPDF(compressed: Bool) -> Data {
        var pdf = Data()
        pdf.appendASCII("%PDF-1.6\n")

        let contentOffset = pdf.count
        pdf.appendASCII("4 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n")

        let objectBodies = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> /Contents 4 0 R >>"
        ]
        var header = ""
        var bodyText = ""
        for (index, body) in objectBodies.enumerated() {
            header += "\(index + 1) \(bodyText.utf8.count) "
            bodyText += body + "\n"
        }
        let payloadText = header + bodyText
        let rawPayload = Array(payloadText.utf8)
        let objStmOffset = pdf.count
        if compressed {
            let deflated = TestZlib.deflate(rawPayload)
            pdf.appendASCII("5 0 obj\n<< /Type /ObjStm /N 3 /First \(header.utf8.count) /Filter /FlateDecode /Length \(deflated.count) >>\nstream\n")
            pdf.append(contentsOf: deflated)
            pdf.appendASCII("\nendstream\nendobj\n")
        } else {
            pdf.appendASCII("5 0 obj\n<< /Type /ObjStm /N 3 /First \(header.utf8.count) /Length \(rawPayload.count) >>\nstream\n")
            pdf.append(contentsOf: rawPayload)
            pdf.appendASCII("\nendstream\nendobj\n")
        }

        // Xref rows, W = [1 4 2]:
        // 0: free, 1-3: type 2 in stream 5, 4/5/6: type 1 direct.
        let xrefOffset = pdf.count
        var rows: [[UInt8]] = []
        func row(_ type: UInt8, _ second: Int, _ third: Int) -> [UInt8] {
            [
                type,
                UInt8((second >> 24) & 0xFF), UInt8((second >> 16) & 0xFF),
                UInt8((second >> 8) & 0xFF), UInt8(second & 0xFF),
                UInt8((third >> 8) & 0xFF), UInt8(third & 0xFF)
            ]
        }
        rows.append(row(0, 0, 0xFFFF))
        rows.append(row(2, 5, 0))
        rows.append(row(2, 5, 1))
        rows.append(row(2, 5, 2))
        rows.append(row(1, contentOffset, 0))
        rows.append(row(1, objStmOffset, 0))
        rows.append(row(1, xrefOffset, 0))

        if compressed {
            // PNG Up predictor over 7-byte rows, then zlib.
            var predicted: [UInt8] = []
            var previous = [UInt8](repeating: 0, count: 7)
            for currentRow in rows {
                predicted.append(2)
                for index in 0..<7 {
                    predicted.append(currentRow[index] &- previous[index])
                }
                previous = currentRow
            }
            let deflated = TestZlib.deflate(predicted)
            pdf.appendASCII("6 0 obj\n<< /Type /XRef /Size 7 /W [1 4 2] /Index [0 7] /Root 1 0 R /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 7 >> /Length \(deflated.count) >>\nstream\n")
            pdf.append(contentsOf: deflated)
            pdf.appendASCII("\nendstream\nendobj\n")
        } else {
            let payload = rows.flatMap(\.self)
            pdf.appendASCII("6 0 obj\n<< /Type /XRef /Size 7 /W [1 4 2] /Index [0 7] /Root 1 0 R /Length \(payload.count) >>\nstream\n")
            pdf.append(contentsOf: payload)
            pdf.appendASCII("\nendstream\nendobj\n")
        }

        pdf.appendASCII("startxref\n\(xrefOffset)\n%%EOF\n")
        return pdf
    }
}

private extension Data {
    mutating func appendASCII(_ string: String) {
        append(contentsOf: string.utf8)
    }
}
