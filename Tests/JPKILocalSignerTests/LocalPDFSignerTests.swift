import Foundation
import JPKILocalSigner
import Testing

@Suite("Local PDF signer")
struct LocalPDFSignerTests {
    @Test("Local signer prepares PDF, requests DigestInfo signature, embeds CMS, and verifies structure")
    func signPDFWithExternalSigner() async throws {
        let result = try await LocalPDFSigner.sign(
            input: LocalPDFSigningInput(
                pdf: Self.minimalUnsignedPDF(),
                certificateDER: Self.minimalCertificateDER,
                signerName: "Taro Yamada",
                signingDate: Date(timeIntervalSince1970: 1_782_048_000),
                contentsByteCapacity: 4_096
            ),
            signer: { digestInfo in
                #expect(digestInfo.count == 51)
                #expect(Array(digestInfo.prefix(19)) == Self.sha256DigestInfoPrefix)
                return Array(repeating: UInt8(0xCC), count: 256)
            }
        )

        let signedPDFText = String(decoding: result.signedPDF, as: UTF8.self)

        #expect(result.signedPDF.count > Self.minimalUnsignedPDF().count)
        #expect(result.signatureStructure.contentsLength == 4_096)
        #expect(result.digestInfo.count == 51)
        #expect(result.cmsDER.starts(with: [0x30]))
        #expect(signedPDFText.contains("/SubFilter /adbe.pkcs7.detached"))
        #expect(signedPDFText.contains("<3082"))
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

    private static let sha256DigestInfoPrefix: [UInt8] = [
        0x30, 0x31,
        0x30, 0x0D,
        0x06, 0x09,
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00,
        0x04, 0x20
    ]

    private static let sha256AlgorithmIdentifier: [UInt8] = [
        0x30, 0x0D,
        0x06, 0x09,
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00
    ]

    private static let minimalCertificateDER: [UInt8] = {
        let version: [UInt8] = [0xA0, 0x03, 0x02, 0x01, 0x02]
        let serialNumber: [UInt8] = [0x02, 0x01, 0x01]
        let issuer: [UInt8] = [0x30, 0x00]
        let validity: [UInt8] = [0x30, 0x00]
        let subject: [UInt8] = [0x30, 0x00]
        let subjectPublicKeyInfo: [UInt8] = [0x30, 0x00]
        let tbsContent = version + serialNumber + sha256AlgorithmIdentifier + issuer + validity + subject + subjectPublicKeyInfo
        let tbsCertificate = [0x30, UInt8(tbsContent.count)] + tbsContent
        let signatureValue: [UInt8] = [0x03, 0x01, 0x00]
        let certificateContent = tbsCertificate + sha256AlgorithmIdentifier + signatureValue
        return [0x30, UInt8(certificateContent.count)] + certificateContent
    }()
}

private extension Data {
    mutating func appendASCII(_ string: String) {
        append(contentsOf: string.utf8)
    }
}
