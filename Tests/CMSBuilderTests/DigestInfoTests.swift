import CMSBuilder
import Foundation
import Testing

@Suite("DigestInfo")
struct DigestInfoTests {
    @Test("SHA-256 DigestInfo wraps digest with the PKCS#1 v1.5 SHA-256 prefix")
    func sha256DigestInfoFromDigest() throws {
        let digest = Array(repeating: UInt8(0xAB), count: 32)
        let digestInfo = try DigestInfo.sha256DigestInfo(digest: digest)

        #expect(digestInfo.count == 51)
        #expect(Array(digestInfo.prefix(19)) == [
            0x30, 0x31,
            0x30, 0x0D,
            0x06, 0x09,
            0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            0x05, 0x00,
            0x04, 0x20
        ])
        #expect(Array(digestInfo.suffix(32)) == digest)
    }

    @Test("DigestInfo rejects non SHA-256 digest length")
    func invalidDigestLength() {
        #expect(throws: DigestInfoError.invalidSHA256DigestLength(31)) {
            try DigestInfo.sha256DigestInfo(digest: Array(repeating: 0, count: 31))
        }
    }

    @Test("Signed attributes include contentType, messageDigest, and signingTime")
    func signedAttributesDER() throws {
        let date = try #require(DateComponents(
            calendar: Calendar(identifier: .gregorian),
            timeZone: TimeZone(secondsFromGMT: 0),
            year: 2026,
            month: 6,
            day: 20,
            hour: 12,
            minute: 34,
            second: 56
        ).date)

        let der = try SignedAttributesBuilder.buildDER(from: SignedAttributesInput(
            messageDigest: Array(repeating: 0xAA, count: 32),
            signingTime: date
        ))

        #expect(der.first == 0x31)
        #expect(Self.bytes(der, contain: [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03]))
        #expect(Self.bytes(der, contain: [0x04, 0x20] + Array(repeating: 0xAA, count: 32)))
        #expect(Self.bytes(der, contain: [0x17, 0x0D] + Array("260620123456Z".utf8)))
    }

    @Test("Detached CMS wraps certificate, signed attributes, and external signature")
    func detachedCMSDER() throws {
        let signedAttributes = try SignedAttributesBuilder.buildDER(from: SignedAttributesInput(
            messageDigest: Array(repeating: 0xBB, count: 32),
            signingTime: Date(timeIntervalSince1970: 1_782_048_000)
        ))
        let signature = Array(repeating: UInt8(0xCC), count: 256)

        let cms = try CMSSignedDataBuilder.buildDetachedSignedData(from: ExternalSignatureCMSInput(
            certificateDER: Self.minimalCertificateDER,
            signedAttributesDER: signedAttributes,
            signature: signature
        ))

        #expect(cms.starts(with: [0x30]))
        #expect(Self.bytes(cms, contain: [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]))
        #expect(Self.bytes(cms, contain: [0xA0]))
        #expect(Self.bytes(cms, contain: [0x04, 0x82, 0x01, 0x00] + signature))
    }

    private static func bytes(_ haystack: [UInt8], contain needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, needle.count <= haystack.count else {
            return false
        }

        return haystack.indices.dropLast(needle.count - 1).contains { index in
            Array(haystack[index..<index + needle.count]) == needle
        }
    }

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
