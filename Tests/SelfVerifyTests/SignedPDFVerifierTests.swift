import CMSBuilder
import Crypto
import Foundation
import JPKILocalSigner
import PDFSigning
@testable import SelfVerify
import SwiftASN1
import Testing
import X509
import _CryptoExtras

@Suite("Signed PDF full verification")
struct SignedPDFVerifierTests {
    @Test("End-to-end RSA-signed PDF passes full self-verification")
    func endToEndFullVerification() async throws {
        let fixture = try await Self.signedFixture()

        let report = try SignedPDFVerifier.verify(pdf: fixture.signedPDF)

        #expect(report.cms.signerMatchesCertificate)
        #expect(report.cms.digestAlgorithmOID == "2.16.840.1.101.3.4.2.1")
        #expect(report.structure.byteRange.secondOffset + report.structure.byteRange.secondLength == fixture.signedPDF.count)
        // Self-signed test certificates must be classified as such, never
        // as trusted authorities.
        #expect(report.trust == .selfSigned)
        #expect(report.kind == .signature)
    }

    @Test("Documents modified after signing are flagged, not rejected")
    func trailingUpdateIsFlagged() async throws {
        let fixture = try await Self.signedFixture()

        // Simulate a viewer appending a non-signature incremental update.
        var extended = fixture.signedPDF
        extended.append(contentsOf: "\n999 0 obj\n<< /ViewerState true >>\nendobj\n%%EOF\n".utf8)

        let inspection = SignedPDFVerifier.inspect(pdf: extended)
        #expect(inspection.hasUnsignedTrailingData)
        #expect(inspection.verdicts.count == 1)
        // The signature itself stays valid for its own revision.
        #expect(inspection.verdicts[0].report != nil)
        #expect(inspection.verdicts[0].report?.coversWholeFile == false)

        // The strict signing-path verifier still rejects such documents.
        #expect(throws: SignatureStructureVerifierError.noSignatureCoversWholeFile(fileLength: extended.count)) {
            try SignedPDFVerifier.verify(pdf: extended)
        }
    }

    @Test("Tampering with signed bytes is detected as a digest mismatch")
    func tamperedPDFFails() async throws {
        let fixture = try await Self.signedFixture()

        var tampered = fixture.signedPDF
        tampered[10] = tampered[10] == UInt8(ascii: "A") ? UInt8(ascii: "B") : UInt8(ascii: "A")

        #expect(throws: SignedPDFVerifierError.messageDigestMismatch) {
            try SignedPDFVerifier.verify(pdf: tampered)
        }
    }

    @Test("A signature from a different key fails verification")
    func wrongKeySignatureFails() async throws {
        let key = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let wrongKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let certificateDER = try Self.selfSignedCertificateDER(for: key, commonName: "Test Signer")
        let input = Self.signingInput(certificateDER: certificateDER)

        let probe = try await LocalPDFSigner.sign(input: input) { _ in
            [UInt8](repeating: 0xAB, count: 256)
        }
        let signature = try wrongKey.signature(
            for: SHA256.hash(data: Data(probe.signedAttributesDER)),
            padding: .insecurePKCS1v1_5
        )

        await #expect(throws: SignedPDFVerifierError.signatureVerificationFailed) {
            try await LocalPDFSigner.sign(input: input, verification: .full) { _ in
                Array(signature.rawRepresentation)
            }
        }
    }

    // MARK: - Co-signing

    @Test("Co-signing preserves and verifies both signatures")
    func coSigningVerifiesBothSignatures() async throws {
        let first = try await Self.signedFixture()

        let secondKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let secondCertificate = try Self.selfSignedCertificateDER(for: secondKey, commonName: "Second Signer")
        let secondInput = LocalPDFSigningInput(
            pdf: first.signedPDF,
            certificateDER: secondCertificate,
            signerName: "Second Signer",
            signingDate: Date(timeIntervalSince1970: 1_782_134_400)
        )
        let probe = try await LocalPDFSigner.sign(input: secondInput) { _ in
            [UInt8](repeating: 0xAB, count: 256)
        }
        let signature = try secondKey.signature(
            for: SHA256.hash(data: Data(probe.signedAttributesDER)),
            padding: .insecurePKCS1v1_5
        )
        let coSigned = try await LocalPDFSigner.sign(input: secondInput, verification: .full) { _ in
            Array(signature.rawRepresentation)
        }

        let reports = try SignedPDFVerifier.verifyAll(pdf: coSigned.signedPDF)
        #expect(reports.count == 2)
        #expect(reports.filter(\.coversWholeFile).count == 1)
        // The first signature still ends at its own revision boundary.
        #expect(reports.contains { !$0.coversWholeFile })
        // Auto-numbered second field.
        let text = String(decoding: coSigned.signedPDF, as: UTF8.self)
        #expect(text.contains("(Signature2)"))
    }

    @Test("Tampering with the first revision breaks the first signature of a co-signed file")
    func coSignedTamperDetected() async throws {
        let first = try await Self.signedFixture()
        let secondKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let secondCertificate = try Self.selfSignedCertificateDER(for: secondKey, commonName: "Second Signer")
        let secondInput = LocalPDFSigningInput(
            pdf: first.signedPDF,
            certificateDER: secondCertificate,
            signerName: "Second Signer",
            signingDate: Date(timeIntervalSince1970: 1_782_134_400)
        )
        let probe = try await LocalPDFSigner.sign(input: secondInput) { _ in
            [UInt8](repeating: 0xAB, count: 256)
        }
        let signature = try secondKey.signature(
            for: SHA256.hash(data: Data(probe.signedAttributesDER)),
            padding: .insecurePKCS1v1_5
        )
        let coSigned = try await LocalPDFSigner.sign(input: secondInput, verification: .full) { _ in
            Array(signature.rawRepresentation)
        }

        var tampered = coSigned.signedPDF
        tampered[10] = tampered[10] == UInt8(ascii: "A") ? UInt8(ascii: "B") : UInt8(ascii: "A")

        #expect(throws: SignedPDFVerifierError.messageDigestMismatch) {
            try SignedPDFVerifier.verifyAll(pdf: tampered)
        }

        let inspection = SignedPDFVerifier.inspect(pdf: tampered)
        #expect(inspection.verdicts.count == 2)
        #expect(inspection.verdicts.contains { $0.report == nil })
    }

    // MARK: - MOJ conformance (in-app checker)

    @Test("TestSigner-style output is MOJ-conformant")
    func mojConformantOutput() async throws {
        let fixture = try await Self.signedFixture()

        let result = MOJConformanceChecker.check(pdf: fixture.signedPDF)

        #expect(result.isConformant, "\(result.items.filter { $0.status == .fail })")
        #expect(result.signatureCount == 1)
        #expect(result.items.count == 9)
    }

    @Test("MOJ check fails on wrong SubFilter and on appended data")
    func mojNonconformance() async throws {
        let fixture = try await Self.signedFixture()

        // SubFilter mutation (same length).
        let pdfText = fixture.signedPDF
        let mutated = Data(
            String(decoding: pdfText, as: UTF8.self)
                .replacingOccurrences(of: "/adbe.pkcs7.detached", with: "/adbe.pkcs7.detacheX")
                .utf8
        )
        let subFilterResult = MOJConformanceChecker.check(pdf: mutated)
        #expect(subFilterResult.items.contains { $0.checkID == "C2" && $0.status == .fail })

        // Data appended after the signature.
        var extended = fixture.signedPDF
        extended.append(contentsOf: "\n999 0 obj\n<< /X true >>\nendobj\n%%EOF\n".utf8)
        let appendedResult = MOJConformanceChecker.check(pdf: extended)
        #expect(!appendedResult.isConformant)
        #expect(appendedResult.items.contains { $0.checkID == "C5" && $0.status == .fail })
    }

    // MARK: - Trust anchors

    @Test("Bundled JPKI trust anchors load and are self-signed")
    func trustAnchorsLoad() {
        let anchors = JPKITrustAnchors.certificates
        #expect(anchors.count == 3)
        for anchor in anchors {
            #expect(anchor.issuer == anchor.subject)
            #expect(String(describing: anchor.subject).contains("O=JPKI"))
            #expect(anchor.publicKey.isValidSignature(anchor.signature, for: anchor))
        }
    }

    @Test("A chain merely claiming JPKI DNs is never classified as JPKI")
    func jpkiImpersonationIsRejected() throws {
        // Forge a CA with the JPKI subject DN and sign a leaf with it. The
        // chain verifies internally, but it must not anchor to the bundled
        // roots, so classification must not be .jpki.
        let caKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let caPrivateKey = Certificate.PrivateKey(caKey)
        let caName = try DistinguishedName {
            CountryName("JP")
            OrganizationName("JPKI")
            OrganizationalUnitName("JPKI for digital signature")
        }
        let caCertificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: caPrivateKey.publicKey,
            notValidBefore: Date(timeIntervalSince1970: 1_750_000_000),
            notValidAfter: Date(timeIntervalSince1970: 1_900_000_000),
            issuer: caName,
            subject: caName,
            signatureAlgorithm: .sha256WithRSAEncryption,
            extensions: Certificate.Extensions {},
            issuerPrivateKey: caPrivateKey
        )

        let leafKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let leafName = try DistinguishedName {
            CommonName("Impersonator")
        }
        let leafCertificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PrivateKey(leafKey).publicKey,
            notValidBefore: Date(timeIntervalSince1970: 1_750_000_000),
            notValidAfter: Date(timeIntervalSince1970: 1_900_000_000),
            issuer: caName,
            subject: leafName,
            signatureAlgorithm: .sha256WithRSAEncryption,
            extensions: Certificate.Extensions {},
            issuerPrivateKey: caPrivateKey
        )

        func der(_ certificate: Certificate) throws -> [UInt8] {
            var serializer = DER.Serializer()
            try serializer.serialize(certificate)
            return serializer.serializedBytes
        }

        let classification = CertificateTrustClassifier.classify(
            signerCertificateDER: try der(leafCertificate),
            allCertificatesDER: [try der(leafCertificate), try der(caCertificate)]
        )

        #expect(classification == .unverifiable(
            reason: "JPKI を名乗っていますが、同梱の JPKI ルート証明書に連鎖しません"
        ))
    }

    // MARK: - Real-world profiles (synthetic)

    @Test("BER indefinite-length CMS parses like its DER equivalent")
    func berIndefiniteLengthParses() async throws {
        let fixture = try await Self.signedFixture()
        let structure = try SignatureStructureVerifier.extractSignatureStructure(from: fixture.signedPDF)
        let contents = try SignedPDFVerifier.hexDecode(Array(fixture.signedPDF)[structure.contentsHexRange])
        let length = try CMSSignedDataParser.encodedLength(of: contents)
        let der = Array(contents[..<length])

        // Re-wrap the outer ContentInfo SEQUENCE with an indefinite length
        // (30 80 ... 00 00), as Apple's CMS encoder does.
        let outerHeaderLength = der[1] < 0x80 ? 2 : 2 + Int(der[1] & 0x7F)
        let ber: [UInt8] = [0x30, 0x80] + Array(der[outerHeaderLength...]) + [0x00, 0x00]

        let parsedDER = try CMSSignedDataParser.parse(der)
        let parsedBER = try CMSSignedDataParser.parse(ber)
        #expect(parsedBER == parsedDER)
        #expect(try CMSSignedDataParser.encodedLength(of: ber) == ber.count)
    }

    @Test("Direct signatures (no signedAttrs) verify against the content digest")
    func directSignatureVerifies() async throws {
        let key = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let certificateDER = try Self.selfSignedCertificateDER(for: key, commonName: "Direct Signer")

        // Sign normally to obtain a prepared PDF layout, then replace the
        // CMS with a direct-signature SignedData over the same ByteRange.
        let input = Self.signingInput(certificateDER: certificateDER)
        let probe = try await LocalPDFSigner.sign(input: input) { _ in
            [UInt8](repeating: 0xAB, count: 256)
        }
        var pdf = probe.signedPDF
        let structure = try SignatureStructureVerifier.extractSignatureStructure(from: pdf)
        let contentDigest = try ByteRangeCalculator.sha256Digest(from: pdf, byteRange: structure.byteRange)
        let signature = try key.signature(
            for: SHA256.hash(data: Data(try ByteRangeCalculator.signedBytes(from: pdf, byteRange: structure.byteRange))),
            padding: .insecurePKCS1v1_5
        )
        _ = contentDigest

        let cms = try TestDER.directSignatureCMS(
            certificateDER: certificateDER,
            signature: Array(signature.rawRepresentation)
        )
        let embedded = try PDFSignatureEmbedder.embedCMS(
            cms,
            into: pdf,
            placeholder: PDFSignaturePlaceholder(
                contentsHexRange: structure.contentsHexRange,
                byteRange: structure.byteRange
            )
        )
        pdf = embedded

        let report = try SignedPDFVerifier.verify(pdf: pdf)
        #expect(report.cms.isDirectSignature)
        #expect(report.cms.messageDigest == nil)
    }

    // MARK: - Fixtures

    private struct Fixture {
        let signedPDF: Data
    }

    /// Signs the minimal PDF with a fresh RSA-2048 key and matching
    /// self-signed certificate. Preparation is deterministic for a fixed
    /// signing date, so a probe pass discovers the signedAttrs the real
    /// signature must cover (mirroring how the card signs a DigestInfo).
    private static func signedFixture() async throws -> Fixture {
        let key = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let certificateDER = try selfSignedCertificateDER(for: key, commonName: "Test Signer")
        let input = signingInput(certificateDER: certificateDER)

        let probe = try await LocalPDFSigner.sign(input: input) { _ in
            [UInt8](repeating: 0xAB, count: 256)
        }
        let signature = try key.signature(
            for: SHA256.hash(data: Data(probe.signedAttributesDER)),
            padding: .insecurePKCS1v1_5
        )

        let result = try await LocalPDFSigner.sign(input: input, verification: .full) { _ in
            Array(signature.rawRepresentation)
        }
        return Fixture(signedPDF: result.signedPDF)
    }

    private static func signingInput(certificateDER: [UInt8]) -> LocalPDFSigningInput {
        LocalPDFSigningInput(
            pdf: minimalUnsignedPDF(),
            certificateDER: certificateDER,
            signerName: "Test Signer",
            signingDate: Date(timeIntervalSince1970: 1_782_048_000)
        )
    }

    private static func selfSignedCertificateDER(
        for key: _RSA.Signing.PrivateKey,
        commonName: String
    ) throws -> [UInt8] {
        let privateKey = Certificate.PrivateKey(key)
        let name = try DistinguishedName {
            CommonName(commonName)
        }
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: privateKey.publicKey,
            notValidBefore: Date(timeIntervalSince1970: 1_750_000_000),
            notValidAfter: Date(timeIntervalSince1970: 1_900_000_000),
            issuer: name,
            subject: name,
            signatureAlgorithm: .sha256WithRSAEncryption,
            extensions: Certificate.Extensions {},
            issuerPrivateKey: privateKey
        )

        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return serializer.serializedBytes
    }

    private static func minimalUnsignedPDF() -> Data {
        var pdf = Data()
        var offsets: [Int] = [0]

        func appendObject(_ number: Int, _ body: String) {
            offsets.append(pdf.count)
            pdf.append(contentsOf: "\(number) 0 obj\n\(body)\nendobj\n".utf8)
        }

        pdf.append(contentsOf: "%PDF-1.7\n".utf8)
        appendObject(1, "<< /Type /Catalog /Pages 2 0 R >>")
        appendObject(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        appendObject(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> /Contents 4 0 R >>")
        appendObject(4, "<< /Length 0 >>\nstream\n\nendstream")
        let xrefOffset = pdf.count
        pdf.append(contentsOf: "xref\n0 5\n0000000000 65535 f \n".utf8)
        for offset in offsets.dropFirst() {
            pdf.append(contentsOf: String(format: "%010d 00000 n \n", offset).utf8)
        }
        pdf.append(contentsOf: "trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n\(xrefOffset)\n%%EOF\n".utf8)
        return pdf
    }
}
