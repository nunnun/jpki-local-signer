import CMSBuilder
import Crypto
import Foundation
import PDFSigning
import _CryptoExtras

/// What kind of CMS object fills the signature slot.
public enum PDFSignatureKind: Equatable, Sendable {
    /// An ordinary (person's) signature.
    case signature
    /// An RFC 3161 document timestamp (ETSI.RFC3161 DocTimeStamp).
    case documentTimestamp
}

/// Result of the static verification (FR-11) for one signature: structure,
/// digest, certificate binding, signature-value checks, and offline chain
/// classification. Revocation is out of scope by design (the receiving
/// registry system verifies it).
public struct SignedPDFVerificationReport: Equatable, Sendable {
    public let structure: PDFSignatureStructure
    public let cms: ParsedCMSSignedData
    /// `false` for a prior signature of a co-signed document, whose range
    /// ends at its own revision boundary instead of the current file end.
    public let coversWholeFile: Bool
    public let kind: PDFSignatureKind
    /// Offline classification of the signer's certificate chain.
    public let trust: CertificateTrustClassification
    /// For document timestamps: the TSA-asserted moment the document
    /// existed (TSTInfo.genTime, UTC). `nil` for ordinary signatures.
    public let timestampDate: Date?
}

/// Non-throwing per-signature verdict for UI use.
public enum PDFSignatureVerdict: Sendable {
    case valid(SignedPDFVerificationReport)
    case invalid(reason: String)

    public var report: SignedPDFVerificationReport? {
        if case .valid(let report) = self { return report }
        return nil
    }
}

/// Whole-document inspection for the verification viewer.
public struct PDFSignatureInspection: Sendable {
    public let verdicts: [PDFSignatureVerdict]
    /// The file contains bytes after the newest signature's coverage —
    /// i.e. it was modified (incrementally updated) after signing.
    public let hasUnsignedTrailingData: Bool

    public init(verdicts: [PDFSignatureVerdict], hasUnsignedTrailingData: Bool) {
        self.verdicts = verdicts
        self.hasUnsignedTrailingData = hasUnsignedTrailingData
    }
}

public enum SignedPDFVerifier {
    static let rsaSignatureAlgorithmOIDs: Set<String> = [
        "1.2.840.113549.1.1.1",  // rsaEncryption
        "1.2.840.113549.1.1.11", // sha256WithRSA
        "1.2.840.113549.1.1.12", // sha384WithRSA
        "1.2.840.113549.1.1.13"  // sha512WithRSA
    ]

    /// Verifies every signature in the document; throws on the first
    /// failure. Returns the newest (whole-file) signature's report. Used by
    /// the signing pipeline, where the freshly added signature must cover
    /// the entire file.
    @discardableResult
    public static func verify(pdf: Data) throws -> SignedPDFVerificationReport {
        let reports = try verifyAll(pdf: pdf)
        guard let newest = reports.first(where: { $0.coversWholeFile }) else {
            throw SignedPDFVerifierError.noSignatureCoversWholeFile
        }
        return newest
    }

    /// Verifies every signature (a co-signed document has several, each
    /// covering its own revision) and throws on the first failure.
    public static func verifyAll(pdf: Data) throws -> [SignedPDFVerificationReport] {
        let structures = try SignatureStructureVerifier.extractSignatureStructures(from: pdf)
        return try structures.map { try verifySignature($0, in: pdf, coversWholeFile: nil) }
    }

    /// Per-signature verdicts that never throw — for the verification
    /// viewer. Unlike `verifyAll`, tolerates documents that were modified
    /// after their newest signature (reported via
    /// `hasUnsignedTrailingData`, mirroring Acrobat's behavior).
    public static func inspect(pdf: Data) -> PDFSignatureInspection {
        let candidates = SignatureStructureVerifier.enumerateSignatureCandidates(in: pdf)
        guard !candidates.isEmpty else {
            return PDFSignatureInspection(
                verdicts: [.invalid(reason: "署名が見つかりません")],
                hasUnsignedTrailingData: false
            )
        }

        let verdicts: [PDFSignatureVerdict] = candidates.map { candidate in
            if let problem = candidate.problem {
                return .invalid(reason: problem)
            }
            guard let structure = candidate.structure else {
                return .invalid(reason: "署名構造を解釈できません")
            }
            do {
                return .valid(try verifySignature(
                    structure,
                    in: pdf,
                    coversWholeFile: candidate.coversWholeFile
                ))
            } catch {
                return .invalid(reason: String(describing: error))
            }
        }

        let newestCoverage = candidates
            .map { $0.byteRange.secondOffset + $0.byteRange.secondLength }
            .max() ?? 0
        return PDFSignatureInspection(
            verdicts: verdicts,
            hasUnsignedTrailingData: newestCoverage < pdf.count
        )
    }

    // MARK: - Single-signature verification

    static func verifySignature(
        _ structure: PDFSignatureStructure,
        in pdf: Data,
        coversWholeFile: Bool?
    ) throws -> SignedPDFVerificationReport {
        // /Contents: hex-decode, then strip the zero padding after the CMS.
        let hexBytes = Array(pdf)[structure.contentsHexRange]
        let contents = try hexDecode(hexBytes)
        let cmsLength = try CMSSignedDataParser.encodedLength(of: contents)
        guard contents[cmsLength...].allSatisfy({ $0 == 0 }) else {
            throw SignedPDFVerifierError.nonZeroContentsPadding
        }
        let cms = try CMSSignedDataParser.parse(Array(contents[..<cmsLength]))

        guard let digest = SupportedDigest(oid: cms.digestAlgorithmOID) else {
            throw SignedPDFVerifierError.unexpectedDigestAlgorithm(cms.digestAlgorithmOID)
        }
        guard rsaSignatureAlgorithmOIDs.contains(cms.signatureAlgorithmOID) else {
            throw SignedPDFVerifierError.unexpectedSignatureAlgorithm(cms.signatureAlgorithmOID)
        }
        guard cms.signerMatchesCertificate else {
            throw SignedPDFVerifierError.signerDoesNotMatchCertificate
        }

        let signedBytes = try ByteRangeCalculator.signedBytes(from: pdf, byteRange: structure.byteRange)

        // Structural pre-check so degenerate/crafted SPKI DER never reaches
        // the crypto backend.
        guard CMSSignedDataParser.subjectPublicKeyInfoIsRSA(cms.subjectPublicKeyInfoDER) else {
            throw SignedPDFVerifierError.unsupportedPublicKey
        }
        let publicKey: _RSA.Signing.PublicKey
        do {
            publicKey = try _RSA.Signing.PublicKey(derRepresentation: Data(cms.subjectPublicKeyInfoDER))
        } catch {
            throw SignedPDFVerifierError.unsupportedPublicKey
        }
        let signature = _RSA.Signing.RSASignature(rawRepresentation: Data(cms.signature))

        var timestampDate: Date?
        if let encapsulatedContent = cms.encapsulatedContent {
            // Non-detached CMS: RFC 3161 document timestamps. messageDigest
            // binds the signature to the TSTInfo; the TSTInfo's
            // messageImprint binds the TSTInfo to the document bytes.
            guard let signedAttributesDER = cms.signedAttributesDER,
                  let messageDigest = cms.messageDigest else {
                throw SignedPDFVerifierError.signatureVerificationFailed
            }
            guard messageDigest == digest.hash(Data(encapsulatedContent)) else {
                throw SignedPDFVerifierError.messageDigestMismatch
            }
            if cms.isTimestampToken {
                let imprint = try CMSSignedDataParser.timestampMessageImprint(inTSTInfo: encapsulatedContent)
                guard let imprintDigest = SupportedDigest(oid: imprint.hashAlgorithmOID) else {
                    throw SignedPDFVerifierError.unexpectedDigestAlgorithm(imprint.hashAlgorithmOID)
                }
                guard imprint.hashedMessage == imprintDigest.hash(signedBytes) else {
                    throw SignedPDFVerifierError.timestampImprintMismatch
                }
                timestampDate = try? CMSSignedDataParser.timestampGenTime(inTSTInfo: encapsulatedContent)
            }
            guard digest.isValidRSASignature(signature, over: Data(signedAttributesDER), publicKey: publicKey) else {
                throw SignedPDFVerifierError.signatureVerificationFailed
            }
        } else if let signedAttributesDER = cms.signedAttributesDER {
            guard cms.messageDigest == digest.hash(signedBytes) else {
                throw SignedPDFVerifierError.messageDigestMismatch
            }
            guard digest.isValidRSASignature(signature, over: Data(signedAttributesDER), publicKey: publicKey) else {
                throw SignedPDFVerifierError.signatureVerificationFailed
            }
        } else {
            // Direct signature (no authenticated attributes; Acrobat's
            // adbe.pkcs7.detached profile): the signature covers the content
            // digest itself.
            guard digest.isValidRSASignature(signature, over: signedBytes, publicKey: publicKey) else {
                throw SignedPDFVerifierError.signatureVerificationFailed
            }
        }

        return SignedPDFVerificationReport(
            structure: structure,
            cms: cms,
            coversWholeFile: coversWholeFile
                ?? (structure.byteRange.secondOffset + structure.byteRange.secondLength == pdf.count),
            kind: cms.isTimestampToken ? .documentTimestamp : .signature,
            trust: CertificateTrustClassifier.classify(
                signerCertificateDER: cms.certificateDER,
                allCertificatesDER: cms.allCertificatesDER
            ),
            timestampDate: timestampDate
        )
    }

    public static func hexDecode(_ hex: ArraySlice<UInt8>) throws -> [UInt8] {
        guard hex.count.isMultiple(of: 2) else {
            throw SignedPDFVerifierError.invalidContentsHex
        }

        func nibble(_ byte: UInt8) throws -> UInt8 {
            switch byte {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): return byte - UInt8(ascii: "0")
            case UInt8(ascii: "A")...UInt8(ascii: "F"): return byte - UInt8(ascii: "A") + 10
            case UInt8(ascii: "a")...UInt8(ascii: "f"): return byte - UInt8(ascii: "a") + 10
            default: throw SignedPDFVerifierError.invalidContentsHex
            }
        }

        var result: [UInt8] = []
        result.reserveCapacity(hex.count / 2)
        var iterator = hex.makeIterator()
        while let high = iterator.next() {
            guard let low = iterator.next() else {
                throw SignedPDFVerifierError.invalidContentsHex
            }
            result.append(try nibble(high) << 4 | nibble(low))
        }
        return result
    }
}

/// Digest algorithms accepted in real-world PDF signatures.
enum SupportedDigest {
    case sha256, sha384, sha512

    init?(oid: String) {
        switch oid {
        case "2.16.840.1.101.3.4.2.1": self = .sha256
        case "2.16.840.1.101.3.4.2.2": self = .sha384
        case "2.16.840.1.101.3.4.2.3": self = .sha512
        default: return nil
        }
    }

    func hash(_ data: Data) -> [UInt8] {
        switch self {
        case .sha256: return Array(SHA256.hash(data: data))
        case .sha384: return Array(SHA384.hash(data: data))
        case .sha512: return Array(SHA512.hash(data: data))
        }
    }

    func isValidRSASignature(
        _ signature: _RSA.Signing.RSASignature,
        over data: Data,
        publicKey: _RSA.Signing.PublicKey
    ) -> Bool {
        switch self {
        case .sha256:
            return publicKey.isValidSignature(signature, for: SHA256.hash(data: data), padding: .insecurePKCS1v1_5)
        case .sha384:
            return publicKey.isValidSignature(signature, for: SHA384.hash(data: data), padding: .insecurePKCS1v1_5)
        case .sha512:
            return publicKey.isValidSignature(signature, for: SHA512.hash(data: data), padding: .insecurePKCS1v1_5)
        }
    }
}

public enum SignedPDFVerifierError: Error, Equatable, Sendable {
    case invalidContentsHex
    case nonZeroContentsPadding
    case unexpectedDigestAlgorithm(String)
    case unexpectedSignatureAlgorithm(String)
    case signerDoesNotMatchCertificate
    case messageDigestMismatch
    case timestampImprintMismatch
    case unsupportedPublicKey
    case signatureVerificationFailed
    case noSignatureCoversWholeFile
}
