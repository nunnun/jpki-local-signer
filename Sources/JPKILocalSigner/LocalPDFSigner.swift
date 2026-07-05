import CMSBuilder
import Foundation
import PDFSigning
import SelfVerify

public typealias DigestInfoSigner = @Sendable (_ digestInfo: [UInt8]) async throws -> [UInt8]

public struct LocalPDFSigningInput: Equatable, Sendable {
    public let pdf: Data
    public let certificateDER: [UInt8]
    public let signerName: String
    public let signingDate: Date
    public let contentsByteCapacity: Int

    public init(
        pdf: Data,
        certificateDER: [UInt8],
        signerName: String,
        signingDate: Date = Date(),
        contentsByteCapacity: Int = PDFSignaturePreparer.defaultContentsByteCapacity
    ) {
        self.pdf = pdf
        self.certificateDER = certificateDER
        self.signerName = signerName
        self.signingDate = signingDate
        self.contentsByteCapacity = contentsByteCapacity
    }
}

public struct LocalPDFSigningResult: Equatable, Sendable {
    public let signedPDF: Data
    public let signatureStructure: PDFSignatureStructure
    public let signedAttributesDER: [UInt8]
    public let digestInfo: [UInt8]
    public let cmsDER: [UInt8]

    public init(
        signedPDF: Data,
        signatureStructure: PDFSignatureStructure,
        signedAttributesDER: [UInt8],
        digestInfo: [UInt8],
        cmsDER: [UInt8]
    ) {
        self.signedPDF = signedPDF
        self.signatureStructure = signatureStructure
        self.signedAttributesDER = signedAttributesDER
        self.digestInfo = digestInfo
        self.cmsDER = cmsDER
    }
}

/// How much of the produced signature to check before returning (FR-11).
public enum SelfVerificationMode: Sendable {
    /// ByteRange / Contents structural consistency only. Use for development
    /// pipelines whose signature values are not real.
    case structureOnly
    /// Structure + CMS parse + messageDigest + certificate binding + RSA
    /// signature verification.
    case full
}

public enum LocalPDFSignerError: Error, Equatable, Sendable {
    case addedSignatureNotFound
}

public enum LocalPDFSigner {
    public static func sign(
        input: LocalPDFSigningInput,
        verification: SelfVerificationMode = .structureOnly,
        signer: DigestInfoSigner
    ) async throws -> LocalPDFSigningResult {
        let prepared = try PDFSignaturePreparer.prepareForSignature(
            pdf: input.pdf,
            options: PDFSignaturePreparationOptions(
                signerName: input.signerName,
                signingDate: input.signingDate,
                contentsByteCapacity: input.contentsByteCapacity
            )
        )
        let messageDigest = try ByteRangeCalculator.sha256Digest(
            from: prepared.pdf,
            byteRange: prepared.placeholder.byteRange
        )
        let signedAttributesDER = try SignedAttributesBuilder.buildDER(from: SignedAttributesInput(
            messageDigest: messageDigest,
            signingTime: input.signingDate
        ))
        let digestInfo = DigestInfo.sha256DigestInfo(for: signedAttributesDER)
        let signature = try await signer(digestInfo)
        let cmsDER = try CMSSignedDataBuilder.buildDetachedSignedData(from: ExternalSignatureCMSInput(
            certificateDER: input.certificateDER,
            signedAttributesDER: signedAttributesDER,
            signature: signature
        ))
        let signedPDF = try PDFSignatureEmbedder.embedCMS(
            cmsDER,
            into: prepared.pdf,
            placeholder: prepared.placeholder
        )
        // Identify our own signature by the placeholder range: a co-signed
        // input legitimately contains other signatures alongside it.
        let signatureStructure: PDFSignatureStructure
        switch verification {
        case .structureOnly:
            let structures = try SignatureStructureVerifier.extractSignatureStructures(from: signedPDF)
            guard let own = structures.first(where: { $0.contentsHexRange == prepared.placeholder.contentsHexRange }) else {
                throw LocalPDFSignerError.addedSignatureNotFound
            }
            signatureStructure = own
        case .full:
            // Verifies every signature — including pre-existing ones, which
            // must survive the incremental update untouched.
            let reports = try SignedPDFVerifier.verifyAll(pdf: signedPDF)
            guard let own = reports.first(where: { $0.structure.contentsHexRange == prepared.placeholder.contentsHexRange }),
                  own.coversWholeFile else {
                throw LocalPDFSignerError.addedSignatureNotFound
            }
            signatureStructure = own.structure
        }

        return LocalPDFSigningResult(
            signedPDF: signedPDF,
            signatureStructure: signatureStructure,
            signedAttributesDER: signedAttributesDER,
            digestInfo: digestInfo,
            cmsDER: cmsDER
        )
    }
}
