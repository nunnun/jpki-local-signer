import Foundation

public struct ExternalSignatureCMSInput: Equatable, Sendable {
    public let certificateDER: [UInt8]
    public let signedAttributesDER: [UInt8]
    public let signature: [UInt8]

    public init(certificateDER: [UInt8], signedAttributesDER: [UInt8], signature: [UInt8]) {
        self.certificateDER = certificateDER
        self.signedAttributesDER = signedAttributesDER
        self.signature = signature
    }
}

public enum CMSSignedDataBuilder {
    public static func buildDetachedSignedData(from input: ExternalSignatureCMSInput) throws -> [UInt8] {
        guard !input.certificateDER.isEmpty else {
            throw CMSSignedDataBuilderError.emptyCertificate
        }
        guard !input.signature.isEmpty else {
            throw CMSSignedDataBuilderError.emptySignature
        }

        let certificateIdentifier = try CertificateIdentifier.extract(from: input.certificateDER)
        let signedAttributesContent = try DEREncoding.contentBytes(of: input.signedAttributesDER, expectedTag: 0x31)
        let sha256Algorithm = try algorithmIdentifier("2.16.840.1.101.3.4.2.1")
        let sha256WithRSAAlgorithm = try algorithmIdentifier("1.2.840.113549.1.1.11")

        let signerInfo = DEREncoding.sequence([
            DEREncoding.integer(1),
            certificateIdentifier.issuerAndSerialNumberDER,
            sha256Algorithm,
            DEREncoding.contextConstructed(0, content: signedAttributesContent),
            sha256WithRSAAlgorithm,
            DEREncoding.octetString(input.signature)
        ])

        let signedData = DEREncoding.sequence([
            DEREncoding.integer(1),
            DEREncoding.setOf([sha256Algorithm]),
            DEREncoding.sequence([try DEREncoding.objectIdentifier("1.2.840.113549.1.7.1")]),
            DEREncoding.contextConstructed(0, content: input.certificateDER),
            DEREncoding.setOf([signerInfo])
        ])

        return try DEREncoding.sequence([
            DEREncoding.objectIdentifier("1.2.840.113549.1.7.2"),
            DEREncoding.contextConstructed(0, content: signedData)
        ])
    }

    private static func algorithmIdentifier(_ oid: String) throws -> [UInt8] {
        try DEREncoding.sequence([
            DEREncoding.objectIdentifier(oid),
            DEREncoding.null()
        ])
    }
}

public enum CMSSignedDataBuilderError: Error, Equatable, Sendable {
    case emptyCertificate
    case emptySignature
    case invalidCertificate
}

struct CertificateIdentifier: Equatable, Sendable {
    let issuerAndSerialNumberDER: [UInt8]

    static func extract(from certificateDER: [UInt8]) throws -> CertificateIdentifier {
        do {
            let certificate = try DEREncoding.requireTLV(certificateDER, at: 0, tag: 0x30)
            guard certificate.totalRange.upperBound == certificateDER.count else {
                throw CMSSignedDataBuilderError.invalidCertificate
            }

            let tbsCertificate = try DEREncoding.requireTLV(certificateDER, at: certificate.contentRange.lowerBound, tag: 0x30)
            var offset = tbsCertificate.contentRange.lowerBound

            let firstTBSField = try DEREncoding.readTLV(certificateDER, at: offset)
            if firstTBSField.tag == 0xA0 {
                offset = firstTBSField.totalRange.upperBound
            }

            let serialNumber = try DEREncoding.requireTLV(certificateDER, at: offset, tag: 0x02)
            let serialNumberDER = Array(certificateDER[serialNumber.totalRange])
            offset = serialNumber.totalRange.upperBound

            let signatureAlgorithm = try DEREncoding.readTLV(certificateDER, at: offset)
            offset = signatureAlgorithm.totalRange.upperBound

            let issuer = try DEREncoding.requireTLV(certificateDER, at: offset, tag: 0x30)
            let issuerDER = Array(certificateDER[issuer.totalRange])

            return CertificateIdentifier(
                issuerAndSerialNumberDER: DEREncoding.sequence([issuerDER, serialNumberDER])
            )
        } catch let error as CMSSignedDataBuilderError {
            throw error
        } catch {
            throw CMSSignedDataBuilderError.invalidCertificate
        }
    }
}
