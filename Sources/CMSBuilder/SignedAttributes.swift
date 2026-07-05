import Foundation

public struct SignedAttributesInput: Equatable, Sendable {
    public let contentTypeOID: String
    public let messageDigest: [UInt8]
    public let signingTime: Date

    public init(
        contentTypeOID: String = "1.2.840.113549.1.7.1",
        messageDigest: [UInt8],
        signingTime: Date
    ) {
        self.contentTypeOID = contentTypeOID
        self.messageDigest = messageDigest
        self.signingTime = signingTime
    }
}

public enum SignedAttributesBuilder {
    public static func buildDER(from input: SignedAttributesInput) throws -> [UInt8] {
        guard input.messageDigest.count == 32 else {
            throw SignedAttributesBuilderError.invalidMessageDigestLength(input.messageDigest.count)
        }

        let contentType = try DEREncoding.sequence([
            DEREncoding.objectIdentifier("1.2.840.113549.1.9.3"),
            DEREncoding.set([try DEREncoding.objectIdentifier(input.contentTypeOID)])
        ])
        let messageDigest = try DEREncoding.sequence([
            DEREncoding.objectIdentifier("1.2.840.113549.1.9.4"),
            DEREncoding.set([DEREncoding.octetString(input.messageDigest)])
        ])
        let signingTime = try DEREncoding.sequence([
            DEREncoding.objectIdentifier("1.2.840.113549.1.9.5"),
            DEREncoding.set([DEREncoding.time(input.signingTime)])
        ])

        return DEREncoding.setOf([contentType, messageDigest, signingTime])
    }
}

public enum SignedAttributesBuilderError: Error, Equatable, Sendable {
    case invalidMessageDigestLength(Int)
}
