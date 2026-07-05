import Foundation

/// Fields extracted from a detached CMS SignedData for self-verification
/// (FR-11). Parsing mirrors `CMSSignedDataBuilder`'s output shape but only
/// assumes standard CMS structure.
public struct ParsedCMSSignedData: Equatable, Sendable {
    /// The signer's certificate (selected from the chain via SignerInfo.sid).
    public let certificateDER: [UInt8]
    /// Every certificate embedded in the SignedData (signer + CA chain).
    public let allCertificatesDER: [[UInt8]]
    /// encapContentInfo.eContentType (pkcs7-data for detached PDF signatures,
    /// id-ct-TSTInfo for RFC 3161 document timestamps).
    public let encapsulatedContentTypeOID: String
    /// encapContentInfo.eContent when present (e.g. the TSTInfo of a
    /// document timestamp). Detached signatures carry none.
    public let encapsulatedContent: [UInt8]?
    /// SubjectPublicKeyInfo of that certificate (for RSA verification).
    public let subjectPublicKeyInfoDER: [UInt8]
    /// IssuerAndSerialNumber computed from the embedded certificate.
    public let certificateIssuerAndSerialNumberDER: [UInt8]
    /// SignerInfo.sid (IssuerAndSerialNumber) as stored in the CMS.
    public let signerIssuerAndSerialNumberDER: [UInt8]
    /// Signed attributes re-encoded with the SET tag (the signed form).
    /// `nil` for direct signatures (no authenticated attributes; the
    /// signature is computed over the content digest itself — the profile
    /// Acrobat uses for adbe.pkcs7.detached).
    public let signedAttributesDER: [UInt8]?
    /// Attribute type OIDs inside signedAttrs (`nil` for direct signatures).
    public let signedAttributeOIDs: [String]?
    /// messageDigest attribute value (`nil` when signedAttrs are absent).
    public let messageDigest: [UInt8]?
    public let digestAlgorithmOID: String
    public let signatureAlgorithmOID: String
    public let signature: [UInt8]

    public var isDirectSignature: Bool {
        signedAttributesDER == nil
    }

    /// RFC 3161 timestamp token (PDF document timestamps embed these).
    public var isTimestampToken: Bool {
        encapsulatedContentTypeOID == "1.2.840.113549.1.9.16.1.4"
    }

    public var signerMatchesCertificate: Bool {
        signerIssuerAndSerialNumberDER == certificateIssuerAndSerialNumberDER
    }
}

public enum CMSSignedDataParser {
    static let signedDataOID = "1.2.840.113549.1.7.2"
    static let messageDigestOID = "1.2.840.113549.1.9.4"

    public static func parse(_ der: [UInt8]) throws -> ParsedCMSSignedData {
        // ContentInfo ::= SEQUENCE { contentType OID, [0] EXPLICIT content }
        let contentInfo = try DEREncoding.requireTLV(der, at: 0, tag: 0x30)
        var offset = contentInfo.contentRange.lowerBound

        let contentType = try DEREncoding.requireTLV(der, at: offset, tag: 0x06)
        guard try decodeOID(Array(der[contentType.contentRange])) == signedDataOID else {
            throw CMSSignedDataParserError.notSignedData
        }
        offset = contentType.totalRange.upperBound

        let explicitContent = try DEREncoding.requireTLV(der, at: offset, tag: 0xA0)
        let signedData = try DEREncoding.requireTLV(der, at: explicitContent.contentRange.lowerBound, tag: 0x30)
        offset = signedData.contentRange.lowerBound

        // SignedData ::= SEQUENCE { version, digestAlgorithms, encapContentInfo,
        //   [0] certificates OPTIONAL, [1] crls OPTIONAL, signerInfos }
        let version = try DEREncoding.requireTLV(der, at: offset, tag: 0x02)
        offset = version.totalRange.upperBound
        let digestAlgorithms = try DEREncoding.requireTLV(der, at: offset, tag: 0x31)
        offset = digestAlgorithms.totalRange.upperBound
        let encapContentInfo = try DEREncoding.requireTLV(der, at: offset, tag: 0x30)
        offset = encapContentInfo.totalRange.upperBound

        // encapContentInfo ::= SEQUENCE { eContentType OID,
        //   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
        let encapType = try DEREncoding.requireTLV(der, at: encapContentInfo.contentRange.lowerBound, tag: 0x06)
        let encapsulatedContentTypeOID = try decodeOID(Array(der[encapType.contentRange]))
        var encapsulatedContent: [UInt8]?
        if encapType.totalRange.upperBound < encapContentInfo.contentRange.upperBound {
            let explicitEContent = try DEREncoding.requireTLV(der, at: encapType.totalRange.upperBound, tag: 0xA0)
            let octetString = try DEREncoding.requireTLV(der, at: explicitEContent.contentRange.lowerBound, tag: 0x04)
            encapsulatedContent = Array(der[octetString.contentRange])
        }

        // certificates [0]: may hold the whole chain (signer + CAs) in any
        // order; the signer's certificate is selected later via SignerInfo.sid.
        var certificates: [[UInt8]] = []
        var next = try DEREncoding.readTLV(der, at: offset)
        if next.tag == 0xA0 {
            var certificateOffset = next.contentRange.lowerBound
            while certificateOffset < next.contentRange.upperBound {
                let certificate = try DEREncoding.readTLV(der, at: certificateOffset)
                if certificate.tag == 0x30 {
                    certificates.append(Array(der[certificate.totalRange]))
                }
                certificateOffset = certificate.totalRange.upperBound
            }
            offset = next.totalRange.upperBound
            next = try DEREncoding.readTLV(der, at: offset)
        }
        if next.tag == 0xA1 { // crls: skip
            offset = next.totalRange.upperBound
            next = try DEREncoding.readTLV(der, at: offset)
        }
        guard !certificates.isEmpty else {
            throw CMSSignedDataParserError.certificateMissing
        }

        // signerInfos SET -> first SignerInfo
        guard next.tag == 0x31 else {
            throw CMSSignedDataParserError.signerInfoMissing
        }
        let signerInfo = try DEREncoding.requireTLV(der, at: next.contentRange.lowerBound, tag: 0x30)
        offset = signerInfo.contentRange.lowerBound

        let signerVersion = try DEREncoding.requireTLV(der, at: offset, tag: 0x02)
        offset = signerVersion.totalRange.upperBound
        let sid = try DEREncoding.requireTLV(der, at: offset, tag: 0x30)
        let signerIssuerAndSerialNumberDER = Array(der[sid.totalRange])
        offset = sid.totalRange.upperBound
        let digestAlgorithm = try DEREncoding.requireTLV(der, at: offset, tag: 0x30)
        let digestAlgorithmOID = try algorithmOID(der, algorithm: digestAlgorithm)
        offset = digestAlgorithm.totalRange.upperBound

        // signedAttrs [0] IMPLICIT is OPTIONAL (RFC 5652 §5.3). When absent,
        // the signature is a direct signature over the content digest.
        var signedAttributesDER: [UInt8]?
        var signedAttributeOIDs: [String]?
        var signerField = try DEREncoding.readTLV(der, at: offset)
        if signerField.tag == 0xA0 {
            let signedAttributesContent = Array(der[signerField.contentRange])
            // The signature covers the attributes re-encoded as SET (RFC 5652 §5.4).
            let reencoded = DEREncoding.tlv(tag: 0x31, content: signedAttributesContent)
            signedAttributesDER = reencoded
            signedAttributeOIDs = try attributeOIDs(inSignedAttributes: reencoded)
            offset = signerField.totalRange.upperBound
            signerField = try DEREncoding.readTLV(der, at: offset)
        }

        guard signerField.tag == 0x30 else {
            throw CMSSignedDataParserError.signerInfoMissing
        }
        let signatureAlgorithmOID = try algorithmOID(der, algorithm: signerField)
        offset = signerField.totalRange.upperBound

        let signature = try DEREncoding.requireTLV(der, at: offset, tag: 0x04)

        // Pick the signer's certificate out of the embedded chain by
        // matching SignerInfo.sid; fall back to the first certificate.
        let identified = certificates.map { certificate in
            (certificate, try? CertificateIdentifier.extract(from: certificate).issuerAndSerialNumberDER)
        }
        let signerCertificate = identified.first { $0.1 == signerIssuerAndSerialNumberDER } ?? identified[0]
        let certificateDER = signerCertificate.0
        guard let certificateIssuerAndSerialNumberDER = signerCertificate.1 else {
            throw CMSSignedDataBuilderError.invalidCertificate
        }

        return ParsedCMSSignedData(
            certificateDER: certificateDER,
            allCertificatesDER: certificates,
            encapsulatedContentTypeOID: encapsulatedContentTypeOID,
            encapsulatedContent: encapsulatedContent,
            subjectPublicKeyInfoDER: try subjectPublicKeyInfo(fromCertificate: certificateDER),
            certificateIssuerAndSerialNumberDER: certificateIssuerAndSerialNumberDER,
            signerIssuerAndSerialNumberDER: signerIssuerAndSerialNumberDER,
            signedAttributesDER: signedAttributesDER,
            signedAttributeOIDs: signedAttributeOIDs,
            messageDigest: try signedAttributesDER.map { try messageDigest(inSignedAttributes: $0) },
            digestAlgorithmOID: digestAlgorithmOID,
            signatureAlgorithmOID: signatureAlgorithmOID,
            signature: Array(der[signature.contentRange])
        )
    }

    /// RFC 3161 TSTInfo.messageImprint: (hashAlgorithmOID, hashedMessage).
    /// TSTInfo ::= SEQUENCE { version, policy, messageImprint SEQUENCE {
    ///   hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING },
    ///   serialNumber, genTime GeneralizedTime, ... }
    public static func timestampMessageImprint(inTSTInfo tstInfo: [UInt8]) throws -> (hashAlgorithmOID: String, hashedMessage: [UInt8]) {
        let outer = try DEREncoding.requireTLV(tstInfo, at: 0, tag: 0x30)
        let version = try DEREncoding.requireTLV(tstInfo, at: outer.contentRange.lowerBound, tag: 0x02)
        let policy = try DEREncoding.requireTLV(tstInfo, at: version.totalRange.upperBound, tag: 0x06)
        let imprint = try DEREncoding.requireTLV(tstInfo, at: policy.totalRange.upperBound, tag: 0x30)
        let algorithm = try DEREncoding.requireTLV(tstInfo, at: imprint.contentRange.lowerBound, tag: 0x30)
        let oid = try DEREncoding.requireTLV(tstInfo, at: algorithm.contentRange.lowerBound, tag: 0x06)
        let hashed = try DEREncoding.requireTLV(tstInfo, at: algorithm.totalRange.upperBound, tag: 0x04)
        return (try decodeOID(Array(tstInfo[oid.contentRange])), Array(tstInfo[hashed.contentRange]))
    }

    /// RFC 3161 TSTInfo.genTime — the moment the TSA asserts the document
    /// existed. GeneralizedTime, always UTC per the RFC ("YYYYMMDDHHMMSS[.f...]Z").
    public static func timestampGenTime(inTSTInfo tstInfo: [UInt8]) throws -> Date {
        let outer = try DEREncoding.requireTLV(tstInfo, at: 0, tag: 0x30)
        let version = try DEREncoding.requireTLV(tstInfo, at: outer.contentRange.lowerBound, tag: 0x02)
        let policy = try DEREncoding.requireTLV(tstInfo, at: version.totalRange.upperBound, tag: 0x06)
        let imprint = try DEREncoding.requireTLV(tstInfo, at: policy.totalRange.upperBound, tag: 0x30)
        let serialNumber = try DEREncoding.requireTLV(tstInfo, at: imprint.totalRange.upperBound, tag: 0x02)
        let genTime = try DEREncoding.requireTLV(tstInfo, at: serialNumber.totalRange.upperBound, tag: 0x18)

        let text = String(decoding: tstInfo[genTime.contentRange], as: UTF8.self)
        guard text.hasSuffix("Z"), text.count >= 15 else {
            throw CMSSignedDataParserError.invalidGeneralizedTime(text)
        }
        let digits = text.prefix(14)
        guard digits.allSatisfy(\.isNumber),
              let year = Int(digits.prefix(4)),
              let month = Int(digits.dropFirst(4).prefix(2)),
              let day = Int(digits.dropFirst(6).prefix(2)),
              let hour = Int(digits.dropFirst(8).prefix(2)),
              let minute = Int(digits.dropFirst(10).prefix(2)),
              let second = Int(digits.dropFirst(12).prefix(2)) else {
            throw CMSSignedDataParserError.invalidGeneralizedTime(text)
        }

        var components = DateComponents()
        components.year = year
        components.month = month
        components.day = day
        components.hour = hour
        components.minute = minute
        components.second = second
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0) ?? .gmt
        guard let date = calendar.date(from: components) else {
            throw CMSSignedDataParserError.invalidGeneralizedTime(text)
        }
        return date
    }

    /// Total encoded length of the outermost TLV; used to strip the zero
    /// padding that fills the /Contents placeholder after the CMS DER.
    public static func encodedLength(of der: [UInt8]) throws -> Int {
        try DEREncoding.readTLV(der, at: 0).totalRange.upperBound
    }

    /// Structural pre-check before handing a SubjectPublicKeyInfo to the
    /// crypto backend: SEQUENCE { AlgorithmIdentifier(rsaEncryption),
    /// BIT STRING }. Keeps degenerate or crafted DER out of BoringSSL.
    public static func subjectPublicKeyInfoIsRSA(_ spki: [UInt8]) -> Bool {
        guard let outer = try? DEREncoding.requireTLV(spki, at: 0, tag: 0x30),
              let algorithm = try? DEREncoding.requireTLV(spki, at: outer.contentRange.lowerBound, tag: 0x30),
              let oid = try? DEREncoding.requireTLV(spki, at: algorithm.contentRange.lowerBound, tag: 0x06),
              let decoded = try? decodeOID(Array(spki[oid.contentRange])),
              let bitString = try? DEREncoding.requireTLV(spki, at: algorithm.totalRange.upperBound, tag: 0x03) else {
            return false
        }
        return decoded == "1.2.840.113549.1.1.1" && !bitString.contentRange.isEmpty
    }

    private static func algorithmOID(_ bytes: [UInt8], algorithm: DEREncodedTLV) throws -> String {
        let oid = try DEREncoding.requireTLV(bytes, at: algorithm.contentRange.lowerBound, tag: 0x06)
        return try decodeOID(Array(bytes[oid.contentRange]))
    }

    private static func attributeOIDs(inSignedAttributes setDER: [UInt8]) throws -> [String] {
        let set = try DEREncoding.requireTLV(setDER, at: 0, tag: 0x31)
        var oids: [String] = []
        var offset = set.contentRange.lowerBound
        while offset < set.contentRange.upperBound {
            let attribute = try DEREncoding.requireTLV(setDER, at: offset, tag: 0x30)
            let type = try DEREncoding.requireTLV(setDER, at: attribute.contentRange.lowerBound, tag: 0x06)
            oids.append(try decodeOID(Array(setDER[type.contentRange])))
            offset = attribute.totalRange.upperBound
        }
        return oids
    }

    private static func messageDigest(inSignedAttributes setDER: [UInt8]) throws -> [UInt8] {
        let set = try DEREncoding.requireTLV(setDER, at: 0, tag: 0x31)
        var offset = set.contentRange.lowerBound
        while offset < set.contentRange.upperBound {
            let attribute = try DEREncoding.requireTLV(setDER, at: offset, tag: 0x30)
            let type = try DEREncoding.requireTLV(setDER, at: attribute.contentRange.lowerBound, tag: 0x06)
            if try decodeOID(Array(setDER[type.contentRange])) == messageDigestOID {
                let values = try DEREncoding.requireTLV(setDER, at: type.totalRange.upperBound, tag: 0x31)
                let value = try DEREncoding.requireTLV(setDER, at: values.contentRange.lowerBound, tag: 0x04)
                return Array(setDER[value.contentRange])
            }
            offset = attribute.totalRange.upperBound
        }
        throw CMSSignedDataParserError.messageDigestAttributeMissing
    }

    /// tbsCertificate: [0] version?, serialNumber, signature, issuer,
    /// validity, subject, subjectPublicKeyInfo.
    private static func subjectPublicKeyInfo(fromCertificate certificateDER: [UInt8]) throws -> [UInt8] {
        let certificate = try DEREncoding.requireTLV(certificateDER, at: 0, tag: 0x30)
        let tbsCertificate = try DEREncoding.requireTLV(certificateDER, at: certificate.contentRange.lowerBound, tag: 0x30)
        var offset = tbsCertificate.contentRange.lowerBound

        let firstField = try DEREncoding.readTLV(certificateDER, at: offset)
        if firstField.tag == 0xA0 {
            offset = firstField.totalRange.upperBound
        }
        for expectedTag: UInt8 in [0x02, 0x30, 0x30, 0x30, 0x30] { // serial, sigAlg, issuer, validity, subject
            let field = try DEREncoding.requireTLV(certificateDER, at: offset, tag: expectedTag)
            offset = field.totalRange.upperBound
        }
        let spki = try DEREncoding.requireTLV(certificateDER, at: offset, tag: 0x30)
        return Array(certificateDER[spki.totalRange])
    }

    static func decodeOID(_ content: [UInt8]) throws -> String {
        guard !content.isEmpty else {
            throw CMSSignedDataParserError.invalidOID
        }

        var components: [UInt] = []
        var value: UInt = 0
        for (index, byte) in content.enumerated() {
            value = value << 7 | UInt(byte & 0x7F)
            if byte & 0x80 == 0 {
                if components.isEmpty {
                    components.append(min(value / 40, 2))
                    components.append(value - min(value / 40, 2) * 40)
                } else {
                    components.append(value)
                }
                value = 0
            } else if index == content.count - 1 {
                throw CMSSignedDataParserError.invalidOID
            }
        }
        return components.map(String.init).joined(separator: ".")
    }
}

public enum CMSSignedDataParserError: Error, Equatable, Sendable {
    case notSignedData
    case certificateMissing
    case signerInfoMissing
    case messageDigestAttributeMissing
    case invalidOID
    case invalidGeneralizedTime(String)
}
