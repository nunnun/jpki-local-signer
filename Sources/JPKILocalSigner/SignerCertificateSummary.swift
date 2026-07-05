import Crypto
import Foundation
import SwiftASN1
import X509

/// Display-oriented view of the 署名用電子証明書 (FR-04: show holder name and
/// validity before/after signing).
public struct SignerCertificateSummary: Equatable, Sendable {
    /// Subject common name. JPKI certificates carry a serial-like value here.
    public let commonName: String?
    /// Holder name from the subjectAltName directoryName entry, where JPKI
    /// certificates store the 氏名 (subject CN is an opaque identifier).
    public let subjectAlternativeCommonName: String?
    /// 住所 from the JPKI subjectAltName otherName (OID 1.2.392.200149.8.5.5.5).
    public let holderAddress: String?
    /// Subject distinguished name (RFC 4514 style).
    public let subjectDistinguishedName: String
    /// Issuer distinguished name (JPKI: 公的個人認証サービス).
    public let issuerDistinguishedName: String
    /// Certificate serial number, upper-case hex.
    public let serialNumberHex: String
    /// SHA-256 fingerprint of the certificate DER, upper-case hex.
    public let sha256FingerprintHex: String
    public let notValidBefore: Date
    public let notValidAfter: Date

    /// Best human-readable holder name.
    public var displayName: String? {
        subjectAlternativeCommonName ?? commonName
    }

    public init(certificateDER: [UInt8]) throws {
        let certificate = try Certificate(derEncoded: certificateDER)
        self.commonName = certificate.subject.firstCommonName
        self.subjectAlternativeCommonName = Self.otherNameUTF8String(of: certificate, oid: Self.jpkiHolderNameOID)
            ?? Self.directoryCommonName(of: certificate)
        self.holderAddress = Self.otherNameUTF8String(of: certificate, oid: Self.jpkiHolderAddressOID)
        self.subjectDistinguishedName = String(describing: certificate.subject)
        self.issuerDistinguishedName = String(describing: certificate.issuer)
        self.serialNumberHex = certificate.serialNumber.bytes.map { String(format: "%02X", $0) }.joined()
        self.sha256FingerprintHex = SHA256.hash(data: Data(certificateDER)).map { String(format: "%02X", $0) }.joined()
        self.notValidBefore = certificate.notValidBefore
        self.notValidAfter = certificate.notValidAfter
    }

    public func isValid(at date: Date) -> Bool {
        (notValidBefore...notValidAfter).contains(date)
    }

    /// JPKI 署名用電子証明書は保有者情報を subjectAltName の otherName に
    /// UTF8String で格納する（.1=氏名, .5=住所）。
    static let jpkiHolderNameOID: ASN1ObjectIdentifier = [1, 2, 392, 200_149, 8, 5, 5, 1]
    static let jpkiHolderAddressOID: ASN1ObjectIdentifier = [1, 2, 392, 200_149, 8, 5, 5, 5]

    private static func otherNameUTF8String(of certificate: Certificate, oid: ASN1ObjectIdentifier) -> String? {
        guard let names = subjectAlternativeNames(of: certificate) else {
            return nil
        }
        for name in names {
            if case .otherName(let otherName) = name, otherName.typeID == oid,
               let value = otherName.value,
               let text = utf8String(fromOtherNameValue: value) {
                return text
            }
        }
        return nil
    }

    private static func directoryCommonName(of certificate: Certificate) -> String? {
        guard let names = subjectAlternativeNames(of: certificate) else {
            return nil
        }
        for name in names {
            if case .directoryName(let directoryName) = name,
               let commonName = directoryName.firstCommonName {
                return commonName
            }
        }
        return nil
    }

    private static func subjectAlternativeNames(of certificate: Certificate) -> SubjectAlternativeNames? {
        guard let extensionValue = certificate.extensions[oid: .X509ExtensionID.subjectAlternativeName] else {
            return nil
        }
        return try? SubjectAlternativeNames(extensionValue)
    }

    /// otherName.value is `[0] EXPLICIT ANY`; unwrap to the inner UTF8String.
    private static func utf8String(fromOtherNameValue value: ASN1Any) -> String? {
        var serializer = DER.Serializer()
        guard (try? serializer.serialize(value)) != nil else {
            return nil
        }
        var bytes = serializer.serializedBytes
        // Unwrap one level of explicit tagging if present.
        if let first = bytes.first, first & 0x20 != 0, first != 0x30, first != 0x31,
           let inner = try? derContent(of: bytes) {
            bytes = inner
        }
        guard bytes.first == 0x0C, let content = try? derContent(of: bytes) else {
            return nil
        }
        return String(decoding: content, as: UTF8.self)
    }

    /// Content octets of a single definite-length DER TLV.
    private static func derContent(of bytes: [UInt8]) throws -> [UInt8] {
        guard bytes.count >= 2 else { throw CertificateSummaryError.invalidDER }
        let first = bytes[1]
        if first < 0x80 {
            let end = 2 + Int(first)
            guard end <= bytes.count else { throw CertificateSummaryError.invalidDER }
            return Array(bytes[2..<end])
        }
        let count = Int(first & 0x7F)
        guard count >= 1, count <= 4, bytes.count >= 2 + count else { throw CertificateSummaryError.invalidDER }
        var length = 0
        for byte in bytes[2..<(2 + count)] {
            length = length << 8 | Int(byte)
        }
        let end = 2 + count + length
        guard end <= bytes.count else { throw CertificateSummaryError.invalidDER }
        return Array(bytes[(2 + count)..<end])
    }
}

enum CertificateSummaryError: Error {
    case invalidDER
}

private extension DistinguishedName {
    var firstCommonName: String? {
        for relativeName in self {
            for attribute in relativeName where attribute.type == .RDNAttributeType.commonName {
                return attribute.value.description
            }
        }
        return nil
    }
}
