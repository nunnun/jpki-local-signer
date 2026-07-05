import Foundation

/// Minimal DER builders for constructing test fixtures that the production
/// builder intentionally cannot produce (e.g. Acrobat-style direct
/// signatures without authenticated attributes).
enum TestDER {
    static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        if content.count < 0x80 {
            return [tag, UInt8(content.count)] + content
        }
        var lengthBytes: [UInt8] = []
        var remaining = content.count
        while remaining > 0 {
            lengthBytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        }
        return [tag, 0x80 | UInt8(lengthBytes.count)] + lengthBytes + content
    }

    static func oid(_ dotted: String) -> [UInt8] {
        let parts = dotted.split(separator: ".").map { UInt($0)! }
        var body: [UInt8] = []
        func appendBase128(_ value: UInt) {
            var encoded = [UInt8(value & 0x7F)]
            var remaining = value >> 7
            while remaining > 0 {
                encoded.insert(UInt8(remaining & 0x7F) | 0x80, at: 0)
                remaining >>= 7
            }
            body.append(contentsOf: encoded)
        }
        appendBase128(parts[0] * 40 + parts[1])
        for part in parts.dropFirst(2) {
            appendBase128(part)
        }
        return tlv(0x06, body)
    }

    /// Reads one TLV, returning (contentStart, contentEnd, nextOffset).
    /// Definite lengths only — test certificates are always DER.
    static func readTLV(_ bytes: [UInt8], at offset: Int) -> (contentStart: Int, contentEnd: Int, next: Int) {
        let first = bytes[offset + 1]
        if first < 0x80 {
            let start = offset + 2
            return (start, start + Int(first), start + Int(first))
        }
        let count = Int(first & 0x7F)
        var length = 0
        for byte in bytes[(offset + 2)..<(offset + 2 + count)] {
            length = length << 8 | Int(byte)
        }
        let start = offset + 2 + count
        return (start, start + length, start + length)
    }

    /// SignedData without signedAttrs: the signature covers the content
    /// digest directly (Acrobat's adbe.pkcs7.detached profile).
    static func directSignatureCMS(certificateDER: [UInt8], signature: [UInt8]) throws -> [UInt8] {
        // issuer + serial from the certificate.
        let certificate = readTLV(certificateDER, at: 0)
        let tbs = readTLV(certificateDER, at: certificate.contentStart)
        var cursor = tbs.contentStart
        if certificateDER[cursor] == 0xA0 { // [0] version
            cursor = readTLV(certificateDER, at: cursor).next
        }
        let serialEnd = readTLV(certificateDER, at: cursor).next
        let serialDER = Array(certificateDER[cursor..<serialEnd])
        let sigAlgEnd = readTLV(certificateDER, at: serialEnd).next
        let issuerEnd = readTLV(certificateDER, at: sigAlgEnd).next
        let issuerDER = Array(certificateDER[sigAlgEnd..<issuerEnd])

        let algoSHA256 = tlv(0x30, oid("2.16.840.1.101.3.4.2.1") + [0x05, 0x00])
        let algoRSA = tlv(0x30, oid("1.2.840.113549.1.1.1") + [0x05, 0x00])
        let signerInfo = tlv(0x30,
            tlv(0x02, [0x01])
            + tlv(0x30, issuerDER + serialDER)
            + algoSHA256
            + algoRSA
            + tlv(0x04, signature)
        )
        let signedData = tlv(0x30,
            tlv(0x02, [0x01])
            + tlv(0x31, algoSHA256)
            + tlv(0x30, oid("1.2.840.113549.1.7.1"))
            + tlv(0xA0, certificateDER)
            + tlv(0x31, signerInfo)
        )
        return tlv(0x30, oid("1.2.840.113549.1.7.2") + tlv(0xA0, signedData))
    }
}
