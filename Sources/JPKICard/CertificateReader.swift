import Foundation
import NFCTransport

/// Reads a DER-encoded certificate from the currently selected EF using
/// chunked READ BINARY. The total length is taken from the outer SEQUENCE
/// header so only the certificate bytes are transferred (NFR-05: keep the
/// NFC session short).
public struct CertificateReader: Sendable {
    public static let maximumCertificateLength = 0x8000

    public let transport: ISO7816Transport

    public init(transport: ISO7816Transport) {
        self.transport = transport
    }

    public func readCertificate() async throws -> [UInt8] {
        let header = try await read(offset: 0, length: 4)
        let totalLength = try Self.derSequenceTotalLength(header: header)
        guard totalLength <= Self.maximumCertificateLength else {
            throw CertificateReaderError.certificateTooLarge(totalLength)
        }

        var bytes = header
        while bytes.count < totalLength {
            let chunkLength = min(256, totalLength - bytes.count)
            let chunk = try await read(offset: bytes.count, length: chunkLength)
            guard !chunk.isEmpty else {
                throw CertificateReaderError.truncatedRead(expected: totalLength, actual: bytes.count)
            }
            bytes.append(contentsOf: chunk)
        }

        return Array(bytes.prefix(totalLength))
    }

    private func read(offset: Int, length: Int) async throws -> [UInt8] {
        let response = try await transport.transmit(.readBinary(offset: offset, expectedLength: length))
        guard response.isSuccess else {
            throw NFCSessionError.cardCommunicationFailed(status: response.status)
        }
        return response.data
    }

    /// Total encoded length (header + content) of a DER SEQUENCE starting at
    /// `header[0]`. Requires at least the tag byte and length bytes.
    static func derSequenceTotalLength(header: [UInt8]) throws -> Int {
        guard header.count >= 2, header[0] == 0x30 else {
            throw CertificateReaderError.invalidDERHeader
        }

        let first = header[1]
        if first < 0x80 {
            return 2 + Int(first)
        }

        let lengthByteCount = Int(first & 0x7F)
        guard (1...2).contains(lengthByteCount), header.count >= 2 + lengthByteCount else {
            throw CertificateReaderError.invalidDERHeader
        }

        var contentLength = 0
        for byte in header[2..<(2 + lengthByteCount)] {
            contentLength = contentLength << 8 | Int(byte)
        }
        return 2 + lengthByteCount + contentLength
    }
}

public enum CertificateReaderError: Error, Equatable, Sendable {
    case invalidDERHeader
    case certificateTooLarge(Int)
    case truncatedRead(expected: Int, actual: Int)
}
