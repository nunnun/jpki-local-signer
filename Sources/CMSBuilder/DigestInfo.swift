import Crypto
import Foundation

public enum DigestInfo {
    private static let sha256AlgorithmIdentifierPrefix: [UInt8] = [
        0x30, 0x31,
        0x30, 0x0D,
        0x06, 0x09,
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00,
        0x04, 0x20
    ]

    public static func sha256DigestInfo(for bytes: some DataProtocol) -> [UInt8] {
        let digest = SHA256.hash(data: bytes)
        return sha256AlgorithmIdentifierPrefix + Array(digest)
    }

    public static func sha256DigestInfo(digest: [UInt8]) throws -> [UInt8] {
        guard digest.count == SHA256.byteCount else {
            throw DigestInfoError.invalidSHA256DigestLength(digest.count)
        }
        return sha256AlgorithmIdentifierPrefix + digest
    }
}

public enum DigestInfoError: Error, Equatable, Sendable {
    case invalidSHA256DigestLength(Int)
}
