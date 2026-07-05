#if DEBUG

import Crypto
import Foundation
import SwiftASN1
import X509
import _CryptoExtras

/// DEBUG-only signing path for the simulator / devices without a card:
/// generates an ephemeral RSA-2048 key and a matching self-signed
/// certificate, then runs the full production pipeline including complete
/// self-verification. Unlike a fake fixed-bytes signature, the output is
/// cryptographically valid, so the in-app verifier shows meaningful results.
///
/// Never compiled into Release builds.
public enum DevelopmentPDFSigner {
    public struct Output: Sendable {
        public let signingResult: LocalPDFSigningResult
        public let certificateDER: [UInt8]
    }

    public static func sign(
        pdf: Data,
        signerName: String,
        signingDate: Date = Date()
    ) async throws -> Output {
        let key = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let certificateDER = try selfSignedCertificateDER(for: key, commonName: signerName)
        let input = LocalPDFSigningInput(
            pdf: pdf,
            certificateDER: certificateDER,
            signerName: signerName,
            signingDate: signingDate
        )

        // Two-pass signing: preparation is deterministic for a fixed date,
        // so a probe pass discovers the signedAttrs the real signature must
        // cover (mirroring how the card signs a DigestInfo).
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
        return Output(signingResult: result, certificateDER: certificateDER)
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
            notValidBefore: Date().addingTimeInterval(-3600),
            notValidAfter: Date().addingTimeInterval(365 * 24 * 3600),
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
}

#endif
