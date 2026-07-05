import Foundation
import X509

/// Where the signer's certificate chain leads. Built entirely offline: each
/// link is cryptographically verified against the certificates embedded in
/// the CMS plus the bundled JPKI trust anchors (`JPKITrustAnchors`).
/// Revocation is never checked (out of scope by design).
public enum CertificateTrustClassification: Equatable, Sendable {
    /// The signer's certificate signs itself (test/development signatures).
    case selfSigned
    /// The chain verifies and is anchored to a bundled JPKI
    /// (公的個人認証サービス) root certificate.
    case jpki(issuer: String)
    /// The chain verifies within the embedded certificates but belongs to a
    /// different authority (e.g. cloud signing services). No root pinning is
    /// performed for these.
    case otherAuthority(issuer: String)
    /// The chain could not be verified (issuer missing, broken signature,
    /// unsupported certificate) — or claims to be JPKI without chaining to a
    /// bundled JPKI root.
    case unverifiable(reason: String)
}

enum CertificateTrustClassifier {
    static func classify(
        signerCertificateDER: [UInt8],
        allCertificatesDER: [[UInt8]]
    ) -> CertificateTrustClassification {
        guard let signer = try? Certificate(derEncoded: signerCertificateDER) else {
            return .unverifiable(reason: "署名者証明書を解釈できない")
        }

        // Self-signed signer: verify its own signature.
        if signer.issuer == signer.subject {
            guard signer.publicKey.isValidSignature(signer.signature, for: signer) else {
                return .unverifiable(reason: "自己署名の署名値が一致しない")
            }
            return .selfSigned
        }

        // Issuer pool: certificates embedded in the CMS plus the bundled
        // JPKI anchors (so a chain anchors even when the PDF does not embed
        // the root itself, e.g. Acrobat direct signatures).
        let anchors = JPKITrustAnchors.certificates
        let pool = allCertificatesDER.compactMap { try? Certificate(derEncoded: $0) } + anchors

        // Walk up the chain, verifying each link. Several candidates can
        // share the issuer DN (the JPKI root generations are all named
        // identically), so pick the one whose signature actually verifies.
        var chain: [Certificate] = [signer]
        var current = signer
        for _ in 0..<8 {
            let candidates = pool.filter { $0.subject == current.issuer && $0 != current }
            if candidates.isEmpty {
                if current == signer {
                    return .unverifiable(reason: "発行者証明書がPDF内にも同梱アンカーにも見つからない")
                }
                break // verified as far as the available certificates go
            }
            guard let issuerCertificate = candidates.first(where: {
                $0.publicKey.isValidSignature(current.signature, for: current)
            }) else {
                return .unverifiable(reason: "証明書チェーンの署名検証に失敗")
            }
            chain.append(issuerCertificate)
            if issuerCertificate.issuer == issuerCertificate.subject {
                break // reached a self-signed top
            }
            current = issuerCertificate
        }

        let issuerDescription = String(describing: signer.issuer)

        // JPKI: the verified chain must contain a bundled anchor. A chain
        // that merely NAMES JPKI in its DNs without anchoring is treated as
        // unverifiable (possible impersonation), never as JPKI.
        if chain.contains(where: { certificate in anchors.contains(certificate) }) {
            return .jpki(issuer: issuerDescription)
        }
        let chainNames = chain.map { String(describing: $0.subject) } + [issuerDescription]
        if chainNames.contains(where: Self.looksLikeJPKI) {
            return .unverifiable(reason: "JPKI を名乗っていますが、同梱の JPKI ルート証明書に連鎖しません")
        }
        return .otherAuthority(issuer: issuerDescription)
    }

    /// JPKI 署名用CA: O=JPKI, OU=JPKI for digital signature 等。
    static func looksLikeJPKI(_ distinguishedName: String) -> Bool {
        distinguishedName.contains("O=JPKI") || distinguishedName.contains("OU=JPKI")
    }
}
