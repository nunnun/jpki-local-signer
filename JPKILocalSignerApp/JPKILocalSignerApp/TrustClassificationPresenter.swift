//
//  TrustClassificationPresenter.swift
//  JPKILocalSignerApp
//
//  Maps `CertificateTrustClassification` to the Japanese UI wording and
//  styling used on verification cards and in the detail sheet. Signature
//  VALIDITY (crypto) and certificate TRUST (who issued it) are separate
//  facts and are always shown side by side: a self-signed test signature is
//  both 「署名値: 有効」 and 「自己署名（テスト用）」 at the same time.

import JPKILocalSigner
import SwiftUI

struct TrustClassificationPresentation {
    let title: String
    /// Secondary caption shown under the title (nil when the title says it all).
    let caption: String?
    let systemImage: String
    let color: Color
}

enum TrustClassificationPresenter {
    static func presentation(for trust: CertificateTrustClassification) -> TrustClassificationPresentation {
        switch trust {
        case .selfSigned:
            return TrustClassificationPresentation(
                title: String(localized: "自己署名証明書（テスト用） — 公的な署名ではありません"),
                caption: nil,
                systemImage: "exclamationmark.triangle.fill",
                color: .orange
            )
        case .jpki:
            return TrustClassificationPresentation(
                title: String(localized: "公的個人認証サービス（JPKI）の証明書"),
                caption: nil,
                systemImage: "checkmark.shield.fill",
                color: .green
            )
        case .otherAuthority(let issuer):
            return TrustClassificationPresentation(
                title: String(localized: "他の認証局: \(shortIssuerName(from: issuer))"),
                caption: String(localized: "JPKI（マイナンバーカード）の署名ではありません"),
                systemImage: "building.columns",
                color: .blue
            )
        case .unverifiable(let reason):
            return TrustClassificationPresentation(
                title: String(localized: "発行元を確認できません"),
                caption: reason,
                systemImage: "questionmark.diamond.fill",
                color: .gray
            )
        }
    }

    /// Short, human-readable name from an RFC 4514 style DN: prefers the
    /// CN= value, then O=, falling back to the whole string.
    static func shortIssuerName(from distinguishedName: String) -> String {
        for prefix in ["CN=", "O="] {
            for component in distinguishedName.split(separator: ",") {
                let trimmed = component.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix(prefix) {
                    let value = String(trimmed.dropFirst(prefix.count))
                    if !value.isEmpty {
                        return value
                    }
                }
            }
        }
        return distinguishedName
    }
}
