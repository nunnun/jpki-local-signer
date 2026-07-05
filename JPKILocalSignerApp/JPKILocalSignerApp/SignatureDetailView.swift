//
//  SignatureDetailView.swift
//  JPKILocalSignerApp
//
//  Per-signature drill-down sheet (署名の詳細) opened from a valid
//  verification card: full certificate fields from
//  `SignerCertificateSummary` plus the structural facts of the signature
//  (direct-signature flag, coverage, ByteRange). Everything is derived
//  offline from the already-parsed report; no networking, no revocation
//  checks (the fixed disclaimer is repeated at the bottom).

import JPKILocalSigner
import SwiftUI

struct SignatureDetailView: View {
    /// 1-based position of this signature in the document, for the title.
    let signatureNumber: Int
    let report: SignedPDFVerificationReport

    @Environment(\.dismiss) private var dismiss

    private var certificateSummary: SignerCertificateSummary? {
        try? SignerCertificateSummary(certificateDER: report.cms.certificateDER)
    }

    var body: some View {
        NavigationStack {
            List {
                if let summary = certificateSummary {
                    certificateSection(summary)
                } else {
                    Section("証明書") {
                        Label("証明書の内容を解釈できませんでした", systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.orange)
                    }
                }

                technicalSection

                Section {
                    Label(
                        "証明書の失効確認（CRL/OCSP）は行っていません。正式な有効性は提出先システムの検証に依ります。",
                        systemImage: "info.circle"
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                    Text("JPKI の判定はアプリ同梱の JPKI ルート証明書（署名用CA 01〜03）との照合によります。その他の認証局はPDF内の証明書チェーンの検証のみで、失効確認（CRL/OCSP）はいずれも行っていません。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("署名 \(signatureNumber) の詳細")
            .inlineNavigationBarTitle()
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("閉じる") {
                        dismiss()
                    }
                }
            }
        }
        .macOSSheetFrame(minHeight: 620)
    }

    // MARK: - 証明書

    @ViewBuilder
    private func certificateSection(_ summary: SignerCertificateSummary) -> some View {
        Section("証明書") {
            TrustClassificationLine(trust: report.trust)

            detailRow(String(localized: "氏名"), summary.displayName ?? String(localized: "不明"))

            if let holderAddress = summary.holderAddress {
                detailRow(String(localized: "住所"), holderAddress)
            }

            if let commonName = summary.commonName {
                detailRow(String(localized: "証明書CN"), commonName, monospaced: true)
            }

            detailRow("Subject DN", summary.subjectDistinguishedName, monospaced: true)
            detailRow(String(localized: "発行者"), summary.issuerDistinguishedName)
            detailRow(String(localized: "シリアル番号"), summary.serialNumberHex, monospaced: true)
            detailRow(
                String(localized: "SHA-256 フィンガープリント"),
                Self.groupedHex(summary.sha256FingerprintHex),
                monospaced: true
            )
            detailRow(
                String(localized: "有効期間"),
                String(localized: "\(Self.dateFormatter.string(from: summary.notValidBefore)) 〜 \(Self.dateFormatter.string(from: summary.notValidAfter))")
            )
        }
    }

    // MARK: - 技術情報

    private var technicalSection: some View {
        Section("技術情報") {
            detailRow(
                String(localized: "種別"),
                report.kind == .documentTimestamp
                    ? String(localized: "文書タイムスタンプ (RFC 3161)")
                    : String(localized: "電子署名")
            )
            if report.kind == .documentTimestamp, let timestampDate = report.timestampDate {
                detailRow(
                    String(localized: "タイムスタンプ時刻"),
                    "\(Self.timestampFormatter.string(from: timestampDate)) (JST)"
                )
            }
            detailRow(
                String(localized: "署名方式"),
                report.cms.isDirectSignature
                    ? String(localized: "直接署名方式 (signedAttrs なし)")
                    : String(localized: "署名属性方式 (signedAttrs あり)")
            )
            detailRow(
                String(localized: "被覆範囲"),
                report.coversWholeFile
                    ? String(localized: "ファイル全体（最新の署名）")
                    : String(localized: "署名時点の版まで（後から追加署名あり）")
            )
            VStack(alignment: .leading, spacing: 4) {
                Text("ByteRange")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(report.structure.byteRange.values.map(String.init).joined(separator: " "))
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
            }
            .accessibilityElement(children: .combine)
        }
    }

    // MARK: - Helpers

    /// Label-over-value row so long values (DNs, hex) can wrap freely.
    private func detailRow(_ label: String, _ value: String, monospaced: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(monospaced ? .callout.monospaced() : .callout)
                .textSelection(.enabled)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(Text(verbatim: "\(label): \(value)"))
    }

    /// "AB12CD34…" → "AB12 CD34 …" so the fingerprint wraps in readable
    /// groups instead of one unbreakable run.
    private static func groupedHex(_ hex: String, groupSize: Int = 4) -> String {
        var groups: [String] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let end = hex.index(index, offsetBy: groupSize, limitedBy: hex.endIndex) ?? hex.endIndex
            groups.append(String(hex[index..<end]))
            index = end
        }
        return groups.joined(separator: " ")
    }

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        formatter.locale = Locale.autoupdatingCurrent
        formatter.timeZone = TimeZone(identifier: "Asia/Tokyo")
        return formatter
    }()

    /// TSA-asserted existence time (UTC in the token) rendered in JST.
    private static let timestampFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy/MM/dd HH:mm:ss"
        formatter.locale = Locale.autoupdatingCurrent
        formatter.timeZone = TimeZone(identifier: "Asia/Tokyo")
        return formatter
    }()
}
