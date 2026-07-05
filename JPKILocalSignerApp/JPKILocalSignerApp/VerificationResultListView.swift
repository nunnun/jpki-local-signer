//
//  VerificationResultListView.swift
//  JPKILocalSignerApp
//
//  Renders the whole-document inspection produced by
//  `SignedPDFVerifier.inspect` (design.md FR-11): a banner when the file was
//  modified after its newest signature, one card per signature (validity AND
//  issuer trust are separate facts, both always shown), plus the fixed
//  disclaimer that revocation status (CRL/OCSP) is never checked. Tapping a
//  valid card opens the certificate/technical detail sheet. This view is
//  shared by the standalone 検証 tab and by the post-signing
//  "署名を検証する" sheet.

import JPKILocalSigner
import SwiftUI

struct VerificationResultListView: View {
    let inspection: PDFSignatureInspection

    @State private var selectedDetail: SignatureDetailSelection?

    private var verdicts: [PDFSignatureVerdict] { inspection.verdicts }

    var body: some View {
        List {
            if inspection.hasUnsignedTrailingData {
                Section {
                    Label(
                        "最後の署名の後に文書が変更されています（署名は各署名時点の内容を保証します）",
                        systemImage: "pencil.line"
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel("最後の署名の後に文書が変更されています。署名は各署名時点の内容を保証します。")
                }
            }

            Section {
                ForEach(Array(verdicts.enumerated()), id: \.offset) { index, verdict in
                    if let report = verdict.report {
                        Button {
                            selectedDetail = SignatureDetailSelection(
                                signatureNumber: index + 1,
                                report: report
                            )
                        } label: {
                            HStack(alignment: .center, spacing: 8) {
                                VerificationVerdictCard(
                                    index: index,
                                    total: verdicts.count,
                                    verdict: verdict
                                )
                                Spacer(minLength: 0)
                                Image(systemName: "chevron.right")
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(.tertiary)
                                    .accessibilityHidden(true)
                            }
                        }
                        .buttonStyle(.plain)
                        .accessibilityHint("証明書と署名の技術情報を表示します")
                    } else {
                        VerificationVerdictCard(
                            index: index,
                            total: verdicts.count,
                            verdict: verdict
                        )
                    }
                }
            } header: {
                Text("署名 (\(verdicts.count)件)")
            } footer: {
                if verdicts.contains(where: { $0.report != nil }) {
                    Text("署名をタップすると証明書の詳細を表示します。")
                }
            }

            Section {
                Label(
                    "証明書の失効確認（CRL/OCSP）は行っていません。正式な有効性は提出先システムの検証に依ります。",
                    systemImage: "info.circle"
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
            }
        }
        .sheet(item: $selectedDetail) { detail in
            SignatureDetailView(
                signatureNumber: detail.signatureNumber,
                report: detail.report
            )
        }
    }
}

/// Sheet-selection payload: which signature (1-based) was tapped.
private struct SignatureDetailSelection: Identifiable {
    let signatureNumber: Int
    let report: SignedPDFVerificationReport

    var id: Int { signatureNumber }
}

private struct VerificationVerdictCard: View {
    let index: Int
    let total: Int
    let verdict: PDFSignatureVerdict

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("署名 \(index + 1) / \(total)")
                .font(.subheadline)
                .fontWeight(.semibold)
                .foregroundStyle(.secondary)

            switch verdict {
            case .valid(let report):
                ValidVerdictContent(report: report)
            case .invalid(let reason):
                InvalidVerdictContent(reason: reason)
            }
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
    }
}

private struct ValidVerdictContent: View {
    let report: SignedPDFVerificationReport

    private var certificateSummary: SignerCertificateSummary? {
        try? SignerCertificateSummary(certificateDER: report.cms.certificateDER)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if report.kind == .documentTimestamp {
                Label("文書タイムスタンプ", systemImage: "clock.badge.checkmark")
                    .font(.subheadline)
                    .fontWeight(.semibold)
                if let timestampDate = report.timestampDate {
                    Text("タイムスタンプ時刻: \(Self.timestampFormatter.string(from: timestampDate)) (JST)")
                        .fontWeight(.medium)
                }
            } else {
                LabeledContent("署名者") {
                    Text(certificateSummary?.displayName ?? String(localized: "不明"))
                }
            }

            if let certificateSummary {
                LabeledContent("証明書有効期間") {
                    Text("\(Self.dateFormatter.string(from: certificateSummary.notValidBefore)) 〜 \(Self.dateFormatter.string(from: certificateSummary.notValidAfter))")
                }
            }

            Label("署名値: 有効", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green)
            Label("文書の完全性: 改ざんなし", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green)

            TrustClassificationLine(trust: report.trust)

            if !report.coversWholeFile {
                Label(
                    "この署名は署名時点の版までを保証します（後から追加署名あり）",
                    systemImage: "clock.arrow.circlepath"
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
            }

            if report.cms.isDirectSignature {
                Label("直接署名方式 (signedAttrs なし)", systemImage: "info.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Text("詳細を表示")
                .font(.caption)
                .foregroundStyle(.tint)
        }
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

/// One line stating who issued the signer's certificate — deliberately
/// separate from the validity checkmarks above it: a cryptographically
/// valid signature can still come from a self-signed test certificate.
struct TrustClassificationLine: View {
    let trust: CertificateTrustClassification

    var body: some View {
        let presentation = TrustClassificationPresenter.presentation(for: trust)
        VStack(alignment: .leading, spacing: 2) {
            Label(presentation.title, systemImage: presentation.systemImage)
                .foregroundStyle(presentation.color)
            if let caption = presentation.caption {
                Text(caption)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

private struct InvalidVerdictContent: View {
    let reason: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("この署名は検証できませんでした", systemImage: "xmark.seal.fill")
                .foregroundStyle(.red)
            Text(reason)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

#Preview {
    // PDFSignatureInspection has no public initializer, so drive the
    // preview through the real API with empty data (yields one .invalid).
    VerificationResultListView(inspection: SignedPDFVerifier.inspect(pdf: Data()))
}
