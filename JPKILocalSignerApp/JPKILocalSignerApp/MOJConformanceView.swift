//
//  MOJConformanceView.swift
//  JPKILocalSignerApp
//
//  登記適合チェック sheet: runs `MOJConformanceChecker.check` (offline,
//  synchronous) and shows whether the PDF matches the 法務省 registration
//  filing format (adbe.pkcs7.detached etc.). This is deliberately a
//  DIFFERENT question from signature validity: a cloud-signed PDF can be a
//  perfectly valid signature (検証 tab) yet non-conformant here, and both
//  facts are shown without contradiction.

import JPKILocalSigner
import SwiftUI

struct MOJConformanceView: View {
    private let result: MOJConformanceResult

    @Environment(\.dismiss) private var dismiss
    @State private var isItemListExpanded = false

    init(pdf: Data) {
        self.result = MOJConformanceChecker.check(pdf: pdf)
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    if result.isConformant {
                        Label("登記オンライン申請に提出可能な形式です", systemImage: "checkmark.seal.fill")
                            .font(.headline)
                            .foregroundStyle(.green)
                            .accessibilityAddTraits(.isHeader)
                    } else {
                        Label("登記オンライン申請には提出できない形式です", systemImage: "xmark.seal.fill")
                            .font(.headline)
                            .foregroundStyle(.red)
                            .accessibilityAddTraits(.isHeader)
                    }

                    LabeledContent("検査した署名数") {
                        Text("\(result.signatureCount)件")
                    }
                }

                Section {
                    DisclosureGroup(isExpanded: $isItemListExpanded) {
                        ForEach(Array(result.items.enumerated()), id: \.offset) { _, item in
                            MOJConformanceItemRow(item: item)
                        }
                    } label: {
                        Text("チェック項目 (\(result.items.count)件)")
                    }
                    .accessibilityHint("各チェック項目の判定結果を表示します")
                } footer: {
                    Text("この判定は法務省の形式要件（adbe.pkcs7.detached 等）への適合であり、署名の有効性とは独立です。クラウド署名等は署名として有効でも登記形式には適合しません。")
                }
            }
            .navigationTitle("登記適合チェック")
            .inlineNavigationBarTitle()
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("閉じる") {
                        dismiss()
                    }
                }
            }
        }
        .macOSSheetFrame()
    }
}

private struct MOJConformanceItemRow: View {
    let item: MOJConformanceItem

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Text(item.checkID)
                    .font(.subheadline.monospaced())
                    .fontWeight(.semibold)
                MOJConformanceStatusChip(status: item.status)
            }
            Text(item.detail)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(Text(verbatim: "\(item.checkID): \(statusReading), \(item.detail)"))
    }

    private var statusReading: String {
        switch item.status {
        case .pass: return String(localized: "適合")
        case .fail: return String(localized: "不適合")
        case .warn: return String(localized: "警告")
        }
    }
}

private struct MOJConformanceStatusChip: View {
    let status: MOJConformanceStatus

    var body: some View {
        Text(status.rawValue)
            .font(.caption2.weight(.bold))
            .padding(.horizontal, 8)
            .padding(.vertical, 2)
            .background(color.opacity(0.15), in: Capsule())
            .foregroundStyle(color)
    }

    private var color: Color {
        switch status {
        case .pass: return .green
        case .fail: return .red
        case .warn: return .orange
        }
    }
}

#Preview {
    MOJConformanceView(pdf: Data())
}
