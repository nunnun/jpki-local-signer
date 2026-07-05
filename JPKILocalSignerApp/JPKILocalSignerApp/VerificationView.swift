//
//  VerificationView.swift
//  JPKILocalSignerApp
//
//  The 検証 tab (design.md FR-11): pick a signed PDF and show the offline
//  self-verification result for each embedded signature, alongside a PDFKit
//  preview of the document itself.

import SwiftUI
import UniformTypeIdentifiers

struct VerificationView: View {
    /// Owned by ContentView so PDFs handed over from other apps
    /// (onOpenURL) can be routed into this tab.
    var model: VerificationFlowModel

    /// The single app-wide file importer lives on ContentView (two
    /// `.fileImporter` modifiers alive at once break presentation on macOS),
    /// so this view only toggles it.
    @Binding var isImporterPresented: Bool

    /// In regular widths (iPad two-pane layout / macOS) the persistent
    /// left pane already shows the PDF, so the inline preview above the
    /// list is omitted.
    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    private var isRegularWidth: Bool { horizontalSizeClass == .regular }
    #else
    private var isRegularWidth: Bool { true }
    #endif

    @State private var isConformancePresented = false

    var body: some View {
        Group {
            if let pdfData = model.pdfData, let inspection = model.inspection {
                VStack(spacing: 0) {
                    if !isRegularWidth {
                        PDFPreviewView(data: pdfData)
                            .frame(minHeight: 220)
                            .accessibilityLabel("PDFプレビュー: \(model.fileName)")

                        Divider()
                    }

                    VerificationResultListView(inspection: inspection)
                }
                .safeAreaInset(edge: .bottom) {
                    VStack(spacing: 8) {
                        Button {
                            isConformancePresented = true
                        } label: {
                            Label("登記適合チェック", systemImage: "checklist")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .accessibilityHint("このPDFが登記オンライン申請の形式要件に適合するかを確認します。署名の有効性の判定とは独立です")

                        Button {
                            model.clearSelection()
                        } label: {
                            Label("別のPDFを選び直す", systemImage: "arrow.uturn.backward")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                    }
                    .padding()
                    .background(.bar)
                }
                .sheet(isPresented: $isConformancePresented) {
                    MOJConformanceView(pdf: pdfData)
                }
            } else {
                VerificationImportPromptView(
                    isImporterPresented: $isImporterPresented,
                    errorMessage: model.errorMessage
                )
            }
        }
    }
}

private struct VerificationImportPromptView: View {
    @Binding var isImporterPresented: Bool
    let errorMessage: String?

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "checkmark.seal")
                .font(.system(size: 64))
                .foregroundStyle(.tint)
                .accessibilityHidden(true)

            VStack(spacing: 8) {
                Text("検証するPDFを選択してください")
                    .font(.title3)
                    .fontWeight(.semibold)
                    .accessibilityAddTraits(.isHeader)
                Text("PDFに埋め込まれた電子署名の値と、署名以降の改ざんの有無を端末内だけで確認します。")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }

            Button {
                isImporterPresented = true
            } label: {
                Label("PDFを選択", systemImage: "folder")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .padding(.horizontal, 40)
            .accessibilityHint("ファイルを開いて検証するPDFを選択します")

            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }

            Spacer()
            Spacer()
        }
        .padding()
    }
}

#Preview {
    VerificationView(model: VerificationFlowModel(), isImporterPresented: .constant(false))
}
