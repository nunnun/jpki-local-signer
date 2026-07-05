//
//  SigningResultView.swift
//  JPKILocalSignerApp
//
//  Result screen (design.md FR-10): shows certificate holder name and
//  validity, and lets the user export/share the signed PDF. The original
//  PDF is left untouched; this view only ever deals with the signed copy.

import JPKILocalSigner
import SwiftUI
import UniformTypeIdentifiers

struct SigningResultView: View {
    let signedPDF: Data
    let signerName: String
    /// Human-readable holder name: JPKI subjectAltName 氏名 with CN fallback
    /// (`SignerCertificateSummary.displayName`). The subject CN itself is an
    /// opaque serial-like identifier on JPKI cards.
    let displayName: String?
    let notValidBefore: Date?
    let notValidAfter: Date?
    let suggestedFileName: String
    let onDone: () -> Void
    /// 「続けて次の人が署名」: restart the signing flow with the signed copy
    /// as the new source (co-signing).
    let onCoSign: () -> Void

    /// Which modal sheet is showing. A single `.sheet(item:)` drives both,
    /// because two `.sheet(isPresented:)` modifiers on one view break
    /// presentation on macOS (only one ever presents).
    private enum ResultSheet: Identifiable {
        case verification
        case conformance
        var id: Int { hashValue }
    }

    @State private var isExporterPresented = false
    @State private var exportDocument: PDFExportDocument
    @State private var exportStatusMessage: String?
    @State private var shareFileURL: URL?
    @State private var activeSheet: ResultSheet?

    init(
        signedPDF: Data,
        signerName: String,
        displayName: String?,
        notValidBefore: Date?,
        notValidAfter: Date?,
        suggestedFileName: String,
        onDone: @escaping () -> Void,
        onCoSign: @escaping () -> Void
    ) {
        self.signedPDF = signedPDF
        self.signerName = signerName
        self.displayName = displayName
        self.notValidBefore = notValidBefore
        self.notValidAfter = notValidAfter
        self.suggestedFileName = suggestedFileName
        self.onDone = onDone
        self.onCoSign = onCoSign
        _exportDocument = State(initialValue: PDFExportDocument(data: signedPDF))
    }

    var body: some View {
        List {
            Section {
                Label("署名が完了しました", systemImage: "checkmark.seal.fill")
                    .font(.headline)
                    .foregroundStyle(.green)
                    .accessibilityAddTraits(.isHeader)
            }

            Section("署名者証明書") {
                LabeledContent("氏名") {
                    Text(displayName ?? signerName)
                }
                if let notValidBefore, let notValidAfter {
                    LabeledContent("有効期間") {
                        Text("\(Self.dateFormatter.string(from: notValidBefore)) 〜 \(Self.dateFormatter.string(from: notValidAfter))")
                    }
                }
            }

            Section("出力") {
                Button {
                    isExporterPresented = true
                } label: {
                    Label("PDFを保存", systemImage: "square.and.arrow.down")
                }
                .accessibilityHint("署名済みPDFをFilesに保存します")

                if let shareFileURL {
                    ShareLink(
                        item: shareFileURL,
                        preview: SharePreview(suggestedFileName, image: Image(systemName: "doc.richtext"))
                    ) {
                        Label("PDFを共有", systemImage: "square.and.arrow.up")
                    }
                    .accessibilityHint("署名済みPDFを他のアプリと共有します")
                }

                if let exportStatusMessage {
                    Text(exportStatusMessage)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Text("元のPDFは変更されていません。書き出されるのは新しく作成された署名済みのコピーです。")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            Section {
                Button {
                    activeSheet = .verification
                } label: {
                    Label("署名を検証する", systemImage: "checkmark.seal")
                }
                .accessibilityHint("署名済みPDFの署名値と改ざんの有無をその場で確認します")

                Button {
                    onCoSign()
                } label: {
                    Label("続けて次の人が署名", systemImage: "person.2")
                }
                .accessibilityHint("署名済みPDFを読み込み直して、次の署名者の署名を追加します。既存の署名は保持されます")

                Button {
                    activeSheet = .conformance
                } label: {
                    Label("登記適合チェック", systemImage: "checklist")
                }
                .accessibilityHint("署名済みPDFが登記オンライン申請の形式要件に適合するかを確認します")
            }

            Section {
                Button("最初からやり直す", role: .none) {
                    onDone()
                }
            }
        }
        .navigationTitle("署名結果")
        .inlineNavigationBarTitle()
        .fileExporter(
            isPresented: $isExporterPresented,
            document: exportDocument,
            contentType: .pdf,
            defaultFilename: suggestedFileName,
            onCompletion: handleExport
        )
        .sheet(item: $activeSheet) { sheet in
            switch sheet {
            case .conformance:
                MOJConformanceView(pdf: signedPDF)
            case .verification:
                NavigationStack {
                    VerificationResultListView(inspection: SignedPDFVerifier.inspect(pdf: signedPDF))
                        .navigationTitle("検証結果")
                        .inlineNavigationBarTitle()
                        .toolbar {
                            ToolbarItem(placement: .confirmationAction) {
                                Button("閉じる") {
                                    activeSheet = nil
                                }
                            }
                        }
                }
                .macOSSheetFrame()
            }
        }
        .task {
            shareFileURL = Self.writeTemporaryFileForSharing(signedPDF, suggestedFileName: suggestedFileName)
        }
        .onDisappear {
            if let shareFileURL {
                try? FileManager.default.removeItem(at: shareFileURL)
            }
        }
    }

    private func handleExport(_ result: Result<URL, Error>) {
        switch result {
        case .success:
            exportStatusMessage = String(localized: "PDFを保存しました。")
        case .failure(let error):
            exportStatusMessage = String(localized: "PDFの保存に失敗しました: \(error.localizedDescription)")
        }
    }

    /// Writes the signed PDF into a private temporary directory so ShareLink
    /// can hand the OS share sheet a real file URL. This is a throwaway
    /// scratch copy for the share sheet only — it is removed when the
    /// result screen disappears and is never treated as the canonical
    /// output (the user's saved export via `.fileExporter` is canonical).
    private static func writeTemporaryFileForSharing(_ data: Data, suggestedFileName: String) -> URL? {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("jpki-local-signer-share", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let url = directory.appendingPathComponent(suggestedFileName)
            try data.write(to: url, options: .atomic)
            return url
        } catch {
            return nil
        }
    }

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .none
        formatter.locale = Locale.autoupdatingCurrent
        return formatter
    }()
}

#Preview {
    NavigationStack {
        SigningResultView(
            signedPDF: Data(),
            signerName: "山田 太郎",
            displayName: "山田 太郎",
            notValidBefore: Date(),
            notValidAfter: Date().addingTimeInterval(60 * 60 * 24 * 365 * 5),
            suggestedFileName: "sample_signed.pdf",
            onDone: {},
            onCoSign: {}
        )
    }
}
