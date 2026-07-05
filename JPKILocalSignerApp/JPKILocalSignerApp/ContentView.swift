//
//  ContentView.swift
//  JPKILocalSignerApp
//
//  Created by Hirotaka Nakajima on 2026/06/20.
//
//  Primary flow (design.md §3.1 / FR-01..FR-12):
//  PDF読み込み → 内容確認 → 署名用PIN入力 → NFC署名 → 結果表示・書き出し。

import JPKILocalSigner
import SwiftUI
import UniformTypeIdentifiers

/// Top-level app mode: the existing signing flow, or the new offline
/// verification viewer.
enum AppMode: String, CaseIterable, Identifiable {
    case sign
    case verify

    var id: String { rawValue }

    var title: String {
        switch self {
        case .sign: return String(localized: "署名")
        case .verify: return String(localized: "検証")
        }
    }
}

/// PDF handed over from another app (share sheet / Files「…で開く」),
/// already read into memory while the security scope was active.
private struct OpenedPDF: Identifiable {
    let id = UUID()
    let data: Data
    let fileName: String
}

struct ContentView: View {
    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    /// Two-pane layout on regular widths (iPad); always on macOS.
    private var isRegularWidth: Bool { horizontalSizeClass == .regular }
    #else
    private var isRegularWidth: Bool { true }
    #endif
    @State private var mode: AppMode = .sign
    @State private var model = SigningFlowModel()
    @State private var verificationModel = VerificationFlowModel()
    @State private var isImporterPresented = false
    @State private var isAboutPresented = false
    @State private var openedPDF: OpenedPDF?

    var body: some View {
        NavigationStack {
            Group {
                if isRegularWidth {
                    regularWidthLayout
                } else {
                    workingPanel
                }
            }
            .navigationTitle("JPKI Local Signer")
            .inlineNavigationBarTitle()
            .toolbar {
                ToolbarItem(placement: .principal) {
                    Picker("表示モード", selection: $mode) {
                        ForEach(AppMode.allCases) { appMode in
                            Text(appMode.title).tag(appMode)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(maxWidth: 220)
                    .accessibilityLabel("表示モード")
                    .accessibilityHint("署名モードと検証モードを切り替えます")
                }
                ToolbarItem(placement: .platformTrailing) {
                    Button {
                        isAboutPresented = true
                    } label: {
                        Image(systemName: "info.circle")
                    }
                    .accessibilityLabel("このアプリについて")
                }
            }
        }
        .fileImporter(
            isPresented: $isImporterPresented,
            allowedContentTypes: [.pdf],
            allowsMultipleSelection: false,
            onCompletion: importPDF
        )
        .sheet(isPresented: $isAboutPresented) {
            AboutView()
        }
        .onOpenURL { url in
            handleOpenedURL(url)
        }
        .confirmationDialog(
            "このPDFをどうしますか",
            isPresented: Binding(
                get: { openedPDF != nil },
                set: { if !$0 { openedPDF = nil } }
            ),
            titleVisibility: .visible,
            presenting: openedPDF
        ) { opened in
            Button("署名する") {
                model.loadPDF(data: opened.data, fileName: opened.fileName)
                mode = .sign
            }
            .accessibilityHint("このPDFを署名モードで開きます")
            Button("検証する") {
                verificationModel.loadPDF(data: opened.data, fileName: opened.fileName)
                mode = .verify
            }
            .accessibilityHint("このPDFを検証モードで開きます")
            Button("キャンセル", role: .cancel) {}
        } message: { opened in
            Text(opened.fileName)
        }
    }

    /// Handles a PDF opened from another app: reads the bytes while the
    /// security scope is active, then asks whether to sign or verify.
    private func handleOpenedURL(_ url: URL) {
        let didStartAccessing = url.startAccessingSecurityScopedResource()
        defer {
            if didStartAccessing {
                url.stopAccessingSecurityScopedResource()
            }
        }

        guard let data = try? Data(contentsOf: url) else {
            model.loadPDFImportFailed()
            return
        }
        openedPDF = OpenedPDF(data: data, fileName: url.lastPathComponent)
    }

    /// The mode-dependent working panel (signing steps / verification
    /// results). In compact widths it is the whole screen; in regular
    /// widths it becomes the right-hand pane next to the persistent
    /// PDF preview.
    @ViewBuilder
    private var workingPanel: some View {
        switch mode {
        case .sign:
            signingFlow
        case .verify:
            VerificationView(model: verificationModel, isImporterPresented: $isImporterPresented)
        }
    }

    // MARK: - Regular-width (iPad) two-pane layout

    private var regularWidthLayout: some View {
        HStack(spacing: 0) {
            previewPane
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            workingPanel
                .frame(width: 460)
        }
    }

    /// Persistent left pane: previews whichever PDF the current mode is
    /// working on (the signed copy once signing finished).
    @ViewBuilder
    private var previewPane: some View {
        if let data = previewPaneData {
            PDFPreviewView(data: data)
                .accessibilityLabel("PDFプレビュー: \(previewPaneFileName)")
        } else {
            VStack(spacing: 16) {
                Image(systemName: "doc.richtext")
                    .font(.system(size: 56))
                    .foregroundStyle(.tertiary)
                    .accessibilityHidden(true)
                Text("PDFが選択されていません")
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color.platformGroupedBackground)
        }
    }

    private var previewPaneData: Data? {
        switch mode {
        case .sign:
            return model.signedPDF ?? model.sourcePDF
        case .verify:
            return verificationModel.pdfData
        }
    }

    private var previewPaneFileName: String {
        switch mode {
        case .sign:
            return model.signedPDF != nil ? model.suggestedExportFileName : model.sourceFileName
        case .verify:
            return verificationModel.fileName
        }
    }

    @ViewBuilder
    private var signingFlow: some View {
        switch model.stage {
        case .importPDF:
            ImportStepView(
                isImporterPresented: $isImporterPresented,
                errorMessage: model.errorMessage
            )
        case .preview, .signing:
            if model.hasSelectedPDF {
                SigningPreparationView(model: model)
            } else {
                ImportStepView(
                    isImporterPresented: $isImporterPresented,
                    errorMessage: model.errorMessage
                )
            }
        case .result:
            if let signedPDF = model.signedPDF {
                SigningResultView(
                    signedPDF: signedPDF,
                    signerName: model.resolvedSignerName,
                    displayName: model.certificateSummary?.displayName,
                    notValidBefore: model.certificateSummary?.notValidBefore,
                    notValidAfter: model.certificateSummary?.notValidAfter,
                    suggestedFileName: model.suggestedExportFileName,
                    onDone: { model.returnToStart() },
                    onCoSign: { model.continueCoSigning() }
                )
            }
        }
    }

    /// Single import handler for the whole app. Routing by mode avoids
    /// having two `.fileImporter` modifiers alive at once, which on macOS
    /// makes one of them silently stop presenting.
    private func importPDF(_ result: Result<[URL], Error>) {
        switch result {
        case .success(let urls):
            guard let url = urls.first else { return }
            switch mode {
            case .sign:
                model.loadPDF(from: url)
            case .verify:
                verificationModel.loadPDF(from: url)
            }
        case .failure:
            switch mode {
            case .sign:
                model.loadPDFImportFailed()
            case .verify:
                verificationModel.loadPDFImportFailed()
            }
        }
    }
}

#Preview {
    ContentView()
}
