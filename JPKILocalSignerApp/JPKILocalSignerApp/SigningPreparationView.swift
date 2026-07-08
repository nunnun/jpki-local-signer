//
//  SigningPreparationView.swift
//  JPKILocalSignerApp
//
//  Steps 2-4 of the flow (design.md FR-02, FR-05, FR-06): preview the PDF,
//  enter the signature PIN, and start the NFC signing session.

import JPKILocalSigner
import SwiftUI

struct SigningPreparationView: View {
    @Bindable var model: SigningFlowModel

    /// In regular widths (iPad two-pane layout / macOS) the persistent
    /// left pane already shows the PDF, so the inline preview row is
    /// omitted.
    #if os(iOS)
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    private var isRegularWidth: Bool { horizontalSizeClass == .regular }
    #else
    private var isRegularWidth: Bool { true }
    #endif

    #if DEBUG
    @State private var developmentSignerName = ""
    #endif

    var body: some View {
        Form {
            Section("PDF") {
                HStack {
                    Image(systemName: "doc.richtext.fill")
                        .foregroundStyle(.green)
                    VStack(alignment: .leading) {
                        Text(model.sourceFileName)
                            .lineLimit(1)
                        Text("\(model.sourcePageCount)ページ")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .accessibilityElement(children: .combine)

                if let pdf = model.sourcePDF {
                    if !isRegularWidth {
                        PDFPreviewView(data: pdf)
                            .frame(minHeight: 360)
                            .accessibilityLabel("PDFプレビュー: \(model.sourceFileName)")
                    }

                    let existingSignatureCount = PDFSignaturePreparer.countSignatureContents(in: pdf)
                    if existingSignatureCount > 0 {
                        Label(
                            "この PDF には既に \(existingSignatureCount) 件の署名があります。追加署名は増分更新で付与され、既存の署名は保持されます。",
                            systemImage: "signature"
                        )
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .accessibilityLabel("この PDF には既に \(existingSignatureCount) 件の署名があります。追加署名は増分更新で付与され、既存の署名は保持されます。")
                    }
                }

                Button(role: .destructive) {
                    model.clearSelection()
                } label: {
                    Label("別のPDFを選び直す", systemImage: "arrow.uturn.backward")
                }
                .disabled(model.isSigning)
            }

            Section {
                SecureField("署名用PIN（英数字6〜16桁）", text: $model.signingPIN)
                    .neverAutocapitalize()
                    .autocorrectionDisabled()
                    .disabled(model.isSigning)
                    .accessibilityLabel("署名用PIN")
                    .accessibilityHint("6文字から16文字の半角英数字で入力してください")

                if !model.signingPIN.isEmpty && !model.isPINValid {
                    Label("PINは6〜16桁の半角英数字で入力してください。", systemImage: "exclamationmark.triangle")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                        .accessibilityElement(children: .combine)
                }
            } header: {
                Text("署名用PIN")
            } footer: {
                Text("暗証番号を5回連続で間違えるとカードがロックされます。ロックされた場合は市区町村窓口での初期化が必要です。入力した暗証番号は保存されません。")
            }

            #if os(macOS)
            Section {
                readerStatus

                Button {
                    Task { await model.refreshReaders() }
                } label: {
                    Label("再読み込み", systemImage: "arrow.clockwise")
                }
                .disabled(model.isSigning)
                .accessibilityHint("カードリーダーの一覧を更新します")

                Button {
                    Task { await model.startSigning() }
                } label: {
                    Label(model.isSigning ? "署名処理中…" : "署名する", systemImage: "creditcard")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(!model.isPINValid || model.isSigning || !model.isCardPresent)
                .accessibilityHint("カードリーダーのマイナンバーカードで署名します")
            } header: {
                Text("カードリーダー")
            } footer: {
                Text("USBカードリーダーにマイナンバーカードを挿入し、「署名する」を押してください。")
            }
            #elseif canImport(CoreNFC)
            Section {
                if JPKINFCPDFSigner.isReadingAvailable {
                    Button {
                        Task { await model.startSigning() }
                    } label: {
                        // Explicit HStack (not Label) so the NFC glyph renders
                        // identically in every state. The button stays enabled
                        // regardless of PIN entry so its appearance never
                        // changes; startSigning() validates the PIN and shows
                        // an inline message if it is missing or malformed.
                        HStack(spacing: 8) {
                            Image(systemName: "wave.3.right")
                            Text(model.isSigning ? "署名処理中…" : "署名する")
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(model.isSigning)
                    .accessibilityHint("マイナンバーカードをiPhoneにかざして署名します")
                } else {
                    Label("この端末はNFC読み取りに対応していません。", systemImage: "wifi.slash")
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("署名")
            } footer: {
                Text("「署名する」を押すと、マイナンバーカードをかざす画面が表示されます。読み取りが終わるまでカードを iPhone の上部に重ねたまま動かさないでください。")
            }
            #else
            Section {
                Label("この環境はNFC読み取りに対応していません。", systemImage: "wifi.slash")
                    .foregroundStyle(.secondary)
            } header: {
                Text("署名")
            }
            #endif

            #if DEBUG
            Section {
                TextField("開発検証用の氏名", text: $developmentSignerName)
                    .textContentType(.name)
                    .disabled(model.isSigning)

                Button {
                    Task { await model.startDevelopmentSigning(signerName: developmentSignerName) }
                } label: {
                    Label(model.isSigning ? "処理中…" : "ダミー署名で検証", systemImage: "hammer")
                }
                .disabled(!model.isPINValid || model.isSigning || developmentSignerName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            } header: {
                Text("開発検証用・ダミー署名")
            } footer: {
                Text("この機能は開発検証用です。実際のマイナンバーカードやNFCは使用せず、ダミーの証明書と署名値でPDF組み立てパイプラインのみを検証します。本番の署名としては使用できません。")
            }
            #endif

            if let errorMessage = model.errorMessage {
                Section {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .accessibilityElement(children: .combine)
                }
            }
        }
        // Grouped style renders label-above-control rows that fit the narrow
        // two-pane column. The macOS default (.columns) puts labels in a wide
        // left column that overflows a fixed-width pane and gets clipped.
        .formStyle(.grouped)
        .disabled(model.isSigning)
        .accessibilityHidden(model.isSigning)
        .overlay {
            if model.isSigning {
                SigningProgressOverlay(message: model.signingProgressMessage)
            }
        }
        .animation(.default, value: model.isSigning)
        #if canImport(CoreNFC) || os(macOS)
        .alert(
            "残り試行回数が1回です",
            isPresented: $model.isLastAttemptConfirmationPresented
        ) {
            Button("続行する", role: .destructive) {
                Task { await model.confirmLastAttemptSigning() }
            }
            .accessibilityHint("最後の1回の試行で署名を続行します。間違えるとカードがロックされます")
            Button("やめる", role: .cancel) {
                model.cancelLastAttemptSigning()
            }
        } message: {
            Text("暗証番号の残り試行回数が1回です。次に間違えるとカードがロックされ、市区町村窓口での初期化が必要になります。続行しますか？")
        }
        #endif
        #if os(macOS)
        .task {
            await model.refreshReaders()
        }
        #endif
    }

    #if os(macOS)
    /// One line per attached reader, or the reason none can be used.
    @ViewBuilder
    private var readerStatus: some View {
        if let readers = model.smartCardReaders {
            if readers.isEmpty {
                Label("カードリーダーが見つかりません", systemImage: "questionmark.square.dashed")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(readers, id: \.slotName) { reader in
                    Label {
                        if reader.cardPresent {
                            Text("リーダー: \(reader.slotName)（カードあり）")
                        } else {
                            Text("リーダー: \(reader.slotName)（カードなし）")
                        }
                    } icon: {
                        Image(systemName: reader.cardPresent ? "creditcard.fill" : "creditcard")
                            .foregroundStyle(reader.cardPresent ? Color.green : Color.secondary)
                    }
                }
            }
        } else if model.hasQueriedReaders {
            Label("スマートカードサービスを利用できません", systemImage: "exclamationmark.triangle")
                .foregroundStyle(.orange)
        }
    }
    #endif
}

private struct SigningProgressOverlay: View {
    let message: String

    var body: some View {
        ZStack {
            Color.black.opacity(0.35)
                .ignoresSafeArea()
            VStack(spacing: 16) {
                ProgressView()
                    .controlSize(.large)
                Text(message)
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.white)
                    .padding(.horizontal, 24)
            }
            .padding(32)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16))
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(message)
        .accessibilityAddTraits(.updatesFrequently)
    }
}
