//
//  SigningFlowModel.swift
//  JPKILocalSignerApp
//
//  Drives the main user flow (design.md §3.1 / FR-01..FR-12):
//  PDF読み込み → 内容確認 → PIN入力 → NFC署名 → 結果表示。
//
//  This type intentionally holds no networking code and never logs or
//  persists the PIN, digest, signature value, or raw card responses
//  (design.md §1.2 / NFR-02 / NFR-03).

import Foundation
import JPKILocalSigner
import Observation

/// Screens in the primary user flow.
enum SigningStage: Equatable {
    case importPDF
    case preview
    case signing
    case result
}

@MainActor
@Observable
final class SigningFlowModel {
    // MARK: PDF state

    private(set) var sourcePDF: Data?
    private(set) var sourceFileName: String = ""
    private(set) var sourcePageCount: Int = 0

    // MARK: PIN entry state

    var signingPIN: String = "" {
        didSet {
            // Defensive: never let the PIN grow unbounded from paste, and
            // strip characters outside the card's alphabet as early as
            // possible so nothing invalid is ever held for long.
            if signingPIN.count > SigningPINPolicy.maximumLength {
                signingPIN = String(signingPIN.prefix(SigningPINPolicy.maximumLength))
            }
        }
    }

    var isPINValid: Bool {
        SigningPINPolicy.isValidFormat(signingPIN)
    }

    // MARK: Flow / progress state

    var stage: SigningStage = .importPDF
    var isSigning = false
    var signingProgressMessage = ""
    var errorMessage: String?

    // MARK: Last-attempt confirmation state (FR-06)

    /// Presented when the card reports exactly one remaining PIN attempt:
    /// the library aborted WITHOUT consuming it, and signing may only
    /// continue after explicit user confirmation.
    var isLastAttemptConfirmationPresented = false
    /// PIN retained only while the last-attempt confirmation is on screen,
    /// so the confirmed retry does not require re-entry. Cleared on
    /// confirm/cancel and never logged or persisted.
    private var pendingLastAttemptPIN: String?

    // MARK: Result state

    private(set) var signedPDF: Data?
    private(set) var certificateSummary: SignerCertificateSummary?
    private(set) var resolvedSignerName: String = ""

    var hasSelectedPDF: Bool { sourcePDF != nil }

    var suggestedExportFileName: String {
        let base = sourceFileName.replacingOccurrences(of: ".pdf", with: "", options: [.caseInsensitive])
        let root = base.isEmpty ? "document" : base
        return "\(root)_signed.pdf"
    }

    // MARK: - PDF import

    func loadPDF(from url: URL) {
        let didStartAccessing = url.startAccessingSecurityScopedResource()
        defer {
            if didStartAccessing {
                url.stopAccessingSecurityScopedResource()
            }
        }

        do {
            let data = try Data(contentsOf: url)
            loadPDF(data: data, fileName: url.lastPathComponent)
        } catch {
            errorMessage = String(localized: "PDFの読み込みに失敗しました。もう一度お試しください。")
        }
    }

    /// Loads already-read PDF bytes (e.g. handed over from another app via
    /// the share sheet / onOpenURL, where the security-scoped read has
    /// already happened).
    func loadPDF(data: Data, fileName: String) {
        guard let document = CGPDFDocumentFromData(data) else {
            errorMessage = String(localized: "選択したファイルはPDFとして読み取れませんでした。")
            return
        }
        sourcePDF = data
        sourceFileName = fileName
        sourcePageCount = document.numberOfPages
        errorMessage = nil
        resetResult()
        stage = .preview
    }

    func loadPDFImportFailed() {
        errorMessage = String(localized: "PDFを選択できませんでした。もう一度お試しください。")
    }

    func clearSelection() {
        sourcePDF = nil
        sourceFileName = ""
        sourcePageCount = 0
        signingPIN = ""
        errorMessage = nil
        resetResult()
        stage = .importPDF
    }

    /// 「続けて次の人が署名」: restart the flow with the just-signed PDF as
    /// the new source, so the next signer adds their signature on top of the
    /// existing one(s) via incremental update. The signed copy — not the
    /// original — becomes the new source; PIN and result state are cleared.
    func continueCoSigning() {
        guard let signedPDF else { return }
        sourcePDF = signedPDF
        sourceFileName = suggestedExportFileName
        if let document = CGPDFDocumentFromData(signedPDF) {
            sourcePageCount = document.numberOfPages
        }
        signingPIN = ""
        errorMessage = nil
        resetResult()
        stage = .preview
    }

    private func resetResult() {
        signedPDF = nil
        certificateSummary = nil
        resolvedSignerName = ""
    }

    // MARK: - Signing (real card: NFC on iOS, USB smart-card reader on macOS)

    #if canImport(CoreNFC) || os(macOS)
    func startSigning() async {
        guard isPINValid else {
            errorMessage = String(localized: "署名用PINは6〜16桁の英数字で入力してください。")
            return
        }

        let pin = signingPIN
        // Clear the PIN from the model as soon as we hand it off; it is
        // only retained (privately) if the card reports one remaining
        // attempt and the user must confirm before continuing.
        signingPIN = ""

        await performSigning(pin: pin, allowLastAttempt: false)
    }

    /// 「続行する」 on the last-attempt confirmation: retries with the
    /// retained PIN, explicitly allowing the final VERIFY attempt.
    func confirmLastAttemptSigning() async {
        guard let pin = pendingLastAttemptPIN else { return }
        pendingLastAttemptPIN = nil
        isLastAttemptConfirmationPresented = false
        await performSigning(pin: pin, allowLastAttempt: true)
    }

    /// 「やめる」 on the last-attempt confirmation: discard the retained
    /// PIN and stay on the preview screen.
    func cancelLastAttemptSigning() {
        pendingLastAttemptPIN = nil
        isLastAttemptConfirmationPresented = false
    }

    private func performSigning(pin: String, allowLastAttempt: Bool) async {
        guard let sourcePDF else { return }

        isSigning = true
        errorMessage = nil
        stage = .signing
        defer { isSigning = false }

        do {
            #if os(macOS)
            signingProgressMessage = String(localized: "カードを待っています…")
            let output = try await JPKISmartCardPDFSigner.sign(
                pdf: sourcePDF,
                pin: pin,
                allowLastAttempt: allowLastAttempt,
                onProgress: { progress in
                    Task { @MainActor [weak self] in
                        self?.applySmartCardProgress(progress)
                    }
                }
            )
            #else
            signingProgressMessage = String(localized: "マイナンバーカードを iPhone にかざしてください…")
            let output = try await JPKINFCPDFSigner.sign(
                pdf: sourcePDF,
                pin: pin,
                allowLastAttempt: allowLastAttempt
            )
            #endif
            signedPDF = output.signingResult.signedPDF
            certificateSummary = output.certificateSummary
            resolvedSignerName = output.signerName
            stage = .result
        } catch JPKINFCPDFSignerError.pinLocked {
            errorMessage = String(localized: "暗証番号がロックされています。市区町村の窓口で初期化してください。")
            stage = .preview
        } catch JPKINFCPDFSignerError.pinLockImminent {
            // The attempt was NOT consumed. Keep the PIN privately and ask
            // for explicit confirmation before the final attempt (FR-06).
            pendingLastAttemptPIN = pin
            isLastAttemptConfirmationPresented = true
            stage = .preview
        } catch let error as NFCSessionError {
            if error == .userCanceled {
                // Silently return to the preview screen (per spec: NFC
                // user-cancel should not surface as an error).
                stage = .preview
            } else {
                errorMessage = SigningErrorPresenter.message(for: error)
                stage = .preview
            }
        } catch {
            errorMessage = SigningErrorPresenter.message(for: error)
            stage = .preview
        }
    }
    #endif

    // MARK: - macOS smart-card reader state

    #if os(macOS)
    /// Attached PC/SC readers; `nil` after a query means smart-card
    /// services are unavailable (e.g. missing smartcard entitlement).
    private(set) var smartCardReaders: [SmartCardSession.ReaderInfo]?
    /// Distinguishes "not queried yet" from "queried, services unavailable".
    private(set) var hasQueriedReaders = false

    var isCardPresent: Bool {
        smartCardReaders?.contains { $0.cardPresent } ?? false
    }

    func refreshReaders() async {
        smartCardReaders = await JPKISmartCardPDFSigner.availableReaders()
        hasQueriedReaders = true
    }

    private func applySmartCardProgress(_ progress: JPKISmartCardPDFSigner.Progress) {
        switch progress {
        case .waitingForCard:
            signingProgressMessage = String(localized: "カードを待っています…")
        case .verifyingPIN(let retriesRemaining):
            signingProgressMessage = String(localized: "暗証番号を確認しています…（残り\(retriesRemaining)回）")
        case .readingCertificate:
            signingProgressMessage = String(localized: "証明書を読み取っています…")
        case .signing:
            signingProgressMessage = String(localized: "署名しています…")
        }
    }
    #endif

    // MARK: - Signing (DEBUG-only dev/dummy path)

    #if DEBUG
    func startDevelopmentSigning(signerName: String) async {
        guard let sourcePDF else { return }
        guard isPINValid else {
            errorMessage = String(localized: "署名用PINは6〜16桁の英数字で入力してください。")
            return
        }
        let trimmedName = signerName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedName.isEmpty else {
            errorMessage = String(localized: "開発検証用の氏名を入力してください。")
            return
        }

        isSigning = true
        errorMessage = nil
        signingProgressMessage = String(localized: "開発検証用の一時鍵で署名しています…")
        stage = .signing
        defer { isSigning = false }

        signingPIN = ""

        do {
            // Ephemeral RSA key + self-signed certificate: the output is
            // cryptographically valid, so 署名を検証する shows real results.
            let output = try await DevelopmentPDFSigner.sign(
                pdf: sourcePDF,
                signerName: trimmedName
            )

            signedPDF = output.signingResult.signedPDF
            certificateSummary = try? SignerCertificateSummary(certificateDER: output.certificateDER)
            resolvedSignerName = trimmedName
            stage = .result
        } catch {
            errorMessage = String(localized: "開発検証用署名に失敗しました: \(error.localizedDescription)")
            stage = .preview
        }
    }
    #endif

    func returnToStart() {
        clearSelection()
    }
}

#if canImport(CoreGraphics)
import CoreGraphics

private func CGPDFDocumentFromData(_ data: Data) -> CGPDFDocument? {
    guard let provider = CGDataProvider(data: data as CFData) else {
        return nil
    }
    return CGPDFDocument(provider)
}
#endif
