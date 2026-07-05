import Foundation
import JPKICard
import NFCTransport

#if canImport(CoreNFC)

/// End-to-end signing entry point for the app: opens one NFC session and,
/// while the card stays in the field, verifies the PIN, reads the signature
/// certificate, prepares the PDF, has the card sign, and assembles the final
/// signed PDF (design §3.1 / NFR-05).
@available(iOS 13.0, *)
public enum JPKINFCPDFSigner {
    public struct Output: Sendable {
        public let signingResult: LocalPDFSigningResult
        public let certificateSummary: SignerCertificateSummary
        public let signerName: String
    }

    public static var isReadingAvailable: Bool {
        ISO7816CardSession.isReadingAvailable
    }

    /// - Parameters:
    ///   - pdf: Source PDF (unmodified; the signed copy is returned).
    ///   - pin: 署名用パスワード (6–16 alphanumerics; letters are upper-cased
    ///     because the card stores them as upper case).
    ///   - signerName: Optional override for the PDF `/Name` entry. Defaults
    ///     to the certificate subject common name.
    ///   - allowLastAttempt: The remaining VERIFY attempts are queried
    ///     (without consuming one) before verifying. When only one attempt
    ///     is left the flow aborts with `pinLockImminent` unless this is
    ///     true, so the UI can demand explicit confirmation (FR-06).
    public static func sign(
        pdf: Data,
        pin: String,
        signerName: String? = nil,
        signingDate: Date = Date(),
        allowLastAttempt: Bool = false
    ) async throws -> Output {
        let normalizedPIN = pin.uppercased()

        return try await ISO7816CardSession.run(
            alertMessage: String(localized: "マイナンバーカードを iPhone 上部に重ねたまま動かさないでください", bundle: .module),
            successMessage: String(localized: "署名が完了しました", bundle: .module),
            errorMessage: Self.alertMessage(for:)
        ) { transport, session in
            let service = JPKICardSigningService(transport: transport)
            try await service.selectApplication()

            // FR-06: query the remaining attempts (does not consume one)
            // before VERIFY, so a typo can never be the locking mistake
            // without explicit consent.
            let retries = try await service.signingPINRetryCount()
            if retries == 0 {
                throw JPKINFCPDFSignerError.pinLocked
            }
            if retries == 1, !allowLastAttempt {
                throw JPKINFCPDFSignerError.pinLockImminent(retriesRemaining: retries)
            }

            session.updateAlertMessage(String(format: String(localized: "暗証番号を確認しています…（残り%d回）", bundle: .module), retries))
            try await service.verifySigningPIN(normalizedPIN)

            session.updateAlertMessage(String(localized: "証明書を読み取っています…", bundle: .module))
            let certificateDER = try await service.readSignatureCertificate()
            let summary = try SignerCertificateSummary(certificateDER: certificateDER)
            guard summary.isValid(at: signingDate) else {
                throw JPKINFCPDFSignerError.certificateOutsideValidity(notValidAfter: summary.notValidAfter)
            }
            let resolvedName = signerName ?? summary.displayName ?? String(localized: "署名者", bundle: .module)

            session.updateAlertMessage(String(localized: "署名しています…", bundle: .module))
            let result = try await LocalPDFSigner.sign(
                input: LocalPDFSigningInput(
                    pdf: pdf,
                    certificateDER: certificateDER,
                    signerName: resolvedName,
                    signingDate: signingDate
                ),
                verification: .full,
                signer: { digestInfo in
                    try await service.signDigestInfo(digestInfo)
                }
            )

            return Output(
                signingResult: result,
                certificateSummary: summary,
                signerName: resolvedName
            )
        }
    }

    /// Japanese text for the NFC sheet when the flow fails (FR-12).
    static func alertMessage(for error: Error) -> String {
        switch error {
        case JPKICardSigningServiceError.pinVerificationFailed(let status):
            if case .pinVerificationFailed(let retries) = status {
                return String(format: String(localized: "暗証番号が違います（残り%d回）。連続で間違えるとロックされます。", bundle: .module), retries)
            }
            if status == .authenticationMethodBlocked {
                return String(localized: "暗証番号がロックされています。市区町村の窓口で初期化してください。", bundle: .module)
            }
            return String(localized: "暗証番号を確認できませんでした。", bundle: .module)
        case JPKICardSigningServiceError.invalidPINFormat:
            return String(localized: "署名用パスワードは英数字6〜16桁です。", bundle: .module)
        case JPKINFCPDFSignerError.certificateOutsideValidity:
            return String(localized: "署名用電子証明書が有効期間外です。", bundle: .module)
        case JPKINFCPDFSignerError.pinLocked:
            return String(localized: "暗証番号がロックされています。市区町村の窓口で初期化してください。", bundle: .module)
        case JPKINFCPDFSignerError.pinLockImminent:
            return String(localized: "暗証番号の残り試行回数が1回です。次に間違えるとロックされるため中断しました。", bundle: .module)
        case NFCSessionError.cardCommunicationFailed:
            return String(localized: "カードとの通信に失敗しました。もう一度かざしてください。", bundle: .module)
        case NFCSessionError.tagConnectionFailed, NFCSessionError.unsupportedTag:
            return String(localized: "カードを認識できませんでした。位置を調整してもう一度かざしてください。", bundle: .module)
        default:
            return String(localized: "署名に失敗しました。もう一度お試しください。", bundle: .module)
        }
    }
}

#endif

/// Errors shared by the card signing coordinators (NFC on iOS, USB
/// smart-card readers on macOS).
public enum JPKINFCPDFSignerError: Error, Equatable, Sendable {
    case certificateOutsideValidity(notValidAfter: Date)
    /// The signature PIN is locked (0 attempts remain); municipal reset needed.
    case pinLocked
    /// Only one VERIFY attempt remains; aborted without consuming it. Retry
    /// with `allowLastAttempt: true` after explicit user confirmation.
    case pinLockImminent(retriesRemaining: Int)
}
