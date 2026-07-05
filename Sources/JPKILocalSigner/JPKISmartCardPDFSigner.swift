#if os(macOS)

import Foundation
import JPKICard
import NFCTransport

/// macOS counterpart of `JPKINFCPDFSigner`: signs a PDF with a My Number
/// Card in a USB (PC/SC) smart-card reader via CryptoTokenKit. Same
/// pipeline, same safety behavior (retry query before VERIFY, abort on the
/// last attempt unless explicitly allowed), same error types.
public enum JPKISmartCardPDFSigner {
    public struct Output: Sendable {
        public let signingResult: LocalPDFSigningResult
        public let certificateSummary: SignerCertificateSummary
        public let signerName: String
    }

    public enum Progress: Sendable {
        case waitingForCard
        case verifyingPIN(retriesRemaining: Int)
        case readingCertificate
        case signing
    }

    /// Readers currently attached (nil when smart-card services are
    /// unavailable — e.g. missing com.apple.security.smartcard entitlement).
    public static func availableReaders() async -> [SmartCardSession.ReaderInfo]? {
        await SmartCardSession.availableReaders()
    }

    public static func sign(
        pdf: Data,
        pin: String,
        signerName: String? = nil,
        signingDate: Date = Date(),
        allowLastAttempt: Bool = false,
        onProgress: (@Sendable (Progress) -> Void)? = nil
    ) async throws -> Output {
        let normalizedPIN = pin.uppercased()
        onProgress?(.waitingForCard)

        return try await SmartCardSession.run { transport in
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

            onProgress?(.verifyingPIN(retriesRemaining: retries))
            try await service.verifySigningPIN(normalizedPIN)

            onProgress?(.readingCertificate)
            let certificateDER = try await service.readSignatureCertificate()
            let summary = try SignerCertificateSummary(certificateDER: certificateDER)
            guard summary.isValid(at: signingDate) else {
                throw JPKINFCPDFSignerError.certificateOutsideValidity(notValidAfter: summary.notValidAfter)
            }
            let resolvedName = signerName ?? summary.displayName ?? String(localized: "署名者", bundle: .module)

            onProgress?(.signing)
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
}

#endif
