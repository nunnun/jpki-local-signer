import Foundation
import NFCTransport

/// Drives the JPKI signature flow over one card session:
///
/// 1. SELECT JPKI AP
/// 2. SELECT EF(署名用PIN) → VERIFY
/// 3. SELECT EF(署名用証明書) → READ BINARY (PIN-protected)
/// 4. SELECT EF(署名用秘密鍵) → COMPUTE DIGITAL SIGNATURE
///
/// The split-phase API lets callers read the certificate and sign one or
/// more DigestInfo values while the card stays in the field.
public struct JPKICardSigningService: Sendable {
    public let transport: ISO7816Transport

    public init(transport: ISO7816Transport) {
        self.transport = transport
    }

    public func selectApplication() async throws {
        let response = try await transport.transmit(JPKIApplet.selectApplicationCommand())
        guard response.isSuccess else {
            throw NFCSessionError.cardCommunicationFailed(status: response.status)
        }
    }

    /// Remaining VERIFY attempts for the signature PIN, without consuming one.
    /// Requires the JPKI AP to be selected.
    public func signingPINRetryCount() async throws -> Int {
        try await selectEF(JPKIApplet.EF.signaturePIN)
        let response = try await transport.transmit(.verifyRetryQuery())
        if let retries = response.pinRetryCount {
            return retries
        }
        if response.status == .authenticationMethodBlocked {
            return 0
        }
        throw JPKICardSigningServiceError.unexpectedRetryQueryResponse(response.status)
    }

    /// SELECT AP → SELECT PIN EF → VERIFY. Call once per card session before
    /// `readSignatureCertificate()` / `signDigestInfo(_:)`.
    public func startSession(pin: String) async throws {
        guard SigningPINPolicy.isValidFormat(pin) else {
            throw JPKICardSigningServiceError.invalidPINFormat
        }

        try await selectApplication()
        try await selectEF(JPKIApplet.EF.signaturePIN)
        try await verifySigningPIN(pin)
    }

    /// VERIFY with the signature PIN. Requires the PIN EF to be selected —
    /// use after `signingPINRetryCount()` to avoid re-selecting (FR-06 flow:
    /// query retries first, then verify in the same session).
    public func verifySigningPIN(_ pin: String) async throws {
        guard SigningPINPolicy.isValidFormat(pin) else {
            throw JPKICardSigningServiceError.invalidPINFormat
        }
        let status = try await PINVerifier(transport: transport).verifySigningPIN(pin)
        guard status == .success else {
            throw JPKICardSigningServiceError.pinVerificationFailed(status)
        }
    }

    /// Reads the 署名用電子証明書 (DER). Requires `startSession(pin:)` first.
    public func readSignatureCertificate() async throws -> [UInt8] {
        try await selectEF(JPKIApplet.EF.signatureCertificate)
        return try await CertificateReader(transport: transport).readCertificate()
    }

    /// Signs a PKCS#1 v1.5 DigestInfo. Requires `startSession(pin:)` first.
    public func signDigestInfo(_ digestInfo: [UInt8]) async throws -> [UInt8] {
        try await selectEF(JPKIApplet.EF.signaturePrivateKey)
        return try await CardSigner(transport: transport).signDigestInfo(digestInfo)
    }

    /// Convenience for the whole flow when the certificate is already known.
    public func signDigestInfo(_ digestInfo: [UInt8], pin: String) async throws -> [UInt8] {
        try await startSession(pin: pin)
        return try await signDigestInfo(digestInfo)
    }

    private func selectEF(_ identifier: [UInt8]) async throws {
        let response = try await transport.transmit(.selectEF(identifier: identifier))
        guard response.isSuccess else {
            throw NFCSessionError.cardCommunicationFailed(status: response.status)
        }
    }
}

public enum JPKICardSigningServiceError: Error, Equatable, Sendable {
    case invalidPINFormat
    case pinVerificationFailed(APDUStatus)
    case unexpectedRetryQueryResponse(APDUStatus)
}
