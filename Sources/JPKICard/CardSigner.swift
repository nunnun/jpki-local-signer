import Foundation
import NFCTransport

public struct CardSigner: Sendable {
    public let transport: ISO7816Transport

    public init(transport: ISO7816Transport) {
        self.transport = transport
    }

    public func signDigestInfo(_ digestInfo: [UInt8]) async throws -> [UInt8] {
        let response = try await transport.transmit(.computeDigitalSignature(digestInfo: digestInfo))
        guard response.isSuccess else {
            throw NFCSessionError.cardCommunicationFailed(status: response.status)
        }
        return response.data
    }
}
