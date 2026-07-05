import Foundation
import NFCTransport

public struct PINVerifier: Sendable {
    public let transport: ISO7816Transport

    public init(transport: ISO7816Transport) {
        self.transport = transport
    }

    public func verifySigningPIN(_ pin: String) async throws -> APDUStatus {
        let response = try await transport.transmit(.verify(pin: pin))
        return response.status
    }
}

public enum SigningPINPolicy {
    public static let minimumLength = 6
    public static let maximumLength = 16

    public static func isValidFormat(_ pin: String) -> Bool {
        guard (minimumLength...maximumLength).contains(pin.count) else {
            return false
        }
        return pin.allSatisfy { character in
            (character.isASCII && character.isLetter) || (character.isASCII && character.isNumber)
        }
    }
}
