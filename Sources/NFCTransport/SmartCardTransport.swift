import Foundation

#if os(macOS)
import CryptoTokenKit

/// macOS: ISO 7816 transport over a PC/SC smart-card reader (USB IC card
/// readers) via CryptoTokenKit. The same `JPKICardSigningService` pipeline
/// used with Core NFC on iOS plugs in unchanged.
public final class TKSmartCardTransport: ISO7816Transport, @unchecked Sendable {
    private let card: TKSmartCard

    public init(card: TKSmartCard) {
        self.card = card
    }

    public func transmit(_ command: APDUCommand) async throws -> APDUResponse {
        let response = try await card.transmit(Data(command.encoded))
        return try APDUResponse(encoded: [UInt8](response))
    }
}

/// One-shot smart-card session: finds a reader with a card inserted, begins
/// a session, runs `body`, and ends the session.
public enum SmartCardSession {
    public struct ReaderInfo: Sendable {
        public let slotName: String
        public let cardPresent: Bool
    }

    /// Readers currently attached. `nil` when smart-card services are not
    /// accessible (missing com.apple.security.smartcard entitlement in a
    /// sandboxed process, or no pcsc availability).
    public static func availableReaders() async -> [ReaderInfo]? {
        guard let manager = TKSmartCardSlotManager.default else {
            return nil
        }
        var readers: [ReaderInfo] = []
        for slotName in manager.slotNames {
            let slot = await manager.getSlot(withName: slotName)
            readers.append(ReaderInfo(
                slotName: slotName,
                cardPresent: slot?.state == .validCard
            ))
        }
        return readers
    }

    /// Runs `body` against the card in the named reader (or the first reader
    /// holding a card when `slotName` is nil).
    public static func run<T: Sendable>(
        slotName: String? = nil,
        body: @Sendable (_ transport: ISO7816Transport) async throws -> T
    ) async throws -> T {
        guard let manager = TKSmartCardSlotManager.default else {
            throw SmartCardSessionError.smartCardServicesUnavailable
        }

        var selectedSlot: TKSmartCardSlot?
        if let slotName {
            selectedSlot = await manager.getSlot(withName: slotName)
        } else {
            for name in manager.slotNames {
                if let slot = await manager.getSlot(withName: name), slot.state == .validCard {
                    selectedSlot = slot
                    break
                }
            }
        }
        guard let slot = selectedSlot else {
            throw SmartCardSessionError.noCardPresent
        }
        guard let card = slot.makeSmartCard() else {
            throw SmartCardSessionError.cardUnavailable
        }

        let began = try await card.beginSession()
        guard began else {
            throw SmartCardSessionError.sessionFailed
        }
        defer { card.endSession() }

        return try await body(TKSmartCardTransport(card: card))
    }
}

public enum SmartCardSessionError: Error, Equatable, Sendable {
    /// TKSmartCardSlotManager unavailable — typically the process lacks the
    /// com.apple.security.smartcard entitlement (sandboxed apps) or smart
    /// card services are disabled.
    case smartCardServicesUnavailable
    case noCardPresent
    case cardUnavailable
    case sessionFailed
}

#endif
