import Foundation

#if canImport(CoreNFC)
import CoreNFC

@available(iOS 13.0, *)
public final class CoreNFCISO7816Transport: ISO7816Transport, @unchecked Sendable {
    private let tag: NFCISO7816Tag

    public init(tag: NFCISO7816Tag) {
        self.tag = tag
    }

    public func transmit(_ command: APDUCommand) async throws -> APDUResponse {
        let apdu = NFCISO7816APDU(
            instructionClass: command.cla,
            instructionCode: command.ins,
            p1Parameter: command.p1,
            p2Parameter: command.p2,
            data: Data(command.data),
            expectedResponseLength: command.coreNFCExpectedResponseLength
        )

        return try await withCheckedThrowingContinuation { continuation in
            tag.sendCommand(apdu: apdu) { data, sw1, sw2, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }

                continuation.resume(returning: APDUResponse(
                    data: Array(data),
                    sw1: sw1,
                    sw2: sw2
                ))
            }
        }
    }
}

@available(iOS 13.0, *)
private extension APDUCommand {
    var coreNFCExpectedResponseLength: Int {
        switch expectedResponseLength {
        case nil:
            return 0
        case .exact(let length):
            return Int(length)
        case .extended(let length):
            return Int(length)
        case .maximum:
            return 256
        }
    }
}
#endif
