import Foundation

public protocol ISO7816Transport: Sendable {
    func transmit(_ command: APDUCommand) async throws -> APDUResponse
}

public enum NFCSessionError: Error, Equatable, Sendable {
    case unsupportedPlatform
    case readingUnavailable
    case sessionInvalidated(description: String)
    case userCanceled
    case tagConnectionFailed
    case unsupportedTag
    case cardCommunicationFailed(status: APDUStatus)
}

#if canImport(CoreNFC)
import CoreNFC

/// One-shot ISO 14443 / ISO 7816 card session. Starts an
/// `NFCTagReaderSession`, waits for a card, connects, and runs `body` with a
/// transport while the card stays in the field. The session ends when `body`
/// returns or throws.
@available(iOS 13.0, *)
public final class ISO7816CardSession: NSObject, @unchecked Sendable {
    public typealias Body<T> = @Sendable (_ transport: ISO7816Transport, _ session: ISO7816CardSession) async throws -> T

    public static var isReadingAvailable: Bool {
        NFCTagReaderSession.readingAvailable
    }

    /// Message shown on the NFC sheet while waiting for / talking to the card.
    public func updateAlertMessage(_ message: String) {
        session?.alertMessage = message
    }

    public static func run<T: Sendable>(
        alertMessage: String,
        successMessage: String,
        errorMessage: @escaping @Sendable (Error) -> String,
        body: @escaping Body<T>
    ) async throws -> T {
        guard isReadingAvailable else {
            throw NFCSessionError.readingUnavailable
        }

        let coordinator = ISO7816CardSession(
            successMessage: successMessage,
            errorMessage: errorMessage,
            body: { transport, session in
                try await body(transport, session)
            }
        )
        return try await coordinator.start(alertMessage: alertMessage) as! T
    }

    private let lock = NSLock()
    private var session: NFCTagReaderSession?
    private var continuation: CheckedContinuation<any Sendable, Error>?
    private var workTask: Task<Void, Never>?

    private let successMessage: String
    private let errorMessage: @Sendable (Error) -> String
    private let body: Body<any Sendable>

    private init(
        successMessage: String,
        errorMessage: @escaping @Sendable (Error) -> String,
        body: @escaping Body<any Sendable>
    ) {
        self.successMessage = successMessage
        self.errorMessage = errorMessage
        self.body = body
    }

    private func start(alertMessage: String) async throws -> any Sendable {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            self.continuation = continuation
            lock.unlock()

            guard let session = NFCTagReaderSession(pollingOption: .iso14443, delegate: self) else {
                finish(with: .failure(NFCSessionError.readingUnavailable), invalidating: nil)
                return
            }

            lock.lock()
            self.session = session
            lock.unlock()

            session.alertMessage = alertMessage
            session.begin()
        }
    }

    /// Resumes the continuation exactly once and optionally closes the sheet.
    private func finish(with result: Result<any Sendable, Error>, invalidating session: NFCTagReaderSession?) {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()

        guard let continuation else {
            return
        }

        if let session {
            switch result {
            case .success:
                session.alertMessage = successMessage
                session.invalidate()
            case .failure(let error):
                session.invalidate(errorMessage: errorMessage(error))
            }
        }

        continuation.resume(with: result)
    }
}

@available(iOS 13.0, *)
extension ISO7816CardSession: NFCTagReaderSessionDelegate {
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        let mapped: Error
        if let nfcError = error as? NFCReaderError,
           nfcError.code == .readerSessionInvalidationErrorUserCanceled {
            mapped = NFCSessionError.userCanceled
        } else {
            mapped = NFCSessionError.sessionInvalidated(description: error.localizedDescription)
        }
        // The session is already dead; never call invalidate on it again.
        finish(with: .failure(mapped), invalidating: nil)
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let firstTag = tags.first, case .iso7816(let iso7816Tag) = firstTag else {
            session.invalidate(errorMessage: errorMessage(NFCSessionError.unsupportedTag))
            return
        }

        session.connect(to: firstTag) { [weak self] error in
            guard let self else { return }
            if error != nil {
                self.finish(with: .failure(NFCSessionError.tagConnectionFailed), invalidating: session)
                return
            }

            let transport = CoreNFCISO7816Transport(tag: iso7816Tag)
            // NFCTagReaderSession is not Sendable; it is only handed to
            // finish(with:invalidating:), which touches it once.
            nonisolated(unsafe) let session = session
            let task = Task { [weak self] in
                guard let self else { return }
                do {
                    let value = try await self.body(transport, self)
                    self.finish(with: .success(value), invalidating: session)
                } catch {
                    self.finish(with: .failure(error), invalidating: session)
                }
            }

            self.lock.lock()
            self.workTask = task
            self.lock.unlock()
        }
    }
}
#endif
