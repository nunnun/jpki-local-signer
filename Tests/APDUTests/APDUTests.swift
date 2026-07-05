import JPKICard
import NFCTransport
import Testing

@Suite("APDU")
struct APDUTests {
    @Test("SELECT JPKI applet encodes command header and AID")
    func selectAppletEncoding() {
        let command = JPKIApplet.selectApplicationCommand()

        #expect(command.encoded == [
            0x00, 0xA4, 0x04, 0x0C, 0x0A,
            0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01
        ])
    }

    @Test("PIN retry count is decoded from 63Cx status")
    func pinRetryStatus() throws {
        let response = try APDUResponse(encoded: [0x63, 0xC3])

        #expect(response.status == .pinVerificationFailed(retriesRemaining: 3))
        #expect(response.pinRetryCount == 3)
    }

    @Test("Signing PIN accepts only 6 to 16 ASCII alphanumerics")
    func signingPINPolicy() {
        #expect(SigningPINPolicy.isValidFormat("ABC123"))
        #expect(SigningPINPolicy.isValidFormat("1234567890ABCDEF"))
        #expect(!SigningPINPolicy.isValidFormat("12345"))
        #expect(!SigningPINPolicy.isValidFormat("1234567890ABCDEFG"))
        #expect(!SigningPINPolicy.isValidFormat("ABC-123"))
        #expect(!SigningPINPolicy.isValidFormat("１２３４５６"))
    }

    @Test("Card signing service selects AP, PIN EF, verifies, selects key EF, and signs DigestInfo")
    func cardSigningServiceSequence() async throws {
        let digestInfo = Array(repeating: UInt8(0xAB), count: 51)
        let signature = Array(repeating: UInt8(0xCD), count: 256)
        let transport = RecordingTransport(responses: [
            APDUResponse(data: [], sw1: 0x90, sw2: 0x00), // SELECT AP
            APDUResponse(data: [], sw1: 0x90, sw2: 0x00), // SELECT EF(sign PIN)
            APDUResponse(data: [], sw1: 0x90, sw2: 0x00), // VERIFY
            APDUResponse(data: [], sw1: 0x90, sw2: 0x00), // SELECT EF(sign key)
            APDUResponse(data: signature, sw1: 0x90, sw2: 0x00) // COMPUTE DIGITAL SIGNATURE
        ])

        let result = try await JPKICardSigningService(transport: transport).signDigestInfo(digestInfo, pin: "ABC123")

        let commands = await transport.commands
        #expect(result == signature)
        #expect(commands.map(\.ins) == [0xA4, 0xA4, 0x20, 0xA4, 0x2A])
        #expect(commands[1].p1 == 0x02)
        #expect(commands[1].data == JPKIApplet.EF.signaturePIN)
        #expect(commands[3].data == JPKIApplet.EF.signaturePrivateKey)
        #expect(commands.last?.data == digestInfo)
    }

    @Test("Retry query reads 63Cx without sending PIN data")
    func retryQuerySequence() async throws {
        let transport = RecordingTransport(responses: [
            APDUResponse(data: [], sw1: 0x90, sw2: 0x00), // SELECT EF(sign PIN)
            APDUResponse(data: [], sw1: 0x63, sw2: 0xC5) // VERIFY (query)
        ])

        let retries = try await JPKICardSigningService(transport: transport).signingPINRetryCount()

        let commands = await transport.commands
        #expect(retries == 5)
        #expect(commands.map(\.ins) == [0xA4, 0x20])
        #expect(commands[1].data.isEmpty)
        #expect(commands[1].encoded == [0x00, 0x20, 0x00, 0x80])
    }

    @Test("Certificate reader parses DER length and chunks READ BINARY")
    func certificateRead() async throws {
        // 700-byte certificate: 0x30 0x82 0x02 0xB8 + 696 content bytes.
        var certificate: [UInt8] = [0x30, 0x82, 0x02, 0xB8]
        certificate.append(contentsOf: (0..<696).map { UInt8($0 % 251) })

        let transport = RecordingTransport(responses: [
            APDUResponse(data: [], sw1: 0x90, sw2: 0x00), // SELECT EF(sign cert)
            APDUResponse(data: Array(certificate[0..<4]), sw1: 0x90, sw2: 0x00),
            APDUResponse(data: Array(certificate[4..<260]), sw1: 0x90, sw2: 0x00),
            APDUResponse(data: Array(certificate[260..<516]), sw1: 0x90, sw2: 0x00),
            APDUResponse(data: Array(certificate[516..<700]), sw1: 0x90, sw2: 0x00)
        ])

        let bytes = try await JPKICardSigningService(transport: transport).readSignatureCertificate()

        let commands = await transport.commands
        #expect(bytes == certificate)
        #expect(commands.map(\.ins) == [0xA4, 0xB0, 0xB0, 0xB0, 0xB0])
        #expect(commands[0].data == JPKIApplet.EF.signatureCertificate)
        // Offsets ride in P1/P2 with bit 8 of P1 clear.
        #expect(commands[2].p1 == 0x00 && commands[2].p2 == 0x04)
        #expect(commands[3].p1 == 0x01 && commands[3].p2 == 0x04)
        #expect(commands[4].p1 == 0x02 && commands[4].p2 == 0x04)
        // Final chunk requests exactly the remaining bytes.
        #expect(commands[4].encoded.last == UInt8(700 - 516))
    }

    @Test("Certificate reader rejects a non-SEQUENCE header")
    func certificateReadRejectsBadHeader() async throws {
        let transport = RecordingTransport(responses: [
            APDUResponse(data: [], sw1: 0x90, sw2: 0x00),
            APDUResponse(data: [0xFF, 0x82, 0x02, 0xB8], sw1: 0x90, sw2: 0x00)
        ])

        await #expect(throws: CertificateReaderError.invalidDERHeader) {
            try await JPKICardSigningService(transport: transport).readSignatureCertificate()
        }
    }
}

private actor RecordingTransport: ISO7816Transport {
    private var responses: [APDUResponse]
    private(set) var commands: [APDUCommand] = []

    init(responses: [APDUResponse]) {
        self.responses = responses
    }

    func transmit(_ command: APDUCommand) async throws -> APDUResponse {
        commands.append(command)
        return responses.removeFirst()
    }
}
