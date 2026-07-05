import Crypto
import Foundation
import JPKILocalSigner
import PDFSigning
import SelfVerify
import SwiftASN1
import X509
import _CryptoExtras

/// TestSigner: generates a signed sample PDF with a fresh RSA-2048 key and a
/// matching self-signed certificate, then runs the full self-verification.
/// Used by the conformance checker's tests and CI as a known-conforming
/// input. Development tool only — no card access, no networking.
///
/// Usage:
///   swift run TestSigner <output.pdf> [signer-name] [input.pdf]
///   swift run TestSigner --verify <signed.pdf>
///
/// Without input.pdf a built-in minimal one-page PDF is signed; with it the
/// given unsigned PDF is signed instead (useful for exercising the preparer
/// against real-world files). `--verify` runs the on-device verifier
/// (structure, digest, certificate binding, RSA signature; no revocation)
/// against every signature in an existing PDF.
@main
struct TestSignerMain {
    static func main() async {
        let arguments = CommandLine.arguments
        guard arguments.count >= 2 else {
            fail("usage: TestSigner <output.pdf> [signer-name] [input.pdf] | --verify <signed.pdf>")
        }

        if arguments[1] == "--verify" {
            guard arguments.count >= 3 else {
                fail("usage: TestSigner --verify <signed.pdf>")
            }
            verify(path: arguments[2])
            return
        }

        if arguments[1] == "--moj" {
            guard arguments.count >= 3 else {
                fail("usage: TestSigner --moj <signed.pdf>")
            }
            mojCheck(path: arguments[2])
            return
        }

        #if os(macOS)
        if arguments[1] == "--card-info" {
            await cardInfo()
            return
        }

        if arguments[1] == "--card-sign" {
            guard arguments.count >= 4 else {
                fail("usage: TestSigner --card-sign <input.pdf> <output.pdf>")
            }
            await cardSign(inputPath: arguments[2], outputPath: arguments[3])
            return
        }
        #endif
        let outputURL = URL(fileURLWithPath: arguments[1])
        let signerName = arguments.count >= 3 ? arguments[2] : "テスト署名者"

        var sourcePDF = minimalUnsignedPDF()
        if arguments.count >= 4 {
            do {
                sourcePDF = try Data(contentsOf: URL(fileURLWithPath: arguments[3]))
            } catch {
                fail("cannot read input PDF: \(error)")
            }
        }

        do {
            let key = try _RSA.Signing.PrivateKey(keySize: .bits2048)
            let certificateDER = try selfSignedCertificateDER(for: key, commonName: signerName)
            let input = LocalPDFSigningInput(
                pdf: sourcePDF,
                certificateDER: certificateDER,
                signerName: signerName,
                signingDate: Date()
            )

            // Two-pass signing: preparation is deterministic for a fixed
            // date, so a probe pass discovers the signedAttrs the real
            // signature must cover (mirroring how the card signs a
            // DigestInfo).
            let probe = try await LocalPDFSigner.sign(input: input) { _ in
                [UInt8](repeating: 0xAB, count: 256)
            }
            let signature = try key.signature(
                for: SHA256.hash(data: Data(probe.signedAttributesDER)),
                padding: .insecurePKCS1v1_5
            )
            let result = try await LocalPDFSigner.sign(input: input, verification: .full) { _ in
                Array(signature.rawRepresentation)
            }

            try result.signedPDF.write(to: outputURL)
            print("TestSigner: wrote \(result.signedPDF.count) bytes to \(outputURL.path) (full self-verification passed)")
        } catch {
            fail("signing failed: \(error)")
        }
    }

    static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data("TestSigner: \(message)\n".utf8))
        exit(1)
    }

    #if os(macOS)
    /// Diagnostics: list PC/SC readers and, when a card is present, probe
    /// the JPKI AP and the PIN retry counter (consumes no attempts).
    static func cardInfo() async {
        guard let readers = await SmartCardSession.availableReaders() else {
            fail("""
            スマートカードサービスにアクセスできません。
            サンドボックス化されたプロセスでは com.apple.security.smartcard entitlement が必要です。
            """)
        }
        if readers.isEmpty {
            print("カードリーダーが見つかりません。USB リーダーを接続してください。")
            exit(1)
        }
        for reader in readers {
            print("リーダー: \(reader.slotName) — カード\(reader.cardPresent ? "あり" : "なし")")
        }
        guard readers.contains(where: \.cardPresent) else {
            exit(1)
        }

        do {
            try await SmartCardSession.run { transport in
                let service = JPKICardSigningService(transport: transport)
                try await service.selectApplication()
                print("JPKI AP: SELECT 成功")
                let retries = try await service.signingPINRetryCount()
                print("署名用パスワード残り試行回数: \(retries)")

                // READ BINARY 経路の検証: 認証用証明書は PIN 不要で読める。
                let selectAuth = try await transport.transmit(.selectEF(identifier: JPKIApplet.EF.authenticationCertificate))
                guard selectAuth.isSuccess else {
                    print("認証用証明書 EF SELECT 失敗: \(selectAuth.status)")
                    return
                }
                let certificateDER = try await CertificateReader(transport: transport).readCertificate()
                print("認証用証明書 読み出し成功: \(certificateDER.count) bytes")
                if let summary = try? SignerCertificateSummary(certificateDER: certificateDER) {
                    print("  Subject CN: \(summary.commonName ?? "?")")
                    print("  有効期間: \(summary.notValidBefore) 〜 \(summary.notValidAfter)")
                    print("  発行者: \(summary.issuerDistinguishedName)")
                }
            }
        } catch {
            fail("カード通信に失敗: \(error)")
        }
    }

    /// Real-card signing over a USB reader (macOS). The same pipeline the
    /// iOS app uses with NFC. PIN is read without echo and never logged.
    static func cardSign(inputPath: String, outputPath: String) async {
        guard let pdf = try? Data(contentsOf: URL(fileURLWithPath: inputPath)) else {
            fail("cannot read input PDF")
        }
        guard let rawPIN = getpass("署名用パスワード (6-16桁英数字): ") else {
            fail("PIN の読み取りに失敗")
        }
        let pin = String(cString: rawPIN).uppercased()

        do {
            let signedPDF: Data = try await SmartCardSession.run { transport in
                let service = JPKICardSigningService(transport: transport)
                try await service.selectApplication()

                let retries = try await service.signingPINRetryCount()
                print("残り試行回数: \(retries)")
                if retries == 0 {
                    fail("暗証番号がロックされています。市区町村の窓口で初期化してください。")
                }
                if retries == 1 {
                    fail("残り1回のため中断しました（誤入力するとロックされます）。")
                }

                try await service.verifySigningPIN(pin)
                print("PIN 検証成功")

                let certificateDER = try await service.readSignatureCertificate()
                let summary = try SignerCertificateSummary(certificateDER: certificateDER)
                print("署名者: \(summary.displayName ?? "?")")
                print("証明書有効期間: \(summary.notValidBefore) 〜 \(summary.notValidAfter)")

                let result = try await LocalPDFSigner.sign(
                    input: LocalPDFSigningInput(
                        pdf: pdf,
                        certificateDER: certificateDER,
                        signerName: summary.displayName ?? "署名者",
                        signingDate: Date()
                    ),
                    verification: .full
                ) { digestInfo in
                    try await service.signDigestInfo(digestInfo)
                }
                return result.signedPDF
            }

            try signedPDF.write(to: URL(fileURLWithPath: outputPath))
            print("署名済み PDF を書き出しました: \(outputPath)（完全自己検証パス済み）")

            let conformance = MOJConformanceChecker.check(pdf: signedPDF)
            print("登記適合チェック: \(conformance.isConformant ? "PASS（提出可能な形式）" : "FAIL")")
        } catch {
            fail("カード署名に失敗: \(error)")
        }
    }
    #endif

    static func mojCheck(path: String) {
        guard let pdf = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            fail("cannot read PDF")
        }
        let result = MOJConformanceChecker.check(pdf: pdf)
        for item in result.items {
            print("\(item.checkID)  \(item.status.rawValue)  \(item.detail)")
        }
        print("RESULT: \(result.isConformant ? "PASS" : "FAIL")")
        exit(result.isConformant ? 0 : 1)
    }

    static func verify(path: String) {
        let pdf: Data
        do {
            pdf = try Data(contentsOf: URL(fileURLWithPath: path))
        } catch {
            fail("cannot read PDF: \(error)")
        }

        let inspection = SignedPDFVerifier.inspect(pdf: pdf)
        var failed = false
        for (index, verdict) in inspection.verdicts.enumerated() {
            switch verdict {
            case .valid(let report):
                var details: [String] = []
                if let summary = try? SignerCertificateSummary(certificateDER: report.cms.certificateDER) {
                    details.append("signer=\(summary.displayName ?? "?")")
                }
                if report.kind == .documentTimestamp {
                    details.append("kind=timestamp")
                    if let date = report.timestampDate {
                        details.append("genTime=\(date)")
                    }
                }
                details.append(report.cms.isDirectSignature ? "profile=direct" : "profile=signedAttrs")
                details.append(report.coversWholeFile ? "covers=whole-file" : "covers=own-revision")
                switch report.trust {
                case .selfSigned: details.append("trust=self-signed")
                case .jpki: details.append("trust=JPKI")
                case .otherAuthority(let issuer): details.append("trust=other-CA(\(issuer))")
                case .unverifiable(let reason): details.append("trust=unverifiable(\(reason))")
                }
                print("signature \(index + 1)/\(inspection.verdicts.count): VALID (\(details.joined(separator: ", ")))")
            case .invalid(let reason):
                failed = true
                print("signature \(index + 1)/\(inspection.verdicts.count): INVALID — \(reason)")
            }
        }
        if inspection.hasUnsignedTrailingData {
            print("note: document was modified (incrementally updated) after the newest signature")
        }
        exit(failed ? 1 : 0)
    }

    static func selfSignedCertificateDER(
        for key: _RSA.Signing.PrivateKey,
        commonName: String
    ) throws -> [UInt8] {
        let privateKey = Certificate.PrivateKey(key)
        let name = try DistinguishedName {
            CommonName(commonName)
        }
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: privateKey.publicKey,
            notValidBefore: Date().addingTimeInterval(-3600),
            notValidAfter: Date().addingTimeInterval(5 * 365 * 24 * 3600),
            issuer: name,
            subject: name,
            signatureAlgorithm: .sha256WithRSAEncryption,
            extensions: Certificate.Extensions {},
            issuerPrivateKey: privateKey
        )
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return serializer.serializedBytes
    }

    static func minimalUnsignedPDF() -> Data {
        var pdf = Data()
        var offsets: [Int] = [0]

        func appendObject(_ number: Int, _ body: String) {
            offsets.append(pdf.count)
            pdf.append(contentsOf: "\(number) 0 obj\n\(body)\nendobj\n".utf8)
        }

        pdf.append(contentsOf: "%PDF-1.7\n".utf8)
        appendObject(1, "<< /Type /Catalog /Pages 2 0 R >>")
        appendObject(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        appendObject(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>")
        appendObject(4, "<< /Length 58 >>\nstream\nBT /F1 24 Tf 72 700 Td (JPKI Local Signer sample) Tj ET\nendstream")
        appendObject(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        let xrefOffset = pdf.count
        pdf.append(contentsOf: "xref\n0 6\n0000000000 65535 f \n".utf8)
        for offset in offsets.dropFirst() {
            pdf.append(contentsOf: String(format: "%010d 00000 n \n", offset).utf8)
        }
        pdf.append(contentsOf: "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n\(xrefOffset)\n%%EOF\n".utf8)
        return pdf
    }
}
