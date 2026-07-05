import Foundation
import NFCTransport

public enum JPKIApplet {
    // Public references disagree on some low-level JPKI APDU constants. Keep them centralized for hardware validation.
    public static let applicationIdentifier: [UInt8] = [0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01]

    public static func selectApplicationCommand() -> APDUCommand {
        APDUCommand.selectFile(identifier: applicationIdentifier)
    }

    /// EF identifiers inside the JPKI AP. Cross-checked against public
    /// references and validated on a real card (R-01).
    public enum EF {
        /// 署名用パスワード (signature PIN). VERIFY target.
        public static let signaturePIN: [UInt8] = [0x00, 0x1B]
        /// 署名用秘密鍵. COMPUTE DIGITAL SIGNATURE target.
        public static let signaturePrivateKey: [UInt8] = [0x00, 0x1A]
        /// 署名用電子証明書 (DER). Readable only after signature PIN VERIFY.
        public static let signatureCertificate: [UInt8] = [0x00, 0x01]
        /// 署名用電子証明書のCA証明書.
        public static let signatureCACertificate: [UInt8] = [0x00, 0x02]
        /// 利用者証明用電子証明書 (auth). PIN 不要で読める — 実機で
        /// READ BINARY 経路を検証する診断用途に使う。
        public static let authenticationCertificate: [UInt8] = [0x00, 0x0A]
    }
}
