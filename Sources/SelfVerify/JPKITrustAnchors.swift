import Foundation
import X509

/// JPKI 署名用CA（公的個人認証サービス）のルート証明書。iOS のシステム信頼
/// ストアには含まれないため、アプリに同梱してピン留めする。
///
/// 出典: J-LIS 配布の署名用CA証明書（世代 01〜03）。SHA-256 フィンガープリント:
/// - jpki-signca01.cer (2015-2025):
///   196454 05A1FE 143774 34BD55 957628 AC4038 557C54 2403A2 243F21 C706FC 9355
/// - jpki-signca02.cer (2019-2029):
///   79679C 33E4CC 931944 0F1AD1 20A597 FF1844 E2EF21 7063AD B17696 6FD5E6 FBEB
/// - jpki-signca03.cer (2023-2033):
///   D227F6 CDE11D 35C525 2178F1 06F843 D24651 944975 413B53 9FA2FB 68DBFA 365F
///
/// 上記3件は J-LIS 公表のフィンガープリントとの一致を確認済み (2026-07-04)。
/// 更新時も J-LIS 公表値との照合を必須とする。アプリの「このアプリについて」
/// 画面（AboutView）にも同じ値を表示しており、両者は一致していること。
enum JPKITrustAnchors {
    /// Parsed anchors. Certificates that fail to load are skipped (the
    /// classifier then simply cannot anchor to them).
    static let certificates: [Certificate] = {
        guard let urls = Bundle.module.urls(forResourcesWithExtension: "cer", subdirectory: "TrustAnchors") else {
            return []
        }
        return urls.sorted { $0.lastPathComponent < $1.lastPathComponent }.compactMap { url in
            guard let data = try? Data(contentsOf: url) else { return nil }
            return try? Certificate(derEncoded: [UInt8](data))
        }
    }()
}
