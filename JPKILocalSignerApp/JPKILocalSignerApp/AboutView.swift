//
//  AboutView.swift
//  JPKILocalSignerApp
//
//  First-launch / about disclaimer (design.md §1.2): OSS signing tool,
//  no network communication, self-responsibility disclaimer.

import SwiftUI

struct AboutView: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Label("ネットワーク通信は一切行いません", systemImage: "wifi.slash")
                    Label("暗証番号・署名値・証明書情報は端末外に送信されません", systemImage: "lock.shield")
                    Label("PINやカードの応答内容を保存・記録することはありません", systemImage: "eye.slash")
                } header: {
                    Text("このアプリについて")
                }

                Section {
                    Text("JPKI Local Signer は、マイナンバーカードの署名用電子証明書を使い、iPhone 単体で PDF に電子署名を行うオープンソースのツールです。署名処理はすべて端末内で完結し、外部サーバーや事業者を経由しません。")
                    Text("本アプリは電子署名を「生成」するツールであり、署名の検証サービスではありません。生成した署名付きPDFの提出先での受理可否は、利用者ご自身で提出先の要件をご確認ください。")
                    Text("本アプリの利用は自己責任で行ってください。作者は利用により生じたいかなる損害についても責任を負いません。")
                } header: {
                    Text("免責事項")
                }

                Section {
                    Text("暗証番号を5回連続で間違えるとカードがロックされ、市区町村窓口での初期化が必要になります。")
                        .foregroundStyle(.secondary)
                } header: {
                    Text("ご注意")
                }

                Section {
                    Text("署名検証で「公的個人認証サービス（JPKI）」と判定する際は、以下の J-LIS 公表の署名用CA（ルート）証明書との照合を行います。SHA-256 フィンガープリント:")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    ForEach(Self.trustAnchorFingerprints, id: \.name) { anchor in
                        VStack(alignment: .leading, spacing: 4) {
                            Text("\(anchor.name)（\(anchor.validity)）")
                                .font(.subheadline.weight(.medium))
                            Text(anchor.fingerprint)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                        }
                        .accessibilityElement(children: .combine)
                    }
                    Text("失効確認（CRL/OCSP）は行いません。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } header: {
                    Text("同梱している JPKI ルート証明書")
                }
            }
            .navigationTitle("このアプリについて")
            .inlineNavigationBarTitle()
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("閉じる") {
                        dismiss()
                    }
                }
            }
        }
        .macOSSheetFrame(minHeight: 620)
    }
}

private extension AboutView {
    /// Sources/SelfVerify/TrustAnchors/ に同梱している JPKI 署名用CA
    /// ルート証明書の SHA-256 フィンガープリント。J-LIS 公表値との一致を
    /// 確認済み (2026-07-04)。JPKITrustAnchors.swift の記載と一致すること。
    static let trustAnchorFingerprints: [(name: String, validity: String, fingerprint: String)] = [
        (
            "署名用CA 01",
            "2015–2025",
            "1964 5405 A1FE 1437 7434 BD55 9576 28AC 4038 557C 5424 03A2 243F 21C7 06FC 9355"
        ),
        (
            "署名用CA 02",
            "2019–2029",
            "7967 9C33 E4CC 9319 440F 1AD1 20A5 97FF 1844 E2EF 2170 63AD B176 966F D5E6 FBEB"
        ),
        (
            "署名用CA 03",
            "2023–2033",
            "D227 F6CD E11D 35C5 2521 78F1 06F8 43D2 4651 9449 7541 3B53 9FA2 FB68 DBFA 365F"
        )
    ]
}

#Preview {
    AboutView()
}
