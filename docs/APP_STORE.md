# App Store 配布準備チェックリスト

本アプリを App Store（iOS）および必要に応じて Mac App Store / Developer ID
配布（macOS）に提出するための準備事項。OSS 利用者が各自のアカウントで配布
する場合の手引きも兼ねる。

## プライバシー

- **プライバシーマニフェスト**: [`PrivacyInfo.xcprivacy`](../JPKILocalSignerApp/JPKILocalSignerApp/PrivacyInfo.xcprivacy) を同梱。
  - `NSPrivacyTracking = false`、トラッキングドメインなし。
  - `NSPrivacyCollectedDataTypes` は空（**何も収集しない**）。
  - `NSPrivacyAccessedAPITypes` は空（required-reason API 不使用。ファイル
    アクセスは自アプリの一時ディレクトリのみで、タイムスタンプ API 等は
    使わない）。
- **App Store Connect のプライバシー「栄養ラベル」**: 「データを収集しない
  （No Data Collected）」を選択。ネットワーク通信がないため送信も追跡もない。

## 輸出コンプライアンス（暗号）

- ビルド設定に `INFOPLIST_KEY_ITSAppUsesNonExemptEncryption = NO` を追加済み
  （Info.plist に `ITSAppUsesNonExemptEncryption = false` として反映）。
- 根拠: 本アプリの暗号利用は**電子署名の生成・検証と認証**に限られ、
  米国 EAR の適用除外に該当する（データ機密のための暗号化は行わない）。
  提出時の輸出コンプライアンス質問には「該当する適用除外のみを使用」で回答。

## iOS 固有

- **Capability**: Near Field Communication Tag Reading を有効化。
- **Entitlement**: `com.apple.developer.nfc.readersession.iso7816.select-identifiers`
  に JPKI AID `D392F000260100000001`、および
  `com.apple.developer.nfc.readersession.formats = [TAG]`
  （[`JPKILocalSignerApp.entitlements`](../JPKILocalSignerApp/JPKILocalSignerApp/JPKILocalSignerApp.entitlements)）。
- **Info.plist**: `NFCReaderUsageDescription`（NFC 使用目的の日本語説明）。
- **対応端末**: NFC 搭載 iPhone、iOS 17 以降。
- 決済系 AID は宣言しない（JPKI AID は実績が多く審査を通過する）。

## macOS 固有

- ネイティブ macOS ターゲット（Mac Catalyst ではない。CryptoTokenKit の
  `TKSmartCardSlotManager` は macOS ネイティブのみ）。
- **Entitlement**: App Sandbox 有効、`com.apple.security.smartcard`、
  `com.apple.security.files.user-selected.read-write`
  （[`JPKILocalSignerApp-macOS.entitlements`](../JPKILocalSignerApp/JPKILocalSignerApp/JPKILocalSignerApp-macOS.entitlements)）。
- Developer ID 配布の場合は **公証（notarization）** が必要。
- 対応: USB PC/SC 対応 IC カードリーダー、macOS 14 以降。

## 審査ノート（App Review への申し送り）

- 本アプリの主要機能はマイナンバーカード（実物の IC カード）を必要とし、
  審査担当者が実機確認できない可能性がある。**DEBUG ビルドの開発検証用
  署名パス**（一時鍵による自己署名）で署名・検証フローを再現できる旨を
  記載するとよい。ただし提出ビルドは Release であり当該パスは含まれない。
- ネットワーク通信は一切行わない。サーバーもアカウントも不要。
- 検証機能は端末内のみで完結し、失効確認（CRL/OCSP）は行わない旨をアプリ
  内（検証画面フッター・「このアプリについて」）に明記済み。

## 免責・表記

- 本アプリは署名「生成」ツールであり署名検証サービスではない。公的個人認証
  法第17条の主務大臣認定の対象外である旨を「このアプリについて」に明記済み。
- 生成物が提出先（登記・供託オンライン申請システム）で受理されるかは利用者
  自身が確認する前提。アプリ内「登記適合チェック」は形式要件の目安であり
  受理を保証しない。

## リリース前チェック

- [ ] `swift test` 全パス、iOS / macOS 両ビルド成功
- [ ] `./scripts/check-no-network.sh` パス
- [ ] スクリーンショット（署名・検証・登記適合チェック）
- [ ] プライバシー栄養ラベル =「データを収集しない」
- [ ] 輸出コンプライアンス =「適用除外」
- [ ] macOS: 公証（Developer ID の場合）
