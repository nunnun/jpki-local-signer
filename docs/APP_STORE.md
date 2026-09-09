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
- **プライバシーポリシー URL**: [`docs/PRIVACY.md`](PRIVACY.md) を GitHub Pages
  （`main` / `docs` ソース）で公開し、`https://nunnun.github.io/jpki-local-signer/privacy/`
  を掲載メタデータの `privacy_url`（`fastlane/metadata/ja` / `en-US`）に使用。

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

## 一般公開（App Store）提出フロー

TestFlight 配布（`fastlane beta`）と同じビルド基盤・同じ App Store Connect API
キーを使い、**TestFlight に上げたビルドをそのまま App Store に昇格**する。掲載
情報は [`fastlane/metadata/`](../fastlane/metadata)（deliver 形式・`ja` / `en-US`）
にテキストで版管理している。

### fastlane レーン

| レーン | 用途 |
|---|---|
| `fastlane beta` | Release ビルドを作成し TestFlight へアップロード（ビルド番号 `yyMMddHHmm` をログ出力） |
| `fastlane upload_metadata` | 掲載文面のみ反映（バイナリ・スクショ・審査提出なし・冪等）。コピー調整の反復用 |
| `fastlane release build_number:<n>` | TestFlight の当該ビルドを昇格。メタデータ同期 + 審査提出。`submit:false` でメタデータのみのドライラン、`with_screenshots:true` で `fastlane/screenshots` も反映 |

CI からは [`.github/workflows/appstore.yml`](../.github/workflows/appstore.yml)
（`workflow_dispatch` 限定）で `fastlane release` を手動起動できる。`v*` タグには
紐付けていない（タグ push で審査自動提出しないため）。

### スクリーンショット

署名フローは Core NFC / 実カードが必要でシミュレータでは完了できないため、**カード
不要の画面**を撮る（検証結果・署名詳細・登記適合チェック・「このアプリについて」・
取り込み/プレビュー/PIN 入力の NFC 直前まで）。`swift run TestSigner out.pdf テスト署名者 <入力PDF>`
で生成したサンプル署名 PDF を検証タブで開いて撮影する。`fastlane/screenshots/<locale>/`
（`ja` / `en-US`）に配置。必須サイズ: iPhone 6.9"（例 16 Pro Max）、iPad 13"（iPad 対応のため）。

### 審査対策

主要機能（署名）は実物のマイナンバーカードが必要で審査担当者が試せない。対策として
[`fastlane/metadata/review_information/notes.txt`](../fastlane/metadata/review_information/notes.txt)
に「Verify タブはカード不要で検証可能」「サンプル署名 PDF を添付」等を英語で記載済み。
**サンプル署名 PDF の添付は deliver に項目がなく手動**（App Store Connect → App Review
Information → Attachment）。`swift run TestSigner` で生成して添付する。

## App Store Connect 上の手動作業（自動化不可）

`fastlane/metadata` で管理できず、App Store Connect の UI / API で設定する項目:

- [ ] アプリレコード作成（Bundle ID `biz.geekproject.JPKILocalSignerApp` / SKU / 主要言語 = 日本語）
- [ ] App Privacy「栄養ラベル」=「データを収集しない（No Data Collected）」
- [ ] 年齢レーティング質問票
- [ ] 価格 = 無料 / 配信地域
- [ ] App Review Information にサンプル署名 PDF を添付
- [ ] `fastlane/metadata/review_information/` の連絡先（氏名・電話・メール）を実値に差し替え（現状プレースホルダ）
- [ ] `fastlane/metadata/copyright.txt` の権利者表記を確認
- [ ] GitHub リポジトリ設定で Pages を `main` / `docs` に有効化（プライバシーポリシー URL）
- [ ] 審査通過後に「Release this version」を手動で押下（`automatic_release: false`）

## リリース前チェック

- [ ] `MARKETING_VERSION` が公開版（例 `1.0.0`）
- [ ] `swift test` 全パス、iOS / macOS 両ビルド成功
- [ ] `./scripts/check-no-network.sh` パス
- [ ] スクリーンショット（検証・登記適合チェック・カード不要 UI）を `fastlane/screenshots` に配置
- [ ] `fastlane/metadata` の文字数・カテゴリを precheck で検証（`fastlane release submit:false` のドライラン）
- [ ] プライバシー栄養ラベル =「データを収集しない」／プライバシーポリシー URL が到達可能
- [ ] 輸出コンプライアンス =「適用除外」
- [ ] macOS: 公証（Developer ID の場合。Mac App Store は今回のスコープ外）
