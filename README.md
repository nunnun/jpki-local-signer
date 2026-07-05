# JPKI Local Signer

[![conformance](https://github.com/nunnun/jpki-local-signer/actions/workflows/conformance.yml/badge.svg)](https://github.com/nunnun/jpki-local-signer/actions/workflows/conformance.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-iOS%2017%2B%20%7C%20macOS%2014%2B-lightgrey.svg)](#対応端末)

**On-device PDF signing and verification with Japan's My Number Card (マイナンバーカード) — no servers, no closed SDKs, no network access.**
JPKI Local Signer reads the JPKI signing certificate from a physical My Number Card (over Core NFC on iPhone/iPad, or a USB PC/SC reader on macOS), builds a detached CMS (PKCS#7) signature and embeds it into a PDF entirely on-device, targeting the `adbe.pkcs7.detached` format required by Japan's registry e-filing system (登記・供託オンライン申請システム). It also verifies signed PDFs offline — signature value, document integrity, and certificate-chain trust (JPKI roots are bundled and pinned) — and can co-sign (multiple signers via incremental update). The entire pipeline is open source so that the claim "your signing material never leaves the device" can be independently audited.

---

## 目的

利用者本人が、自分のマイナンバーカードを使って、自分のPDF文書に **iOS端末上のみで完結する形で電子署名** を施し、電子登記申請（登記・供託オンライン申請システム）に提出可能な「電子署名付きPDFファイル」（`adbe.pkcs7.detached` 準拠）を生成するためのアプリです。

- カード内の秘密鍵はカードの外に出ません（COMPUTE DIGITAL SIGNATURE をカード内で実行し、署名値のみを受け取ります）。
- 署名対象のハッシュ計算・CMS（PKCS#7 SignedData）の組み立て・PDFへの埋め込みは、すべて端末内で完結します。
- サーバー・クラウド・外部の署名API・PF（プラットフォーム）事業者は一切利用しません。

## 大切にしていること：透明性・監査可能性

本プロジェクトが重視するのは、機能の豊富さよりも **透明性** です。

- **ネットワーク通信を一切実装しません。** `URLSession` などの通信APIをリンクせず、ビルド構成上もネットワーク到達手段を持ちません。これは [`scripts/check-no-network.sh`](scripts/check-no-network.sh) で機械的に検証でき、CIでも実行できます。
- **クローズドSDKに依存しません。** 依存ライブラリはすべてソースが公開されたOSS（Apple公式の swift-crypto / swift-certificates / swift-asn1、いずれも Apache-2.0）のみです。
- **機微データをログ出力・永続化しません。** PIN、ハッシュ値、署名値、カードからの応答は一切ログに出さず、ディスクにも書き出しません。
- **すべてOSS（Apache License 2.0）で公開します。** 署名パイプライン全体をレビュー・再現ビルドできます。

詳細な設計方針・脅威モデルの根拠は [`docs/design.md`](docs/design.md) を参照してください。

## アーキテクチャ概要

Swift Package（`JPKILocalSigner`）としてコアロジックをモジュール分割し、各層を独立にテスト可能にしています。UIはSwiftUIアプリ（`JPKILocalSignerApp`）から、このパッケージのAPIを呼び出します。

| モジュール | 役割 |
|---|---|
| `NFCTransport` | カードとの APDU 送受信ラッパ（async/await）。iOS は Core NFC（`NFCTagReaderSession` / ISO 7816）、macOS は CryptoTokenKit（`TKSmartCard`／USB PC/SC リーダー）。共通の `ISO7816Transport` プロトコルで抽象化。 |
| `JPKICard` | JPKI-AP（アプリケーション）の操作。AP/EF の SELECT、署名用PINのVERIFY・残回数取得、証明書読み出し、COMPUTE DIGITAL SIGNATURE によるカード内署名。 |
| `CMSBuilder` | PKCS#7 detached SignedData の構築（外部署名値を swift-asn1 でDER手組み・証明書内包）と、検証用の CMS パース（BER 不定長・signedAttrs 有無・証明書チェーン内包に対応）。 |
| `PDFSigning` | PDFの署名辞書付与、ByteRange計算、増分更新による `/Contents` 埋め込み。xref ストリーム・間接 AcroForm/Annots・連署（既存署名を保持した追加署名）に対応。 |
| `SelfVerify` | 署名済みPDFの静的検証（全署名の ByteRange 整合・CMS パース・messageDigest 一致・RSA 署名値検証）と、同梱 JPKI ルートへのチェーン照合による信頼分類（JPKI / 自己署名 / 他認証局）、RFC 3161 文書タイムスタンプの識別。失効確認（CRL/OCSP）は行わない。 |
| `JPKILocalSigner` | 上記を束ねるトップレベルAPI。iOS の NFC 署名（`JPKINFCPDFSigner`）、macOS の USB リーダー署名（`JPKISmartCardPDFSigner`）、証明書表示（`SignerCertificateSummary`）。 |
| `JPKILocalSignerApp`（Xcodeプロジェクト） | iOS + ネイティブ macOS の SwiftUI アプリ。署名（取り込み・プレビュー・PIN入力・かざし/リーダー操作・結果）と検証（全署名の判定・信頼分類・証明書詳細・登記適合チェック）の両モードを提供。 |

## ビルド方法

### 必要環境

- Xcode 26 系
- iOS 17.0 以降をターゲットとする実機（NFC搭載 iPhone。シミュレータではCore NFCは動作しません）

### 手順

1. リポジトリをクローンします。
2. `JPKILocalSignerApp.xcodeproj` を Xcode で開きます。
3. `JPKILocalSignerApp` ターゲットの **Signing & Capabilities** で、**自分の Apple Developer チーム（Development Team）** を選択してください。本プロジェクトの署名用プロビジョニングプロファイルは同梱されていないため、OSSとして自己ビルドする方は各自のチームでプロビジョニングし直す必要があります。
4. 以下のCapability / Entitlementが設定されていることを確認します（既にプロジェクトに含まれています）。
   - Capability: **Near Field Communication Tag Reading**
   - Entitlement: `com.apple.developer.nfc.readersession.iso7816.select-identifiers` に JPKI-AP の AID `D392F000260100000001` を宣言
   - `Info.plist` の `NFCReaderUsageDescription`（NFC利用理由の説明文）
5. NFC搭載の実機を接続し、ビルド・実行します。

> App Store配布にはこれらのentitlementの承認が必要です。自己ビルドで実機テストのみ行う場合は、通常の開発用プロビジョニングプロファイルで動作します。

## macOS での実カード署名（USB IC カードリーダー）

署名パイプラインは macOS でもそのまま動作し、USB の IC カードリーダー
（PC/SC 対応）経由でマイナンバーカード署名を実行できます（CryptoTokenKit）。

```sh
scripts/card-sign.sh --card-info                 # リーダーとカードの診断
scripts/card-sign.sh --card-sign in.pdf out.pdf  # 実カードで署名（PIN はエコーなし入力）
scripts/card-sign.sh --verify signed.pdf         # 署名検証
scripts/card-sign.sh --moj signed.pdf            # 登記適合チェック
```

TKSmartCardSlotManager の利用には `com.apple.security.smartcard` entitlement が
必要なため、スクリプトがビルド後に ad-hoc 署名を行います。PIN 残回数は
VERIFY 前に照会され、残り1回の場合は中断します（試行を消費しません）。

## テストの実行方法

コアロジック（Swift Package部分）のテストは、Xcodeを介さずコマンドラインから実行できます。

```sh
env DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test
```

主なテスト内容:

- `APDUTests`: APDUコマンドの組み立て、ステータスワード（SW1/SW2）の解釈
- `CMSBuilderTests`: DigestInfo構築、CMS DERの検証
- `PDFSigningTests`: ByteRange計算の整合性
- `SelfVerifyTests`: 生成した署名済みPDFの自己検証
- `JPKILocalSignerTests`: 署名フロー全体の結合テスト

アプリ側のUI/ユニットテスト（`JPKILocalSignerAppTests` / `JPKILocalSignerAppUITests`）はXcodeから実行してください。

ネットワークAPI不使用の検証は以下で行えます。

```sh
./scripts/check-no-network.sh
```

## 対応端末

- **iOS / iPadOS 17.0 以降**: NFC搭載の iPhone（`NFCTagReaderSession` によるISO 7816通信に対応した機種）。かざして署名。
- **macOS 14.0 以降**: USB の IC カードリーダー（PC/SC 対応）を接続して署名。ネイティブ macOS アプリ（Mac Catalyst ではない）。

物理カード方式のため、Wallet搭載カード（スマホ用署名用電子証明書）のような iOS 18.5 以降 / iPhone XS 以降といった機種制約は受けません。検証（署名の確認）は iOS / macOS のどちらでも、カード不要で行えます。

## ドキュメント

- [`docs/design.md`](docs/design.md) — 設計仕様・脅威モデル・スコープ
- [`docs/BUILD.md`](docs/BUILD.md) — ビルド手順・ツールチェーン・再現性
- [`sbom.json`](sbom.json) — 依存関係（CycloneDX、version/revision/license）
- [`docs/APP_STORE.md`](docs/APP_STORE.md) — App Store 配布準備（プライバシー・輸出コンプライアンス・審査ノート）
- [`SECURITY.md`](SECURITY.md) / [`CONTRIBUTING.md`](CONTRIBUTING.md)

## 重要な注意事項

- **APDUの各種定数（AID・EF識別子・P1/P2・SW解釈など）（design.md R-01）**: JPKIカードのAPDU仕様は開かれた規範文書として公開されておらず、本リポジトリの定数は公開実装・商用ライブラリ間で相互裏付けした値です。**2026-07-05 に実物のマイナンバーカード（USB PC/SC リーダー・macOS）で AP SELECT・署名用PINの残回数照会と VERIFY・署名用証明書の READ BINARY・COMPUTE DIGITAL SIGNATURE を実行し、生成した署名が証明書公開鍵・OpenSSL・登記適合チェックで検証できることを確認済み**（`scripts/card-sign.sh`）。ただし1枚のカード・1機種のリーダーでの確認であり、他世代のカードでは引き続き検証を推奨します。
- **登記・供託オンライン申請システムでの受理可否は、提出者ご自身の責任で必ず事前確認してください（design.md R-06）。** 法務省は「規定の形式・設定値を満たしていれば独自生成物も利用可」としていますが、ホワイトリスト方式ではなく仕様適合方式であり、受理を保証するものではありません。

## 免責事項

- 本アプリは電子署名を **生成** するツールであり、署名を **検証** するサービスではありません。失効確認（CRL等）は行いません。検証は提出先システムの責務です。
- 本アプリは公的個人認証法第17条に基づく主務大臣認定の対象ではありません（同認定は署名検証者に対する制度であり、署名生成のみを行う本アプリは対象外です）。
- 本アプリの利用は自己責任でお願いします。詳細は [`SECURITY.md`](SECURITY.md) を参照してください。

## 謝辞

マイナンバーカードによる PDF 電子署名の道を切り拓いてきた先行プロジェクト、とりわけ [hirukawa/jpki-pdf-signer](https://github.com/hirukawa/jpki-pdf-signer)（Windows・OSS）に敬意と感謝を表します。あわせて、依存ライブラリである Apple の swift-crypto / swift-asn1 / swift-certificates（いずれも Apache-2.0）、および署名用CA証明書を公開する J-LIS に感謝します（詳細は [`NOTICE`](NOTICE)）。

`jpki-local-signer` の `local` は、本プロジェクトの核である「サーバにも認定事業者にも依存せず、端末内で完結する」という設計方針を表しています。iOS/iPadOS には他アプリから呼び出せる公式クライアントライブラリが存在しないため Core NFC でカードと直接 APDU 通信し、macOS では USB の PC/SC リーダーを利用します。詳細は [`docs/design.md`](docs/design.md) を参照してください。

## ライセンス

[Apache License 2.0](LICENSE)。第三者コンポーネントの謝辞・同梱 J-LIS 証明書の出所は [`NOTICE`](NOTICE) を参照してください。
