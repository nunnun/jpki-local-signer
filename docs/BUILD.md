# ビルド手順・再現性

本書は JPKI Local Signer を再現可能な形でビルドするための手順と、依存関係
（SBOM）の確認方法をまとめる。設計上の透明性方針（ネットワーク非依存・
クローズドSDK非依存）を、ビルド時に機械的に検証できることを重視する。

## ツールチェーン

| 項目 | 値 |
|---|---|
| Swift | 6.0 以上（`Package.swift` の tools-version）。開発・検証は 6.2〜6.3 系で実施 |
| Xcode | 26 系（`/Applications/Xcode.app`） |
| iOS 最小デプロイメントターゲット | 17.0 |
| macOS 最小デプロイメントターゲット | 14.0 |

macOS の CLI では `xcode-select` が Command Line Tools を指していると
swift-testing 等が見つからないため、コマンドは
`DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer` を前置する。

## 依存関係（すべて Apple 公式 OSS・Apache-2.0）

`Package.resolved`（version 3）でリビジョン単位に固定している。正確な
version / revision / license は [`sbom.json`](../sbom.json)（CycloneDX 1.5）
を参照。

| パッケージ | version | 用途 |
|---|---|---|
| apple/swift-crypto | 4.5.0 | SHA-256/384/512、RSA PKCS#1 v1.5 署名検証（`_CryptoExtras`） |
| apple/swift-asn1 | 1.7.0 | DER（swift-certificates 経由の推移的依存） |
| apple/swift-certificates | 1.19.1 | X.509 パース・チェーン署名検証（信頼分類） |

クローズドSDK・C バインディング（OpenSSL 等）・ネットワークライブラリは
一切含まない。

## パッケージのビルドとテスト

```sh
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
swift build
swift test          # 42 tests / 6 suites
```

## アプリのビルド

iOS（署名は Core NFC、要 NFC entitlement・実機）:

```sh
xcodebuild -project JPKILocalSignerApp.xcodeproj -scheme JPKILocalSignerApp \
  -destination 'generic/platform=iOS' build
```

macOS（署名は USB PC/SC リーダー、要 smartcard entitlement）:

```sh
xcodebuild -project JPKILocalSignerApp.xcodeproj -scheme JPKILocalSignerApp \
  -destination 'platform=macOS' build
```

共有スキーム `JPKILocalSignerApp` はアプリターゲットのみをビルドする
（テンプレートの Tests/UITests ターゲットは未整備）。

## 透明性の機械的検証

```sh
# ネットワーク API を一切リンクしていないこと（NFR-01）
./scripts/check-no-network.sh

# 生成物が登記オンライン申請の形式要件に適合すること（C1〜C9）
swift run TestSigner /tmp/base_signed.pdf                 # 適合サンプル生成
python3 tools/conformance-check/check.py /tmp/base_signed.pdf
```

CI（`.github/workflows/conformance.yml`）でも上記を毎コミット実行する。

## 再現性について

- 依存は `Package.resolved` のリビジョンで固定。同一ツールチェーン + 同一
  `Package.resolved` で同一のソースが取得される。
- パッケージ自体はビルドスクリプト・コード生成・ネットワークアクセスを
  持たない（プラグイン不使用）。
- SwiftPM はビルド時に依存を取得するため、完全オフライン再現には事前に
  `swift package resolve` 済みの `.build`／キャッシュ、またはミラーを用いる。
- macOS 実カード署名の検証には `scripts/card-sign.sh`（ビルド後に
  `com.apple.security.smartcard` entitlement で ad-hoc 署名して実行）を使う。

## 同梱データの検証

`Sources/SelfVerify/TrustAnchors/` の JPKI 署名用CA ルート証明書は、
`Sources/SelfVerify/JPKITrustAnchors.swift` およびアプリの「このアプリに
ついて」画面に記載の SHA-256 フィンガープリントと一致する。更新時は
J-LIS 公表値との照合を必須とする。

```sh
for f in Sources/SelfVerify/TrustAnchors/*.cer; do
  echo "$f"; openssl x509 -inform DER -in "$f" -noout -fingerprint -sha256
done
```
