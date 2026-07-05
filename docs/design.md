# JPKI Local Signer（`jpki-local-signer`）— 機能要件・技術スタック仕様書

> 本書は、マイナンバーカードの署名用電子証明書を用い、**iOS端末上だけで完結する**PDF電子署名アプリの設計仕様である。電子登記申請（登記・供託オンライン申請システム）の「電子署名付きPDFファイル」要件を満たすことを目標とする。本書は OSS 公開を前提とし、後続の Claude Code による実装の入力として用いる。
>
> 作成日: 2026-06-20 / 想定読者: 実装者（Claude Code 含む）・レビュアー

| 項目 | 値 |
|---|---|
| リポジトリ名 | `jpki-local-signer` |
| Swift package / ターゲット名 | `JPKILocalSigner` |
| 表示名 | JPKI Local Signer |

---

## 0. 設計上の確定事項（前段調査の結論）

本仕様に至るまでに以下を一次ソースで確認済み。詳細根拠は §12 参照。

- **サーバ依存方式は不採用**。デジタル認証アプリの署名APIはサーバ（RPサーバ＋デジタル庁OP）を介する設計で端末内完結が不可能。加えて民間が署名APIを使う場合、大臣認定プラットフォーム事業者との連携が必須で、署名値・証明書がPF事業者へJWE暗号化返却される構造のため回避不能。透明性・自己完結の目標と不整合。
- **Wallet搭載カード（スマホ用署名用電子証明書）は不採用**。サードパーティが端末内で署名を完結する経路が現状存在しない（Verify with Wallet API は検証専用、署名はマイナポータル/マイナアプリ経由のサーバ依存）。
- **採用方式 = 物理カード + Core NFC + APDU 直接通信 + 端末内 CMS/PDF 組み立て**。秘密鍵はカード外に出ず、外部サーバ・外部事業者の関与が一切ない唯一の方式。
- **署名生成のみを行うため、公的個人認証法第17条の主務大臣認定は不要**（認定は「署名検証者」の要件。検証は提出先の登記システムが行う）。

---

## 1. プロジェクト概要と OSS 方針

### 1.1 目的

利用者本人が、自分のマイナンバーカードで、自分のPDF文書に、iOS端末上のみで電子署名を施し、電子登記申請に提出可能な署名付きPDFを生成する。

### 1.2 OSS 公開方針（透明性確保の中核）

本アプリの存在理由は「署名処理パイプライン全体が監査可能であること」である。本プロジェクトが重視するのは機能の豊富さではなく**透明性**である。

- **ライセンス**: Apache License 2.0 を推奨。
  - 理由: 依存ライブラリ（swift-crypto / swift-certificates / swift-asn1）がすべて Apache-2.0 でライセンス整合。特許条項を含み、暗号・セキュリティ用途で安全。MIT も選択肢だが特許明示の観点で Apache-2.0 を優先。
  - ※これは推奨であり最終決定は要承認。
- **透明性を担保する設計上の制約（後述 NFR と連動）**:
  - **ネットワーク通信を一切実装しない**。`URLSession` 等の通信APIを使用せず、ビルド構成上もネットワーク到達手段を持たない。「署名材料が端末外へ出ないこと」をコードレビューで検証可能にする。
  - 全依存はソースが公開された OSS のみ。クローズドSDK（PF事業者SDK等）を導入しない。
  - 暗証番号（PIN）・ハッシュ・署名値・カード応答を**永続化もログ出力もしない**。
- **リポジトリ同梱物**: `LICENSE`、`SECURITY.md`（後述の免責・脅威モデル）、`README.md`（ビルド手順・entitlement取得手順）、`CONTRIBUTING.md`、再現ビルド手順。
- **免責**: 本アプリは署名「生成」ツールであり署名検証サービスではない。主務大臣認定対象外。利用は自己責任である旨を `SECURITY.md` と起動時に明記。

### 1.3 設計方針・命名・先行事例への謝辞

**先行事例への謝辞**: マイナンバーカードを用いた PDF 電子署名は、[hirukawa/jpki-pdf-signer](https://github.com/hirukawa/jpki-pdf-signer)（Windows・OSS）をはじめとする先行プロジェクトが道を切り拓いてきた。本プロジェクトはそれらの成果に敬意を表する。

**設計含意**: デスクトップOSには公式クライアントソフト（ライブラリ）へ処理を委譲できる経路が存在するが、iOS/iPadOS にはサードパーティのアプリから呼び出せる同等の公開ライブラリが存在しない。そのため iOS では Core NFC で**カードと直接 APDU 通信する**方式を採り、端末内完結・ネットワーク非依存・全工程監査可能を設計の中核に置く。macOS では USB の PC/SC リーダーを CryptoTokenKit 経由で同様に扱う。

**命名**: `jpki-local-signer` の `local` は、本プロジェクトの核である「サーバにも認定事業者にも依存せず端末内で完結する」という設計方針を名称で表現している。

---

## 2. スコープ

### 2.1 やること（In Scope）

- 物理マイナンバーカードの NFC 読み取り（Core NFC / ISO 7816）
- 署名用電子証明書（公開鍵証明書）の読み出し
- 署名用PINの検証（残回数表示・ロック前警告）
- カード内署名（COMPUTE DIGITAL SIGNATURE, RSASSA-PKCS1-v1_5 / SHA-256）
- CMS（PKCS#7）SignedData（detached）の端末内組み立て
- PDFへの署名辞書付与・ByteRange計算・`/Contents`埋め込み（adbe.pkcs7.detached準拠）
- 複数署名（連署）: 署名済みPDFへの増分更新による追加署名。既存署名のバイト列を保持し、Acrobat 連署と同一構造を生成
- 署名検証ビューア: PDF内の全署名の静的検証（構造・ByteRange被覆・messageDigest・証明書拘束・RSA署名値）を端末内で実行し結果表示。signedAttrs 有無（直接署名方式）、BER 不定長、証明書チェーン内包、連署の版被覆に対応。※失効確認は行わない
- 署名済みPDFの保存・共有（Files / 共有シート）

### 2.2 やらないこと（Out of Scope）

- サーバ通信・クラウド処理（恒久的に持たない）
- Wallet搭載カード（スマホ用署名用電子証明書）対応
- デジタル認証アプリ連携
- 失効確認（CRL/OCSP）・証明書チェーンのトラストアンカー検証 — 提出先システムの責務（署名値・構造の静的検証はアプリ内で提供する。In Scope 参照）
- PAdES（ETSI EN 319 142）対応 — 登記要件は adbe.pkcs7.detached であり対象外
- 「署名付きPDFフォルダ」(PDF+XML) 方式 — 申請用総合ソフト専用のため生成不可

---

## 3. 機能要件（FR）

| ID | 要件 | 受け入れ基準 |
|---|---|---|
| FR-01 | PDF読み込み | Files/共有シート経由でローカルPDFを入力できる。複数ページ可。 |
| FR-02 | 署名対象プレビュー | 署名前にPDF内容を表示し、利用者が対象を確認できる。 |
| FR-03 | カード検出 | `NFCTagReaderSession`(.iso14443) でカードを検出し、JPKI-AP を SELECT できる。 |
| FR-04 | 証明書読み出し | 署名用電子証明書（DER）を読み出し、氏名・有効期限を表示できる。 |
| FR-05 | PIN入力 | 署名用PIN（英数字6〜16桁）を安全に入力できる（マスク表示、貼り付け制御）。 |
| FR-06 | PIN残回数管理 | VERIFY前に残回数を取得し、残り少数で警告。5回連続失敗でロックされる旨を事前明示。ロック時は窓口初期化が必要と案内。 |
| FR-07 | カード署名 | signedAttrs のダイジェストに対し COMPUTE DIGITAL SIGNATURE を実行し署名値を取得する。 |
| FR-08 | CMS生成 | detached CMS SignedData（署名者証明書を内包、SHA-256, RSA）を端末内で構築する。 |
| FR-09 | PDF署名埋め込み | 署名辞書（§7.3の設定値）を付与し、ByteRangeを正しく計算、`/Contents`にCMSを埋め込む。 |
| FR-10 | 出力保存 | 署名済みPDFをFilesへ保存／共有できる。元PDFは非破壊。 |
| FR-11 | 自己検証（任意） | 生成直後に自PDFの署名構造（ByteRange整合・CMSパース・証明書一致）を端末内で静的検証し結果表示。※失効確認は行わない。 |
| FR-12 | エラー提示 | カード切断・PIN誤り・証明書失効/期限切れ・未搭載等を明確な日本語メッセージで提示。 |

### 3.1 主要ユーザーフロー

1. PDFを取り込む → 2. 内容確認 → 3. 署名用PIN入力 → 4. 「カードをかざす」→ NFCセッション開始 → 5. AP SELECT → 証明書読み出し → PIN VERIFY → 署名実行（**一連のかざし継続中に完了**）→ 6. CMS構築 → PDF埋め込み → 7. 保存/共有。

---

## 4. 非機能要件（NFR）

| ID | 区分 | 要件 |
|---|---|---|
| NFR-01 | セキュリティ/透明性 | ネットワーク通信機能を一切持たない。通信APIをリンクしない。 |
| NFR-02 | セキュリティ | PIN・ハッシュ・署名値・カード応答を永続化しない。メモリ上の機微データは使用後すみやかにゼロ化。 |
| NFR-03 | プライバシー | ログに機微情報（PIN/署名値/証明書シリアル等）を出力しない。クラッシュレポートSDKも導入しない。 |
| NFR-04 | 監査性 | 署名パイプラインを独立モジュールに分離し、テストで各段の入出力を検証可能にする（PIN/署名値を除く）。 |
| NFR-05 | 可用性 | NFCセッションのタイムアウト（約20秒）内に証明書読み出し＋VERIFY＋署名を完了する設計とする。 |
| NFR-06 | 保守性 | 依存は最小限・最新安定版に固定（§5）。バージョンは明示ピン。 |
| NFR-07 | 互換性 | 登記・供託オンライン申請システムの「電子署名付きPDFファイル」要件（§7.3）に適合。 |
| NFR-08 | アクセシビリティ | VoiceOver対応、PIN入力・かざし操作のガイドを提供。 |

---

## 5. 技術スタック（バージョンは 2026-06-20 時点の最新安定版で確認済み）

### 5.1 開発環境

| 項目 | 採用 | 備考 |
|---|---|---|
| 言語 | Swift 6.3.1 | 2026-04-17 リリースの最新安定版。Strict Concurrency 前提。 |
| IDE/ツールチェーン | Xcode 26 系 | iOS 26 と整合する現行系列。 |
| 最小デプロイメントターゲット | iOS 17.0 | 物理カード方式のためWallet版の iOS 18.5 要件に非依存。Core NFC ISO7816 は iOS 13+ だが、Swift 6 並行性と広い端末カバレッジのバランスで 17.0 を floor とする。 |
| 検証対象OS | iOS 26.5.1（現行） | 現行最新でのリグレッション確認。 |
| パッケージ管理 | Swift Package Manager | CocoaPods/Carthage は使用しない。 |

### 5.2 依存ライブラリ（すべて Apache-2.0 / OSS）

| パッケージ | バージョン | ライセンス | 用途 |
|---|---|---|---|
| apple/swift-crypto | 4.5.0 | Apache-2.0 | SHA-256、DigestInfo構築補助、定数時間比較。 |
| apple/swift-certificates | 1.19.1 | Apache-2.0 | X.509署名用証明書のDERパース、証明書チェーン取り扱い。 |
| apple/swift-asn1 | 1.7.0 | Apache-2.0 | CMS(PKCS#7) SignedData の DER エンコード/デコード（**外部署名値の注入のため低レベルASN.1で構築**）。 |

> いずれも純Swift・Apple公式・Apache-2.0。OpenSSL等のCバインディングを避け、ビルド再現性とライセンス整合性を確保する。

### 5.3 OS フレームワーク

| フレームワーク | 用途 |
|---|---|
| CoreNFC | `NFCTagReaderSession` / `NFCISO7816Tag` によるAPDU送受信。 |
| PDFKit | PDFの表示・正規化（**署名埋め込みには使わない**。低レベル埋め込みは自前実装。§7.4）。 |
| CryptoKit（補助） | 端末標準のSHA-256等。swift-cryptoと役割重複時はswift-cryptoに一本化可。 |
| UniformTypeIdentifiers / Files | 入出力・共有。 |

### 5.4 重要な技術判断：CMS は外部署名値で手組みする

swift-certificates の CMS API は「秘密鍵オブジェクトで署名する」前提で、**カードが計算した外部署名値を注入する経路を持たない**。本アプリの署名鍵はカード内にあり外部に出ないため、高レベルCMS APIは使用できない。

→ **swift-asn1 を用いて CMS `SignedData` / `SignerInfo` を低レベルに構築**し、`signatureAlgorithm`=`sha256WithRSAEncryption`、`signature`=カード応答（生RSA署名値）を設定する。証明書のDERは swift-certificates でパース・内包。これは本プロジェクトの中核実装であり、テストで重点的に検証する。

---

## 6. アーキテクチャ / モジュール構成

レイヤを分離し、各層を独立テスト可能にする（監査性 NFR-04）。

```
JPKILocalSigner/
├─ Package.swift                    # SPM 依存ピン（§5.2）
├─ Sources/
│  ├─ NFCTransport/                 # Core NFC セッション管理・APDU送受信（async/await ラッパ）
│  │   ├─ APDUCommand.swift
│  │   ├─ APDUResponse.swift        # SW1/SW2 解釈、PIN残回数抽出
│  │   └─ NFCSession.swift
│  ├─ JPKICard/                     # JPKI-AP 操作（カード仕様の抽象化）
│  │   ├─ JPKIApplet.swift          # SELECT AP / SELECT EF
│  │   ├─ PINVerifier.swift         # 署名用PIN VERIFY・残回数
│  │   └─ CardSigner.swift          # COMPUTE DIGITAL SIGNATURE
│  ├─ CMSBuilder/                   # PKCS#7 detached SignedData（外部署名値注入）
│  │   ├─ SignedAttributes.swift
│  │   ├─ DigestInfo.swift
│  │   └─ CMSSignedData.swift       # swift-asn1 で DER 構築
│  ├─ PDFSigning/                   # PDF署名辞書・ByteRange・/Contents 埋め込み
│  │   ├─ PDFSignaturePreparer.swift  # プレースホルダ確保・増分更新
│  │   ├─ ByteRangeCalculator.swift
│  │   └─ PDFSignatureEmbedder.swift
│  ├─ SelfVerify/                   # 生成PDFの静的自己検証（任意, FR-11）
│  └─ App/                          # SwiftUI UI・フロー制御
└─ Tests/
   ├─ CMSBuilderTests/             # 既知ベクタでのCMS DER一致
   ├─ PDFSigningTests/             # ByteRange整合・往復検証
   └─ APDUTests/                   # APDU組み立て・SW解釈
```

---

## 7. 署名パイプライン詳細（実装の核）

### 7.1 APDU シーケンス（論理フロー）

```
1. SELECT FILE  : JPKI-AP を選択      （AID: D3 92 F0 00 26 01 00 00 00 01 ※要検証）
2. SELECT FILE  : 署名用PIN の EF を選択
3. VERIFY       : 署名用PIN を検証     （事前に残回数を取得し警告）
4. SELECT FILE  : 署名用秘密鍵の EF を選択
5. COMPUTE DIGITAL SIGNATURE : DigestInfo(SHA-256) を入力し署名値を取得
```

> **ソース品質の注意**: JPKI カードの APDU 詳細（各 EF 識別子・P1/P2・残回数を返す SW の解釈）は規範文書として開かれた形では公開されていない。上記は公開実装・商用ライブラリ間で相互裏付けされた水準であり、**実装時に動作するリファレンス（OSS実装やテストカード応答）で各値を実機検証すること**。AID も含め定数は検証対象。
>
> ※ただし J-LIS は「利用者クライアントソフトに係る技術仕様」を公開している（§12 参照）。これは**利用者クライアントソフト（ライブラリ）のAPI仕様**であり、本プロジェクトが直接叩く生APDUレベルの定義を含むとは限らないが、R-01 緩和の手がかりとして実装着手時に精査する。

### 7.2 暗号パラメータ

- 署名鍵: RSA-2048（カード内）
- 署名方式: RSASSA-PKCS1-v1_5
- ダイジェスト: SHA-256
- カード入力: SHA-256 ハッシュに DigestInfo（ASN.1; sha256 OID）を付加したもの
- 署名対象: 後述 signedAttrs の DER の SHA-256 → DigestInfo 化 → カードへ

### 7.3 登記が要求する PDF 署名設定値（法務省一次仕様・適合必須）

「電子署名付きPDFファイル」方式。Adobe PDF Public-Key Digital Signature and Encryption Specification Version 3.2 の PKCS#7 Signature Format 部に準拠。

| 項目 | 値 |
|---|---|
| Type | `Sig` |
| Filter | 設定値は問わない（法務省仕様）。本実装は慣用値 Adobe.PPKLite を使用 |
| SubFilter | `adbe.pkcs7.detached` |
| Name | 電子署名者の氏名 |
| M | 署名時刻 |
| ByteRange | 署名対象バイト範囲（`/Contents` を除く2区間） |
| Contents | PKCS#7 署名データ（16進バイナリ） |

> 法務省仕様で値が規定されているのは Type / SubFilter / Name / M / ByteRange / Contents。Filter およびその他領域は「設定値は問いません」とされている。

> 法務省ページは列挙ツール（PDF署名プラグイン/Acrobat/SkyPDF等）以外で作成した場合も「規定の形式・設定値を満たしていれば利用可」とし、開発元が適合性を確認する前提。**ホワイトリストではなく仕様適合方式**である。自前生成の適合性は §10 で検証する。

### 7.4 PDF 埋め込み手順（detached / 増分更新）

iOS には detached PDF 署名を完結できる成熟 OSS ライブラリが存在しないため、増分更新（incremental update）を自前実装する。

```
1. （必要なら）PDFKit で入力PDFを正規化
2. 署名辞書 + 署名フィールドを増分更新で追記。
   /Contents は固定長のゼロ埋め16進プレースホルダで確保
3. /Contents を除いた2区間として ByteRange を確定
4. ByteRange のバイト列を SHA-256 でハッシュ化 → messageDigest
5. signedAttrs（contentType=data, messageDigest, signingTime）を構築 → DER
6. signedAttrs DER の SHA-256 → DigestInfo 化 → カードで署名（§7.1-5）
7. 署名値で CMS SignedData(detached) を構築（証明書内包・signedAttrs内包）
8. CMS の DER を16進化し、確保済み /Contents プレースホルダへ上書き
9. ファイル確定
```

> 注意: ByteRange と `/Contents` 長は手順2で**先に固定**し、CMS長がプレースホルダ長を超えないよう十分なマージンを確保する。CMS長は証明書サイズに依存するため、確保長は実測の上で決定する。

---

## 8. iOS 固有の前提・設定

- **Entitlement**: `com.apple.developer.nfc.readersession.iso7816.select-identifiers` に JPKI-AP の AID を宣言。`NFCReaderUsageDescription`（Info.plist）必須。「Near Field Communication Tag Reading」Capability を有効化。
- **配布**: App Store 配布には上記 entitlement が必要（決済AIDは禁止だが JPKI AID は実績多数で許可される）。OSS 利用者の自己ビルドには各自のプロビジョニングプロファイルが必要。READMEに手順を明記。
- **対応端末**: NFC 搭載 iPhone（物理カード方式のため Wallet 対応要件 iOS 18.5 / iPhone XS 以降には縛られない）。

---

## 9. 既知の技術的リスク・課題

| リスク | 内容 | 対応方針 |
|---|---|---|
| R-01 APDU仕様の非公開 | EF識別子・P1/P2・SW解釈が規範文書として開かれた形で非公開 | リファレンス実装/テストカードで実機検証。定数を1箇所に集約し検証可能にする。J-LIS「利用者クライアントソフト技術仕様」（§12）も精査し、低レベル定義の有無を確認する。 |
| R-02 CMS外部署名値 | 高レベルCMS APIが外部署名に非対応 | swift-asn1 で手組み（§5.4）。既知ベクタでDER一致テスト。 |
| R-03 PDF署名OSS不在 | iOSにdetached PDF署名の成熟ライブラリなし | 増分更新を自前実装（§7.4）。往復検証テスト。 |
| R-04 NFCタイムアウト | 約20秒内に証明書+VERIFY+署名を完了必要 | APDU往復を最小化。証明書はチャンク読み出しを最適化。 |
| R-05 PINロック | 5回失敗でロック→窓口初期化 | 残回数を事前取得・警告。誤入力抑止UI。 |
| R-06 登記適合の実証 | 自前PDFが登記で受理されるかは要実証 | §10 の手順で検証。受理可否は提出前に必ず確認。 |
| R-07 ByteRange/Contents長 | CMS長がプレースホルダを超過する恐れ | 確保長を実測マージン付きで決定。境界テスト。 |
| R-08 カード世代差 | 将来のカード更改で鍵長/アルゴリズム変更の可能性 | 現行は RSA-2048/SHA256。アルゴリズムを抽象化し将来差し替え可能に。 |

---

## 10. テスト・適合性検証戦略

- **単体**: APDU 組み立て/SW 解釈、DigestInfo 構築、CMS DER の既知ベクタ一致、ByteRange 計算。
- **結合（往復）**: 生成した署名付きPDFを、独立実装（例: Acrobat の署名検証、OpenSSL `pkcs7`/`asn1parse`、`pdfsig`）でパースし、構造・ダイジェスト整合・証明書一致を確認。
- **適合性**: §7.3 の設定値が出力に正しく現れることを機械的に検証。適合性チェッカ（`tools/conformance-check`、Python + pikepdf）が署名辞書の各キー・ByteRange の被覆・CMS 構造・messageDigest 一致を決定論的に検査し、CI で毎コミット実行する。
- **登記適合の実証**: 登記・供託オンライン申請システムの仕様・受理可否を提出前に確認（自前生成物は開発元責任で適合確認、と法務省が明記しているため）。
- **実機**: テスト用マイナンバーカード（J-LIS 入手）で署名〜検証の通し確認。

---

## 11. OSS 公開チェックリスト

- [x] `LICENSE`（Apache-2.0）
- [x] `README.md`（目的・ビルド手順・entitlement・対応端末・免責）
- [x] `SECURITY.md`（脅威モデル・機微データ非永続/非送信・認定対象外・脆弱性報告窓口）
- [x] `CONTRIBUTING.md`
- [x] 依存バージョンのピン（§5.2）と SBOM（`sbom.json`）
- [x] ネットワークAPI不使用の保証（`scripts/check-no-network.sh` + CI）
- [x] 機微情報のログ出力がないことのレビュー観点を文書化（SECURITY.md / CONTRIBUTING.md）
- [ ] 秘匿情報（証明書・PIN・鍵）をリポジトリに含めない
- [x] 再現ビルド手順（`docs/BUILD.md`）
- [x] 適合性チェッカ同梱（第三者が出力の適合を独立検証可能）
- [x] App Store 配布準備（`docs/APP_STORE.md`・プライバシーマニフェスト・輸出コンプライアンス）
- [x] アクセシビリティ対応（NFR-08 監査済み）

---

## 12. 参照（一次ソース優先・到達確認済み）

**規範・公式（一次）**
- 法務省 登記・供託オンライン申請システム「PDFファイルへの電子署名の付与」（adbe.pkcs7.detached 等の署名形式・設定値）: https://www.touki-kyoutaku-online.moj.go.jp/cautions/append/sign_pdf.html
- デジタル庁 開発者サイト「デジタル認証アプリ 実装ガイドライン」（署名API=サーバ依存・PF事業者必須の根拠）: https://developers.digital.go.jp/documents/auth-and-sign/implement-guideline/
- デジタル庁 デジタル認証アプリ FAQ「署名APIに大臣認定は必要か」（PF事業者連携必須）: https://support.aas.digital.go.jp/hc/ja/articles/33751574713625-
- Apple Developer「Entitlements」（iso7816 select-identifiers）: https://developer.apple.com/documentation/bundleresources/entitlements
- Apple Developer「Get started with the Verify with Wallet API」（用途＝検証専用）: https://developer.apple.com/wallet/get-started-with-verify-with-wallet/

**実装参考（要精査・APDU/低レベル）**
- J-LIS「利用者クライアントソフトに係る技術仕様について」（R-01の手がかり。利用者クライアントソフトのAPI仕様であり、生APDU定義の有無は要確認）: https://www.j-lis.go.jp/jpki/procedure/procedure1_2_3.html

**バージョン根拠（一次）**
- Swift（6.3.1, 2026-04-17）: https://www.swift.org/
- apple/swift-certificates（1.19.1, Apache-2.0）: https://github.com/apple/swift-certificates/releases
- apple/swift-crypto（4.5.0, Apache-2.0）: https://github.com/apple/swift-crypto
- apple/swift-asn1（1.7.0, Apache-2.0）: https://github.com/apple/swift-asn1
- Apple security releases（iOS 現行 26.5.1）: https://support.apple.com/en-us/100100

> APDU レベルの定数（EF識別子・P1/P2・SW解釈）は開かれた規範文書が乏しいため、実装時に動作リファレンスで実機検証する前提とする（R-01）。
