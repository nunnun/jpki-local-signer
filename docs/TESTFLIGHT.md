# TestFlight 提出用コピー（コピペ用）

App Store Connect → TestFlight に貼り付ける文面。内部テストは Beta App Review
不要。外部テストは「Test Information」＋「Beta App Review」が必要で、以下が要る。

---

## Test Information（外部テストで1回だけ）

### Beta App Description（ベータ版の説明）

**日本語**
> マイナンバーカードでPDFに電子署名するアプリのベータ版です。iPhoneのNFCでカードを読み取り、署名用電子証明書で `adbe.pkcs7.detached` 形式のCMS署名をPDFに付与します（登記・供託オンライン申請システム向け）。カード内の秘密鍵はカードの外に出ず、署名・検証はすべて端末内で完結します。ネットワーク通信は一切行いません。

**English**
> Beta of an app that digitally signs PDFs with Japan's My Number Card (マイナンバーカード). It reads the card over NFC and embeds an `adbe.pkcs7.detached` CMS signature into a PDF for Japan's registry e-filing system. The card's private key never leaves the card; signing and verification run entirely on-device with no network access.

### Feedback Email
App Store Connect に直接入力する（フィードバック用メールアドレス）。公開リポジトリには記載しない。

### Marketing URL
`https://github.com/nunnun/jpki-local-signer`

### Privacy Policy URL
データを一切収集せず通信もしないため簡潔なポリシーで足りる。リポジトリに
`docs/PRIVACY.md` を置いてその URL を使うか、既存の説明ページを指定する。
（未作成なら別途用意する。）

---

## What to Test（ビルドごと）

**日本語**
> - 署名フロー：PDFを選ぶ → 署名用PINを入力 → マイナンバーカードをiPhone上部にかざす → 署名付きPDFが生成されるか
> - 検証フロー：署名付きPDFを開き、署名値・改ざん有無・証明書チェーンの検証結果が正しく表示されるか
> - 登記適合チェックの表示
> - 「Sign」ボタンの見た目・挙動、日本語/英語の表示
> ※ 署名には実物のマイナンバーカードとNFC対応iPhone（iOS 17以降）が必要です。

---

## App Review への申し送り（Review Notes）— 英語で記入

> This app's **signing** feature requires a physical Japanese My Number Card
> (マイナンバーカード) and NFC, which a reviewer typically cannot test. The
> card's private key never leaves the card: the app runs COMPUTE DIGITAL
> SIGNATURE on-card and embeds only the resulting signature into a PDF
> (`adbe.pkcs7.detached`, for Japan's government registry e-filing system).
>
> **No card needed to review the app:** use the **Verify** tab — open a signed
> PDF and the app validates the signature value, document integrity, and
> certificate chain fully offline. A sample signed PDF is attached to this
> submission.
>
> There is **no sign-in / account**, and the app makes **no network requests**
> (it links no networking APIs; this is enforced by `scripts/check-no-network.sh`).
> It collects no data.

*(審査担当者が検証フローを試せるよう、署名済みサンプル PDF を提出物に添付する
とよい。`swift run TestSigner out.pdf テスト署名者 <入力PDF>` で自己署名の
サンプルを生成できる。)*

### Contact Information（Beta App Review 用）
- 氏名 / メール / 電話番号を記入（審査時の連絡先）。

### Sign-In Required?
- **No**（ログイン不要）。

---

## 提出フロー

1. ビルドが App Store Connect で「処理完了」になるまで待つ（数分〜15分）
2. **内部テスト**：TestFlight → Internal Testing にテスターを追加 → 即配信（レビュー不要）
3. **外部テスト**：上記 Test Information を記入 → 外部グループを作成しビルドを割当 → **Beta App Review に提出** → 通過後に配信
