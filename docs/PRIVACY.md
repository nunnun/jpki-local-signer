# プライバシーポリシー / Privacy Policy

**JPKI Local Signer**

最終更新 / Last updated: 2026-07-10

---

## 日本語

JPKI Local Signer（以下「本アプリ」）は、利用者のプライバシーを最優先に設計されています。

### 収集する情報
本アプリは、**個人情報を含む一切のデータを収集・送信・追跡しません。**

- サーバーやクラウドを利用せず、**ネットワーク通信を一切行いません**（通信用 API をアプリに組み込んでいません）。
- 署名用パスワード（PIN）は**保存しません**。カードへ受け渡した後、直ちに破棄します。
- マイナンバーカード内の秘密鍵は**カードの外に出ません**。署名演算はカード内で実行され、本アプリは署名値のみを受け取ります。
- 署名対象の文書・ハッシュ値・署名値・カードからの応答を、**ログ出力せず、ディスクにも永続化しません**（署名済み PDF の保存先は利用者が明示的に選んだ場所のみ）。
- 解析・トラッキング・広告の仕組みは一切含みません。

### 権限の利用目的
- **NFC**：マイナンバーカードの読み取り（署名用電子証明書の取得とカード内署名）にのみ使用します。
- **ファイルアクセス**：利用者が選択した PDF の読み込みと、署名済み PDF の保存にのみ使用します。

### データの第三者提供
収集するデータ自体が存在しないため、第三者への提供はありません。

### お問い合わせ
GitHub Issues: https://github.com/nunnun/jpki-local-signer/issues

---

## English

JPKI Local Signer ("the app") is designed with user privacy as the top priority.

### Information we collect
The app **does not collect, transmit, or track any data, including personal information.**

- It uses **no servers or cloud services and makes no network requests** (no networking APIs are linked into the app).
- The signing password (PIN) is **never stored**; it is discarded immediately after being passed to the card.
- The private key on the My Number Card **never leaves the card**. The signing operation runs on-card, and the app receives only the resulting signature value.
- Documents, hashes, signature values, and card responses are **never logged or persisted** to disk (signed PDFs are saved only to a location the user explicitly chooses).
- The app contains no analytics, tracking, or advertising.

### Why permissions are used
- **NFC** is used solely to read the My Number Card (to obtain the signing certificate and to sign on-card).
- **File access** is used solely to read a user-selected PDF and to save the signed PDF.

### Sharing with third parties
Because no data is collected, none is shared.

### Contact
GitHub Issues: https://github.com/nunnun/jpki-local-signer/issues
