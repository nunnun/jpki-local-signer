# Contributing to JPKI Local Signer

本プロジェクトへの貢献に関心をお寄せいただきありがとうございます。本アプリはマイナンバーカードの秘密鍵・PIN・署名値といった機微な情報を扱うため、通常のOSS以上に「透明性」と「検証可能性」を重視しています。プルリクエストを送る前に以下をご確認ください。

## 基本方針

- 本プロジェクトは [`docs/design.md`](docs/design.md) を設計上のリファレンスとしています。仕様に関わる変更は、まず design.md との整合性を確認してください。
- ライセンスは [Apache License 2.0](LICENSE) です。コントリビューションも同ライセンスの下で提供されるものとみなします（DCOスタイルのサインオフを推奨します。下記参照）。

## プルリクエスト前のチェック

### 1. テストを実行する

```sh
env DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test
```

すべてのテストがパスすることを確認してください。UI関連の変更を行った場合は、Xcodeから `JPKILocalSignerAppTests` / `JPKILocalSignerAppUITests` も実行してください。

### 2. ネットワークAPIを絶対に使用しない

本プロジェクトの存在意義は「ネットワークに一切繋がらない」ことの監査可能性です。`URLSession` などの通信APIやソケット系APIを新たに導入するプルリクエストは、理由の如何を問わず受け付けられません。以下のチェックをCIおよびローカルで実行します。

```sh
./scripts/check-no-network.sh
```

### 3. 機微データをログ出力・永続化しない

PIN、ハッシュ値、署名値、カードからの生応答などをログ（`print`、`os_log`、ファイル出力等）に出さないでください。デバッグ目的の一時的なログも、コミット前に必ず除去してください。

### 4. APDU関連の定数変更には実機での検証結果を添える

AID・EF識別子・P1/P2・SW（ステータスワード）解釈などのAPDU定数（design.md R-01）を変更する場合は、実機で動作確認した結果をPRの説明に記載してください。裏付けのない推測による変更は受け付けられません。

macOS では USB の IC カードリーダー（PC/SC 対応）と実カードで、Xcode を介さず
コマンドラインから検証できます（実カード検証の最短経路）。

```sh
scripts/card-sign.sh --card-info                 # リーダー・カード・AP・残回数の診断
scripts/card-sign.sh --card-sign in.pdf out.pdf  # 実カード署名（PINはエコーなし入力）
```

`scripts/card-sign.sh` はビルド後に `com.apple.security.smartcard` entitlement で
ad-hoc 署名してから実行します。PINは `getpass` で受け取り、ログにも残しません。

### 5. DER（CMS）/ PDF埋め込みまわりの変更には往復検証テストを追加する

`CMSBuilder` や `PDFSigning` の実装を変更する場合は、既知ベクタでのDER一致テストに加え、可能であれば OpenSSL（`openssl asn1parse` / `openssl pkcs7` 等）や `pdfsig` など独立実装によるクロス検証の手順・結果をPRに記載してください。

### 6. コードスタイル

既存のモジュール（`NFCTransport` / `JPKICard` / `CMSBuilder` / `PDFSigning` / `SelfVerify` / `JPKILocalSigner`）の記法・命名・レイヤ分離方針に合わせてください。新しい責務は、既存のレイヤ構造（§6 アーキテクチャ）のどこに属するかを明確にした上で追加してください。

## コミットのサインオフ（DCOスタイル）

コミットには、変更内容が自分自身の成果であり、Apache-2.0の下で提供することに同意する旨を示す `Signed-off-by` 行を含めてください。

```sh
git commit -s -m "コミットメッセージ"
```

## Issue / セキュリティ報告

機能要望やバグ報告は通常のGitHub Issueで構いません。ただし、**セキュリティ上の懸念（機微データの漏洩経路の疑いなど）は公開Issueに書かず**、[`SECURITY.md`](SECURITY.md) の手順に従って報告してください。
