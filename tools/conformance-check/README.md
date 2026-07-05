# conformance-check — 登記オンライン申請「電子署名付きPDF」適合性チェッカ

法務省 登記・供託オンライン申請システムの「電子署名付きPDFファイル」要件
（<https://www.touki-kyoutaku-online.moj.go.jp/cautions/append/sign_pdf.html>）への
適合を機械検証する CLI ツール。仕様書 `docs/design.md` §10「適合性検証」の具体化であり、
CI（GitHub Actions）で毎コミット実行される。

- 決定論的なルールベース検査のみを行う。**ネットワークアクセスは行わない。**
- **スコープ外**: 証明書チェーン検証・失効（CRL/OCSP）確認は行わない。
  これらは提出先（登記・供託オンライン申請システム）の責務である。

> **本ツールの判定基準は「登記に提出できる形式か」であり、「PDF として正しい
> 署名か」ではない。** クラウドサイン・DocuSign 等（ETSI 系 SubFilter、署名後の
> 増分更新、文書タイムスタンプ）は署名として有効でも本チェッカでは FAIL する。
> それは仕様どおりの挙動であり、**FAIL を通すための修正をしないこと**。
> 一般的な署名検証はアプリ側（SelfVerify / 検証ビューア）が担う。

## 使い方

```sh
cd tools/conformance-check
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python check.py <署名済み.pdf>
```

Python 3.13 以上。項目ごとに PASS / FAIL / WARN と根拠（実測値）を出力し、
FAIL が1件でもあれば exit code 1 を返す。

## 検査項目

| ID | 内容 |
|---|---|
| C1 | 署名辞書が存在し `/Type /Sig` であること |
| C2 | `/SubFilter` が `adbe.pkcs7.detached` であること |
| C3 | `/Name` が存在し空でないこと |
| C4 | `/M` が PDF 日付形式（`D:YYYYMMDDHHmmSS` + タイムゾーンオフセット。`Z` / `±HH'mm'`）であること |
| C5 | `/ByteRange [a b c d]` が a=0 で、`/Contents` の値部分（`<`〜`>`）のみを除外してファイル全体を正確に被覆すること（1バイトの隙間・重複も不可）。除外区間のデコード結果が署名辞書の `/Contents` 値と一致することも確認。連署（複数署名）は各署名を個別に検査し、最も広い署名がファイル全体を、先行署名は自身の署名時点のリビジョン境界（`%%EOF`）までを被覆すること |
| C6 | `/Contents` が16進文字列で、DER/BER の CMS ContentInfo（SignedData）としてパース可能。末尾パディングは 0x00 のみ。BER 不定長は RFC 5652 により許容（Apple の CMS エンコーダ等が生成し、実在の受理済み署名PDFで使われている） |
| C7 | CMS 内に署名者証明書が存在すること。signedAttrs がある場合は contentType / messageDigest を含むこと（signingTime は RFC 5652 で任意のため欠落は WARN。日時は `/M` で担保）。signedAttrs の無い**直接署名方式**（Acrobat の adbe.pkcs7.detached が該当）も適合とする |
| C8 | signedAttrs がある場合、messageDigest が ByteRange 対象バイト列の SHA-256 と一致すること。直接署名方式では非適用（WARN で通知。署名値の検証は下記 OpenSSL クロスチェックで行う） |
| C9 | （WARN）digestAlgorithm=sha256、signatureAlgorithm=sha256WithRSAEncryption（RSASSA-PKCS1-v1_5） |

## テスト

```sh
# 起点となる適合PDF（TestSigner 出力）を生成してからテストを実行
env DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
    swift run --package-path ../.. TestSigner /tmp/base_signed.pdf
CONFORMANCE_BASE_PDF=/tmp/base_signed.pdf .venv/bin/pytest tests/
```

`CONFORMANCE_BASE_PDF` が未設定の場合、テストは `swift run TestSigner` の実行を試みる
（Swift ツールチェーンがなければ該当テストは skip）。

### 既知適合PDF（known-good）によるテスト

手元にある**既知適合の実署名済みPDF**（例: 過去に登記オンラインで受理されたもの、
Acrobat で有効性を確認済みのもの）を `fixtures/known-good/` に置くと、
全件が PASS することを確認するテストが有効になる。

```
tools/conformance-check/fixtures/known-good/*.pdf
```

> **注意**: 実署名済みPDFは氏名・証明書等の個人情報を含むため、
> `fixtures/known-good/` は `.gitignore` 済みであり**リポジトリに絶対にコミットしないこと**。
> 配置はローカル環境のみに留める。

### 合成ネガティブテスト

TestSigner で生成した適合PDFを起点に、SubFilter 改変・ByteRange のずらし・
Contents 破壊・M 欠落などの変異体をテスト実行時に動的生成し、対応する検査項目が
FAIL することを確認する（変異体はコミットしない）。

## OpenSSL による独立クロスチェック

本チェッカとは独立に、OpenSSL で署名を検証する手順（別実装での往復検証、
仕様書 §10）:

```sh
# tools/conformance-check/ で実行（check.py の TLV ウォーカーで BER 不定長にも対応）
python3 - <<'EOF'
import re, sys
sys.path.insert(0, ".")
import check
data = open("signed.pdf", "rb").read()
a, b, c, d = map(int, re.search(rb'/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]', data).groups())
open("content.bin", "wb").write(data[a:a+b] + data[c:c+d])
cms = bytes.fromhex(re.search(rb'/Contents\s*<([0-9A-Fa-f]+)>', data).group(1).decode())
_, _, _, end = check.der_tlv(cms, 0)  # DER 定長・BER 不定長のどちらでも正確な終端を得る
open("cms.der", "wb").write(cms[:end])
EOF

# 署名値と messageDigest の検証（-noverify は証明書チェーン検証のみ省略）
openssl cms -verify -inform DER -in cms.der -content content.bin -binary -noverify -out /dev/null
# または旧コマンド:
openssl smime -verify -inform DER -in cms.der -content content.bin -binary -noverify -out /dev/null

# CMS 構造の目視確認
openssl asn1parse -inform DER -in cms.der | head -40
```
