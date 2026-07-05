#!/usr/bin/env python3
"""登記・供託オンライン申請システム「電子署名付きPDFファイル」適合性チェッカ。

法務省仕様（https://www.touki-kyoutaku-online.moj.go.jp/cautions/append/sign_pdf.html）
の署名辞書要件（Type / SubFilter / Name / M / ByteRange / Contents）への適合を
決定論的なルールベースで機械検証する。ネットワークアクセスは行わない。

検査項目:
  C1: 署名辞書が存在し /Type /Sig であること
  C2: /SubFilter が adbe.pkcs7.detached であること
  C3: /Name が存在し空でないこと
  C4: /M が PDF 日付形式（D:YYYYMMDDHHmmSS + タイムゾーンオフセット）であること
  C5: /ByteRange [a b c d] が a=0 で、/Contents の値部分（< 〜 >）のみを
      除外してファイル全体を正確に被覆すること（隙間・重複不可）。
      連署（複数署名）の場合は各署名を個別に検査し、最も広い署名が全体を、
      先行署名は自身の署名時点のリビジョン境界（%%EOF）までを被覆すること
  C6: /Contents が16進文字列で、DER/BER の CMS ContentInfo (SignedData) を含み、
      末尾パディングが 0x00 のみであること（BER 不定長は RFC 5652 により許容。
      実在の署名実装、例えば Apple の CMS エンコーダが生成する）
  C7: 署名者証明書が CMS 内に存在すること。signedAttrs がある場合は
      contentType / messageDigest を含むこと（signingTime は RFC 5652 で
      任意のため欠落は WARN）。signedAttrs の無い直接署名方式（Acrobat の
      adbe.pkcs7.detached 等）も適合とする
  C8: signedAttrs がある場合、messageDigest が ByteRange 対象バイト列の
      SHA-256 と一致すること（直接署名方式では非適用 = WARN で通知し、
      openssl cms -verify での署名値検証を促す）
  C9: (WARN) digestAlgorithm=sha256, signatureAlgorithm=sha256WithRSAEncryption

スコープ外（提出先システムの責務）: 証明書チェーン検証・失効確認。

署名辞書が pikepdf（qpdf）で解釈できない場合も、生バイトのフォールバックで
C5〜C9 を検査する（全9項目を常に報告する）。

Usage: check.py <pdf>
Exit code: FAIL が1件でもあれば 1、それ以外は 0。
"""

from __future__ import annotations

import binascii
import hashlib
import re
import sys
from dataclasses import dataclass

import pikepdf

# --- OIDs -------------------------------------------------------------------

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA256_RSA = "1.2.840.113549.1.1.11"
OID_RSA = "1.2.840.113549.1.1.1"

PDF_DATE_RE = re.compile(r"^D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(Z|[+-]\d{2}'\d{2}'?)$")
HEX_RE = re.compile(rb"\A(?:[0-9A-Fa-f]{2})+\Z")


@dataclass
class CheckResult:
    check_id: str
    status: str  # PASS / FAIL / WARN
    detail: str


# --- Minimal DER walker -----------------------------------------------------


class DERError(ValueError):
    pass


def der_tlv(buf: bytes, offset: int) -> tuple[int, int, int, int]:
    """Returns (tag, content_start, content_end, next_offset) of the TLV at
    offset. Supports BER indefinite lengths (RFC 5652 permits BER for
    ContentInfo; e.g. Apple's CMS encoder emits 30 80 ... 00 00)."""
    if offset + 2 > len(buf):
        raise DERError(f"truncated TLV at {offset}")
    tag = buf[offset]
    first = buf[offset + 1]
    if first == 0x80:  # BER indefinite length
        if tag & 0x20 == 0:
            raise DERError(f"indefinite length on primitive tag at {offset}")
        start = offset + 2
        cursor = start
        while True:
            if cursor + 2 > len(buf):
                raise DERError(f"unterminated indefinite length at {offset}")
            if buf[cursor] == 0x00 and buf[cursor + 1] == 0x00:
                return tag, start, cursor, cursor + 2
            _, _, _, cursor = der_tlv(buf, cursor)
    if first < 0x80:
        start = offset + 2
        length = first
    else:
        count = first & 0x7F
        if count > 8 or offset + 2 + count > len(buf):
            raise DERError(f"invalid length at {offset}")
        length = int.from_bytes(buf[offset + 2 : offset + 2 + count], "big")
        start = offset + 2 + count
    end = start + length
    if end > len(buf):
        raise DERError(f"TLV overruns buffer at {offset}")
    return tag, start, end, end


def der_children(buf: bytes, start: int, end: int):
    offset = start
    while offset < end:
        tag, cstart, cend, next_offset = der_tlv(buf, offset)
        yield tag, offset, cstart, cend
        offset = next_offset


def decode_oid(content: bytes) -> str:
    if not content:
        raise DERError("empty OID")
    components: list[int] = []
    value = 0
    for index, byte in enumerate(content):
        value = (value << 7) | (byte & 0x7F)
        if byte & 0x80 == 0:
            if not components:
                first = 2 if value >= 80 else value // 40
                components.append(first)
                components.append(value - first * 40)
            else:
                components.append(value)
            value = 0
        elif index == len(content) - 1:
            raise DERError("truncated OID")
    return ".".join(map(str, components))


# --- CMS parse (structure only, no crypto) ----------------------------------


@dataclass
class ParsedCMS:
    has_certificate: bool
    signed_attrs_present: bool
    signed_attr_oids: list[str]
    message_digest: bytes | None
    digest_algorithm_oid: str | None
    signature_algorithm_oid: str | None


def parse_cms(der: bytes) -> ParsedCMS:
    tag, start, end, _ = der_tlv(der, 0)
    if tag != 0x30:
        raise DERError("ContentInfo is not a SEQUENCE")
    children = list(der_children(der, start, end))
    if len(children) < 2 or children[0][0] != 0x06:
        raise DERError("ContentInfo missing contentType")
    content_type = decode_oid(der[children[0][2] : children[0][3]])
    if content_type != OID_SIGNED_DATA:
        raise DERError(f"contentType is {content_type}, not SignedData")
    if children[1][0] != 0xA0:
        raise DERError("ContentInfo missing [0] content")

    tag, sd_start, sd_end, _ = der_tlv(der, children[1][2])
    if tag != 0x30:
        raise DERError("SignedData is not a SEQUENCE")
    fields = list(der_children(der, sd_start, sd_end))
    index = 0

    def expect(tag_value: int, name: str):
        nonlocal index
        if index >= len(fields) or fields[index][0] != tag_value:
            raise DERError(f"SignedData missing {name}")
        field = fields[index]
        index += 1
        return field

    expect(0x02, "version")
    expect(0x31, "digestAlgorithms")
    expect(0x30, "encapContentInfo")

    has_certificate = False
    if index < len(fields) and fields[index][0] == 0xA0:
        cert_field = fields[index]
        # 少なくとも1つの Certificate (SEQUENCE) を含むこと
        for tag_value, _, _, _ in der_children(der, cert_field[2], cert_field[3]):
            if tag_value == 0x30:
                has_certificate = True
                break
        index += 1
    if index < len(fields) and fields[index][0] == 0xA1:  # crls
        index += 1

    signer_infos = expect(0x31, "signerInfos")
    si_children = list(der_children(der, signer_infos[2], signer_infos[3]))
    if not si_children or si_children[0][0] != 0x30:
        raise DERError("signerInfos is empty")
    si_fields = list(der_children(der, si_children[0][2], si_children[0][3]))

    digest_algorithm_oid = None
    signature_algorithm_oid = None
    signed_attr_oids: list[str] = []
    message_digest = None

    cursor = 0
    if cursor < len(si_fields) and si_fields[cursor][0] == 0x02:  # version
        cursor += 1
    if cursor < len(si_fields) and si_fields[cursor][0] == 0x30:  # sid
        cursor += 1
    if cursor < len(si_fields) and si_fields[cursor][0] == 0x30:  # digestAlgorithm
        algorithm = si_fields[cursor]
        for tag_value, _, cstart, cend in der_children(der, algorithm[2], algorithm[3]):
            if tag_value == 0x06:
                digest_algorithm_oid = decode_oid(der[cstart:cend])
                break
        cursor += 1
    signed_attrs_present = False
    if cursor < len(si_fields) and si_fields[cursor][0] == 0xA0:  # signedAttrs
        signed_attrs_present = True
        attrs = si_fields[cursor]
        for tag_value, _, astart, aend in der_children(der, attrs[2], attrs[3]):
            if tag_value != 0x30:
                continue
            attr_children = list(der_children(der, astart, aend))
            if not attr_children or attr_children[0][0] != 0x06:
                continue
            oid = decode_oid(der[attr_children[0][2] : attr_children[0][3]])
            signed_attr_oids.append(oid)
            if oid == OID_MESSAGE_DIGEST and len(attr_children) >= 2 and attr_children[1][0] == 0x31:
                for vtag, _, vstart, vend in der_children(der, attr_children[1][2], attr_children[1][3]):
                    if vtag == 0x04:
                        message_digest = der[vstart:vend]
                        break
        cursor += 1
    if cursor < len(si_fields) and si_fields[cursor][0] == 0x30:  # signatureAlgorithm
        algorithm = si_fields[cursor]
        for tag_value, _, cstart, cend in der_children(der, algorithm[2], algorithm[3]):
            if tag_value == 0x06:
                signature_algorithm_oid = decode_oid(der[cstart:cend])
                break
        cursor += 1

    return ParsedCMS(
        has_certificate=has_certificate,
        signed_attrs_present=signed_attrs_present,
        signed_attr_oids=signed_attr_oids,
        message_digest=message_digest,
        digest_algorithm_oid=digest_algorithm_oid,
        signature_algorithm_oid=signature_algorithm_oid,
    )


# --- Signature dictionary lookup --------------------------------------------


def find_signature_dicts(pdf: pikepdf.Pdf) -> list[pikepdf.Dictionary]:
    found = []
    seen = set()

    def add(candidate):
        if not isinstance(candidate, pikepdf.Dictionary):
            return
        key = candidate.objgen
        if key in seen:
            return
        if "/ByteRange" in candidate and "/Contents" in candidate:
            seen.add(key)
            found.append(candidate)

    def walk_fields(fields, depth: int = 0):
        if depth > 16:
            return
        for field in fields:
            try:
                if field.get("/FT") == pikepdf.Name("/Sig") and "/V" in field:
                    add(field.V)
                if "/Kids" in field:
                    walk_fields(field.Kids, depth + 1)
            except (AttributeError, TypeError, pikepdf.PdfError):
                continue

    try:
        walk_fields(pdf.Root.AcroForm.Fields)
    except AttributeError:
        pass

    if not found:
        for obj in pdf.objects:
            try:
                if isinstance(obj, pikepdf.Dictionary) and obj.get("/Type") == pikepdf.Name("/Sig"):
                    add(obj)
            except (TypeError, pikepdf.PdfError):
                continue
    return found


# --- Checks ------------------------------------------------------------------


def run_checks(path: str) -> list[CheckResult]:
    results: list[CheckResult] = []
    raw = open(path, "rb").read()

    def report(check_id: str, ok: bool, detail: str, warn_only: bool = False) -> bool:
        status = "PASS" if ok else ("WARN" if warn_only else "FAIL")
        results.append(CheckResult(check_id, status, detail))
        return ok

    sig = None
    try:
        pdf = pikepdf.open(path)
    except pikepdf.PdfError as error:
        report("C1", False, f"PDF として開けない: {error}")
        pdf = None

    if pdf is not None:
        with pdf:
            signatures = find_signature_dicts(pdf)
            if not signatures:
                report("C1", False, "署名辞書（/ByteRange と /Contents を持つ辞書）が見つからない")
            else:
                sig = signatures[0]
                # 複数署名（連署）: 各署名を個別に検査する。最も広い範囲を
                # 被覆する署名がファイル全体を覆い、先行署名は自身の署名時点
                # のリビジョン境界（%%EOF）で終わっていなければならない。
                total = len(signatures)
                byte_ranges = []
                for candidate in signatures:
                    try:
                        values = [int(x) for x in candidate["/ByteRange"]]
                        byte_ranges.append(values if len(values) == 4 else None)
                    except (KeyError, TypeError, ValueError):
                        byte_ranges.append(None)
                coverages = [br[2] + br[3] if br else -1 for br in byte_ranges]
                widest = coverages.index(max(coverages)) if coverages else 0

                for position, candidate in enumerate(signatures):
                    prefix = f"[署名{position + 1}/{total}] " if total > 1 else ""

                    def prefixed(check_id, ok, detail, warn_only=False, _prefix=prefix):
                        return report(check_id, ok, _prefix + detail, warn_only)

                    check_dictionary_entries(candidate, prefixed)
                    byte_range = read_byte_range(candidate, prefixed)
                    contents_bytes = bytes(candidate["/Contents"])
                    check_payload(
                        raw,
                        byte_range,
                        contents_bytes,
                        prefixed,
                        must_cover_whole_file=(position == widest),
                    )

    if sig is None:
        # 生バイトへのフォールバック: 辞書が解釈できなくても、ByteRange と
        # /Contents 16進文字列の生表現に基づき C5〜C9 を検査する。
        for check_id in ("C2", "C3", "C4"):
            report(check_id, False, "署名辞書が解釈できないため検査不能")
        byte_range = None
        match = re.search(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", raw)
        if match:
            byte_range = [int(x) for x in match.groups()]
        else:
            report("C5", False, "/ByteRange が生バイトからも見つからない")
        contents_bytes = None
        contents_match = re.search(rb"/Contents\s*<([^>]*)>", raw, re.DOTALL)
        if contents_match:
            interior = re.sub(rb"[\x00\t\n\x0c\r ]", b"", contents_match.group(1))
            if HEX_RE.match(interior):
                contents_bytes = binascii.unhexlify(interior)
            else:
                report("C6", False, "/Contents の内部が16進文字列でない")
        else:
            report("C6", False, "/Contents <...> が生バイトからも見つからない")
        check_payload(raw, byte_range, contents_bytes, report)

    # 重複を除去しつつ全 ID が報告されていることを保証する。
    reported = {result.check_id for result in results}
    for index in range(1, 10):
        check_id = f"C{index}"
        if check_id not in reported:
            results.append(CheckResult(check_id, "FAIL", "前提条件の不成立により検査不能"))
    results.sort(key=lambda result: result.check_id)
    return results


def check_dictionary_entries(sig, report) -> None:
    # C1: /Type /Sig
    type_value = sig.get("/Type")
    report(
        "C1",
        type_value == pikepdf.Name("/Sig"),
        f"/Type = {type_value!s} (obj {sig.objgen[0]} {sig.objgen[1]})",
    )

    # C2: /SubFilter
    subfilter = sig.get("/SubFilter")
    report("C2", subfilter == pikepdf.Name("/adbe.pkcs7.detached"), f"/SubFilter = {subfilter!s}")

    # C3: /Name
    name_value = sig.get("/Name")
    name_text = str(name_value) if name_value is not None else ""
    report(
        "C3",
        name_value is not None and len(name_text) > 0,
        f"/Name = {name_text!r}" if name_value is not None else "/Name が存在しない",
    )

    # C4: /M
    m_value = sig.get("/M")
    if m_value is None:
        report("C4", False, "/M が存在しない")
    else:
        m_text = str(m_value)
        match = PDF_DATE_RE.match(m_text)
        valid = False
        if match:
            year, month, day, hour, minute, second = map(int, match.groups()[:6])
            valid = 1 <= month <= 12 and 1 <= day <= 31 and hour <= 23 and minute <= 59 and second <= 59
        report("C4", valid, f"/M = {m_text!r}")


def read_byte_range(sig, report) -> list[int] | None:
    try:
        byte_range = [int(x) for x in sig["/ByteRange"]]
    except (KeyError, TypeError, ValueError):
        report("C5", False, "/ByteRange が [a b c d] の整数配列でない")
        return None
    if len(byte_range) != 4:
        report("C5", False, f"/ByteRange の要素数が {len(byte_range)}（4 を期待）")
        return None
    return byte_range


def check_payload(
    raw: bytes,
    byte_range: list[int] | None,
    contents_bytes: bytes | None,
    report,
    must_cover_whole_file: bool = True,
) -> None:
    """C5〜C9: ByteRange 被覆・CMS 構造・messageDigest・アルゴリズム。

    must_cover_whole_file=False は連署の先行署名用: その署名は自身の署名時点
    のリビジョン（%%EOF 境界）までを被覆していればよい。
    """

    # C5
    if byte_range is not None:
        a, b, c, d = byte_range
        problems = []
        if a != 0:
            problems.append(f"a={a} (0 でない)")
        if must_cover_whole_file:
            if not (0 <= b <= c and c + d == len(raw)):
                problems.append(f"被覆不一致: [0,{b}) + [{c},{c + d}) vs ファイル長 {len(raw)}")
        else:
            revision_tail = raw[max(0, c + d - 12) : c + d].rstrip(b"\r\n \t")
            if not (0 <= b <= c and c + d <= len(raw) and revision_tail.endswith(b"%%EOF")):
                problems.append(
                    f"先行署名の被覆範囲 [0,{b}) + [{c},{c + d}) がリビジョン境界(%%EOF)で終わっていない"
                )
        gap = raw[b:c] if 0 <= b <= c <= len(raw) else b""
        if len(gap) < 4 or gap[:1] != b"<" or gap[-1:] != b">":
            problems.append("除外区間が <...> 形式でない")
        else:
            interior = gap[1:-1]
            if not HEX_RE.match(interior):
                problems.append("除外区間の内部が16進文字列でない")
            elif contents_bytes is not None and binascii.unhexlify(interior) != contents_bytes:
                problems.append("除外区間が署名辞書の /Contents 値と一致しない")
        report(
            "C5",
            not problems,
            f"/ByteRange = {byte_range}, 除外区間 [{b},{c})"
            + ("" if not problems else "; " + "; ".join(problems)),
        )
    else:
        report("C5", False, "/ByteRange が取得できず検査不能")

    # C6
    cms = None
    if contents_bytes is None:
        report("C6", False, "/Contents が取得できず検査不能")
    else:
        try:
            tag, _, _, tlv_end = der_tlv(contents_bytes, 0)
            if tag != 0x30:
                raise DERError(f"先頭タグが SEQUENCE でない (0x{tag:02X})")
            cms_der = contents_bytes[:tlv_end]
            padding = contents_bytes[tlv_end:]
            if any(padding):
                raise DERError("末尾パディングに 0x00 以外を含む")
            cms = parse_cms(cms_der)
            report(
                "C6",
                True,
                f"CMS ContentInfo(SignedData) {len(cms_der)} bytes + 0x00 パディング {len(padding)} bytes",
            )
        except (DERError, binascii.Error) as error:
            report("C6", False, f"CMS として解釈できない: {error}")

    # C7
    if cms is None:
        report("C7", False, "C6 不成立のため検査不能")
    elif not cms.signed_attrs_present:
        # Acrobat の adbe.pkcs7.detached は authenticated attributes を持たない
        # 直接署名方式（署名は文書ダイジェストの DigestInfo に直接掛かる）。
        # 法務省仕様は signedAttrs を要求していないため証明書の存在のみ検査。
        report(
            "C7",
            cms.has_certificate,
            "signedAttrs なし（直接署名方式・Acrobat 等）; "
            + ("署名者証明書あり" if cms.has_certificate else "署名者証明書が存在しない"),
        )
    else:
        # contentType / messageDigest は signedAttrs があれば RFC 5652 で必須。
        # signingTime は任意（日時は辞書の /M で担保される）ため欠落は WARN。
        missing = [
            label
            for label, oid in [
                ("contentType", OID_CONTENT_TYPE),
                ("messageDigest", OID_MESSAGE_DIGEST),
            ]
            if oid not in cms.signed_attr_oids
        ]
        if not cms.has_certificate:
            missing.append("署名者証明書")
        signing_time_missing = OID_SIGNING_TIME not in cms.signed_attr_oids
        detail = (
            "signedAttrs: " + ", ".join(cms.signed_attr_oids)
            + ("; 証明書あり" if cms.has_certificate else "")
        )
        if missing:
            report("C7", False, detail + f"; 欠落: {', '.join(missing)}")
        elif signing_time_missing:
            report(
                "C7",
                False,
                detail + "; signingTime なし（RFC 5652 では任意・日時は /M で担保。実在の受理済み署名にも存在する形式）",
                warn_only=True,
            )
        else:
            report("C7", True, detail)

    # C8
    if cms is not None and not cms.signed_attrs_present:
        report(
            "C8",
            False,
            "直接署名方式のため messageDigest 属性は存在せず本検査は非適用。"
            "署名値の検証は openssl cms -verify で行うこと（README 参照）",
            warn_only=True,
        )
    elif cms is None or cms.message_digest is None or byte_range is None:
        report("C8", False, "messageDigest または ByteRange が取得できず検査不能")
    else:
        a, b, c, d = byte_range
        computed = hashlib.sha256(raw[a : a + b] + raw[c : c + d]).digest()
        report(
            "C8",
            computed == cms.message_digest,
            f"SHA-256(ByteRange) = {computed.hex()}, messageDigest = {cms.message_digest.hex()}",
        )

    # C9 (WARN)
    if cms is None:
        report("C9", False, "C6 不成立のため検査不能", warn_only=True)
    else:
        digest_ok = cms.digest_algorithm_oid == OID_SHA256
        signature_ok = cms.signature_algorithm_oid in (OID_SHA256_RSA, OID_RSA)
        report(
            "C9",
            digest_ok and signature_ok,
            f"digestAlgorithm = {cms.digest_algorithm_oid}, signatureAlgorithm = {cms.signature_algorithm_oid}",
            warn_only=True,
        )


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: check.py <pdf>", file=sys.stderr)
        return 2

    results = run_checks(sys.argv[1])
    width = max(len(result.check_id) for result in results)
    for result in results:
        print(f"{result.check_id:<{width}}  {result.status:<4}  {result.detail}")

    fails = sum(1 for r in results if r.status == "FAIL")
    warns = sum(1 for r in results if r.status == "WARN")
    passes = sum(1 for r in results if r.status == "PASS")
    verdict = "FAIL" if fails else "PASS"
    print(f"RESULT: {verdict} ({passes} PASS, {warns} WARN, {fails} FAIL)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
