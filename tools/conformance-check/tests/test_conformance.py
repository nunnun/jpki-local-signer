"""適合性チェッカのテスト。

- 起点: TestSigner（swift run TestSigner）が生成する適合PDF。
  CONFORMANCE_BASE_PDF 環境変数でパスを指定するか、未指定なら生成を試みる。
- 合成ネガティブ: 起点PDFから変異体を動的生成し、対応する検査項目が FAIL する
  ことを確認する。変異体はコミットしない。
- fixtures/known-good/ に置かれた既知適合PDF（gitignore 対象、コミット禁止）が
  あれば全件 PASS することを確認する。
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check  # noqa: E402

TOOL_DIR = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = TOOL_DIR.parents[1]
KNOWN_GOOD_DIR = TOOL_DIR / "fixtures" / "known-good"


# --- base PDF ----------------------------------------------------------------


@pytest.fixture(scope="session")
def base_pdf(tmp_path_factory) -> bytes:
    env_path = os.environ.get("CONFORMANCE_BASE_PDF")
    if env_path:
        return pathlib.Path(env_path).read_bytes()

    output = tmp_path_factory.mktemp("base") / "base_signed.pdf"
    env = dict(os.environ)
    xcode = "/Applications/Xcode.app/Contents/Developer"
    if sys.platform == "darwin" and os.path.isdir(xcode):
        env.setdefault("DEVELOPER_DIR", xcode)
    try:
        subprocess.run(
            ["swift", "run", "--package-path", str(REPO_ROOT), "TestSigner", str(output)],
            check=True,
            env=env,
            capture_output=True,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as error:
        pytest.skip(f"TestSigner を実行できない: {error}")
    return output.read_bytes()


def statuses(pdf_bytes: bytes, tmp_path: pathlib.Path) -> dict[str, str]:
    path = tmp_path / "candidate.pdf"
    path.write_bytes(pdf_bytes)
    results = check.run_checks(str(path))
    # 同一 ID が複数回報告された場合は最も悪い状態を採用する。
    rank = {"PASS": 0, "WARN": 1, "FAIL": 2}
    merged: dict[str, str] = {}
    for result in results:
        if rank[result.status] >= rank.get(merged.get(result.check_id, "PASS"), 0):
            merged[result.check_id] = result.status
    return merged


def mutate(data: bytes, old: bytes, new: bytes) -> bytes:
    assert len(old) == len(new), "変異はファイル長を変えない"
    count = data.count(old)
    assert count == 1, f"パターン {old!r} が {count} 回出現（1回を期待）"
    return data.replace(old, new)


# --- positive ----------------------------------------------------------------


def test_testsigner_output_passes_all(base_pdf, tmp_path):
    result = statuses(base_pdf, tmp_path)
    assert set(result) == {f"C{i}" for i in range(1, 10)}
    assert all(status == "PASS" for status in result.values()), result


def test_exit_codes(base_pdf, tmp_path):
    good = tmp_path / "good.pdf"
    good.write_bytes(base_pdf)
    bad = tmp_path / "bad.pdf"
    bad.write_bytes(mutate(base_pdf, b"/adbe.pkcs7.detached", b"/adbe.pkcs7.detacheX"))

    interpreter = sys.executable
    ok = subprocess.run([interpreter, str(TOOL_DIR / "check.py"), str(good)], capture_output=True)
    assert ok.returncode == 0, ok.stdout
    ng = subprocess.run([interpreter, str(TOOL_DIR / "check.py"), str(bad)], capture_output=True)
    assert ng.returncode == 1, ng.stdout


@pytest.mark.parametrize(
    "pdf_path",
    sorted(KNOWN_GOOD_DIR.glob("*.pdf")) or [None],
    ids=lambda p: p.name if p else "none",
)
def test_known_good_fixtures(pdf_path, tmp_path):
    if pdf_path is None:
        pytest.skip("fixtures/known-good/ に既知適合PDFが置かれていない（ローカル配置手順は README 参照）")
    result = statuses(pdf_path.read_bytes(), tmp_path)
    fails = {check_id for check_id, status in result.items() if status == "FAIL"}
    assert not fails, f"{pdf_path.name}: FAIL {sorted(fails)}"


# --- synthetic negatives ------------------------------------------------------


def test_c1_type_mutation_fails(base_pdf, tmp_path):
    mutant = mutate(base_pdf, b"/Type /Sig /Filter", b"/Type /Sit /Filter")
    assert statuses(mutant, tmp_path)["C1"] == "FAIL"


def test_c2_subfilter_mutation_fails(base_pdf, tmp_path):
    mutant = mutate(base_pdf, b"/adbe.pkcs7.detached", b"/adbe.pkcs7.detacheX")
    assert statuses(mutant, tmp_path)["C2"] == "FAIL"


def test_c3_name_removal_fails(base_pdf, tmp_path):
    mutant = mutate(base_pdf, b"/Name <FEFF", b"/Namf <FEFF")
    assert statuses(mutant, tmp_path)["C3"] == "FAIL"


def test_c4_malformed_date_fails(base_pdf, tmp_path):
    mutant = mutate(base_pdf, b"/M (D:", b"/M (E:")
    assert statuses(mutant, tmp_path)["C4"] == "FAIL"


def test_c4_missing_m_fails(base_pdf, tmp_path):
    mutant = mutate(base_pdf, b"/M (D:", b"/Q (D:")
    assert statuses(mutant, tmp_path)["C4"] == "FAIL"


def test_c5_shifted_byterange_fails(base_pdf, tmp_path):
    match = re.search(rb"/ByteRange \[(\d{10}) (\d{10}) (\d{10}) (\d{10})\]", base_pdf)
    assert match, "固定幅 ByteRange が見つからない"
    b_value = int(match.group(2))
    old = b"/ByteRange [%s %s" % (match.group(1), match.group(2))
    new = b"/ByteRange [%s %010d" % (match.group(1), b_value + 1)
    mutant = mutate(base_pdf, old, new)
    assert statuses(mutant, tmp_path)["C5"] == "FAIL"


def test_c6_corrupt_contents_hex_fails(base_pdf, tmp_path):
    match = re.search(rb"/Contents <([0-9A-Fa-f]{4})", base_pdf)
    assert match
    mutant = mutate(base_pdf, b"/Contents <" + match.group(1), b"/Contents <ZZ" + match.group(1)[2:])
    assert statuses(mutant, tmp_path)["C6"] == "FAIL"


def test_c6_nonzero_padding_fails(base_pdf, tmp_path):
    match = re.search(rb"/Contents <([0-9A-Fa-f]+)>", base_pdf)
    assert match
    hex_payload = match.group(1)
    assert hex_payload.endswith(b"0000"), "パディング領域が存在しない"
    old = hex_payload[-16:] + b">"
    new = hex_payload[-16:-2] + b"01>"
    mutant = mutate(base_pdf, old, new)
    assert statuses(mutant, tmp_path)["C6"] == "FAIL"


def test_c7_missing_signing_time_warns(base_pdf, tmp_path):
    # signedAttrs 内の signingTime OID (1.2.840.113549.1.9.5) を別 OID に置換。
    # signingTime は RFC 5652 で任意（実在の受理済み署名にも無い）ため WARN。
    mutant = mutate(base_pdf, b"06092A864886F70D010905", b"06092A864886F70D010906")
    assert statuses(mutant, tmp_path)["C7"] == "WARN"


def test_c7_missing_message_digest_fails(base_pdf, tmp_path):
    # messageDigest OID (1.2.840.113549.1.9.4) の除去は FAIL のまま
    mutant = mutate(base_pdf, b"06092A864886F70D010904", b"06092A864886F70D010906")
    assert statuses(mutant, tmp_path)["C7"] == "FAIL"


def test_c8_tampered_content_fails(base_pdf, tmp_path):
    mutant = mutate(base_pdf, b"%PDF-1.7", b"%PDF-1.6")
    result = statuses(mutant, tmp_path)
    assert result["C5"] == "PASS"  # 構造は保たれたまま
    assert result["C8"] == "FAIL"  # ダイジェストのみ不一致


def test_c5_appended_data_after_signature_fails(base_pdf, tmp_path):
    # 署名後にデータを追記した場合、（唯一の）署名がファイル全体を
    # 被覆しなくなるため C5 が FAIL しなければならない。
    mutant = base_pdf + b"\n999 0 obj\n<< /Injected true >>\nendobj\n%%EOF\n"
    assert statuses(mutant, tmp_path)["C5"] == "FAIL"


# --- direct-signature (no signedAttrs) profile --------------------------------


def _tlv(tag: int, content: bytes) -> bytes:
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length_bytes)]) + length_bytes + content


def _oid(dotted: str) -> bytes:
    parts = list(map(int, dotted.split(".")))
    body = bytearray([parts[0] * 40 + parts[1]])
    for value in parts[2:]:
        encoded = [value & 0x7F]
        value >>= 7
        while value:
            encoded.insert(0, (value & 0x7F) | 0x80)
            value >>= 7
        body.extend(encoded)
    return _tlv(0x06, bytes(body))


def _build_direct_signature_cms(certificate_der: bytes) -> bytes:
    """signedAttrs を持たない SignedData（Acrobat の直接署名方式を模す）。"""
    _, tbs_start, _, _ = check.der_tlv(certificate_der, 0)
    _, content_start, _, _ = check.der_tlv(certificate_der, tbs_start)
    cursor = content_start
    tag, _, _, nxt = check.der_tlv(certificate_der, cursor)
    if tag == 0xA0:  # [0] version
        cursor = nxt
    _, _, _, serial_end = check.der_tlv(certificate_der, cursor)  # serialNumber
    serial_der = certificate_der[cursor:serial_end]
    _, _, _, sigalg_end = check.der_tlv(certificate_der, serial_end)  # signature
    _, _, _, issuer_end = check.der_tlv(certificate_der, sigalg_end)  # issuer
    issuer_der = certificate_der[sigalg_end:issuer_end]

    algo_sha256 = _tlv(0x30, _oid(check.OID_SHA256) + b"\x05\x00")
    algo_rsa = _tlv(0x30, _oid(check.OID_RSA) + b"\x05\x00")
    signer_info = _tlv(0x30, b"".join([
        _tlv(0x02, b"\x01"),
        _tlv(0x30, issuer_der + serial_der),
        algo_sha256,
        algo_rsa,
        _tlv(0x04, bytes(256)),
    ]))
    signed_data = _tlv(0x30, b"".join([
        _tlv(0x02, b"\x01"),
        _tlv(0x31, algo_sha256),
        _tlv(0x30, _oid("1.2.840.113549.1.7.1")),
        _tlv(0xA0, certificate_der),
        _tlv(0x31, signer_info),
    ]))
    return _tlv(0x30, _oid(check.OID_SIGNED_DATA) + _tlv(0xA0, signed_data))


def test_direct_signature_without_signed_attrs(base_pdf, tmp_path):
    # base の CMS から証明書を取り出し、signedAttrs 無しの CMS に差し替える。
    match = re.search(rb"/Contents <([0-9A-Fa-f]+)>", base_pdf)
    assert match
    interior = match.group(1)
    original = bytes.fromhex(interior.decode())
    _, sd_start, sd_end, _ = check.der_tlv(original, 0)
    # ContentInfo -> [0] -> SignedData -> ... [0] certificates から先頭証明書を取得
    children = list(check.der_children(original, sd_start, sd_end))
    _, inner_start, inner_end, _ = check.der_tlv(original, children[1][2])
    certificate_der = None
    for tag, offset, cstart, cend in check.der_children(original, inner_start, inner_end):
        if tag == 0xA0:
            cert_tag, _, _, cert_next = check.der_tlv(original, cstart)
            assert cert_tag == 0x30
            certificate_der = original[cstart:cert_next]
            break
    assert certificate_der

    replacement = _build_direct_signature_cms(certificate_der)
    new_hex = replacement.hex().upper().encode()
    assert len(new_hex) <= len(interior), "プレースホルダに収まること"
    padded = new_hex + b"0" * (len(interior) - len(new_hex))
    mutant = mutate(base_pdf, interior, padded)

    result = statuses(mutant, tmp_path)
    assert result["C6"] == "PASS"
    assert result["C7"] == "PASS"  # 証明書ありなら signedAttrs 無しでも適合
    assert result["C8"] == "WARN"  # messageDigest 検査は非適用
    assert result["C5"] == "PASS"
