import CMSBuilder
import Crypto
import Foundation
import PDFSigning

/// 登記・供託オンライン申請システムの「電子署名付きPDFファイル」要件への
/// 適合を判定する(tools/conformance-check の Swift 実装。判定セマンティクス
/// は Python 版と一致させること)。
///
/// 判定基準は「登記に提出できる形式か」であり「PDF として正しい署名か」では
/// ない — 一般的な署名有効性は `SignedPDFVerifier` が担う。ETSI 系 SubFilter
/// や署名後の増分更新を持つ PDF(クラウド署名等)が FAIL するのは仕様。
public enum MOJConformanceStatus: String, Sendable {
    case pass = "PASS"
    case fail = "FAIL"
    case warn = "WARN"
}

public struct MOJConformanceItem: Sendable {
    /// C1〜C9.
    public let checkID: String
    public let status: MOJConformanceStatus
    public let detail: String
}

public struct MOJConformanceResult: Sendable {
    public let items: [MOJConformanceItem]
    public let signatureCount: Int

    /// FAIL がひとつも無ければ提出可能な形式。
    public var isConformant: Bool {
        !items.contains { $0.status == .fail }
    }
}

public enum MOJConformanceChecker {
    static let contentTypeOID = "1.2.840.113549.1.9.3"
    static let messageDigestOID = "1.2.840.113549.1.9.4"
    static let signingTimeOID = "1.2.840.113549.1.9.5"
    static let sha256OID = "2.16.840.1.101.3.4.2.1"

    public static func check(pdf: Data) -> MOJConformanceResult {
        var items: [MOJConformanceItem] = []
        let candidates = SignatureStructureVerifier.enumerateSignatureCandidates(in: pdf)
        let dictionaries = PDFSignatureDictionaries.enumerate(in: pdf)

        guard !candidates.isEmpty else {
            items.append(MOJConformanceItem(checkID: "C1", status: .fail, detail: "署名辞書が見つからない"))
            for id in ["C2", "C3", "C4", "C5", "C6", "C7", "C8"] {
                items.append(MOJConformanceItem(checkID: id, status: .fail, detail: "署名が無いため検査不能"))
            }
            items.append(MOJConformanceItem(checkID: "C9", status: .warn, detail: "署名が無いため検査不能"))
            return MOJConformanceResult(items: items, signatureCount: 0)
        }

        let total = candidates.count
        let coverages = candidates.map { $0.byteRange.secondOffset + $0.byteRange.secondLength }
        let widestIndex = coverages.firstIndex(of: coverages.max() ?? 0) ?? 0

        for (index, candidate) in candidates.enumerated() {
            let prefix = total > 1 ? "[署名\(index + 1)/\(total)] " : ""
            let dictionary = index < dictionaries.count ? dictionaries[index] : nil

            func report(_ id: String, _ ok: Bool, _ detail: String, warnOnly: Bool = false) {
                items.append(MOJConformanceItem(
                    checkID: id,
                    status: ok ? .pass : (warnOnly ? .warn : .fail),
                    detail: prefix + detail
                ))
            }

            // C1: /Type /Sig
            report("C1", dictionary?.type == "Sig", "/Type = \(dictionary?.type.map { "/\($0)" } ?? "なし")")

            // C2: /SubFilter
            report(
                "C2",
                dictionary?.subFilter == "adbe.pkcs7.detached",
                "/SubFilter = \(dictionary?.subFilter.map { "/\($0)" } ?? "なし")"
            )

            // C3: /Name
            let name = dictionary?.name ?? ""
            report("C3", !name.isEmpty, name.isEmpty ? "/Name が存在しないか空" : "/Name = \(name)")

            // C4: /M
            if let m = dictionary?.modificationDate {
                report("C4", isValidPDFDate(m), "/M = \(m)")
            } else {
                report("C4", false, "/M が存在しない")
            }

            // C5: ByteRange coverage
            if let problem = candidate.problem {
                report("C5", false, "\(problem); /ByteRange = \(candidate.byteRange.values)")
            } else if index == widestIndex {
                report(
                    "C5",
                    candidate.coversWholeFile,
                    candidate.coversWholeFile
                        ? "/ByteRange = \(candidate.byteRange.values)（ファイル全体を被覆）"
                        : "最も広い署名がファイル全体を被覆していない（署名後にデータが追加されている）"
                )
            } else {
                report(
                    "C5",
                    candidate.endsAtRevisionBoundary,
                    "/ByteRange = \(candidate.byteRange.values)（署名時点のリビジョンを被覆）"
                )
            }

            // C6..C9: CMS structure
            guard let structure = candidate.structure else {
                report("C6", false, "署名構造が不正のため検査不能")
                report("C7", false, "同上")
                report("C8", false, "同上")
                report("C9", false, "同上", warnOnly: true)
                continue
            }

            var cms: ParsedCMSSignedData?
            do {
                let contents = try SignedPDFVerifier.hexDecode(Array(pdf)[structure.contentsHexRange])
                let cmsLength = try CMSSignedDataParser.encodedLength(of: contents)
                guard contents[cmsLength...].allSatisfy({ $0 == 0 }) else {
                    throw SignedPDFVerifierError.nonZeroContentsPadding
                }
                cms = try CMSSignedDataParser.parse(Array(contents[..<cmsLength]))
                report("C6", true, "CMS ContentInfo(SignedData) \(cmsLength) bytes + 0x00 パディング \(contents.count - cmsLength) bytes")
            } catch CMSSignedDataParserError.certificateMissing {
                report("C6", true, "CMS は解釈可能")
                report("C7", false, "署名者証明書が CMS 内に存在しない")
                report("C8", false, "C7 不成立のため検査不能")
                report("C9", false, "同上", warnOnly: true)
                continue
            } catch CMSSignedDataParserError.messageDigestAttributeMissing {
                report("C6", true, "CMS は解釈可能")
                report("C7", false, "signedAttrs に messageDigest が存在しない")
                report("C8", false, "C7 不成立のため検査不能")
                report("C9", false, "同上", warnOnly: true)
                continue
            } catch {
                report("C6", false, "CMS として解釈できない: \(error)")
                report("C7", false, "C6 不成立のため検査不能")
                report("C8", false, "同上")
                report("C9", false, "同上", warnOnly: true)
                continue
            }

            guard let parsed = cms else { continue }

            // C7: certificate + signedAttrs contents. signingTime は RFC 5652
            // で任意のため欠落は WARN(日時は /M で担保)。
            if let attributeOIDs = parsed.signedAttributeOIDs {
                let missing = [contentTypeOID].filter { !attributeOIDs.contains($0) }
                if !missing.isEmpty {
                    report("C7", false, "signedAttrs に contentType が存在しない")
                } else if !attributeOIDs.contains(signingTimeOID) {
                    report("C7", false, "signingTime なし（RFC 5652 では任意・日時は /M で担保）", warnOnly: true)
                } else {
                    report("C7", true, "signedAttrs: contentType / messageDigest / signingTime; 証明書あり")
                }
            } else {
                report("C7", true, "signedAttrs なし（直接署名方式・Acrobat 等）; 署名者証明書あり")
            }

            // C8: messageDigest vs SHA-256(ByteRange)
            if let messageDigest = parsed.messageDigest {
                let signedBytes = (try? ByteRangeCalculator.signedBytes(from: pdf, byteRange: structure.byteRange)) ?? Data()
                let computed = Array(SHA256.hash(data: signedBytes))
                report(
                    "C8",
                    computed == messageDigest,
                    computed == messageDigest ? "messageDigest は ByteRange の SHA-256 と一致" : "messageDigest が ByteRange の SHA-256 と一致しない"
                )
            } else {
                report(
                    "C8",
                    false,
                    "直接署名方式のため messageDigest 検査は非適用（署名値の検証は検証ビューアで行う）",
                    warnOnly: true
                )
            }

            // C9 (WARN): algorithms
            let signatureOK = ["1.2.840.113549.1.1.1", "1.2.840.113549.1.1.11"].contains(parsed.signatureAlgorithmOID)
            report(
                "C9",
                parsed.digestAlgorithmOID == sha256OID && signatureOK,
                "digestAlgorithm = \(parsed.digestAlgorithmOID), signatureAlgorithm = \(parsed.signatureAlgorithmOID)",
                warnOnly: true
            )
        }

        return MOJConformanceResult(items: items, signatureCount: total)
    }

    /// `D:YYYYMMDDHHmmSS` + タイムゾーンオフセット（`Z` / `±HH'mm'`）。
    static func isValidPDFDate(_ text: String) -> Bool {
        guard text.hasPrefix("D:"), text.count >= 17 else { return false }
        let digits = text.dropFirst(2).prefix(14)
        guard digits.count == 14, digits.allSatisfy(\.isNumber) else { return false }
        guard let month = Int(digits.dropFirst(4).prefix(2)),
              let day = Int(digits.dropFirst(6).prefix(2)),
              let hour = Int(digits.dropFirst(8).prefix(2)),
              let minute = Int(digits.dropFirst(10).prefix(2)),
              let second = Int(digits.dropFirst(12).prefix(2)),
              (1...12).contains(month), (1...31).contains(day),
              hour <= 23, minute <= 59, second <= 59 else { return false }

        let zone = String(text.dropFirst(16))
        if zone == "Z" { return true }
        // ±HH'mm' （末尾アポストロフィは省略可）
        let pattern = /^[+-]\d{2}'\d{2}'?$/
        return zone.wholeMatch(of: pattern) != nil
    }
}
