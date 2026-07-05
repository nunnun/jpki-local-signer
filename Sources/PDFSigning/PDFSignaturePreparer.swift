import Foundation

public struct PDFSignaturePlaceholder: Equatable, Sendable {
    public let contentsHexRange: Range<Int>
    public let byteRange: PDFByteRange

    public init(contentsHexRange: Range<Int>, byteRange: PDFByteRange) {
        self.contentsHexRange = contentsHexRange
        self.byteRange = byteRange
    }

    public var contentsByteCapacity: Int {
        contentsHexRange.count / 2
    }
}

public struct PreparedPDFSignature: Equatable, Sendable {
    public let pdf: Data
    public let placeholder: PDFSignaturePlaceholder

    public init(pdf: Data, placeholder: PDFSignaturePlaceholder) {
        self.pdf = pdf
        self.placeholder = placeholder
    }
}

public struct PDFSignaturePreparationOptions: Equatable, Sendable {
    public let signerName: String
    public let signingDate: Date
    /// `nil` auto-numbers the field ("Signature<N+1>" where N is the number
    /// of signatures already present) so co-signing never collides.
    public let fieldName: String?
    public let contentsByteCapacity: Int

    public init(
        signerName: String,
        signingDate: Date,
        fieldName: String? = nil,
        contentsByteCapacity: Int = PDFSignaturePreparer.defaultContentsByteCapacity
    ) {
        self.signerName = signerName
        self.signingDate = signingDate
        self.fieldName = fieldName
        self.contentsByteCapacity = contentsByteCapacity
    }
}

public enum PDFSignaturePreparer {
    public static let defaultContentsByteCapacity = 16_384

    private static let byteRangePlaceholder = "[0000000000 0000000000 0000000000 0000000000]"

    public static func prepareForSignature(
        pdf: Data,
        options: PDFSignaturePreparationOptions
    ) throws -> PreparedPDFSignature {
        guard options.contentsByteCapacity > 0 else {
            throw PDFSignaturePreparerError.invalidContentsCapacity(options.contentsByteCapacity)
        }

        let index = try PDFDocumentIndex.parse(pdf)
        let page = try firstPage(in: index)

        let signatureObjectNumber = index.nextObjectNumber
        let fieldObjectNumber = signatureObjectNumber + 1
        let fieldReference = "\(fieldObjectNumber) 0 R"
        let fieldName = options.fieldName ?? "Signature\(countSignatureContents(in: pdf) + 1)"

        // Objects rewritten by this incremental update, in emit order.
        var updates: [(number: Int, generation: Int, body: String)] = []
        try planAcroFormUpdate(fieldReference: fieldReference, index: index, updates: &updates)
        try planAnnotationsUpdate(fieldReference: fieldReference, page: page, index: index, updates: &updates)

        let contentsHex = String(repeating: "0", count: options.contentsByteCapacity * 2)
        let signatureBody = """
        << /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /ByteRange \(byteRangePlaceholder) /Contents <\(contentsHex)> /M (\(pdfDateString(options.signingDate))) /Name \(pdfTextString(options.signerName)) >>
        """
        let fieldBody = """
        << /Type /Annot /Subtype /Widget /FT /Sig /T \(pdfTextString(fieldName)) /V \(signatureObjectNumber) 0 R /Rect [0 0 0 0] /F 132 /P \(page.number) \(page.generation) R >>
        """
        updates.append((signatureObjectNumber, 0, signatureBody))
        updates.append((fieldObjectNumber, 0, fieldBody))

        // The new placeholder's exact offset is derived while emitting the
        // increment (never by re-scanning the file) so a co-signed document
        // may legitimately contain other /Contents hex strings.
        var contentsHexStart: Int?
        var increment = Data()
        var entries: [PDFXrefEntry] = []
        for update in updates {
            let objectStart = pdf.count + increment.count
            entries.append(PDFXrefEntry(
                number: update.number,
                generation: update.generation,
                offset: objectStart
            ))
            let header = "\(update.number) \(update.generation) obj\n"
            if update.number == signatureObjectNumber,
               let markerRange = update.body.range(of: "/Contents <") {
                let prefixLength = update.body[..<markerRange.upperBound].utf8.count
                contentsHexStart = objectStart + header.utf8.count + prefixLength
            }
            increment.appendLatin1(header + update.body + "\nendobj\n")
        }

        let xrefOffset = pdf.count + increment.count
        if index.usesXrefStream {
            let xrefStreamNumber = fieldObjectNumber + 1
            entries.append(PDFXrefEntry(number: xrefStreamNumber, generation: 0, offset: xrefOffset))
            let size = xrefStreamNumber + 1
            increment.append(xrefStreamObject(
                number: xrefStreamNumber,
                entries: entries,
                size: size,
                rootReference: index.rootReference,
                previousXrefOffset: index.lastXrefOffset
            ))
            increment.appendLatin1("startxref\n\(xrefOffset)\n%%EOF\n")
        } else {
            increment.appendLatin1(classicXref(entries: entries))
            increment.appendLatin1("trailer\n<< /Size \(fieldObjectNumber + 1) /Root \(index.rootReference.number) \(index.rootReference.generation) R /Prev \(index.lastXrefOffset) >>\nstartxref\n\(xrefOffset)\n%%EOF\n")
        }

        var preparedPDF = pdf
        preparedPDF.append(increment)

        guard let contentsHexStart else {
            throw PDFSignaturePreparerError.contentsPlaceholderNotFound
        }
        let contentsHexRange = contentsHexStart..<(contentsHexStart + options.contentsByteCapacity * 2)
        let bytes = [UInt8](preparedPDF)
        guard contentsHexRange.lowerBound >= 1,
              contentsHexRange.upperBound < bytes.count,
              bytes[contentsHexRange.lowerBound - 1] == UInt8(ascii: "<"),
              bytes[contentsHexRange.upperBound] == UInt8(ascii: ">"),
              bytes[contentsHexRange].allSatisfy({ $0 == UInt8(ascii: "0") }) else {
            throw PDFSignaturePreparerError.contentsPlaceholderNotFound
        }

        let finalByteRange = try ByteRangeCalculator.byteRange(
            excludingContentsHexRange: contentsHexRange,
            fileLength: preparedPDF.count
        )
        // Only the increment may contain the textual placeholder; existing
        // signatures in a co-signed input keep their real ByteRange values.
        try replaceByteRangePlaceholder(in: &preparedPDF, with: finalByteRange, searchFrom: pdf.count)

        return PreparedPDFSignature(
            pdf: preparedPDF,
            placeholder: PDFSignaturePlaceholder(
                contentsHexRange: contentsHexRange,
                byteRange: finalByteRange
            )
        )
    }

    /// Number of `/Contents <hex>` signature payloads already present.
    /// Page `/Contents` entries reference streams (`N 0 R`), never hex
    /// strings, so this counts exactly the embedded signatures.
    public static func countSignatureContents(in pdf: Data) -> Int {
        let bytes = [UInt8](pdf)
        let marker = [UInt8]("/Contents".utf8)
        var count = 0
        var searchIndex = 0

        while let markerRange = range(of: marker, in: bytes, from: searchIndex) {
            var cursor = markerRange.upperBound
            skipPDFWhitespace(in: bytes, from: &cursor)
            if cursor < bytes.count, bytes[cursor] == UInt8(ascii: "<") {
                count += 1
            }
            searchIndex = markerRange.upperBound
        }
        return count
    }

    // MARK: - Page tree

    private struct PageObject {
        let number: Int
        let generation: Int
        let body: String
    }

    /// First page in page-tree order (Root → /Pages → /Kids…).
    private static func firstPage(in index: PDFDocumentIndex) throws -> PageObject {
        let rootBody = try index.objectBody(index.rootReference.number)
        guard var reference = PDFDictionaryScanner.reference(named: "Pages", in: rootBody) else {
            throw PDFSignaturePreparerError.pageObjectNotFound
        }

        for _ in 0..<64 {
            let body = try index.objectBody(reference.number)
            let type = PDFDictionaryScanner.name(named: "Type", in: body)
            if type == "Page" {
                return PageObject(
                    number: reference.number,
                    generation: index.generation(of: reference.number),
                    body: body
                )
            }
            guard type == "Pages",
                  let kids = PDFDictionaryScanner.referenceArray(named: "Kids", in: body),
                  let firstKid = kids.first else {
                throw PDFSignaturePreparerError.pageObjectNotFound
            }
            reference = firstKid
        }

        throw PDFSignaturePreparerError.pageObjectNotFound
    }

    // MARK: - AcroForm

    private static func planAcroFormUpdate(
        fieldReference: String,
        index: PDFDocumentIndex,
        updates: inout [(number: Int, generation: Int, body: String)]
    ) throws {
        let root = index.rootReference
        let rootBody = try index.objectBody(root.number)

        guard let valueRange = PDFDictionaryScanner.valueRange(named: "AcroForm", in: rootBody) else {
            let updated = try appendEntry(
                "/AcroForm << /Fields [\(fieldReference)] /SigFlags 3 >>",
                toDictionaryBody: rootBody
            )
            updates.append((root.number, index.generation(of: root.number), updated))
            return
        }

        let value = rootBody[valueRange]
        if value.hasPrefix("<<") {
            let dictionaryRange = try balancedDictionaryRange(in: rootBody, from: valueRange.lowerBound)
            let updatedAcroForm = try acroFormBodyAddingSignatureField(
                fieldReference,
                to: String(rootBody[dictionaryRange]),
                index: index,
                updates: &updates
            )
            var updatedRoot = rootBody
            updatedRoot.replaceSubrange(dictionaryRange, with: updatedAcroForm)
            updates.append((root.number, index.generation(of: root.number), updatedRoot))
            return
        }

        if let reference = PDFDictionaryScanner.parseReference(value) {
            let acroFormBody = try index.objectBody(reference.number)
            guard acroFormBody.hasPrefix("<<") else {
                throw PDFSignaturePreparerError.existingAcroFormUnsupported
            }
            let updated = try acroFormBodyAddingSignatureField(
                fieldReference,
                to: acroFormBody,
                index: index,
                updates: &updates
            )
            if updated != acroFormBody {
                updates.append((reference.number, index.generation(of: reference.number), updated))
            }
            return
        }

        throw PDFSignaturePreparerError.existingAcroFormUnsupported
    }

    /// Appends the field reference to /Fields (inline or indirect array) and
    /// ensures /SigFlags 3. Indirect /Fields arrays are rewritten as their own
    /// objects via `updates`.
    private static func acroFormBodyAddingSignatureField(
        _ fieldReference: String,
        to body: String,
        index: PDFDocumentIndex,
        updates: inout [(number: Int, generation: Int, body: String)]
    ) throws -> String {
        var updated = body

        if let fieldsValueRange = PDFDictionaryScanner.valueRange(named: "Fields", in: updated) {
            let value = updated[fieldsValueRange]
            if value.hasPrefix("[") {
                let fieldsRange = try balancedArrayRange(in: updated, from: fieldsValueRange.lowerBound)
                let insertIndex = updated.index(before: fieldsRange.upperBound)
                updated.insert(contentsOf: " \(fieldReference)", at: insertIndex)
            } else if let reference = PDFDictionaryScanner.parseReference(value) {
                let arrayBody = try index.objectBody(reference.number)
                guard arrayBody.hasPrefix("[") else {
                    throw PDFSignaturePreparerError.existingAcroFormUnsupported
                }
                let arrayRange = try balancedArrayRange(in: arrayBody, from: arrayBody.startIndex)
                var updatedArray = arrayBody
                updatedArray.insert(contentsOf: " \(fieldReference)", at: updatedArray.index(before: arrayRange.upperBound))
                updates.append((reference.number, index.generation(of: reference.number), updatedArray))
            } else {
                throw PDFSignaturePreparerError.existingAcroFormUnsupported
            }
        } else {
            let insertIndex = try dictionaryClosingIndex(in: updated)
            updated.insert(contentsOf: " /Fields [\(fieldReference)]", at: insertIndex)
        }

        if PDFDictionaryScanner.range(ofName: "SigFlags", in: updated) == nil {
            let insertIndex = try dictionaryClosingIndex(in: updated)
            updated.insert(contentsOf: " /SigFlags 3", at: insertIndex)
        }

        return updated
    }

    // MARK: - Page annotations

    private static func planAnnotationsUpdate(
        fieldReference: String,
        page: PageObject,
        index: PDFDocumentIndex,
        updates: inout [(number: Int, generation: Int, body: String)]
    ) throws {
        guard let valueRange = PDFDictionaryScanner.valueRange(named: "Annots", in: page.body) else {
            let updated = try appendEntry("/Annots [\(fieldReference)]", toDictionaryBody: page.body)
            updates.append((page.number, page.generation, updated))
            return
        }

        let value = page.body[valueRange]
        if value.hasPrefix("[") {
            let annotsRange = try balancedArrayRange(in: page.body, from: valueRange.lowerBound)
            var updated = page.body
            updated.insert(contentsOf: " \(fieldReference)", at: updated.index(before: annotsRange.upperBound))
            updates.append((page.number, page.generation, updated))
            return
        }

        if let reference = PDFDictionaryScanner.parseReference(value) {
            let arrayBody = try index.objectBody(reference.number)
            guard arrayBody.hasPrefix("[") else {
                throw PDFSignaturePreparerError.existingPageAnnotationsUnsupported
            }
            let arrayRange = try balancedArrayRange(in: arrayBody, from: arrayBody.startIndex)
            var updatedArray = arrayBody
            updatedArray.insert(contentsOf: " \(fieldReference)", at: updatedArray.index(before: arrayRange.upperBound))
            updates.append((reference.number, index.generation(of: reference.number), updatedArray))
            return
        }

        throw PDFSignaturePreparerError.existingPageAnnotationsUnsupported
    }

    // MARK: - Placeholder

    public static func findSignaturePlaceholder(in pdf: Data) throws -> PDFSignaturePlaceholder {
        let bytes = [UInt8](pdf)
        let marker = [UInt8]("/Contents".utf8)
        var matches: [Range<Int>] = []
        var searchIndex = 0

        while let markerRange = range(of: marker, in: bytes, from: searchIndex) {
            var cursor = markerRange.upperBound
            skipPDFWhitespace(in: bytes, from: &cursor)

            guard cursor < bytes.count, bytes[cursor] == UInt8(ascii: "<") else {
                searchIndex = markerRange.upperBound
                continue
            }

            let hexStart = cursor + 1
            cursor = hexStart
            while cursor < bytes.count, bytes[cursor] != UInt8(ascii: ">") {
                cursor += 1
            }

            guard cursor < bytes.count else {
                throw PDFSignaturePreparerError.unterminatedContentsHex
            }

            matches.append(hexStart..<cursor)
            searchIndex = cursor + 1
        }

        guard matches.count == 1, let contentsHexRange = matches.first else {
            if matches.isEmpty {
                throw PDFSignaturePreparerError.contentsPlaceholderNotFound
            }
            throw PDFSignaturePreparerError.multipleContentsPlaceholdersFound(matches.count)
        }

        guard contentsHexRange.count > 0, contentsHexRange.count.isMultiple(of: 2) else {
            throw PDFSignaturePreparerError.invalidContentsHexLength(contentsHexRange.count)
        }

        for byte in bytes[contentsHexRange] {
            guard isHexDigit(byte) else {
                throw PDFSignaturePreparerError.invalidContentsHexByte(byte)
            }
        }

        let byteRange = try ByteRangeCalculator.byteRange(
            excludingContentsHexRange: contentsHexRange,
            fileLength: pdf.count
        )
        return PDFSignaturePlaceholder(contentsHexRange: contentsHexRange, byteRange: byteRange)
    }

    // MARK: - Xref emission

    private static func classicXref(entries: [PDFXrefEntry]) -> String {
        var output = "xref\n"
        for entry in entries.sorted(by: { $0.number < $1.number }) {
            output += "\(entry.number) 1\n"
            output += String(format: "%010d %05d n \n", entry.offset, entry.generation)
        }
        return output
    }

    /// Uncompressed cross-reference stream (/W [1 4 2]) covering `entries`
    /// plus itself.
    private static func xrefStreamObject(
        number: Int,
        entries: [PDFXrefEntry],
        size: Int,
        rootReference: (number: Int, generation: Int),
        previousXrefOffset: Int
    ) -> Data {
        let sorted = entries.sorted(by: { $0.number < $1.number })

        var payload: [UInt8] = []
        var indexPairs: [Int] = []
        for entry in sorted {
            indexPairs.append(entry.number)
            indexPairs.append(1)
            payload.append(0x01)
            payload.append(UInt8((entry.offset >> 24) & 0xFF))
            payload.append(UInt8((entry.offset >> 16) & 0xFF))
            payload.append(UInt8((entry.offset >> 8) & 0xFF))
            payload.append(UInt8(entry.offset & 0xFF))
            payload.append(UInt8((entry.generation >> 8) & 0xFF))
            payload.append(UInt8(entry.generation & 0xFF))
        }

        let indexText = indexPairs.map(String.init).joined(separator: " ")
        var object = Data()
        object.appendLatin1("\(number) 0 obj\n<< /Type /XRef /Size \(size) /Index [\(indexText)] /W [1 4 2] /Root \(rootReference.number) \(rootReference.generation) R /Prev \(previousXrefOffset) /Length \(payload.count) >>\nstream\n")
        object.append(contentsOf: payload)
        object.appendLatin1("\nendstream\nendobj\n")
        return object
    }

    // MARK: - String manipulation helpers

    private static func appendEntry(_ entry: String, toDictionaryBody body: String) throws -> String {
        guard let insertIndex = body.range(of: ">>", options: .backwards)?.lowerBound else {
            throw PDFSignaturePreparerError.invalidObjectDictionary
        }

        var updated = body
        updated.insert(contentsOf: " \(entry) ", at: insertIndex)
        return updated
    }

    private static func dictionaryClosingIndex(in body: String) throws -> String.Index {
        guard body.hasPrefix("<<") else {
            throw PDFSignaturePreparerError.invalidObjectDictionary
        }
        let range = try balancedDictionaryRange(in: body, from: body.startIndex)
        return body.index(range.upperBound, offsetBy: -2)
    }

    private static func balancedDictionaryRange(in text: String, from startIndex: String.Index) throws -> Range<String.Index> {
        guard text[startIndex...].hasPrefix("<<") else {
            throw PDFSignaturePreparerError.invalidObjectDictionary
        }

        var index = startIndex
        var depth = 0
        while index < text.endIndex {
            if text[index...].hasPrefix("<<") {
                depth += 1
                index = text.index(index, offsetBy: 2)
            } else if text[index...].hasPrefix(">>") {
                depth -= 1
                index = text.index(index, offsetBy: 2)
                if depth == 0 {
                    return startIndex..<index
                }
            } else {
                index = text.index(after: index)
            }
        }

        throw PDFSignaturePreparerError.invalidObjectDictionary
    }

    private static func balancedArrayRange(in text: String, from startIndex: String.Index) throws -> Range<String.Index> {
        guard text[startIndex...].hasPrefix("[") else {
            throw PDFSignaturePreparerError.invalidObjectDictionary
        }

        var index = startIndex
        var depth = 0
        while index < text.endIndex {
            if text[index] == "[" {
                depth += 1
            } else if text[index] == "]" {
                depth -= 1
                if depth == 0 {
                    return startIndex..<text.index(after: index)
                }
            }
            index = text.index(after: index)
        }

        throw PDFSignaturePreparerError.invalidObjectDictionary
    }

    private static func replaceByteRangePlaceholder(in pdf: inout Data, with byteRange: PDFByteRange, searchFrom startIndex: Int) throws {
        let replacement = String(
            format: "[%010d %010d %010d %010d]",
            byteRange.firstOffset,
            byteRange.firstLength,
            byteRange.secondOffset,
            byteRange.secondLength
        )
        guard replacement.count == byteRangePlaceholder.count else {
            throw PDFSignaturePreparerError.byteRangeTooLarge
        }

        let bytes = [UInt8](pdf)
        guard let range = range(of: [UInt8](byteRangePlaceholder.utf8), in: bytes, from: startIndex) else {
            throw PDFSignaturePreparerError.byteRangePlaceholderNotFound
        }
        pdf.replaceSubrange(range, with: Data(replacement.utf8))
    }

    private static func range(of needle: [UInt8], in haystack: [UInt8], from startIndex: Int) -> Range<Int>? {
        guard !needle.isEmpty, needle.count <= haystack.count else {
            return nil
        }

        let lastStart = haystack.count - needle.count
        guard startIndex <= lastStart else {
            return nil
        }

        let first = needle[0]
        var index = startIndex
        outer: while index <= lastStart {
            if haystack[index] != first {
                index += 1
                continue
            }
            for offset in 1..<needle.count where haystack[index + offset] != needle[offset] {
                index += 1
                continue outer
            }
            return index..<index + needle.count
        }

        return nil
    }

    private static func skipPDFWhitespace(in bytes: [UInt8], from cursor: inout Int) {
        while cursor < bytes.count, PDFLexer.isWhitespace(bytes[cursor]) {
            cursor += 1
        }
    }

    private static func isHexDigit(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
            || (UInt8(ascii: "A")...UInt8(ascii: "F")).contains(byte)
            || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(byte)
    }

    private static func pdfDateString(_ date: Date) -> String {
        let components = utcCalendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        return String(
            format: "D:%04d%02d%02d%02d%02d%02dZ",
            locale: Locale(identifier: "en_US_POSIX"),
            components.year ?? 1970,
            components.month ?? 1,
            components.day ?? 1,
            components.hour ?? 0,
            components.minute ?? 0,
            components.second ?? 0
        )
    }

    /// PDF text string: ASCII stays a literal string; anything else becomes a
    /// UTF-16BE hex string with BOM so Japanese names survive (PDF 32000-1
    /// §7.9.2.2).
    static func pdfTextString(_ value: String) -> String {
        if value.allSatisfy({ $0.isASCII }) {
            var escaped = ""
            for character in value {
                switch character {
                case "\\": escaped += "\\\\"
                case "(": escaped += "\\("
                case ")": escaped += "\\)"
                default: escaped.append(character)
                }
            }
            return "(\(escaped))"
        }

        var hex = "FEFF"
        for unit in value.utf16 {
            hex += String(format: "%04X", unit)
        }
        return "<\(hex)>"
    }

    private static var utcCalendar: Calendar {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0) ?? .gmt
        return calendar
    }
}

public enum PDFSignaturePreparerError: Error, Equatable, Sendable {
    case contentsPlaceholderNotFound
    case multipleContentsPlaceholdersFound(Int)
    case unterminatedContentsHex
    case invalidContentsHexLength(Int)
    case invalidContentsHexByte(UInt8)
    case invalidContentsCapacity(Int)
    case invalidPDF
    case rootObjectNotFound
    case pageObjectNotFound
    case objectNotFound(Int)
    case invalidObjectDictionary
    case existingAcroFormUnsupported
    case existingPageAnnotationsUnsupported
    case unsupportedStreamFilter(String)
    case unsupportedStreamLength
    case streamDecodeFailed
    case byteRangePlaceholderNotFound
    case byteRangeTooLarge
}

struct PDFXrefEntry: Equatable, Sendable {
    let number: Int
    let generation: Int
    let offset: Int
}

extension Data {
    mutating func appendLatin1(_ string: String) {
        append(contentsOf: string.latin1Bytes)
    }
}
