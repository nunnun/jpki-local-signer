import Foundation
import Testing
@testable import PDFSigning

@Suite("PDF dictionary scanner")
struct PDFDictionaryScannerTests {
    // Regression: a page dictionary carries a transparency-group sub-dictionary
    // `/Group<</Type/Group…>>`. Top-level `/Type` must resolve to `Page`, not
    // the nested group's `Group`. This shape is emitted by 申請用総合ソフト and
    // most real-world PDFs, and previously made firstPage() throw
    // pageObjectNotFound.
    @Test("Top-level /Type ignores nested /Type inside /Group")
    func typeIgnoresNestedGroupType() {
        let page = "<</Type/Page/Parent 2 0 R/MediaBox[ 0 0 595.32 841.92]"
            + "/Contents 4 0 R/Group<</Type/Group/S/Transparency/CS/DeviceRGB>>>>"
        #expect(PDFDictionaryScanner.name(named: "Type", in: page) == "Page")
    }

    @Test("Reference value skips nested dictionaries and arrays")
    func referenceResolvesTopLevelKey() {
        let catalog = "<</Type/Catalog/Pages 2 0 R/Lang(ja)"
            + "/MarkInfo<</Marked true>>/Metadata 600 0 R>>"
        let pages = PDFDictionaryScanner.reference(named: "Pages", in: catalog)
        #expect(pages?.number == 2)
        #expect(pages?.generation == 0)
    }

    @Test("Keys inside a literal string are not matched")
    func literalStringContentsAreSkipped() {
        // The `(… /Type/Fake …)` literal must not be treated as a key.
        let body = "<</Title(has /Type/Fake inside)/Type/Page>>"
        #expect(PDFDictionaryScanner.name(named: "Type", in: body) == "Page")
    }

    @Test("Kids array is read from the top-level page tree node")
    func kidsArrayResolves() {
        let pages = "<</Type/Pages/Count 2/Kids[ 3 0 R 26 0 R] >>"
        let kids = PDFDictionaryScanner.referenceArray(named: "Kids", in: pages)
        #expect(kids?.map(\.number) == [3, 26])
    }
}
