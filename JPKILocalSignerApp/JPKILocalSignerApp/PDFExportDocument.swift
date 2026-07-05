//
//  PDFExportDocument.swift
//  JPKILocalSignerApp
//

import SwiftUI
import UniformTypeIdentifiers

/// Wraps signed PDF bytes for `.fileExporter`. The original source PDF is
/// never modified; this document only ever carries the newly produced,
/// signed copy (design.md FR-10).
struct PDFExportDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.pdf] }

    var data: Data

    init(data: Data = Data()) {
        self.data = data
    }

    init(configuration: ReadConfiguration) throws {
        data = configuration.file.regularFileContents ?? Data()
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}
