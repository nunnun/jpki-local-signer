//
//  VerificationFlowModel.swift
//  JPKILocalSignerApp
//
//  Drives the standalone 検証 tab (design.md FR-11): import a PDF and run the
//  offline, synchronous self-verification over its embedded signature(s).
//  Like the signing flow, this holds no networking code and never persists
//  anything beyond the in-memory PDF bytes needed to render the preview.

import Foundation
import JPKILocalSigner
import Observation

@MainActor
@Observable
final class VerificationFlowModel {
    private(set) var pdfData: Data?
    private(set) var fileName: String = ""
    private(set) var inspection: PDFSignatureInspection?
    var errorMessage: String?

    var hasSelectedPDF: Bool { pdfData != nil }

    func loadPDF(from url: URL) {
        let didStartAccessing = url.startAccessingSecurityScopedResource()
        defer {
            if didStartAccessing {
                url.stopAccessingSecurityScopedResource()
            }
        }

        do {
            let data = try Data(contentsOf: url)
            loadPDF(data: data, fileName: url.lastPathComponent)
        } catch {
            errorMessage = String(localized: "PDFの読み込みに失敗しました。もう一度お試しください。")
        }
    }

    /// Loads already-read PDF bytes (e.g. handed over from another app via
    /// the share sheet / onOpenURL, where the security-scoped read has
    /// already happened).
    func loadPDF(data: Data, fileName: String) {
        pdfData = data
        self.fileName = fileName
        errorMessage = nil
        inspection = SignedPDFVerifier.inspect(pdf: data)
    }

    func loadPDFImportFailed() {
        errorMessage = String(localized: "PDFを選択できませんでした。もう一度お試しください。")
    }

    func clearSelection() {
        pdfData = nil
        fileName = ""
        inspection = nil
        errorMessage = nil
    }
}
