//
//  PDFPreviewView.swift
//  JPKILocalSignerApp
//
//  PDFKit-based preview so the user can confirm the exact document contents
//  before signing (design.md FR-02). UIViewRepresentable on iOS,
//  NSViewRepresentable on native macOS.

import PDFKit
import SwiftUI

#if canImport(UIKit)

struct PDFPreviewView: UIViewRepresentable {
    let data: Data

    func makeUIView(context: Context) -> PDFView {
        let view = PDFView()
        view.autoScales = true
        view.displayMode = .singlePageContinuous
        view.displayDirection = .vertical
        view.document = PDFDocument(data: data)
        view.accessibilityLabel = String(localized: "PDFプレビュー")
        return view
    }

    func updateUIView(_ uiView: PDFView, context: Context) {
        if uiView.document?.dataRepresentation() != data {
            uiView.document = PDFDocument(data: data)
        }
    }
}

#else

struct PDFPreviewView: NSViewRepresentable {
    let data: Data

    func makeNSView(context: Context) -> PDFView {
        let view = PDFView()
        view.autoScales = true
        view.displayMode = .singlePageContinuous
        view.displayDirection = .vertical
        view.document = PDFDocument(data: data)
        view.setAccessibilityLabel(String(localized: "PDFプレビュー"))
        return view
    }

    func updateNSView(_ nsView: PDFView, context: Context) {
        if nsView.document?.dataRepresentation() != data {
            nsView.document = PDFDocument(data: data)
        }
    }
}

#endif
