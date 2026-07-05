//
//  ImportStepView.swift
//  JPKILocalSignerApp
//
//  Step 1 of the flow (design.md FR-01): pick a local PDF to sign.

import SwiftUI

struct ImportStepView: View {
    @Binding var isImporterPresented: Bool
    let errorMessage: String?

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "doc.badge.plus")
                .font(.system(size: 64))
                .foregroundStyle(.tint)
                .accessibilityHidden(true)

            VStack(spacing: 8) {
                Text("署名するPDFを選択してください")
                    .font(.title3)
                    .fontWeight(.semibold)
                    .accessibilityAddTraits(.isHeader)
                Text("マイナンバーカードの署名用電子証明書で、選択したPDFに電子署名を行います。")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }

            Button {
                isImporterPresented = true
            } label: {
                Label("PDFを選択", systemImage: "folder")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .padding(.horizontal, 40)
            .accessibilityHint("ファイルを開いてPDFを選択します")

            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }

            Spacer()
            Spacer()
        }
        .padding()
    }
}

#Preview {
    ImportStepView(isImporterPresented: .constant(false), errorMessage: nil)
}
