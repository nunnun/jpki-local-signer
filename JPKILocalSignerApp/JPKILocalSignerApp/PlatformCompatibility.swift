//
//  PlatformCompatibility.swift
//  JPKILocalSignerApp
//
//  Small shims so the same SwiftUI code compiles on iOS and native macOS
//  (NOT Catalyst): iOS-only modifiers become no-ops on macOS, and platform
//  colors/toolbar placements are unified behind one name.

import SwiftUI

extension View {
    /// `navigationBarTitleDisplayMode(.inline)` on iOS; no-op on macOS.
    @ViewBuilder
    func inlineNavigationBarTitle() -> some View {
        #if os(iOS)
        self.navigationBarTitleDisplayMode(.inline)
        #else
        self
        #endif
    }

    /// `textInputAutocapitalization(.never)` on iOS; no-op on macOS.
    @ViewBuilder
    func neverAutocapitalize() -> some View {
        #if os(iOS)
        self.textInputAutocapitalization(.never)
        #else
        self
        #endif
    }
}

extension View {
    /// Gives a sheet an explicit size on macOS. Unlike iOS (where sheets
    /// fill the screen), a macOS `.sheet` with no intrinsic width/height
    /// collapses to just its title and toolbar, hiding the content. No-op
    /// on iOS.
    @ViewBuilder
    func macOSSheetFrame(minWidth: CGFloat = 480, minHeight: CGFloat = 560) -> some View {
        #if os(macOS)
        self.frame(minWidth: minWidth, idealWidth: minWidth, minHeight: minHeight, idealHeight: minHeight)
        #else
        self
        #endif
    }
}

extension ToolbarItemPlacement {
    /// Trailing navigation-bar slot on iOS; automatic on macOS.
    static var platformTrailing: ToolbarItemPlacement {
        #if os(iOS)
        .topBarTrailing
        #else
        .automatic
        #endif
    }
}

extension Color {
    /// Grouped-list background on iOS; window background on macOS.
    static var platformGroupedBackground: Color {
        #if os(iOS)
        Color(.systemGroupedBackground)
        #else
        Color(nsColor: .windowBackgroundColor)
        #endif
    }
}
