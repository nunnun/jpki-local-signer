//
//  JPKILocalSignerAppApp.swift
//  JPKILocalSignerApp
//
//  Created by Hirotaka Nakajima on 2026/06/20.
//

import SwiftUI

@main
struct JPKILocalSignerAppApp: App {
    var body: some Scene {
        #if os(macOS)
        WindowGroup {
            ContentView()
        }
        .defaultSize(width: 1100, height: 760)
        #else
        WindowGroup {
            ContentView()
        }
        #endif
    }
}
