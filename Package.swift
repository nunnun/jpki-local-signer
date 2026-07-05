// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "JPKILocalSigner",
    defaultLocalization: "ja",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(
            name: "JPKILocalSigner",
            targets: ["JPKILocalSigner"]
        ),
        .executable(
            name: "TestSigner",
            targets: ["TestSigner"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "4.5.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", exact: "1.7.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", exact: "1.19.1")
    ],
    targets: [
        .target(
            name: "NFCTransport"
        ),
        .target(
            name: "JPKICard",
            dependencies: ["NFCTransport"]
        ),
        .target(
            name: "CMSBuilder",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "X509", package: "swift-certificates")
            ]
        ),
        .target(
            name: "PDFSigning",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto")
            ]
        ),
        .target(
            name: "SelfVerify",
            dependencies: [
                "PDFSigning",
                "CMSBuilder",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates")
            ],
            resources: [
                .copy("TrustAnchors")
            ]
        ),
        .target(
            name: "JPKILocalSigner",
            dependencies: [
                "NFCTransport",
                "JPKICard",
                "CMSBuilder",
                "PDFSigning",
                "SelfVerify",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "X509", package: "swift-certificates")
            ],
            resources: [
                .process("Localizable.xcstrings")
            ]
        ),
        .executableTarget(
            name: "TestSigner",
            dependencies: [
                "JPKILocalSigner",
                "PDFSigning",
                "SelfVerify",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1")
            ]
        ),
        .testTarget(
            name: "APDUTests",
            dependencies: ["NFCTransport", "JPKICard"]
        ),
        .testTarget(
            name: "CMSBuilderTests",
            dependencies: ["CMSBuilder"]
        ),
        .testTarget(
            name: "PDFSigningTests",
            dependencies: ["PDFSigning"]
        ),
        .testTarget(
            name: "SelfVerifyTests",
            dependencies: [
                "PDFSigning",
                "SelfVerify",
                "CMSBuilder",
                "JPKILocalSigner",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1")
            ]
        ),
        .testTarget(
            name: "JPKILocalSignerTests",
            dependencies: ["JPKILocalSigner"]
        )
    ]
)
