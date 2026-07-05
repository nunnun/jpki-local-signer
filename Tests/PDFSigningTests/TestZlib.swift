import Foundation

#if canImport(Compression)
import Compression
#endif

/// zlib (RFC 1950) encoder for building /FlateDecode test fixtures:
/// 2-byte header + raw DEFLATE + Adler-32 checksum.
enum TestZlib {
    static func deflate(_ input: [UInt8]) -> [UInt8] {
        #if canImport(Compression)
        let capacity = max(input.count * 2, 1 << 12)
        var output = [UInt8](repeating: 0, count: capacity)
        let written = output.withUnsafeMutableBufferPointer { outputBuffer in
            input.withUnsafeBufferPointer { inputBuffer in
                compression_encode_buffer(
                    outputBuffer.baseAddress!,
                    capacity,
                    inputBuffer.baseAddress!,
                    input.count,
                    nil,
                    COMPRESSION_ZLIB
                )
            }
        }
        precondition(written > 0, "deflate failed")

        var result: [UInt8] = [0x78, 0x9C]
        result.append(contentsOf: output.prefix(written))
        let checksum = adler32(input)
        result.append(UInt8((checksum >> 24) & 0xFF))
        result.append(UInt8((checksum >> 16) & 0xFF))
        result.append(UInt8((checksum >> 8) & 0xFF))
        result.append(UInt8(checksum & 0xFF))
        return result
        #else
        fatalError("Compression framework unavailable")
        #endif
    }

    private static func adler32(_ input: [UInt8]) -> UInt32 {
        var a: UInt32 = 1
        var b: UInt32 = 0
        for byte in input {
            a = (a + UInt32(byte)) % 65521
            b = (b + a) % 65521
        }
        return b << 16 | a
    }
}
