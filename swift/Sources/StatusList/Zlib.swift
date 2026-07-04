import CZlib

/// Minimal zlib (RFC 1950) wrappers for Token Status List `lst` payloads. Uses the system zlib
/// (`libz`), available on Linux and macOS, so the core stays cross-platform.
enum Zlib {

    static func inflate(_ input: [UInt8]) throws -> [UInt8] {
        var stream = z_stream()
        guard inflateInit_(&stream, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            throw StatusListError("zlib inflateInit failed")
        }
        defer { inflateEnd(&stream) }

        var input = input
        var output = [UInt8]()
        let chunk = 16384
        var outBuf = [UInt8](repeating: 0, count: chunk)
        var status: Int32 = Z_OK

        input.withUnsafeMutableBufferPointer { inPtr in
            stream.next_in = inPtr.baseAddress
            stream.avail_in = uInt(inPtr.count)
            repeat {
                let produced: Int = outBuf.withUnsafeMutableBufferPointer { outPtr in
                    stream.next_out = outPtr.baseAddress
                    stream.avail_out = uInt(chunk)
                    status = CZlib.inflate(&stream, Z_NO_FLUSH)
                    return chunk - Int(stream.avail_out)
                }
                output.append(contentsOf: outBuf[0..<produced])
            } while status == Z_OK
        }
        guard status == Z_STREAM_END else { throw StatusListError("invalid DEFLATE data (status \(status))") }
        return output
    }

    /// Test-only: compress with zlib (the wallet never produces status lists).
    static func deflate(_ input: [UInt8]) throws -> [UInt8] {
        var stream = z_stream()
        guard deflateInit_(&stream, Z_DEFAULT_COMPRESSION, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            throw StatusListError("zlib deflateInit failed")
        }
        defer { deflateEnd(&stream) }

        var input = input
        var output = [UInt8]()
        let chunk = 16384
        var outBuf = [UInt8](repeating: 0, count: chunk)
        var status: Int32 = Z_OK

        input.withUnsafeMutableBufferPointer { inPtr in
            stream.next_in = inPtr.baseAddress
            stream.avail_in = uInt(inPtr.count)
            repeat {
                let produced: Int = outBuf.withUnsafeMutableBufferPointer { outPtr in
                    stream.next_out = outPtr.baseAddress
                    stream.avail_out = uInt(chunk)
                    status = CZlib.deflate(&stream, Z_FINISH)
                    return chunk - Int(stream.avail_out)
                }
                output.append(contentsOf: outBuf[0..<produced])
            } while status == Z_OK
        }
        guard status == Z_STREAM_END else { throw StatusListError("deflate failed (status \(status))") }
        return output
    }
}
