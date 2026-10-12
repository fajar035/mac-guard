import Foundation
import Testing
@testable import MacGuardKit

@Test("Entropy of uniform bytes is zero")
func entropyOfUniformBytesIsZero() {
    #expect(abs(Shannon.entropy(Data(repeating: 0x41, count: 100))) < 0.0001)
}

@Test("Entropy of random-looking bytes is high")
func entropyOfRandomBytesIsHigh() {
    var bytes = [UInt8]()
    var generator = SystemRandomNumberGenerator()
    for _ in 0..<4096 { bytes.append(UInt8.random(in: 0...255, using: &generator)) }
    #expect(Shannon.entropy(Data(bytes)) > 7.9)
}

@Test("Entropy of empty data is zero")
func entropyOfEmptyIsZero() {
    #expect(Shannon.entropy(Data()) == 0)
}

@Test("Single-file size is reported correctly")
func singleFileSizeIsReported() throws {
    let path = NSTemporaryDirectory() + "/mg-size-\(UUID().uuidString).bin"
    try Data(repeating: 0, count: 4096).write(to: URL(fileURLWithPath: path))
    defer { try? FileManager.default.removeItem(atPath: path) }
    // The previous implementation returned 0 for anything that was not a directory.
    #expect(PathUtil.size(path) == 4096)
}

@Test("Hex digest is stable and full length")
func digestIsStable() {
    let a = Digesting.sha256Hex(Data("macguard".utf8))
    let b = Digesting.sha256Hex(Data("macguard".utf8))
    #expect(a == b)
    #expect(a.count == 64)
    #expect(a != Digesting.sha256Hex(Data("macguard!".utf8)))
}