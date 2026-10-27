import Crypto
import NIOCore
import Testing
@testable import NIOSSH

struct KeyExpansionTests {
    @Test func expandsAcrossMultipleHashBlocks() {
        var base = SHA256()
        base.update(data: Array("shared-secret-and-exchange-hash".utf8))
        let key = EllipticCurveKeyExchange<Curve25519.KeyAgreement.PrivateKey>.deriveKey(
            baseHasher: base, discriminatorByte: UInt8(ascii: "E"), sessionID: ByteBuffer(string: "session"), length: 80)
        let expected: [UInt8] = [92, 190, 232, 204, 120, 112, 187, 109, 231, 79, 66, 106, 20, 123, 182, 246, 130, 3, 212, 33, 84, 241, 209, 38, 38, 165, 107, 172, 99, 76, 140, 13, 62, 225, 165, 64, 78, 101, 165, 228, 56, 217, 149, 129, 155, 199, 69, 215, 55, 168, 84, 196, 215, 137, 218, 71, 224, 147, 182, 250, 165, 65, 41, 58, 19, 183, 1, 176, 154, 197, 35, 8, 154, 189, 238, 123, 6, 51, 144, 202]
        #expect(key == expected)
    }
}
