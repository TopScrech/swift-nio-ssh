import Crypto
import Foundation
import NIOCore
import NIOEmbedded
import Testing
import _CryptoExtras

@testable import NIOSSH

struct RSAInteropTests {
    @Test(arguments: [RSASignatureAlgorithm.sha512, .sha256, .sha1])
    func exchangeHashIsSignedAsMessage(algorithm: RSASignatureAlgorithm) throws {
        let key = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let sshKey = NIOSSHPrivateKey(rsaKey: key)
        // KEX hash and signature hash are independent, including SHA-384 KEX
        let exchangeHash = SHA384.hash(data: Data("exchange transcript".utf8))
        let signature = try sshKey.sign(digest: exchangeHash, rsaSignatureAlgorithm: algorithm)
        let bytes = exchangeHash.withUnsafeBytes { Data($0) }
        let valid: Bool
        switch signature.backingSignature {
        case .rsaSHA512(let value):
            valid = key.publicKey.isValidSignature(value, for: SHA512.hash(data: bytes), padding: .insecurePKCS1v1_5)
        case .rsaSHA256(let value):
            valid = key.publicKey.isValidSignature(value, for: SHA256.hash(data: bytes), padding: .insecurePKCS1v1_5)
        case .rsaSHA1(let value):
            valid = key.publicKey.isValidSignature(value, for: Insecure.SHA1.hash(data: bytes), padding: .insecurePKCS1v1_5)
        default:
            valid = false
        }
        #expect(valid)
        #expect(signature.rsaAlgorithm == algorithm)
        #expect(sshKey.publicKey.isValidSignature(signature, for: exchangeHash))
    }

    @Test(arguments: [RSASignatureAlgorithm.sha512, .sha256, .sha1])
    func authenticationWireRoundTrip(algorithm: RSASignatureAlgorithm) throws {
        let key = NIOSSHPrivateKey(rsaKey: try .init(keySize: .bits2048))
        let payload = UserAuthSignablePayload(sessionIdentifier: ByteBuffer(string: "session"), userName: "test", serviceName: "ssh-connection", publicKey: key.publicKey, rsaSignatureAlgorithm: algorithm)
        let signature = try key.sign(payload, rsaSignatureAlgorithm: algorithm)
        let message = SSHMessage.userAuthRequest(.init(username: "test", service: "ssh-connection", method: .publicKey(.known(key: key.publicKey, signature: signature, rsaSignatureAlgorithm: algorithm))))
        var bytes = ByteBuffer()
        bytes.writeSSHMessage(message)
        #expect(try bytes.readSSHMessage() == message)
        #expect(key.publicKey.isValidSignature(signature, for: payload))

        let probeResponse = SSHMessage.userAuthPKOK(.init(key: key.publicKey, rsaSignatureAlgorithm: algorithm))
        bytes.clear()
        bytes.writeSSHMessage(probeResponse)
        #expect(try bytes.readSSHMessage() == probeResponse)
    }

    @Test
    func rejectsMismatchedAuthenticationAlgorithm() throws {
        let key = NIOSSHPrivateKey(rsaKey: try .init(keySize: .bits2048))
        let payload = UserAuthSignablePayload(sessionIdentifier: ByteBuffer(string: "session"), userName: "test", serviceName: "ssh-connection", publicKey: key.publicKey)
        let signature = try key.sign(payload, rsaSignatureAlgorithm: .sha1)
        var bytes = ByteBuffer()
        bytes.writeSSHMessage(.userAuthRequest(.init(username: "test", service: "ssh-connection", method: .publicKey(.known(key: key.publicKey, signature: signature, rsaSignatureAlgorithm: .sha512)))))
        #expect(throws: (any Error).self) { try bytes.readSSHMessage() }
    }

    @Test(arguments: [RSASignatureAlgorithm.sha512, .sha256, .sha1])
    func rsaOnlyServerHandshake(algorithm: RSASignatureAlgorithm) throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        let key = NIOSSHPrivateKey(rsaKey: try .init(keySize: .bits2048))
        var client = SSHKeyExchangeStateMachine(allocator: allocator, loop: loop, role: .client(.init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())), remoteVersion: Constants.version, protectionSchemes: [AES256GCMOpenSSHTransportProtection.self], previousSessionIdentifier: nil)
        var server = SSHKeyExchangeStateMachine(allocator: allocator, loop: loop, role: .server(.init(hostKeys: [key], userAuthDelegate: DenyAllServerAuthDelegate())), remoteVersion: Constants.version, protectionSchemes: [AES256GCMOpenSSHTransportProtection.self], previousSessionIdentifier: nil)
        var serverMessage = server.createKeyExchangeMessage()
        serverMessage.serverHostKeyAlgorithms = [Substring(algorithm.algorithmName)]
        var clientMessage = client.createKeyExchangeMessage()
        clientMessage.serverHostKeyAlgorithms = [Substring(algorithm.algorithmName)]
        server.send(keyExchange: serverMessage)
        client.send(keyExchange: clientMessage)
        #expect(try server.handle(keyExchange: clientMessage) == nil)
        let clientResult = try client.handle(keyExchange: serverMessage)
        let messages = try #require(clientResult)
        guard case .keyExchangeInit(let request) = try #require(messages.first) else {
            Issue.record("Expected key exchange request")
            return
        }
        client.send(keyExchangeInit: request)
        let serverResult = try server.handle(keyExchangeInit: request)
        let replies = try #require(serverResult)
        guard case .keyExchangeReply(let reply) = try #require(replies.first) else {
            Issue.record("Expected key exchange reply")
            return
        }
        #expect(reply.signature.rsaAlgorithm == algorithm)
        try server.send(keyExchangeReply: reply)
        _ = server.sendNewKeys()
        if algorithm != .sha1 {
            var downgraded = reply
            downgraded.signature = NIOSSHSignature(backingSignature: .rsaSHA1(.init(rawRepresentation: Data(repeating: 0, count: 256))))
            #expect(throws: (any Error).self) { try client.handle(keyExchangeReply: downgraded) }
        }
        _ = try client.handle(keyExchangeReply: reply).wait()
        #expect(client._testOnly_negotiatedHostKeyAlgorithm == Substring(algorithm.algorithmName))
    }
}
