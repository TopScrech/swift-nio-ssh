# RSA support

This fork starts from apple/swift-nio-ssh main at d198592 and adds RSA support using Swift Crypto, without the Wellz26/citadel2 custom-algorithm API

Supported host-key and user-authentication signatures, in preference order:

- `rsa-sha2-512`
- `rsa-sha2-256`
- `ssh-rsa` (SHA-1, retained for legacy compatibility)

Ed25519 and ECDSA remain preferred over RSA during host-key negotiation
RSA public-key blobs retain the `ssh-rsa` key format regardless of the signature algorithm
RSA keys must be at least 2048 bits, following Swift Crypto's standard key import policy
RSA OpenSSH certificates are not supported

## Usage

```swift
import NIOSSH
import _CryptoExtras

let key = try _RSA.Signing.PrivateKey(pemRepresentation: pem)
let hostKey = NIOSSHPrivateKey(rsaKey: key)
let authentication = NIOSSHUserAuthenticationOffer.PrivateKey(
    privateKey: hostKey,
    rsaSignatureAlgorithm: .sha512
)
```

Client host-key negotiation automatically supports all three RSA algorithms
User authentication defaults to SHA-512; callers can explicitly select SHA-256 or legacy SHA-1 for the target server
There is no automatic user-authentication downgrade

## Citadel migration

Citadel's existing `Insecure.RSA` custom-key implementation and custom key-exchange registration APIs are not drop-in compatible with this fork
Citadel must use `NIOSSHPrivateKey(rsaKey:)` and Apple's configuration APIs before switching its dependency

## Validation and attribution

The implementation incorporates daiimus's RSA contribution from apple/swift-nio-ssh PR 219 with additional fixes for algorithm negotiation, hashing the exchange hash as the signed message, authentication wire parsing, PK_OK algorithm preservation, and rejecting mismatched signature algorithms
The original contribution's authorship and license are retained

The test suite includes RSA-only handshakes for SHA-512, SHA-256 and SHA-1, independent signature-digest checks, authentication serialization, and downgrade rejection
