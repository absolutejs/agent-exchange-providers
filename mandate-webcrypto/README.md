# `@absolutejs/agent-exchange-mandate-webcrypto`

Interchangeable WebCrypto ES256 compact-JWS signer and verifier for
`@absolutejs/agent-exchange` standing mandates.

The signer requires a non-exportable P-256 private key. The verifier resolves a
public key only from the independently trusted issuer and the protected `kid`,
then enforces `alg: ES256`, the AbsoluteJS mandate `typ`, strict compact encoding,
and a 64-byte JWS ECDSA signature.

This experimental `0.x` package has not been independently audited. Production
services should keep signing keys in a KMS or HSM; implement the same core signer
contract with that service instead of exporting key material.
