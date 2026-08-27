# @absolutejs/agent-exchange-oauth-webcrypto

An ES256 DPoP signer backed by WebCrypto. Generated private keys are
non-exportable. Every proof uses a fresh 128-bit `jti`, normalized `htu`, current
`iat`, optional server nonce, and `ath` when an access token is supplied.

Version `0.2.1` uses the canonical-base64url-enforcing `0.3.1` conformance
verifier so alternate compact proof encodings cannot alias the same signature.
