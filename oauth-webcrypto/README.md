# @absolutejs/agent-exchange-oauth-webcrypto

An ES256 DPoP signer backed by WebCrypto. Generated private keys are
non-exportable. Every proof uses a fresh 128-bit `jti`, normalized `htu`, current
`iat`, optional server nonce, and `ath` when an access token is supplied.
