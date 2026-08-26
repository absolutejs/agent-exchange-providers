# Security

Do not persist `CryptoKey` material through JSON or expose the signer to agent
models. For durable server deployments, substitute a KMS/HSM signer implementing
the same `DpopProofSigner` contract.
