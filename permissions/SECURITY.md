# Security

Treat profiles and persistence as trusted server configuration. Authenticate and
authorize callers before passing owner principals or WebAuthn approval evidence.
Never accept caller-supplied approval timestamps or verification assertions as
verified evidence. Use Auth's session-bound single-use ceremony storage and the
Agent Exchange WebAuthn verifier. Approval and execution are separate: the signed
mandate authority must validate and atomically consume the exact exchange.

Expiry and use limits are deliberately finite and must be shown before approval.
Re-check application access and permission state throughout execution. Denying or
revoking races safely with activation: a losing issuer revokes its new mandate.
PostgreSQL tenancy is mandatory; the package does not implement company policy.
Report vulnerabilities privately to the repository owner.
