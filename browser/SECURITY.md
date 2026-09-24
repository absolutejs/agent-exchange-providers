# Security

Trusted provider configuration controls exact origins, paths and selectors. Never
accept these fields from email, a model-generated tool argument or an untrusted
request. Only bind a top-level page whose requested account has been checked.
The destination requires a WebAuthn-backed, tool-confined, single-use exchange.
The caller must verify and consume its mandate, enforce revocation, and prevent
concurrent service/mailbox attempts when the provider lacks challenge IDs.

Provider DOM code is trusted at its exact origin; this is not a sandbox against a
compromised provider. Browser instrumentation must not record protected payloads.
No raw browser exception, code, form snapshot or response body is returned.
