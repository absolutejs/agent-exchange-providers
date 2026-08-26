# @absolutejs/agent-exchange-oauth

A deliberately strict OAuth authorization-code handoff for Agent Exchange.

The client requires HTTPS metadata, PAR (RFC 9126), S256 PKCE (RFC 7636), an
exact authorization-server issuer (RFC 9207), one exact resource indicator (RFC
8707), Rich Authorization Requests (RFC 9396), and a DPoP-bound access token
(RFC 9449). The recipient redeems the one-time grant and immediately performs a
purpose-bound operation; the access token is never returned by this package.

This profile is intentionally not a general OAuth client. Provider-specific
compatibility belongs in explicit adapters or the paid AbsoluteJS PaaS; the open
package remains BYO authorization server and DPoP signer.
