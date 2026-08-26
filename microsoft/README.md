# @absolutejs/agent-exchange-microsoft

Tenant-bound Microsoft Graph OAuth configuration for BYO deployments. The
adapter refuses `common`, `organizations`, and `consumers`; callers provide one
exact tenant UUID to avoid authority mix-up.

Microsoft documents authorization code + S256 PKCE for Graph. The generally
available Graph flow does not document the complete PAR/RAR/resource-indicator
and sender-constrained access-token profile required by AbsoluteJS, so this
adapter intentionally fails the strongest conformance check.
