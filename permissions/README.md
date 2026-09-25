# Agent Exchange Permissions

Reusable allow-once / always-allow / deny orchestration for Agent Exchange signed
mandates. Use trusted service profiles, an authenticated mailbox owner, and the
Agent Exchange WebAuthn adapter to approve the exact returned draft.

`createAgentExchangePermissionManager` owns draft creation, profile matching,
service revision invalidation, approval, denial and revocation. One-use grants last
15 minutes. Saved grants last 30 days with at most 100 uses; disclose these limits
before requesting approval. Non-routine profiles cannot use saved approval.

`createPostgresAgentExchangePermissionStore` scopes records by tenant and owner.
Install `AGENT_EXCHANGE_PERMISSIONS_POSTGRES_MIGRATION` and the Mandate Stores
migration before use. Reuse excludes exhausted/revoked mandates. Actual execution
must still call the signed mandate authority's `authorize` (which atomically
consumes a use), and check `assertActive` before each sensitive stage. A permission
lookup alone does not authorize secret access.

New services must be supplied as trusted, validated configuration. Unknown IDs are
rejected. Change `revision` or `adapterRevision` when sender matching, destination,
action, or other semantics change. Exact HTTPS origins only; no wildcards. Profile
labels and all grant fields participate in scope matching. Approvals do not create
source or destination adapters or bypass their validation.

The host app supplies company/task eligibility, validated authenticated principals,
passkey ceremonies, and a UI. Never send the stored draft or signed mandate in
public status responses. List permissions only for the authenticated owner. A
requester cancelling one request must not revoke a mailbox owner's saved grant.

Deny rejects the pending request only. It does not create a permanent block. To
stop previously saved access, revoke that grant separately. Revocation prevents
future stages and cannot recall an already dispatched provider operation.

Saved permissions may be explicitly enabled for `routine` or `authentication`
profiles. Authentication grants remain bound to the exact owner, requester,
mailbox, origin, operation and profile/adapter revision. They require owner
passkey approval and expire after 30 days or 100 uses. Recovery and other
security-changing risks cannot enable saved permission. Hosts must classify
operations honestly and recheck active access before every execution.
