# Security

Report vulnerabilities privately through GitHub Security Advisories on the
`absolutejs/agent-exchange-providers` repository.

A2A messages are not identity or authorization evidence. Production hosts must
authenticate the caller using the Agent Card's declared security scheme, verify
the exact OAuth audience and delegated actor, resolve the full request from
trusted storage, and authorize or consume its signed mandate before reading a
protected source. Keep task stores, logs, traces, errors, push notifications, and
artifacts free of secrets and full request payloads.
