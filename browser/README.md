# Agent Exchange Browser

A deterministic six-digit verification destination bound to one browser page,
exact HTTPS origin, form route, immutable exchange, tenant and short expiry.

`createBrowserVerificationDestination` accepts a Playwright-compatible page and
trusted provider selectors, plus `assertAuthorized` and `verifySuccess` callbacks.
The package snapshots the exact page/form URL privately, invalidates the binding
on main-frame navigation, checks input/form uniqueness, rejects password/hidden
fields, and repeats destination checks after input handlers execute. It permits
only one submission attempt, even when submission fails or has an unknown result.
Use it behind Agent Exchange's encrypted receiver and destination registry.

`verifySuccess` must verify authenticated access for the expected account. A
redirect alone is not proof. This package does not bypass passwords or CAPTCHAs,
retrieve mailbox codes, authenticate callers, or mint grants. The host checks the
requester and mailbox-owner mandate before binding a page. Mail matching still
requires a trusted sender profile and a bounded, unambiguous correlation window.

Disable browser tracing, screenshots, recordings and body logging during protected
submission. Only the redacted success/error result may reach a model. Mutable
copies are wiped, but transient browser/runtime strings cannot be guaranteed to
be erased. The provider's page necessarily receives the code.

`discoverBrowserVerificationProfile` inspects a conventional single-input OTP
form at the exact owner-approved origin. It never returns input values or page
text, rejects ambiguous controls/password forms and cross-origin actions, and
produces a session-local profile for the existing destination binder. Discovery
does not grant authority. Hosts must still verify the expected signed-in account.

## Desktop extension destination

`createExtensionVerificationPage` adapts an explicitly clicked Chrome MV3 tab to
this package's existing verification destination and account observer. Use only
`activeTab` and `scripting`; no persistent all-site or browsing-history permission
is needed. It restricts execution to the selected tab's top frame, checks the
exact service origin, forwards navigation changes to the destination binder, and
removes listeners on close. The caller still verifies the mandate and current
requester access. Keep the adapter in the extension worker and never expose its
`evaluate` method or accept JavaScript through external messages. Chrome docs:
https://developer.chrome.com/docs/extensions/develop/concepts/activeTab and
https://developer.chrome.com/docs/extensions/reference/api/scripting.
