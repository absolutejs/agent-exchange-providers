# @absolutejs/browser-session

Reusable lifecycle for owner-bound, short-lived browser sessions. It reserves
capacity before launching, checks current application authorization on every
operation, serializes human interaction against protected verification, and
closes late-starting browsers during shutdown. Unconfirmed process termination
keeps its capacity slot occupied instead of silently launching another browser.

Actors must come from ABS Auth at the host boundary. `resourceRef` binds the
application's task/discovery context; `accountRef` binds the approved account.
The host implements business access checks through `authorize`. Session IDs are
identifiers, not authentication tokens. No page object is returned to clients.

`./playwright` provides an isolated Chromium process per session, Chromium's
sandbox enabled, blocked service workers/WebSockets, HTTPS-only requests through
ABS Egress's public-IP-pinned transport, bounded response sizes and kill fallback.
The deployment must additionally restrict private-network egress at the OS or
container boundary, run unprivileged with bounded CPU/RAM/PIDs and ephemeral
profile storage, and expose debugging only on loopback. It must not log input
bodies, enable traces/video, export cookies or send screenshots to a model.

`maskedBrowserPreview` masks password and marked OTP inputs for human-only UI.
The host must stop previews and input while its verification callback runs.
Verification must use the Agent Exchange destination adapter, bind the exact
approved origin/document/account, check revocation immediately before submission,
and verify the resulting signed-in account. Pool access alone grants no sign-in
permission.

Browser resources are deliberately ephemeral. Persist requests, authorization
and audit records in ABS's durable packages. A runner restart loses its browser
sessions; mark affected attempts interrupted and never automatically replay an
uncertain sign-in. Launchers must honor abort and terminate within bounded time.

Version 0.2 adds `getBrowserFocus`: fixed field categories, bounds and an opaque
DOM-element binding, never values or arbitrary page labels. Text input requires
the returned `focusId`; changed focus or a reloaded document fails closed. Filling
replaces the selected field value so retrying acknowledged input cannot append a
password twice. Hosts must show the selected field and confirm accepted input.
Human input waits for an in-flight preview; protected verification stays exclusive.
