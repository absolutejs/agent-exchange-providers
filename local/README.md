# @absolutejs/agent-exchange-local

A model-blind local recipient for approved six-digit email-code disclosure.
`clipboardServiceProfile` derives a separate permission from a reviewed email
profile. A browser-bound permission cannot authorize clipboard disclosure.

`createLocalCodeRecipient` creates per-request nonexportable recipient keys,
validates the authenticated exchange context, requester, service, mailbox,
operation and challenge, rechecks authorization, prevents replay, and sends the
plaintext only to a `PrivateClipboard`. The receipt contains no code. Remote
hosts receive only the public key; the mailbox endpoint seals to that key using
ABS E2EE. `createPostgresLocalDeliveryStore` carries ciphertext and receipts
between authenticated endpoints with fixed recipient keys and bounded expiry.
Deploy its `LOCAL_DELIVERY_MIGRATION` before handling requests. Hosts must
recheck owner identity and current permission on every read and acknowledgement.

`@absolutejs/agent-exchange-local/windows` provides the Windows/WSL clipboard
adapter. It feeds six digits through stdin to a fixed short-lived native helper,
opts out of Windows history/cloud sync, and clears its own clipboard write after
30 seconds (`LOCAL_CLIPBOARD_TTL_MS`, counted from the write, not from the
exchange request) using the clipboard sequence under a native clipboard lock.
It does not clear a later clipboard write. No secret enters argv, env, files,
stdout or stderr. Other platforms fail closed until a private adapter is supplied.

Windows format documentation:
https://learn.microsoft.com/en-us/windows/win32/dataxchg/clipboard-formats#cloud-clipboard-and-clipboard-history-formats

Local delivery means **copied**, not signed in. No browser is required and the
recipient can paste elsewhere; the owner must approve that disclosure explicitly.
The OS, mailbox endpoint, and local recipient are trusted. An MCP protocol hides
values from model context; it cannot stop arbitrary local programs or an agent
with unrestricted shell access from deliberately inspecting the OS clipboard.
Third-party clipboard monitors are outside Windows history opt-out controls.
Expiry is best effort if the helper/OS is killed or suspended. The recipient must
never expose envelopes, clipboard reads, mail bodies or tokens as MCP tools.
