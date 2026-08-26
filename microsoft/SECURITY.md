# Security

Use delegated `Mail.Read`, not application-wide mail permissions, for an
individual user's mailbox. Keep Graph bearer tokens in a trusted tool or broker,
never in model context. National-cloud deployments require a separate, explicit
adapter because their authority and Graph endpoints differ.
