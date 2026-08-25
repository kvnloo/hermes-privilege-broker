# Threat model

The requester and operator may each be malicious but must not possess the other's account or socket. Payload identity is untrusted. Root, the kernel, the installed catalog, and immutable executable ancestors are trusted. Telegram is presentation/transport only and is not the execution authority.

Denied surfaces: arbitrary argv, shell strings, PATH, caller environment/cwd/stdin/TTY/FDs, scripts, interpreters, package hooks, mutable catalog/executable ancestors, self-approval, replay, expired or mutated grants, and automatic rerun after uncertain execution.

Crash invariant: a durable decision and reserve precede spawn. A crash after reserve is ambiguous and requires a new request with human reconciliation, never replay. A terminal ledger-write failure leaves the reserved/running durable state and therefore remains ambiguous.

Residual boundary: root compromise, kernel compromise, or replacement of trusted immutable packaging is out of scope. Telegram delivery/authentication integration must preserve operator credential isolation and bind callback data to the exact request digest.
