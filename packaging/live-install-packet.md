# Live install packet (review gate)

Exact operator and Telegram chat ID: `1083429746`. This identifier is not a secret. No bot token is included in this packet; provide it only through a root-readable systemd credential at installation time.

This packet does not authorize installation by itself. The exact Git revision and wheel hashes must receive independent approval before a captain runs any command as root. Hermes never invokes this packet, sudo, or a package manager.

## Root-side prerequisites and apply sequence

1. Verify the independently approved Git revision and SHA-256 hashes of both wheels.
2. Create locked system account `hermes-privilege-broker` and distinct groups `hermes-privilege-requester` and `hermes-privilege-operator`. Add only the explicitly selected Hermes requester account to the requester group and a distinct operator service account to the operator group.
3. Install the broker wheel and Telegram operator wheel into separate root-owned virtual environments. Do not install either into Hermes' interpreter.
4. Install root-owned configuration under `/etc/hermes-privilege-broker` with mode `0700` directories and `0600` files. Resolve numeric requester/operator UIDs and GIDs during the attended install; never guess them.
5. Set `allowed_user_ids` and `chat_id` to `[1083429746]` and `1083429746`. Store `TELEGRAM_BOT_TOKEN` only as a systemd credential readable by the operator service account; never place it in arguments, Git, the broker config, or logs.
6. Install two services: the root broker and the distinct unprivileged Telegram operator frontend. The operator gets only the operator socket; Hermes gets only the requester socket.
7. Run `systemd-analyze verify` on both staged units, then start the broker first and operator second. Verify socket owner/group/mode, process UIDs, catalog and executable hashes, and a harmless typed catalog operation before enabling either service.

## Rollback / uninstall

Stop and disable both units, remove only files listed in the reviewed manifest, revoke both sockets, and preserve the ledger by default for audit. Removing accounts/groups or purging the ledger requires a second explicit captain decision. Never alter sudoers.

## Hard stop conditions

Stop on any revision/hash mismatch, overlapping requester/operator UID, writable or symlinked ancestor, missing systemd credential support, token exposure, non-ELF catalog executable, failed unit verification, stale grant survival, or inability to run the harmless operation. Do not loosen a check to finish installation.