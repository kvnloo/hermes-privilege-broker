# Installation lifecycle

The install packet is one deterministic Python zip application. Running it without an action is a dry-run and prints the complete manifest. Only the explicit `apply` or `update` actions mutate the host. `verify` checks every installed file/directory's exact mode, root ownership on the live root, and immutable content. `uninstall` disables both units, removes only manifest files and the three dedicated identities/two groups, and preserves the SQLite ledger by default.

Prerequisite (fail closed): `/etc/hermes-privilege-broker/telegram-bot.token` must already be a regular `0600 root:root` file. Its value is never accepted in argv, environment, catalog, plan, or logs. systemd `LoadCredential=` supplies a private read-only copy to the dedicated operator service.

Installed authority is split:

- root broker service with distinct requester/operator Unix sockets;
- `hermes-privilege-requester` account/group can reach only the requester socket;
- `hermes-privilege-operator` account/group and separately installed Telegram unit can reach only the operator socket;
- catalog contains exactly `system.identity`, fixed to root-owned ELF `/usr/bin/id` with no slots or caller argv;
- no shell, sudoers, `NOPASSWD`, privileged blanket group, guessed Hermes home, caller environment, or install hook.

The release-specific command, exact commit/tree, artifact hash, plan, expected output, rollback command, and verification command are generated in `release/INSTALL_PACKET.md` only after the exact revision passes the clean rehearsal and independent review gate. No command in this development document is authorization to install on a live host.
