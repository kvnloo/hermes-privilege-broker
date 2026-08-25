# Installation lifecycle

`hermes-privilege-broker plan` is the default and only implemented action in this development revision. It prints, without mutation, the complete intended root-owned manifest:

- system accounts/groups: `hermes-privilege-broker`, `hermes-privilege-requester`, `hermes-privilege-operator`
- `/usr/libexec/hermes-privilege-broker` 0755 root:root
- `/etc/hermes-privilege-broker/catalog.json` 0600 root:root
- `/var/lib/hermes-privilege-broker/ledger.sqlite` 0600 root:root
- `/run/hermes-privilege-broker/request.sock` 0660 root:hermes-privilege-requester
- `/run/hermes-privilege-broker/operator.sock` 0660 root:hermes-privilege-operator
- `hermes-privilege-broker.service`
- separately installed `hermes-privilege-operator-telegram`
- root-owned `/etc`, `/var/lib`, and `/run` package directories, broker configuration, systemd unit, and SQLite `-wal`/`-shm` runtime sidecars

`apply`, `update`, and `uninstall` intentionally fail closed until packaging is independently reviewed. There is no sudoers entry, `NOPASSWD`, blanket privileged group, guessed Hermes home, or implicit install/update hook.

The attended root-side sequence, rollback rules, hard-stop conditions, and the known non-secret Telegram captain/chat ID are frozen in `packaging/live-install-packet.md`. It contains no token and is not an installer or authorization to run sudo.
