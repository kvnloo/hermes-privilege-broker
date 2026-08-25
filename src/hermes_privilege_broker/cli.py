import argparse
import json

_MANIFEST = [
    ["account", "hermes-privilege-broker"],
    ["group", "hermes-privilege-requester"],
    ["group", "hermes-privilege-operator"],
    ["directory", "/etc/hermes-privilege-broker", "0755", "root:root"],
    ["directory", "/var/lib/hermes-privilege-broker", "0700", "root:root"],
    ["directory", "/run/hermes-privilege-broker", "0755", "root:root"],
    ["file", "/usr/libexec/hermes-privilege-broker", "0755", "root:root"],
    ["file", "/usr/libexec/hermes-privilege-operator-telegram", "0755", "root:root"],
    ["file", "/etc/hermes-privilege-broker/broker.json", "0600", "root:root"],
    ["file", "/etc/hermes-privilege-broker/catalog.json", "0600", "root:root"],
    ["file", "/var/lib/hermes-privilege-broker/ledger.sqlite", "0600", "root:root"],
    ["runtime", "/var/lib/hermes-privilege-broker/ledger.sqlite-wal", "0600", "root:root"],
    ["runtime", "/var/lib/hermes-privilege-broker/ledger.sqlite-shm", "0600", "root:root"],
    ["socket", "/run/hermes-privilege-broker/request.sock", "0660", "root:hermes-privilege-requester"],
    ["socket", "/run/hermes-privilege-broker/operator.sock", "0660", "root:hermes-privilege-operator"],
    ["file", "/usr/lib/systemd/system/hermes-privilege-broker.service", "0644", "root:root"],
]


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", nargs="?", default="plan", choices=("plan", "apply", "update", "uninstall"))
    args = parser.parse_args(argv)
    if args.action != "plan":
        parser.error(f"{args.action} is disabled pending independent packaging review")
    print(json.dumps({"platform": "linux", "dry_run": True, "changes_applied": False, "manifest": _MANIFEST, "apply": "create/verify manifest atomically, then enable service", "update": "stage and verify, atomic switch, rollback on failure", "uninstall": "disable service; remove only manifest-owned sockets/files/accounts; preserve ledger unless explicitly purged"}, indent=2))


if __name__ == "__main__":
    main()
