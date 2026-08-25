#!/usr/bin/python3
"""Run the packaged broker lifecycle in an unprivileged, networkless bwrap."""
import argparse
import json
import os
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
from multiprocessing import Pipe, Process
from pathlib import Path


def _frame(path, message):
    payload = json.dumps(message, separators=(",", ":")).encode()
    with socket.socket(socket.AF_UNIX) as connection:
        connection.connect(path)
        connection.sendall(struct.pack("!I", len(payload)) + payload)
        size = struct.unpack("!I", _exact(connection, 4))[0]
        return json.loads(_exact(connection, size))


def _exact(connection, size):
    value = bytearray()
    while len(value) < size:
        chunk = connection.recv(size - len(value))
        if not chunk:
            raise RuntimeError("truncated response")
        value.extend(chunk)
    return bytes(value)


def _client(channel, uid, gid, socket_path):
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    while True:
        message = channel.recv()
        if message is None:
            return
        try:
            channel.send(_frame(socket_path, message))
        except Exception as exc:
            channel.send({"client_error": type(exc).__name__, "detail": str(exc)})


class RehearsalSystem:
    def __init__(self):
        self.accounts = set()
        self.groups = set()
        self.enabled = False

    def group(self, name, present):
        (self.groups.add if present else self.groups.discard)(name)
        return {"hermes-privilege-requester": 2101, "hermes-privilege-operator": 2102}[name]

    def account(self, name, present, group=None):
        (self.accounts.add if present else self.accounts.discard)(name)
        return {"hermes-privilege-broker": 2000, "hermes-privilege-requester": 2001,
                "hermes-privilege-operator": 2002}[name]

    def has_group(self, name):
        return name in self.groups

    def has_account(self, name):
        return name in self.accounts

    def service(self, enabled):
        self.enabled = enabled


def _wait_sockets(paths):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if all(Path(path).is_socket() for path in paths):
            return
        time.sleep(0.01)
    raise RuntimeError("installed broker service did not bind sockets")


def _wait_socket_metadata(expected):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        values = [(stat.S_IMODE(os.stat(path).st_mode), os.stat(path).st_uid, os.stat(path).st_gid)
                  for path in expected]
        if values == [(0o660, 0, gid) for gid in expected.values()]:
            return
        time.sleep(0.01)
    raise RuntimeError("installed broker socket metadata did not settle")


def _residue(root):
    ledger = root / "var/lib/hermes-privilege-broker/ledger.sqlite"
    return sorted("/" + str(path.relative_to(root)) for path in root.rglob("*")
                  if path != ledger and not path.is_dir())


def _inner(repo, evidence, sandbox):
    sys.path.insert(0, str(repo / "src"))
    from hermes_privilege_broker.broker import Broker
    from hermes_privilege_broker.catalog import load_catalog
    from hermes_privilege_broker.daemon import UnixDaemon

    from hermes_privilege_broker.ledger import Ledger
    from hermes_privilege_broker.packaging import InstallError, Installer

    root = sandbox / "root"
    root.mkdir()
    system = RehearsalSystem()
    installer = Installer(root, system)
    installer.apply()
    assert system.enabled
    config = json.loads((root / "etc/hermes-privilege-broker/broker.json").read_text())
    request_socket = str(root / config["requester_socket"].lstrip("/"))
    operator_socket = str(root / config["operator_socket"].lstrip("/"))
    catalog = load_catalog(root / config["catalog"].lstrip("/"), allow_unsafe_ancestors=True)
    ledger_path = root / config["ledger"].lstrip("/")


    def start():
        ledger = Ledger(ledger_path, trusted_uid=0, allow_unsafe_ancestors=True)
        broker = Broker(catalog, ledger, requester_uids={2001}, operator_uids={2002})
        daemon = UnixDaemon(broker, request_socket, operator_socket, {2001}, {2002}, 2101, 2102)
        import threading
        thread = threading.Thread(target=daemon.serve, daemon=True)
        thread.start()
        _wait_sockets((request_socket, operator_socket))
        return daemon, thread

    daemon, thread = start()
    _wait_socket_metadata({request_socket: 2101, operator_socket: 2102})
    sockets = {}
    for path in (request_socket, operator_socket):
        metadata = os.stat(path)
        sockets[Path(path).name] = {"mode": format(stat.S_IMODE(metadata.st_mode), "04o"),
                                   "uid": metadata.st_uid, "gid": metadata.st_gid}

    requester_parent, requester_child = Pipe()
    operator_parent, operator_child = Pipe()
    requester = Process(target=_client, args=(requester_child, 2001, 2101, request_socket))
    operator = Process(target=_client, args=(operator_child, 2002, 2102, operator_socket))
    requester.start(); operator.start()
    request = {"request_id": "rehearsal-id", "operation_id": "system.identity", "slots": {},
               "reason": "rootless lifecycle rehearsal"}
    requester_parent.send({"method": "submit", "request": request})
    submitted = requester_parent.recv()
    assert submitted.get("ok"), submitted
    digest = submitted["result"]["request_digest"]
    operator_parent.send({"method": "approve", "request_id": request["request_id"],
                          "request_digest": digest})
    grant = operator_parent.recv()["result"]["grant"]
    requester_parent.send({"method": "consume", "grant": grant, "request": request})
    result = requester_parent.recv()
    assert result.get("ok") and result["result"]["state"] == "result", result
    assert result["result"]["exit_code"] == 0 and "uid=" in result["result"]["stdout"]
    requester_parent.send({"method": "consume", "grant": grant, "request": request})
    assert requester_parent.recv() == {"ok": False, "error": "RequestError"}

    request2 = {**request, "request_id": "restart-id"}
    requester_parent.send({"method": "submit", "request": request2})
    digest2 = requester_parent.recv()["result"]["request_digest"]
    operator_parent.send({"method": "approve", "request_id": "restart-id", "request_digest": digest2})
    grant2 = operator_parent.recv()["result"]["grant"]
    daemon.close(); thread.join(2)
    daemon.broker.ledger.db.close()
    daemon, thread = start()
    requester_parent.send({"method": "consume", "grant": grant2, "request": request2})
    assert requester_parent.recv() == {"ok": False, "error": "RequestError"}
    requester_parent.send(None); operator_parent.send(None)
    requester.join(2); operator.join(2)
    daemon.close(); thread.join(2)
    daemon.broker.ledger.db.close()

    installer.uninstall()
    ledger = root / "var/lib/hermes-privilege-broker/ledger.sqlite"
    assert ledger.exists() and _residue(root) == []
    failed_root = sandbox / "failed-root"
    failed_root.mkdir()
    failed_ledger = failed_root / "var/lib/hermes-privilege-broker/ledger.sqlite"
    failed_ledger.parent.mkdir(parents=True)
    failed_ledger.write_bytes(b"preserved-ledger")
    failed = Installer(failed_root, RehearsalSystem())
    original = failed._install_file
    count = 0
    def inject(entry):
        nonlocal count
        count += 1
        if count == 3:
            raise OSError("rehearsed failure")
        original(entry)
    failed._install_file = inject
    try:
        failed.apply()
        raise AssertionError("failure injection did not fire")
    except InstallError:
        pass
    assert failed_ledger.read_bytes() == b"preserved-ledger" and _residue(failed_root) == []

    payload = {
        "schema": "hermes-rootless-rehearsal-v1",
        "namespace": {"host_root": "read-only", "network": "private", "pid": "private",
                      "privilege": "unprivileged-user-namespace"},
        "operation": {"executable": "/usr/bin/id", "executions": 1,
                      "flow": ["requester-submit", "operator-approve", "requester-consume", "result"],
                      "result_state": "succeeded"},
        "replay": "denied", "restart_grant": "revoked", "sockets": sockets,
        "uninstall": {"preserved": ["/var/lib/hermes-privilege-broker/ledger.sqlite"], "residue": []},
        "failed_apply": {"preserved": ["/var/lib/hermes-privilege-broker/ledger.sqlite"], "residue": []},
    }
    evidence.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--inner", action="store_true")
    parser.add_argument("--sandbox", type=Path)
    args = parser.parse_args(argv)
    if args.inner:
        _inner(args.repo, args.evidence, args.sandbox)
        return
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".hermes-id-", dir=args.repo) as temporary:
        identity = Path(temporary) / "id"
        shutil.copy2("/usr/bin/id", identity)
        namespace = subprocess.Popen([
            "/usr/bin/unshare", "--fork", "--user", "--map-users=0:1000:1", "--map-users=1:100000:65536",
            "--map-groups=0:1000:1", "--map-groups=1:100000:65536", "/usr/bin/sleep", "60",
        ], start_new_session=True)
        parent_userns = os.readlink("/proc/self/ns/user")
        deadline = time.monotonic() + 5
        while os.readlink(f"/proc/{namespace.pid}/ns/user") == parent_userns:
            if namespace.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("failed to establish subordinate-ID user namespace")
            time.sleep(0.01)
        userns = os.open(f"/proc/{namespace.pid}/ns/user", os.O_RDONLY)
        command = ["/usr/bin/bwrap", "--userns", str(userns), "--uid", "0", "--gid", "0",
                   "--cap-add", "ALL",
                   "--unshare-pid", "--unshare-net", "--die-with-parent", "--new-session",
                   "--ro-bind", "/", "/", "--ro-bind", str(identity), "/usr/bin/id",
                   "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/tmp/sandbox",
                   "--dir", "/tmp/evidence",
                   "--bind", str(args.evidence.parent), "/tmp/evidence",
                   "/usr/bin/python3", str(Path(__file__).resolve()), "--inner",
                   "--repo", str(args.repo), "--sandbox", "/tmp/sandbox",
                   "--evidence", "/tmp/evidence/" + args.evidence.name]
        try:
            subprocess.run(command, check=True, env={"PATH": "/usr/bin"}, pass_fds=(userns,))
        finally:
            os.close(userns)
            os.killpg(namespace.pid, signal.SIGTERM)
            namespace.wait()


if __name__ == "__main__":
    main()
