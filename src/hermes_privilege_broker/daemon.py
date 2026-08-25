import json
import os
import socket
import stat
import struct
import threading

from .broker import RequestError
from .broker import Broker
from .catalog import load_catalog
from .ledger import Ledger
from .transport import peer_identity, require_peer

_MAX_FRAME = 16_384


def receive_frame(connection):
    header = _receive_exact(connection, 4)
    length = struct.unpack("!I", header)[0]
    if length > _MAX_FRAME:
        raise RequestError("frame too large")
    return _receive_exact(connection, length)


def send_frame(connection, value):
    payload = json.dumps(value, separators=(",", ":")).encode()
    if len(payload) > _MAX_FRAME:
        raise RequestError("response too large")
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def _receive_exact(connection, length):
    result = bytearray()
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        if not chunk:
            raise RequestError("truncated frame")
        result.extend(chunk)
    return bytes(result)


def dispatch(broker, role, message, identity):
    method = message.get("method") if isinstance(message, dict) else None
    if role == "requester" and method == "submit" and set(message) == {"method", "request"}:
        return {"request_digest": broker.submit(message["request"], identity)}
    if role == "requester" and method == "status" and set(message) == {"method", "request_id"}:
        return broker.status(message["request_id"])
    if role == "requester" and method == "consume" and set(message) == {"method", "grant", "request"}:
        return broker.consume(message["grant"], message["request"], identity)
    if role == "operator" and method == "status" and set(message) == {"method", "request_id"}:
        return broker.status(message["request_id"])
    if role == "operator" and method == "pending" and set(message) == {"method"}:
        return broker.pending(identity)
    if role == "operator" and method == "approve" and set(message) == {"method", "request_id", "request_digest"}:
        return {"grant": broker.approve(message["request_id"], identity, message["request_digest"])}
    if role == "operator" and method == "deny" and set(message) == {"method", "request_id", "request_digest"}:
        broker.deny(message["request_id"], identity, message["request_digest"])
        return {"state": "denied"}
    raise RequestError("method is not authorized on this socket")


class UnixDaemon:
    def __init__(self, broker, requester_path, operator_path, requester_uids, operator_uids, requester_gid=-1, operator_gid=-1):
        self.broker = broker
        self.specs = (("requester", requester_path, set(requester_uids), requester_gid), ("operator", operator_path, set(operator_uids), operator_gid))
        self.sockets = []
        self.stopping = threading.Event()

    def bind(self):
        try:
            for role, path, uids, gid in self.specs:
                if os.path.lexists(path):
                    raise RuntimeError(f"refusing existing socket path: {path}")
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(path)
                self.sockets.append((role, listener, uids, path))
                os.chown(path, 0, gid)
                os.chmod(path, 0o660)
                listener.listen(16)
        except Exception:
            self.close()
            raise

    def serve(self):
        self.bind()
        threads = [threading.Thread(target=self._accept, args=spec[:3], daemon=True) for spec in self.sockets]
        for thread in threads:
            thread.start()
        self.stopping.wait()

    def _accept(self, role, listener, allowed):
        while not self.stopping.is_set():
            try:
                connection, _ = listener.accept()
            except OSError:
                if self.stopping.is_set():
                    return
                raise
            try:
                identity = peer_identity(connection)
                require_peer(identity, allowed)
                frame = receive_frame(connection)
                response = dispatch(self.broker, role, json.loads(frame), identity)
                send_frame(connection, {"ok": True, "result": response})
            except Exception as exc:
                try:
                    send_frame(connection, {"ok": False, "error": type(exc).__name__})
                except OSError:
                    pass
            finally:
                connection.close()

    def close(self):
        self.stopping.set()
        for _role, listener, _uids, path in self.sockets:
            listener.close()
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        self.sockets.clear()


def _secure_root_path(path, *, leaf_may_not_exist=False):
    if not isinstance(path, str) or not os.path.isabs(path) or "\0" in path:
        raise ValueError("path must be absolute")
    candidate = os.path.dirname(path) if leaf_may_not_exist else path
    while True:
        metadata = os.lstat(candidate)
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError("unsafe path component")
        if candidate != path and not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("path ancestor is not a directory")
        if candidate == "/":
            break
        candidate = os.path.dirname(candidate)


def main():
    config_path = "/etc/hermes-privilege-broker/broker.json"
    metadata = os.lstat(config_path)
    if metadata.st_uid != 0 or metadata.st_mode & 0o077 or not os.path.isfile(config_path):
        raise SystemExit("unsafe broker config")
    _secure_root_path(config_path)
    with open(config_path, encoding="utf-8") as handle:
        config = json.load(handle)
    required = {"catalog", "ledger", "requester_socket", "operator_socket", "requester_uids", "operator_uids", "requester_gid", "operator_gid"}
    if set(config) != required:
        raise SystemExit("invalid broker config schema")
    for key in ("catalog", "ledger", "requester_socket", "operator_socket"):
        _secure_root_path(config[key], leaf_may_not_exist=key in {"ledger", "requester_socket", "operator_socket"})
    for key in ("requester_uids", "operator_uids"):
        if not isinstance(config[key], list) or not config[key] or len(set(config[key])) != len(config[key]) or any(type(value) is not int or not 0 <= value <= 4_294_967_294 for value in config[key]):
            raise SystemExit("invalid UID list")
    if set(config["requester_uids"]) & set(config["operator_uids"]):
        raise SystemExit("authority sets overlap")
    if config["requester_socket"] == config["operator_socket"]:
        raise SystemExit("socket paths must be distinct")
    if any(type(config[key]) is not int or not 0 <= config[key] <= 4_294_967_294 for key in ("requester_gid", "operator_gid")):
        raise SystemExit("invalid GID")
    catalog = load_catalog(config["catalog"])
    ledger = Ledger(config["ledger"])
    broker = Broker(catalog, ledger, requester_uids=set(config["requester_uids"]), operator_uids=set(config["operator_uids"]))
    UnixDaemon(broker, config["requester_socket"], config["operator_socket"], broker.requesters, broker.operators, config["requester_gid"], config["operator_gid"]).serve()


if __name__ == "__main__":
    main()
