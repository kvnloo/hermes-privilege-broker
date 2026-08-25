import hashlib
import os
import secrets
import threading
import time
from dataclasses import dataclass

from .executor import execute_verified


class RequestError(RuntimeError):
    pass


@dataclass(frozen=True)
class Identity:
    uid: int
    pid: int
    start_time: int


class Broker:
    def __init__(self, catalog, ledger, *, requester_uids, operator_uids, grant_ttl=30.0):
        if set(requester_uids) & set(operator_uids):
            raise ValueError("authorities overlap")
        self.catalog = catalog
        self.ledger = ledger
        self.requesters = set(requester_uids)
        self.operators = set(operator_uids)
        self.ttl = grant_ttl
        self.grants = {}
        self.consumed = set()
        self.lock = threading.Lock()

    def _role(self, identity, role):
        if identity.uid not in role:
            raise RequestError("wrong requester" if role is self.requesters else "wrong operator")

    def submit(self, request, identity):
        self._role(identity, self.requesters)
        plan = self.catalog.plan(request)
        if self.ledger.get(plan.request_id):
            raise RequestError("duplicate request")
        self.ledger.transition(plan.request_id, "pending", {"request": request, "request_digest": plan.request_digest, "catalog_digest": plan.catalog_digest, "uid": identity.uid, "pid": identity.pid, "start_time": identity.start_time})
        return plan.request_digest

    def approve(self, request_id, identity, request_digest=None):
        self._role(identity, self.operators)
        row = self.ledger.get(request_id)
        if not row or row["state"] != "pending":
            raise RequestError("not pending")
        if request_digest is not None and request_digest != row["request_digest"]:
            raise RequestError("request mutation")
        token = secrets.token_urlsafe(32)
        self.grants[token] = {**row, "rid": request_id, "expires": time.monotonic() + self.ttl}
        self.ledger.transition(request_id, "approved", {**row, "operator_uid": identity.uid})
        return token

    def deny(self, request_id, identity, request_digest):
        self._role(identity, self.operators)
        row = self.ledger.get(request_id)
        if not row or row["state"] != "pending" or row["request_digest"] != request_digest:
            raise RequestError("request mutation")
        self.ledger.transition(request_id, "denied", {"request_digest": request_digest, "operator_uid": identity.uid})

    def _reserve(self, token, request, identity):
        self._role(identity, self.requesters)
        grant = self.grants.get(token)
        if not grant:
            if token in self.consumed:
                raise RequestError("grant replay")
            raise RequestError("grant revoked")
        if time.monotonic() > grant["expires"]:
            self.grants.pop(token, None)
            raise RequestError("grant expired")
        plan = self.catalog.plan(request)
        identity_tuple = identity.uid, identity.pid, identity.start_time
        grant_tuple = grant["uid"], grant["pid"], grant["start_time"]
        if plan.request_digest != grant["request_digest"] or plan.catalog_digest != grant["catalog_digest"] or identity_tuple != grant_tuple:
            raise RequestError("request mutation")
        row = self.ledger.get(plan.request_id)
        if row["state"] != "approved":
            raise RequestError("replay")
        self.ledger.transition(plan.request_id, "reserved", {"request_digest": plan.request_digest, "catalog_digest": plan.catalog_digest})
        self.grants.pop(token, None)
        self.consumed.add(token)
        return plan

    def reserve_for_test(self, token, request, identity):
        with self.lock:
            return self._reserve(token, request, identity)

    def consume(self, token, request, identity, execute=True):
        with self.lock:
            plan = self._reserve(token, request, identity)
        if not execute:
            return {"state": "reserved"}
        fd = os.open(plan.executable, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            digest = hashlib.sha256(os.read(fd, os.fstat(fd).st_size)).hexdigest()
            os.lseek(fd, 0, 0)
            if digest != plan.executable_digest:
                self.ledger.transition(plan.request_id, "ambiguous", {"error": "executable mutation"})
                raise RequestError("executable mutation")
            self.ledger.transition(plan.request_id, "running", {"executable_digest": digest})
            result = execute_verified(fd, list(plan.argv), timeout_ms=plan.timeout_ms, output_bytes=plan.output_bytes)
            fd = -1
        finally:
            if fd >= 0:
                os.close(fd)
        data = {"state": "result", "exit_code": result.exit_code, "stdout": result.stdout.decode(errors="replace"), "stderr": result.stderr.decode(errors="replace"), "truncated": result.truncated, "timed_out": result.timed_out}
        self.ledger.transition(plan.request_id, "result", data)
        return data

    def status(self, request_id):
        return self.ledger.get(request_id) or {"state": "unknown"}

    def pending(self, identity):
        self._role(identity, self.operators)
        return self.ledger.pending()
