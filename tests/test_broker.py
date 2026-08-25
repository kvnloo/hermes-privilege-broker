import json
import os
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from hermes_privilege_broker.broker import Broker, Identity, RequestError
from hermes_privilege_broker.catalog import CatalogError, load_catalog
from hermes_privilege_broker.executor import execute_verified
from hermes_privilege_broker.ledger import Ledger, LedgerError
from hermes_privilege_broker.protocol import canonical_digest
from hermes_privilege_broker.transport import peer_identity, require_peer
from hermes_privilege_broker.daemon import dispatch
from hermes_privilege_operator import telegram
from hermes_privilege_operator.telegram import parse_callback, render_approval


def catalog_file(tmp_path: Path, executable=None, *, owner=None):
    if executable is None:
        copied = tmp_path / "echo"
        copied.write_bytes(Path("/bin/echo").read_bytes())
        copied.chmod(0o755)
        executable = str(copied)
    p = tmp_path / "catalog.json"
    p.write_text(json.dumps({"version": 1, "operations": [{
        "operation_id": "harmless.echo", "executable": executable,
        "argv": [{"slot": "message"}], "timeout_ms": 1000,
        "output_bytes": 4096, "slots": {"message": {"type": "string", "max_bytes": 32}}
    }]}))
    p.chmod(0o600)
    return p


def make_broker(tmp_path, *, ttl=0.2):
    cat = load_catalog(catalog_file(tmp_path), trusted_uid=os.getuid(), allow_unsafe_ancestors=True)
    return Broker(cat, Ledger(tmp_path / "ledger.sqlite", trusted_uid=os.getuid(), allow_unsafe_ancestors=True), requester_uids={1001}, operator_uids={1002}, grant_ttl=ttl)


def req(request_id="r1", message="hello"):
    return {"request_id": request_id, "operation_id": "harmless.echo", "slots": {"message": message}, "reason": "test"}


def test_catalog_is_typed_canonical_and_rejects_extra_fields(tmp_path):
    cat = load_catalog(catalog_file(tmp_path), trusted_uid=os.getuid(), allow_unsafe_ancestors=True)
    plan = cat.plan(req())
    assert plan.argv == ("hello",)
    assert len(cat.digest) == 64
    with pytest.raises(CatalogError):
        cat.plan({**req(), "argv": ["arbitrary"]})


def test_catalog_rejects_shebang_renamed_interpreter_and_mutable_owner(tmp_path):
    script = tmp_path / "innocent"
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o755)
    with pytest.raises(CatalogError, match="script"):
        load_catalog(catalog_file(tmp_path, str(script)), trusted_uid=os.getuid(), allow_unsafe_ancestors=True)
    renamed = tmp_path / "harmless-tool"
    renamed.write_bytes(Path(os.path.realpath(sys.executable)).read_bytes())
    renamed.chmod(0o755)
    with pytest.raises(CatalogError, match="interpreter"):
        load_catalog(catalog_file(tmp_path, str(renamed)), trusted_uid=os.getuid(), allow_unsafe_ancestors=True)
    catalog_file(tmp_path).chmod(0o666)
    with pytest.raises(CatalogError, match="writable"):
        load_catalog(tmp_path / "catalog.json", trusted_uid=os.getuid(), allow_unsafe_ancestors=True)


def test_requester_and_operator_authorities_are_separate(tmp_path):
    b = make_broker(tmp_path)
    requester = Identity(1001, os.getpid(), 7)
    operator = Identity(1002, os.getpid(), 7)
    b.submit(req(), requester)
    with pytest.raises(RequestError, match="requester"):
        b.submit(req("r2"), operator)
    with pytest.raises(RequestError, match="operator"):
        b.approve("r1", requester)
    grant = b.approve("r1", operator)
    assert grant


def test_socket_authority_comes_from_kernel_peer_credentials():
    left, right = socket.socketpair(socket.AF_UNIX)
    identity = peer_identity(left)
    assert identity.uid == os.getuid() and identity.pid == os.getpid() and identity.start_time > 0
    require_peer(identity, {os.getuid()})
    with pytest.raises(PermissionError):
        require_peer(identity, {os.getuid() + 1})
    left.close(); right.close()


def test_role_dispatch_exposes_only_role_specific_methods(tmp_path):
    b = make_broker(tmp_path)
    requester, operator = Identity(1001, 10, 20), Identity(1002, 11, 21)
    response = dispatch(b, "requester", {"method": "submit", "request": req()}, requester)
    digest = response["request_digest"]
    with pytest.raises(RequestError):
        dispatch(b, "requester", {"method": "approve", "request_id": "r1", "request_digest": digest}, requester)
    response = dispatch(b, "operator", {"method": "approve", "request_id": "r1", "request_digest": digest}, operator)
    assert response["grant"]


def test_malformed_catalog_bounds_fail_closed(tmp_path):
    path = catalog_file(tmp_path)
    data = json.loads(path.read_text())
    data["operations"][0]["timeout_ms"] = -1
    path.write_text(json.dumps(data)); path.chmod(0o600)
    with pytest.raises(CatalogError):
        load_catalog(path, trusted_uid=os.getuid(), allow_unsafe_ancestors=True)
    data["operations"][0]["timeout_ms"] = 1000
    data["operations"][0]["argv"] = ["bad\0literal"]
    path.write_text(json.dumps(data)); path.chmod(0o600)
    with pytest.raises(CatalogError):
        load_catalog(path, trusted_uid=os.getuid(), allow_unsafe_ancestors=True)


def test_grant_is_single_use_expiring_and_mutation_bound(tmp_path):
    b = make_broker(tmp_path, ttl=0.01)
    i, o = Identity(1001, 10, 20), Identity(1002, 11, 21)
    b.submit(req(), i); token = b.approve("r1", o)
    with pytest.raises(RequestError, match="mutation"):
        b.consume(token, req(message="changed"), i, execute=False)
    time.sleep(0.02)
    with pytest.raises(RequestError, match="expired"):
        b.consume(token, req(), i, execute=False)
    b.submit(req("r2"), i); token = b.approve("r2", o)
    b.consume(token, req("r2"), i, execute=False)
    with pytest.raises(RequestError, match="replay"):
        b.consume(token, req("r2"), i, execute=False)


def test_restart_marks_reserved_or_running_ambiguous_and_revokes_grants(tmp_path):
    b = make_broker(tmp_path)
    i, o = Identity(1001, 10, 20), Identity(1002, 11, 21)
    b.submit(req(), i); token = b.approve("r1", o)
    b.reserve_for_test(token, req(), i)
    b2 = Broker(b.catalog, Ledger(tmp_path / "ledger.sqlite", trusted_uid=os.getuid(), allow_unsafe_ancestors=True), requester_uids={1001}, operator_uids={1002})
    assert b2.status("r1")["state"] == "ambiguous"
    with pytest.raises(RequestError, match="revoked"):
        b2.consume(token, req(), i, execute=False)


def test_ledger_failure_prevents_execution(tmp_path, monkeypatch):
    b = make_broker(tmp_path)
    i, o = Identity(1001, 10, 20), Identity(1002, 11, 21)
    b.submit(req(), i); token = b.approve("r1", o)
    monkeypatch.setattr(b.ledger, "transition", lambda *a, **k: (_ for _ in ()).throw(LedgerError("disk")))
    with pytest.raises(LedgerError):
        b.consume(token, req(), i)


def test_fd_bound_execution_survives_path_swap_and_caps_output(tmp_path):
    target = tmp_path / "echo"
    target.write_bytes(Path("/bin/echo").read_bytes()); target.chmod(0o755)
    fd = os.open(target, os.O_RDONLY)
    target.unlink(); target.write_bytes(Path("/bin/false").read_bytes()); target.chmod(0o755)
    result = execute_verified(fd, ["ok"], timeout_ms=1000, output_bytes=2)
    assert result.exit_code == 0 and result.stdout == b"ok" and result.truncated


def test_timeout_kills_process_group_descendants(tmp_path):
    result = execute_verified(os.open("/bin/sleep", os.O_RDONLY), ["10"], timeout_ms=10, output_bytes=10)
    assert result.timed_out and result.exit_code is None


def test_timeout_kills_descendant_after_group_leader_exits(tmp_path):
    executable = tmp_path / "leader-exits"
    subprocess.run(["cc", "tests/helpers/leader_exits.c", "-o", executable], check=True)
    started = time.monotonic()
    result = execute_verified(os.open(executable, os.O_RDONLY), [], timeout_ms=20, output_bytes=10)
    assert result.timed_out and time.monotonic() - started < 2


def test_telegram_rendering_is_inert_and_bounded():
    text = render_approval({"operation_id": "<b>x</b>", "reason": "```\u202e" + "x" * 5000, "slots": {"x": "<tag>"}})
    assert "<b>" not in text and "```" not in text and len(text.encode()) <= 1024
    callback = parse_callback({"from": {"id": 42}, "data": "approve:r1:" + "a" * 64}, {42})
    assert callback == ("approve", "r1", "a" * 64)
    with pytest.raises(PermissionError):
        parse_callback({"from": {"id": 7}, "data": "approve:r1:" + "a" * 64}, {42})


def test_operator_frontend_discovers_and_publishes_pending_request(tmp_path, monkeypatch):
    broker = make_broker(tmp_path)
    requester, operator = Identity(1001, 10, 20), Identity(1002, 11, 21)
    digest = dispatch(broker, "requester", {"method": "submit", "request": req()}, requester)["request_digest"]
    published = []

    def operator_call(message):
        return dispatch(broker, "operator", message, operator)

    monkeypatch.setattr("hermes_privilege_operator.telegram._operator_call", lambda _socket, message: operator_call(message))
    monkeypatch.setattr("hermes_privilege_operator.telegram.telegram_api", lambda _token, method, payload: published.append((method, payload)) or {"message_id": 1})

    seen = telegram.publish_new_pending("operator.sock", "1:" + "x" * 20, 42, set())

    assert seen == {("r1", digest)}
    assert published[0][0] == "sendMessage"
    assert f"approve:r1:{digest}" in published[0][1]["reply_markup"]
    assert telegram.publish_new_pending("operator.sock", "1:" + "x" * 20, 42, seen) == seen
    assert len(published) == 1


def test_pending_discovery_is_operator_only_and_bounded(tmp_path):
    broker = make_broker(tmp_path)
    requester, operator = Identity(1001, 10, 20), Identity(1002, 11, 21)
    dispatch(broker, "requester", {"method": "submit", "request": req()}, requester)
    with pytest.raises(RequestError):
        dispatch(broker, "requester", {"method": "pending"}, requester)
    pending = dispatch(broker, "operator", {"method": "pending"}, operator)
    assert len(pending) == 1 and pending[0]["request"]["request_id"] == "r1"


def test_exact_harmless_operation(tmp_path):
    b = make_broker(tmp_path)
    i, o = Identity(1001, 10, 20), Identity(1002, 11, 21)
    b.submit(req(), i); token = b.approve("r1", o)
    result = b.consume(token, req(), i)
    assert result["state"] == "result" and result["exit_code"] == 0 and result["stdout"] == "hello\n"
