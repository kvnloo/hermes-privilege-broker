import hashlib
import json
import os
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest

from hermes_privilege_broker.packaging import Installer, InstallError, manifest
from hermes_privilege_broker.cli import main
from hermes_privilege_operator.telegram import load_operator_config


class FakeSystem:
    def __init__(self):
        self.accounts = set()
        self.groups = set()
        self.enabled = False
        self.calls = []

    def group(self, name, present):
        self.calls.append(("group", name, present))
        (self.groups.add if present else self.groups.discard)(name)
        return {"hermes-privilege-requester": 2101, "hermes-privilege-operator": 2102}[name]

    def account(self, name, present, group=None):
        self.calls.append(("account", name, present, group))
        (self.accounts.add if present else self.accounts.discard)(name)
        return {"hermes-privilege-broker": 2000, "hermes-privilege-requester": 2001, "hermes-privilege-operator": 2002}[name]

    def service(self, enabled):
        self.calls.append(("service", enabled))
        self.enabled = enabled

    def has_group(self, name):
        return name in self.groups

    def has_account(self, name):
        return name in self.accounts


def test_plan_is_deterministic_dry_run_and_has_one_harmless_operation(tmp_path):
    plan = Installer(tmp_path, FakeSystem()).plan()
    assert plan["dry_run"] is True
    assert plan["manifest"] == manifest()
    assert plan == Installer(tmp_path, FakeSystem()).plan()
    catalog = next(x for x in plan["manifest"] if x["path"].endswith("catalog.json"))
    payload = json.loads(catalog["content"])
    assert payload == {"version": 1, "operations": [{"operation_id": "system.identity", "executable": "/usr/bin/id", "argv": [], "timeout_ms": 1000, "output_bytes": 4096, "slots": {}}]}


def test_apply_is_idempotent_exact_and_uninstall_preserves_ledger(tmp_path):
    system = FakeSystem()
    installer = Installer(tmp_path, system)
    installer.apply()
    installer.apply()
    for entry in manifest():
        if entry["kind"] != "file":
            continue
        path = tmp_path / entry["path"].lstrip("/")
        if not entry["path"].endswith("broker.json"):
            assert path.read_bytes() == entry["content"].encode()
        assert stat.S_IMODE(path.stat().st_mode) == int(entry["mode"], 8)
    assert system.groups == {"hermes-privilege-requester", "hermes-privilege-operator"}
    assert system.accounts == {"hermes-privilege-broker", "hermes-privilege-requester", "hermes-privilege-operator"}
    assert system.enabled
    config = json.loads((tmp_path / "etc/hermes-privilege-broker/broker.json").read_text())
    assert config["requester_uids"] == [2001]
    assert config["operator_uids"] == [2002]
    assert config["requester_gid"] == 2101
    assert config["operator_gid"] == 2102
    ledger = tmp_path / "var/lib/hermes-privilege-broker/ledger.sqlite"
    ledger.write_bytes(b"audit")
    installer.uninstall()
    assert ledger.read_bytes() == b"audit"
    assert not system.enabled
    assert system.accounts == set()
    assert system.groups == set()
    assert not (tmp_path / "run/hermes-privilege-broker").exists()
    assert (tmp_path / "var/lib/hermes-privilege-broker").exists()


def test_apply_rolls_back_partial_failure(tmp_path, monkeypatch):
    system = FakeSystem()
    installer = Installer(tmp_path, system)
    original = installer._install_file
    count = 0
    def fail(entry):
        nonlocal count
        count += 1
        if count == 3:
            raise OSError("injected")
        return original(entry)
    monkeypatch.setattr(installer, "_install_file", fail)
    with pytest.raises(InstallError, match="rolled back"):
        installer.apply()
    assert not (tmp_path / "etc/hermes-privilege-broker/catalog.json").exists()
    assert not system.enabled
    assert system.accounts == set()
    assert system.groups == set()
    assert not (tmp_path / "etc/hermes-privilege-broker").exists()
    assert not (tmp_path / "run/hermes-privilege-broker").exists()
    assert not (tmp_path / "usr/lib/hermes-privilege-broker").exists()


def test_apply_rejects_symlinked_or_wrong_existing_target(tmp_path):
    target = tmp_path / "etc/hermes-privilege-broker"
    target.parent.mkdir(parents=True)
    target.symlink_to(tmp_path)
    with pytest.raises(InstallError):
        Installer(tmp_path, FakeSystem()).apply()


def test_cli_defaults_to_plan_and_requires_explicit_apply(monkeypatch, capsys):
    called = []
    monkeypatch.setattr(Installer, "apply", lambda self: called.append("apply"))
    main([])
    assert json.loads(capsys.readouterr().out)["dry_run"] is True
    assert called == []
    main(["apply"])
    assert called == ["apply"]


def test_manifest_has_split_services_fixed_telegram_config_and_no_secret(tmp_path):
    entries = manifest()
    paths = {entry["path"] for entry in entries}
    assert "/usr/lib/systemd/system/hermes-privilege-broker.service" in paths
    assert "/usr/lib/systemd/system/hermes-privilege-operator-telegram.service" in paths
    operator = next(entry for entry in entries if entry["path"].endswith("operator.json"))
    assert json.loads(operator["content"]) == {
        "allowed_user_ids": [1083429746],
        "chat_id": 1083429746,
        "operator_socket": "/run/hermes-privilege-broker/operator.sock",
        "token_file": "/etc/hermes-privilege-broker/telegram-bot.token",
    }
    serialized = json.dumps(entries)
    assert "TELEGRAM_BOT_TOKEN" not in serialized
    assert "NOPASSWD" not in serialized


def test_apply_requires_exact_root_owned_token_on_live_root(monkeypatch):
    installer = Installer(Path("/"), FakeSystem())
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(installer, "_verify_token", lambda: (_ for _ in ()).throw(InstallError("unsafe Telegram credential")))
    with pytest.raises(InstallError, match="credential"):
        installer.apply()


def test_verify_detects_content_or_mode_drift(tmp_path):
    installer = Installer(tmp_path, FakeSystem())
    installer.apply()
    installer.verify()
    catalog = tmp_path / "etc/hermes-privilege-broker/catalog.json"
    catalog.write_text("{}")
    with pytest.raises(InstallError, match="content"):
        installer.verify()


def test_verify_detects_dynamic_broker_config_tampering(tmp_path):
    installer = Installer(tmp_path, FakeSystem())
    installer.apply()
    broker = tmp_path / "etc/hermes-privilege-broker/broker.json"
    payload = json.loads(broker.read_text())
    payload["catalog"] = "/tmp/attacker-catalog.json"
    payload["requester_uids"] = [0]
    broker.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(InstallError, match="content"):
        installer.verify()


def test_partial_update_restores_preexisting_file(tmp_path, monkeypatch):
    installer = Installer(tmp_path, FakeSystem())
    installer.apply()
    catalog = tmp_path / "etc/hermes-privilege-broker/catalog.json"
    old = b"old-catalog\n"
    catalog.write_bytes(old)
    original = installer._install_file
    count = 0
    def fail(entry):
        nonlocal count
        count += 1
        original(entry)
        if count == 2:
            raise OSError("injected")
    monkeypatch.setattr(installer, "_install_file", fail)
    with pytest.raises(InstallError, match="rolled back"):
        installer.update()
    assert catalog.read_bytes() == old


def test_operator_loads_only_fixed_config_and_systemd_credential(tmp_path):
    config = tmp_path / "operator.json"
    credential = tmp_path / "telegram-bot.token"
    config.write_text(json.dumps({
        "allowed_user_ids": [1083429746], "chat_id": 1083429746,
        "operator_socket": "/run/hermes-privilege-broker/operator.sock",
        "token_file": "/etc/hermes-privilege-broker/telegram-bot.token",
    }))
    credential.write_text("123456:abcdefghijklmnopqrstuvwxyz_ABCD\n")
    os.chmod(config, 0o644)
    os.chmod(credential, 0o400)
    loaded = load_operator_config(config, credential, require_root=False)
    assert loaded[0] == "/run/hermes-privilege-broker/operator.sock"
    assert loaded[1] == "123456:abcdefghijklmnopqrstuvwxyz_ABCD"
    assert loaded[2:] == ({1083429746}, 1083429746)
    os.chmod(credential, 0o444)
    with pytest.raises(PermissionError, match="credential"):
        load_operator_config(config, credential, require_root=False)


def test_manifest_contains_runtime_code_for_broker_and_operator_packages():
    files = {entry["path"]: entry for entry in manifest() if entry["kind"] == "file"}
    broker_prefix = "/usr/lib/hermes-privilege-broker/python/hermes_privilege_broker/"
    operator_prefix = "/usr/lib/hermes-privilege-broker/python/hermes_privilege_operator/"
    assert broker_prefix + "daemon.py" in files
    assert broker_prefix + "broker.py" in files
    assert operator_prefix + "telegram.py" in files
    assert all(entry["mode"] == "0644" for path, entry in files.items() if path.startswith((broker_prefix, operator_prefix)))


def test_install_artifact_is_deterministic_and_defaults_to_plan(tmp_path):
    from hermes_privilege_broker.build_packet import build
    first = tmp_path / "first.pyz"
    second = tmp_path / "second.pyz"
    build(first)
    build(second)
    assert hashlib.sha256(first.read_bytes()).digest() == hashlib.sha256(second.read_bytes()).digest()
    result = subprocess.run(["/usr/bin/python3", "-I", str(first)], check=True, capture_output=True, text=True, env={})
    assert json.loads(result.stdout)["dry_run"] is True


def test_release_archive_hash_manifest_verifies_after_clean_extraction(tmp_path):
    from hermes_privilege_broker.build_packet import build_archive
    release = tmp_path / "release"
    release.mkdir()
    (release / "installer.pyz").write_bytes(b"installer")
    (release / "plan.json").write_bytes(b"{}\n")
    archive = build_archive(release, tmp_path / "packet.tar.gz")
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    with tarfile.open(archive, "r:gz") as packet:
        packet.extractall(extracted, filter="data")
    result = subprocess.run(["/usr/bin/sha256sum", "-c", "SHA256SUMS"], cwd=extracted,
                            text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert sorted(path.name for path in extracted.iterdir()) == ["SHA256SUMS", "installer.pyz", "plan.json"]


def test_post_install_verifier_targets_the_packaged_installer(tmp_path):
    from hermes_privilege_broker.build_packet import write_post_install_verify

    script = write_post_install_verify(tmp_path, "hermes-privilege-broker-install-deadbee.pyz")

    text = script.read_text()
    assert '"$PACKET_DIR/hermes-privilege-broker-install-deadbee.pyz" verify' in text
    assert "0af993a" not in text
