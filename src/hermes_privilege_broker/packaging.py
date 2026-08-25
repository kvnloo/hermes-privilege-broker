import json
import os
import shutil
import stat
import tempfile
from pathlib import Path


class InstallError(RuntimeError):
    pass


_CATALOG = {"version": 1, "operations": [{"operation_id": "system.identity", "executable": "/usr/bin/id", "argv": [], "timeout_ms": 1000, "output_bytes": 4096, "slots": {}}]}
_UNIT = """[Unit]\nDescription=Hermes privilege broker\nAfter=local-fs.target\n[Service]\nType=simple\nUser=root\nGroup=root\nExecStart=/usr/libexec/hermes-privilege-broker-daemon\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nReadWritePaths=/var/lib/hermes-privilege-broker /run/hermes-privilege-broker\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n"""
_OPERATOR_UNIT = """[Unit]\nDescription=Hermes privilege operator Telegram frontend\nAfter=network-online.target hermes-privilege-broker.service\nRequires=hermes-privilege-broker.service\n[Service]\nType=simple\nUser=hermes-privilege-operator\nGroup=hermes-privilege-operator\nLoadCredential=telegram-bot.token:/etc/hermes-privilege-broker/telegram-bot.token\nExecStart=/usr/libexec/hermes-privilege-operator-telegram\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n"""
_WRAPPER = "#!/usr/bin/python3\nimport sys\nsys.path.insert(0, '/usr/lib/hermes-privilege-broker/python')\nfrom hermes_privilege_broker.daemon import main\nmain()\n"
_OPERATOR = "#!/usr/bin/python3\nimport sys\nsys.path.insert(0, '/usr/lib/hermes-privilege-broker/python')\nfrom hermes_privilege_operator.telegram import main\nmain()\n"


def _runtime_payload():
    import pkgutil
    packages = {
        "hermes_privilege_broker": ("__init__.py", "broker.py", "catalog.py", "daemon.py", "executor.py", "ledger.py", "protocol.py", "transport.py"),
        "hermes_privilege_operator": ("__init__.py", "telegram.py"),
    }
    entries = []
    for package, names in packages.items():
        for name in names:
            data = pkgutil.get_data(package, name)
            if data is None:
                raise InstallError(f"missing packaged runtime: {package}/{name}")
            destination = f"/usr/lib/hermes-privilege-broker/python/{package}/{name}"
            entries.append({"kind": "file", "path": destination, "mode": "0644", "owner": "root:root", "content": data.decode("utf-8")})
    return entries


def manifest():
    catalog = json.dumps(_CATALOG, sort_keys=True, separators=(",", ":")) + "\n"
    config = json.dumps({
        "catalog": "/etc/hermes-privilege-broker/catalog.json",
        "ledger": "/var/lib/hermes-privilege-broker/ledger.sqlite",
        "requester_socket": "/run/hermes-privilege-broker/request.sock",
        "operator_socket": "/run/hermes-privilege-broker/operator.sock",
        "requester_uids": [], "operator_uids": [], "requester_gid": -1, "operator_gid": -1,
    }, sort_keys=True, separators=(",", ":")) + "\n"
    operator = json.dumps({
        "allowed_user_ids": [1083429746],
        "chat_id": 1083429746,
        "operator_socket": "/run/hermes-privilege-broker/operator.sock",
        "token_file": "/etc/hermes-privilege-broker/telegram-bot.token",
    }, sort_keys=True, separators=(",", ":")) + "\n"
    return [
        {"kind": "directory", "path": "/etc/hermes-privilege-broker", "mode": "0755", "owner": "root:root"},
        {"kind": "directory", "path": "/var/lib/hermes-privilege-broker", "mode": "0700", "owner": "root:root"},
        {"kind": "directory", "path": "/run/hermes-privilege-broker", "mode": "0755", "owner": "root:root"},
        {"kind": "directory", "path": "/usr/lib/hermes-privilege-broker", "mode": "0755", "owner": "root:root"},
        {"kind": "directory", "path": "/usr/lib/hermes-privilege-broker/python", "mode": "0755", "owner": "root:root"},
        {"kind": "directory", "path": "/usr/lib/hermes-privilege-broker/python/hermes_privilege_broker", "mode": "0755", "owner": "root:root"},
        {"kind": "directory", "path": "/usr/lib/hermes-privilege-broker/python/hermes_privilege_operator", "mode": "0755", "owner": "root:root"},
        {"kind": "file", "path": "/etc/hermes-privilege-broker/catalog.json", "mode": "0600", "owner": "root:root", "content": catalog},
        {"kind": "file", "path": "/etc/hermes-privilege-broker/broker.json", "mode": "0600", "owner": "root:root", "content": config},
        {"kind": "file", "path": "/etc/hermes-privilege-broker/operator.json", "mode": "0644", "owner": "root:root", "content": operator},
        {"kind": "file", "path": "/usr/libexec/hermes-privilege-broker-daemon", "mode": "0755", "owner": "root:root", "content": _WRAPPER},
        {"kind": "file", "path": "/usr/libexec/hermes-privilege-operator-telegram", "mode": "0755", "owner": "root:root", "content": _OPERATOR},
        {"kind": "file", "path": "/usr/lib/systemd/system/hermes-privilege-broker.service", "mode": "0644", "owner": "root:root", "content": _UNIT},
        {"kind": "file", "path": "/usr/lib/systemd/system/hermes-privilege-operator-telegram.service", "mode": "0644", "owner": "root:root", "content": _OPERATOR_UNIT},
        {"kind": "preserved", "path": "/var/lib/hermes-privilege-broker/ledger.sqlite", "mode": "0600", "owner": "root:root"},
    ] + _runtime_payload()


class Installer:
    def __init__(self, root=Path("/"), system=None):
        self.root = Path(root)
        self.system = system

    def plan(self):
        return {"version": 1, "dry_run": True, "changes_applied": False, "manifest": manifest()}

    def _target(self, path):
        return self.root / path.lstrip("/")

    def _check_ancestors(self, target):
        current = target.parent
        try:
            target.relative_to(self.root)
        except ValueError as exc:
            raise InstallError("target escapes installation root") from exc
        while True:
            try:
                metadata = os.lstat(current)
            except FileNotFoundError:
                metadata = None
            if metadata is not None:
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    raise InstallError(f"symlink ancestor refused: {current}")
                if self.root == Path("/") and (metadata.st_uid != 0 or metadata.st_mode & 0o022):
                    raise InstallError(f"unsafe ancestor ownership or mode: {current}")
            if current == self.root:
                break
            current = current.parent

    def _install_file(self, entry):
        target = self._target(entry["path"])
        self._check_ancestors(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and (target.is_symlink() or not target.is_file()):
            raise InstallError(f"unsafe target: {target}")
        data = entry["content"].encode()
        if target.exists() and target.read_bytes() == data and stat.S_IMODE(target.stat().st_mode) == int(entry["mode"], 8):
            return
        fd, temporary = tempfile.mkstemp(prefix=".hermes-install-", dir=target.parent)
        try:
            os.write(fd, data); os.fsync(fd); os.fchmod(fd, int(entry["mode"], 8)); os.close(fd); fd = -1
            os.replace(temporary, target)
            if self.root == Path("/"):
                os.chown(target, 0, 0)
        finally:
            if fd >= 0: os.close(fd)
            try: os.unlink(temporary)
            except FileNotFoundError: pass

    def _verify_token(self):
        target = self._target("/etc/hermes-privilege-broker/telegram-bot.token")
        try:
            metadata = os.lstat(target)
        except FileNotFoundError as exc:
            raise InstallError("missing Telegram credential") from exc
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise InstallError("unsafe Telegram credential mode")
        if self.root == Path("/") and (metadata.st_uid != 0 or metadata.st_gid != 0):
            raise InstallError("unsafe Telegram credential owner")

    def verify(self):
        for entry in manifest():
            if entry["kind"] not in {"file", "directory"}:
                continue
            target = self._target(entry["path"])
            try:
                metadata = os.lstat(target)
            except FileNotFoundError as exc:
                raise InstallError(f"missing manifest path: {entry['path']}") from exc
            if stat.S_IMODE(metadata.st_mode) != int(entry["mode"], 8):
                raise InstallError(f"mode mismatch: {entry['path']}")
            if self.root == Path("/") and (metadata.st_uid != 0 or metadata.st_gid != 0):
                raise InstallError(f"owner mismatch: {entry['path']}")
            if entry["kind"] == "file" and not entry["path"].endswith("broker.json"):
                if target.read_bytes() != entry["content"].encode():
                    raise InstallError(f"content mismatch: {entry['path']}")

    def apply(self):
        if self.root == Path("/") and os.geteuid() != 0:
            raise InstallError("apply requires root")
        if self.system is None:
            self.system = LinuxSystem()
        if self.root == Path("/"):
            self._verify_token()
        snapshots = []
        try:
            gids = {}
            for group in ("hermes-privilege-requester", "hermes-privilege-operator"):
                gids[group] = self.system.group(group, True)
            uids = {}
            for account, group in (("hermes-privilege-broker", None), ("hermes-privilege-requester", "hermes-privilege-requester"), ("hermes-privilege-operator", "hermes-privilege-operator")):
                uids[account] = self.system.account(account, True, group)
            for entry in manifest():
                if entry["kind"] == "directory":
                    target = self._target(entry["path"])
                    self._check_ancestors(target)
                    target.mkdir(parents=True, exist_ok=True)
                    os.chmod(target, int(entry["mode"], 8))
                    if self.root == Path("/"):
                        os.chown(target, 0, 0)
            for entry in manifest():
                if entry["kind"] == "file":
                    if entry["path"].endswith("broker.json"):
                        config = json.loads(entry["content"])
                        config.update(requester_uids=[uids["hermes-privilege-requester"]], operator_uids=[uids["hermes-privilege-operator"]], requester_gid=gids["hermes-privilege-requester"], operator_gid=gids["hermes-privilege-operator"])
                        entry = {**entry, "content": json.dumps(config, sort_keys=True, separators=(",", ":")) + "\n"}
                    target = self._target(entry["path"])
                    snapshots.append((target, target.read_bytes() if target.exists() else None,
                                      stat.S_IMODE(target.stat().st_mode) if target.exists() else None))
                    self._install_file(entry)
            self.verify()
            self.system.service(True)
        except Exception as exc:
            try: self.system.service(False)
            except Exception: pass
            for target, content, mode in reversed(snapshots):
                try:
                    if content is None:
                        target.unlink()
                    else:
                        target.write_bytes(content)
                        os.chmod(target, mode)
                except FileNotFoundError:
                    pass
            raise InstallError("apply failed and rolled back") from exc

    update = apply

    def uninstall(self):
        if self.system is None: self.system = LinuxSystem()
        self.system.service(False)
        for entry in reversed(manifest()):
            if entry["kind"] == "file":
                try: self._target(entry["path"]).unlink()
                except FileNotFoundError: pass
            elif entry["kind"] == "directory" and entry["path"] != "/var/lib/hermes-privilege-broker":
                try: self._target(entry["path"]).rmdir()
                except (FileNotFoundError, OSError): pass
        for account in ("hermes-privilege-operator", "hermes-privilege-requester", "hermes-privilege-broker"):
            self.system.account(account, False)
        for group in ("hermes-privilege-operator", "hermes-privilege-requester"):
            self.system.group(group, False)


class LinuxSystem:
    """Fixed-argv host integration. No shell and no caller environment."""
    def _run(self, argv):
        import subprocess
        subprocess.run(argv, check=True, env={"PATH": "/usr/sbin:/usr/bin"}, stdin=subprocess.DEVNULL)

    def group(self, name, present):
        if present:
            import grp
            try: grp.getgrnam(name)
            except KeyError: self._run(["/usr/sbin/groupadd", "--system", name])
            import grp
            return grp.getgrnam(name).gr_gid
        import grp
        try: grp.getgrnam(name)
        except KeyError: return None
        self._run(["/usr/sbin/groupdel", name])
        return None

    def account(self, name, present, group=None):
        if present:
            import pwd
            try: pwd.getpwnam(name)
            except KeyError:
                argv = ["/usr/sbin/useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin"]
                if group: argv += ["--gid", group]
                argv += [name]
                self._run(argv)
            import pwd
            return pwd.getpwnam(name).pw_uid
        import pwd
        try: pwd.getpwnam(name)
        except KeyError: return None
        self._run(["/usr/sbin/userdel", name])
        return None

    def service(self, enabled):
        self._run(["/usr/bin/systemctl", "daemon-reload"])
        units = ["hermes-privilege-broker.service", "hermes-privilege-operator-telegram.service"]
        self._run(["/usr/bin/systemctl", "enable", "--now", *units] if enabled else ["/usr/bin/systemctl", "disable", "--now", *reversed(units)])
