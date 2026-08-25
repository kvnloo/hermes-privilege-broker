import argparse
import gzip
import hashlib
import io
import re
import tarfile
import zipfile
from pathlib import Path


_FILES = (
    "hermes_privilege_broker/__init__.py", "hermes_privilege_broker/broker.py",
    "hermes_privilege_broker/catalog.py", "hermes_privilege_broker/cli.py",
    "hermes_privilege_broker/daemon.py", "hermes_privilege_broker/executor.py",
    "hermes_privilege_broker/ledger.py", "hermes_privilege_broker/packaging.py",
    "hermes_privilege_broker/protocol.py", "hermes_privilege_broker/transport.py",
    "hermes_privilege_operator/__init__.py", "hermes_privilege_operator/telegram.py",
)
_MAIN = b"from hermes_privilege_broker.cli import main\nmain()\n"


def _write(archive, name, content, mode=0o644):
    info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (mode & 0xFFFF) << 16
    archive.writestr(info, content)


def build(output):
    output = Path(output)
    source = Path(__file__).resolve().parents[1]
    with zipfile.ZipFile(output, "w") as archive:
        _write(archive, "__main__.py", _MAIN)
        for relative in _FILES:
            _write(archive, relative, (source / relative).read_bytes())
    return output


def build_archive(release, output):
    release = Path(release)
    output = Path(output)
    files = sorted(path for path in release.iterdir()
                   if path.is_file() and not path.is_symlink() and path.name != "SHA256SUMS")
    sums = "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files).encode()
    members = [(path.name, path.read_bytes(), 0o755 if path.stat().st_mode & 0o111 else 0o644)
               for path in files]
    members.append(("SHA256SUMS", sums, 0o644))
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as packet:
        for name, data, mode in sorted(members):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mtime = 0
            packet.addfile(info, io.BytesIO(data))
    with output.open("wb") as handle:
        with gzip.GzipFile(filename="", mode="wb", fileobj=handle, mtime=0) as compressed:
            compressed.write(raw.getvalue())
    return output


def write_post_install_verify(release, installer_name):
    release = Path(release)
    if re.fullmatch(r"[A-Za-z0-9._-]+\.pyz", installer_name, flags=re.ASCII) is None:
        raise ValueError("installer_name must be a safe ASCII .pyz basename")
    output = release / "post-install-verify.sh"
    output.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "if [ \"$(/usr/bin/id -u)\" -ne 0 ]; then\n"
        "  echo 'verification requires root' >&2\n"
        "  exit 1\n"
        "fi\n"
        "PACKET_DIR=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\n"
        f'/usr/bin/python3 -I "$PACKET_DIR/{installer_name}" verify\n'
        "/usr/bin/systemctl is-active --quiet hermes-privilege-broker.service\n"
        "/usr/bin/systemctl is-active --quiet hermes-privilege-operator-telegram.service\n"
        "/usr/bin/getent passwd hermes-privilege-broker >/dev/null\n"
        "/usr/bin/getent passwd hermes-privilege-requester >/dev/null\n"
        "/usr/bin/getent passwd hermes-privilege-operator >/dev/null\n"
        "/usr/bin/stat -c '%U:%G %a %n' \\\n"
        "  /etc/hermes-privilege-broker/catalog.json \\\n"
        "  /run/hermes-privilege-broker/request.sock \\\n"
        "  /run/hermes-privilege-broker/operator.sock\n"
        "echo 'verification=PASS'\n"
    )
    output.chmod(0o755)
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    build(parser.parse_args().output)


if __name__ == "__main__":
    main()
