import argparse
import gzip
import hashlib
import io
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    build(parser.parse_args().output)


if __name__ == "__main__":
    main()
