import argparse
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    build(parser.parse_args().output)


if __name__ == "__main__":
    main()
