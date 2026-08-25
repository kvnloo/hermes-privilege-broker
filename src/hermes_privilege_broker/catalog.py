import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from .protocol import canonical_digest


class CatalogError(ValueError):
    pass


_INTERPRETERS = {"python", "python3", "bash", "sh", "dash", "zsh", "perl", "ruby", "node", "env"}
_REQ_FIELDS = {"request_id", "operation_id", "slots", "reason"}


@dataclass(frozen=True)
class Plan:
    request_id: str
    operation_id: str
    executable: str
    argv: tuple[str, ...]
    timeout_ms: int
    output_bytes: int
    request_digest: str
    catalog_digest: str
    executable_digest: str


@dataclass(frozen=True)
class Catalog:
    operations: dict
    digest: str
    trusted_uid: int

    def plan(self, request):
        if set(request) != _REQ_FIELDS:
            raise CatalogError("request fields must be exact")
        if not all(isinstance(request[key], str) for key in ("request_id", "operation_id", "reason")):
            raise CatalogError("invalid request strings")
        if len(request["request_id"].encode()) > 128 or len(request["reason"].encode()) > 512:
            raise CatalogError("request field too large")
        operation = self.operations.get(request["operation_id"])
        slots = request["slots"]
        if not operation:
            raise CatalogError("unknown operation")
        if not isinstance(slots, dict) or set(slots) != set(operation["slots"]):
            raise CatalogError("slot mismatch")
        argv = []
        for item in operation["argv"]:
            if isinstance(item, str):
                argv.append(item)
                continue
            name = item.get("slot") if isinstance(item, dict) and set(item) == {"slot"} else None
            spec, value = operation["slots"].get(name), slots.get(name)
            if not spec or spec["type"] != "string" or not isinstance(value, str) or "\0" in value:
                raise CatalogError("invalid slot")
            if len(value.encode()) > spec["max_bytes"]:
                raise CatalogError("slot too large")
            argv.append(value)
        return Plan(request["request_id"], request["operation_id"], operation["executable"], tuple(argv), operation["timeout_ms"], operation["output_bytes"], canonical_digest(request), self.digest, operation["executable_digest"])


def _secure(path, uid, ancestors=True):
    paths = [Path(path), *Path(path).parents] if ancestors else [Path(path)]
    for candidate in paths:
        metadata = os.lstat(candidate)
        if stat.S_ISLNK(metadata.st_mode):
            raise CatalogError("symlink component")
        if metadata.st_uid != uid:
            raise CatalogError("wrong owner")
        if metadata.st_mode & 0o022:
            raise CatalogError("writable component")


def load_catalog(path, *, trusted_uid=0, allow_unsafe_ancestors=False):
    path = Path(path)
    _secure(path, trusted_uid, not allow_unsafe_ancestors)
    data = json.loads(path.read_bytes())
    if set(data) != {"version", "operations"} or data["version"] != 1 or not isinstance(data["operations"], list):
        raise CatalogError("invalid catalog")
    operations = {}
    for operation in data["operations"]:
        required = {"operation_id", "executable", "argv", "timeout_ms", "output_bytes", "slots"}
        if not isinstance(operation, dict) or set(operation) != required:
            raise CatalogError("invalid operation")
        operation_id = operation["operation_id"]
        if not isinstance(operation_id, str) or not operation_id or len(operation_id.encode()) > 128 or operation_id in operations:
            raise CatalogError("invalid operation id")
        if not isinstance(operation["executable"], str) or "\0" in operation["executable"]:
            raise CatalogError("invalid executable")
        if type(operation["timeout_ms"]) is not int or not 1 <= operation["timeout_ms"] <= 300_000:
            raise CatalogError("invalid timeout")
        if type(operation["output_bytes"]) is not int or not 1 <= operation["output_bytes"] <= 1_048_576:
            raise CatalogError("invalid output limit")
        if not isinstance(operation["argv"], list) or len(operation["argv"]) > 64 or not isinstance(operation["slots"], dict) or len(operation["slots"]) > 32:
            raise CatalogError("invalid argv or slots")
        for slot_name, spec in operation["slots"].items():
            if not isinstance(slot_name, str) or not slot_name or len(slot_name.encode()) > 64 or not isinstance(spec, dict) or set(spec) != {"type", "max_bytes"}:
                raise CatalogError("invalid slot schema")
            if spec["type"] != "string" or type(spec["max_bytes"]) is not int or not 1 <= spec["max_bytes"] <= 4096:
                raise CatalogError("invalid slot bound")
        for item in operation["argv"]:
            if isinstance(item, str) and ("\0" in item or len(item.encode()) > 4096):
                raise CatalogError("invalid argv literal")
            if not isinstance(item, (str, dict)):
                raise CatalogError("invalid argv item")
            if isinstance(item, dict):
                if set(item) != {"slot"} or not isinstance(item["slot"], str) or not item["slot"] or len(item["slot"].encode()) > 64 or item["slot"] not in operation["slots"]:
                    raise CatalogError("invalid argv slot reference")
        executable = Path(operation["executable"])
        name = executable.name.lower()
        if not executable.is_absolute():
            raise CatalogError("executable not absolute")
        _secure(executable, trusted_uid, not allow_unsafe_ancestors)
        contents = executable.read_bytes()
        if contents.startswith(b"#!"):
            raise CatalogError("script forbidden")
        known_interpreter_digests = set()
        for directory in (Path("/bin"), Path("/usr/bin"), Path("/usr/local/bin")):
            for candidate in directory.glob("*"):
                if not any(candidate.name == prefix or candidate.name.startswith(prefix + ".") or (candidate.name.startswith(prefix) and candidate.name[len(prefix):].isdigit()) for prefix in _INTERPRETERS):
                    continue
                try:
                    known_interpreter_digests.add(hashlib.sha256(candidate.resolve().read_bytes()).digest())
                except OSError:
                    pass
        content_digest = hashlib.sha256(contents).digest()
        if name in _INTERPRETERS or content_digest in known_interpreter_digests or any(name.startswith(prefix + ".") or (name.startswith(prefix) and name[len(prefix):].isdigit()) for prefix in _INTERPRETERS):
            raise CatalogError("interpreter forbidden")
        if not contents.startswith(b"\x7fELF"):
            raise CatalogError("non-ELF executable")
        clean = dict(operation)
        clean["executable_digest"] = content_digest.hex()
        operations[operation_id] = clean
    return Catalog(operations, canonical_digest(data), trusted_uid)
