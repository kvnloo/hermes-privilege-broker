import json
import sqlite3
import os
import stat
import time


class LedgerError(RuntimeError):
    pass


class Ledger:
    def __init__(self, path, *, trusted_uid=0, allow_unsafe_ancestors=False):
        path = os.path.abspath(path)
        parent = os.path.dirname(path)
        checks = [parent] if allow_unsafe_ancestors else [parent, *self._ancestors(parent)]
        for candidate in checks:
            metadata = os.lstat(candidate)
            if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != trusted_uid or metadata.st_mode & 0o022:
                raise LedgerError("untrusted ledger ancestor")
        if os.path.lexists(path):
            metadata = os.lstat(path)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != trusted_uid or metadata.st_mode & 0o077:
                raise LedgerError("untrusted ledger file")
        for sidecar in (path + "-wal", path + "-shm"):
            if os.path.lexists(sidecar):
                metadata = os.lstat(sidecar)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != trusted_uid or metadata.st_mode & 0o077:
                    raise LedgerError("untrusted ledger sidecar")
        old_umask = os.umask(0o077)
        try:
            self.db = sqlite3.connect(path, isolation_level=None)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY,state TEXT NOT NULL,data TEXT NOT NULL,updated REAL NOT NULL)")
            self.db.execute("UPDATE requests SET state='ambiguous' WHERE state IN ('reserved','running')")
        except Exception as exc:
            raise LedgerError(str(exc)) from exc
        finally:
            os.umask(old_umask)

    @staticmethod
    def _ancestors(path):
        result = []
        while path != "/":
            path = os.path.dirname(path)
            result.append(path)
        return result

    def transition(self, rid, state, data):
        try:
            payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute("INSERT INTO requests VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,data=excluded.data,updated=excluded.updated", (rid, state, payload, time.time()))
            self.db.execute("COMMIT")
        except Exception as exc:
            try:
                self.db.execute("ROLLBACK")
            except Exception:
                pass
            raise LedgerError(str(exc)) from exc

    def get(self, rid):
        row = self.db.execute("SELECT state,data FROM requests WHERE id=?", (rid,)).fetchone()
        return None if not row else {**json.loads(row[1]), "state": row[0]}
