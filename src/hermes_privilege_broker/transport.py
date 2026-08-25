import os
import socket
import struct

from .broker import Identity


def _start_time(pid):
    fields = open(f"/proc/{pid}/stat", encoding="ascii").read().split()
    return int(fields[21])


def peer_identity(connection):
    pid, uid, _gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    identity = Identity(uid, pid, _start_time(pid))
    if hasattr(os, "pidfd_open"):
        descriptor = os.pidfd_open(pid)
        os.close(descriptor)
    return identity


def require_peer(identity, allowed_uids):
    if identity.uid not in allowed_uids:
        raise PermissionError("peer UID is not authorized for this socket")
    if _start_time(identity.pid) != identity.start_time:
        raise PermissionError("peer process identity changed")
