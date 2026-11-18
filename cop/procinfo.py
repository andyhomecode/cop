"""Small /proc readers shared by the process and exec monitors."""
from __future__ import annotations

import os
import re

_SOCKET_RE = re.compile(r"^socket:\[(\d+)\]$")


def proc_stat(pid: int) -> tuple[str, int] | None:
    """(comm, ppid) from /proc/<pid>/stat, or None if the process is gone."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            data = f.read()
    except OSError:
        return None
    # comm is in parentheses and may contain spaces or ')'
    lp, rp = data.find("("), data.rfind(")")
    if lp < 0 or rp < 0:
        return None
    rest = data[rp + 2:].split()
    try:
        return data[lp + 1:rp], int(rest[1])
    except (IndexError, ValueError):
        return None


def _inet_socket_inodes(pid: int) -> set[str]:
    inodes: set[str] = set()
    for name in ("tcp", "tcp6", "udp", "udp6"):
        try:
            with open(f"/proc/{pid}/net/{name}") as f:
                next(f, None)
                for line in f:
                    parts = line.split()
                    if len(parts) > 9:
                        inodes.add(parts[9])
        except OSError:
            continue
    return inodes


def stdio_on_one_inet_socket(pid: int) -> bool:
    """True if stdin, stdout and stderr are all the same TCP/UDP socket.

    That's the shape of a reverse shell (bash -i >& /dev/tcp/..., nc -e). A
    unix socketpair (e.g. how some daemons wire up children) doesn't count.
    """
    try:
        links = [os.readlink(f"/proc/{pid}/fd/{i}") for i in (0, 1, 2)]
    except OSError:
        return False
    if len(set(links)) != 1:
        return False
    m = _SOCKET_RE.match(links[0])
    if not m:
        return False
    return m.group(1) in _inet_socket_inodes(pid)
