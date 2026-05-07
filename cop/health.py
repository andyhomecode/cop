from __future__ import annotations

import asyncio
import json
import re
import socket
import subprocess

_NETHOGS_SECS = 5
_SUDO_RE = re.compile(r"COMMAND=(.+)$")
_USER_RE = re.compile(r"(\w+)\s*:")


async def _run(cmd: list[str], timeout: float = 8.0) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace").strip()
    except Exception:
        return ""


def _parse_nethogs(raw: str) -> list[dict]:
    """Parse nethogs -t output. Format per line: <path>/<pid>/<uid>\t<sent>\t<recv>"""
    chunks = re.split(r"\s*Refreshing:\s*", raw)
    lines = chunks[-1].splitlines() if chunks else []
    out = []
    for line in lines:
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        identifier = parts[0].strip()
        if identifier.startswith("Program") or identifier.startswith("unknown TCP"):
            continue
        try:
            sent, recv = float(parts[1]), float(parts[2])
        except ValueError:
            continue
        if sent < 0.01 and recv < 0.01:
            continue

        # identifier: <path_or_name>/<pid>/<uid> — last two segments are always pid/uid
        segs = identifier.split("/")
        pid = None
        path = identifier
        if len(segs) >= 2:
            try:
                int(segs[-1])   # uid
                pid = int(segs[-2])
                path = "/".join(segs[:-2])
            except ValueError:
                pass

        if path.startswith("/"):
            prog = path.rsplit("/", 1)[-1]
        else:
            # e.g. "sshd: user@pts" → "sshd"
            prog = re.split(r"[\s:/]", path)[0]

        out.append({"prog": prog or path, "pid": pid, "sent": sent, "recv": recv})
    return out


def _pid_remote_addrs(pid: int) -> list[tuple[str, int]]:
    """Return unique remote (ip, port) pairs for ESTAB connections of pid."""
    try:
        out = subprocess.check_output(
            ["ss", "-t", "-n", "-p"],
            text=True, stderr=subprocess.DEVNULL, timeout=5,
        )
    except Exception:
        return []
    addrs: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    pid_tag = f"pid={pid}"
    for line in out.splitlines():
        if pid_tag not in line:
            continue
        parts = line.split()
        if len(parts) < 5 or parts[0] != "ESTAB":
            continue
        try:
            rraw, rport_s = parts[4].rsplit(":", 1)
            rip = rraw.strip("[]")
            rport = int(rport_s)
        except (ValueError, IndexError):
            continue
        if rip.startswith("127.") or rip == "::1":
            continue
        key = (rip, rport)
        if key not in seen:
            seen.add(key)
            addrs.append(key)
    return addrs


async def _reverse_dns(ip: str) -> str:
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip),
            timeout=2.0,
        )
        host = result[0]
        return host if host != ip else ""
    except Exception:
        return ""


async def _enrich_entry(entry: dict) -> dict:
    if not entry["pid"]:
        return {**entry, "dest": ""}
    addrs = _pid_remote_addrs(entry["pid"])
    if not addrs:
        return {**entry, "dest": ""}
    # Deduplicate IPs, resolve up to 2
    seen_ips: list[str] = []
    for ip, _port in addrs:
        if ip not in seen_ips:
            seen_ips.append(ip)
    top_ips = seen_ips[:2]
    hostnames = await asyncio.gather(*[_reverse_dns(ip) for ip in top_ips])
    ip_to_host = dict(zip(top_ips, hostnames))

    dest_parts = []
    seen_labels: set[str] = set()
    for ip, port in addrs:
        if ip not in top_ips:
            continue
        host = ip_to_host.get(ip, "")
        label = f"{host}:{port}" if host else f"{ip}:{port}"
        if label not in seen_labels:
            seen_labels.add(label)
            dest_parts.append(label)
        if len(dest_parts) >= 2:
            break

    extra = len(seen_ips) - len(top_ips)
    dest = " → " + ", ".join(dest_parts) if dest_parts else ""
    if extra > 0:
        dest += f" +{extra}"
    return {**entry, "dest": dest}


def _parse_docker_stats(raw: str) -> list[dict]:
    containers = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            cpu = float(obj.get("CPUPerc", "0%").rstrip("%"))
        except ValueError:
            cpu = 0.0
        containers.append({
            "name": obj.get("Name", obj.get("ID", "?")),
            "cpu": cpu,
            "mem_perc": obj.get("MemPerc", "?"),
            "mem_usage": obj.get("MemUsage", "?").split(" / ")[0],
            "net_io": obj.get("NetIO", "?"),
        })
    containers.sort(key=lambda c: c["cpu"], reverse=True)
    return containers


async def gather() -> str:
    who, last, ps, sudo = await asyncio.gather(
        _run(["who"]),
        _run(["last", "-n", "10"]),
        _run(["ps", "aux", "--sort=-%cpu"]),
        _run(["journalctl", "_COMM=sudo", "--since=24h ago", "--no-pager", "-o", "cat", "-n", "15"]),
    )
    nethogs, docker_raw = await asyncio.gather(
        _run(["nethogs", "-t", "-c", "2", f"-d{_NETHOGS_SECS}"], timeout=_NETHOGS_SECS * 3),
        _run(["docker", "stats", "--format", "json", "--no-stream"]),
    )

    sections: list[str] = []

    # Logged in
    if who:
        users = [f"  {l}" for l in who.splitlines()]
        sections.append("👥 Logged in:\n" + "\n".join(users))
    else:
        sections.append("👥 Logged in: nobody")

    # Recent logins
    if last:
        logins = [l for l in last.splitlines() if l and not l.startswith("wtmp")][:6]
        sections.append("🔐 Recent logins:\n" + "\n".join(f"  {l}" for l in logins))

    # Sudo actions
    if sudo:
        lines = []
        for line in sudo.splitlines():
            user_m = _USER_RE.search(line)
            cmd_m = _SUDO_RE.search(line)
            if user_m and cmd_m:
                lines.append(f"  {user_m.group(1)}: {cmd_m.group(1).strip()}")
        if lines:
            sections.append("🔑 Sudo (24h):\n" + "\n".join(lines[-8:]))

    # Top processes
    if ps:
        rows = ps.splitlines()[1:8]
        procs = []
        for row in rows:
            parts = row.split(None, 10)
            if len(parts) >= 11:
                cpu, mem, cmd = parts[2], parts[3], parts[10][:35]
                procs.append(f"  {cpu:>5}% cpu  {mem:>4}% mem  {cmd}")
        if procs:
            sections.append("⚙️ Top processes:\n" + "\n".join(procs))

    # Docker containers
    if docker_raw:
        containers = _parse_docker_stats(docker_raw)
        if containers:
            rows = []
            for c in containers:
                rows.append(f"  {c['name']:<22} CPU: {c['cpu']:>5.2f}%  Mem: {c['mem_perc']:>5} ({c['mem_usage']})  Net: {c['net_io']}")
            sections.append("🐳 Containers:\n" + "\n".join(rows))

    # Network
    net_entries = _parse_nethogs(nethogs)
    if net_entries:
        enriched = await asyncio.gather(*[_enrich_entry(e) for e in net_entries])
        net_lines = []
        for e in enriched:
            pid_s = f"/{e['pid']}" if e["pid"] else ""
            label = f"{e['prog']}{pid_s}"
            rate = f"↑{e['sent']:.1f} ↓{e['recv']:.1f} KB/s"
            net_lines.append(f"  {label:<22} {rate}{e['dest']}")
        sections.append("🌐 Network:\n" + "\n".join(net_lines))
    elif nethogs:
        sections.append("🌐 Network: no significant traffic")

    return "\n\n".join(sections)
