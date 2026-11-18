# cop — Security Monitoring Daemon

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Python daemon that actively monitors a Linux machine for signs of compromise: unexpected processes, new listening ports, sensitive file changes, honeypot tripwires, Docker anomalies, SSH brute-force, and resource abuse. Alerts are delivered via [ntfy.sh](https://ntfy.sh) and/or Telegram (with two-way reply support).

## Architecture

```
cop daemon (asyncio)
├── ProcessMonitor      — new/unexpected processes, root shells, suspicious spawns, reverse shells
├── NetworkMonitor      — new listening ports, outbound data volume, suspicious outbound ports
├── FileMonitor         — inotify on ~/.ssh, /etc, /home, docker.sock
├── DockerMonitor       — container events stream (start, exec, pull, restart loops)
├── AuthMonitor         — tail /var/log/auth.log (SSH brute force, unknown IPs, sudo)
├── ResourceMonitor     — sustained CPU spikes, memory, network bandwidth
├── PersistenceMonitor  — new/changed cron jobs, systemd units and drop-ins
├── PackageMonitor      — one summary per apt/dpkg run (from dpkg.log + apt history)
├── KernelMonitor       — poll /proc/modules for modules loaded after startup
├── TripwireMonitor     — watches honeypot files; fires CRITICAL on any open
└── ExecMonitor         — every program start, from auditd: app-spawned shells in public containers, /tmp payloads, reverse shells

Alert flow: monitor → AlertEngine (redact secrets → dedup per rule + subject → cooldown) → [Ollama scorer] → ntfy.sh + Telegram + alerts.jsonl

**Dedup is per rule *and* subject** (the file, user, port, IP, module, package or container the alert is about), so four users created in a minute give four alerts, and a real `/etc` change isn't hidden behind unrelated events of the same rule. A repeat of the same subject within the cooldown is only counted; the next alert that goes out says `(+N repeats held back since the last alert)`. Held-back repeats aren't stored, and alert history older than `alerts.retention_days` (90) is deleted at startup and daily.
State: SQLite at ~/.local/share/cop/baseline.db (when run as root)
```

Each monitor runs as an independent asyncio Task. A crash in one monitor logs an error and disables that monitor without affecting the others.

The daemon sends startup and shutdown notifications on every service start/stop — both go to ntfy; startup also goes to Telegram.

## Installation

```bash
cd /path/to/cop
python3 -m venv venv
venv/bin/pip install -e ".[dev]"

# Must run as root: learns full process list, all ports, auth.log, Docker socket
sudo venv/bin/cop learn

# Verify baseline was captured
sudo venv/bin/cop baseline show

# Run daemon in foreground (Ctrl+C to stop)
sudo venv/bin/cop run
```

### Install as systemd service

```bash
sudo cp cop.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cop
sudo journalctl -u cop -f
```

cop runs as root for full process visibility, `/var/log/auth.log` access, and Docker socket access. **Always run `cop learn` as root** — running it as a regular user produces an incomplete baseline and causes false positives on startup.

## Configuration

Copy `config.example.yaml` to `/root/.config/cop/config.yaml` and edit as needed. All fields are optional — defaults are conservative and suitable for most Linux hosts. **Unknown keys are reported** at startup (journal and the startup Telegram message) instead of being silently ignored.

Config search order:
1. `--config <path>` flag
2. `/root/.config/cop/config.yaml` (cop runs as root, so `~` resolves to `/root`)
3. `/etc/cop/config.yaml`
4. Built-in defaults

Key settings to review:

| Field | Default | Notes |
|---|---|---|
| `ntfy.url` | `https://ntfy.sh/your-cop-topic` | Set to your ntfy topic |
| `ntfy.token` | `""` | Set if using ntfy access control |
| `monitors.file.watch_paths` | `~/.ssh, /root/.ssh, /etc, /home, /var/run/docker.sock` | Replaces the default list |
| `monitors.file.extra_watch_paths` | `[]` | Added to `watch_paths` (prefer this, so the defaults keep applying) |
| `monitors.file.extra_critical_paths` | `[]` | Added to the built-in `critical_paths` (globs; `*` matches across `/`) |
| `monitors.file.quiet_during_package_ops` | `true` | Skip non-critical file events while apt/dpkg runs |
| `monitors.file.ignore_paths` | `[]` | Path prefixes to silence entirely (e.g. cache directories inside a watched tree) |
| `monitors.network.baseline_ports_override` | `[]` | Ports that always count as known (never fire `new_listen_port`) |
| `monitors.network.ignore_loopback_ephemeral_ports` | `true` | Don't alert on loopback ports in the kernel's ephemeral range (OAuth/IDE callbacks) |
| `monitors.network.suspicious_outbound_ports` | `[1080, 3333, 4444, ...]` | Ports that fire `suspicious_outbound_port` CRITICAL when any process connects to them |
| `monitors.network.trusted_outbound_process_names` | `[]` | Process names exempt from suspicious outbound port alerting |
| `monitors.network.data_volume_threshold_mb` | `100` | Unexplained traffic rate (MB/min) that counts as high for `data_volume_anomaly` |
| `monitors.network.data_volume_sustained_seconds` | `300` | How long unexplained traffic must stay over the threshold before alerting |
| `monitors.network.alert_on_inbound` | `false` | Also alert on unexplained inbound volume (`data_volume_anomaly_recv`) |
| `monitors.network.trusted_docker_containers` | `[]` | Containers whose traffic is subtracted before checking `data_volume_anomaly` (e.g. a media server, a torrent client). Read via `docker stats`; containers sharing a network namespace (`network_mode: service:X`) are counted once |
| `monitors.network.trusted_systemd_units` | `[]` | systemd units whose traffic is subtracted too (e.g. `dropboxd@dropboxsync.service`). Needs `IPAccounting=yes` on the unit: `sudo systemctl set-property <unit> IPAccounting=yes` |
| `monitors.resource.net_alerts_enabled` | `false` | Turn on the raw system-wide `high_network_send`/`_recv` rate alerts |
| `monitors.persistence.cron_paths` | (all standard cron dirs) | Directories to watch for new/modified cron files |
| `monitors.persistence.systemd_paths` | `/etc/systemd/system`, `system.control`, user unit dirs (globs ok) | Directories to watch for units and their `*.d/` drop-ins |
| `monitors.persistence.known_units` | `[]` | Unit filenames pre-approved and excluded from `new_systemd_unit` alerts |
| `monitors.package.log_path` | `/var/log/dpkg.log` | Path to dpkg log |
| `monitors.package.ignored_packages` | `[]` | Package names to leave out of summaries |
| `monitors.package.summary_quiet_seconds` | `60` | A run ends after this long with no dpkg activity |
| `monitors.package.apt_history_path` | `/var/log/apt/history.log` | Where "who ran it" comes from |
| `monitors.package.alert_on_install` / `alert_on_remove` | `true` | Whether an install / removal makes the summary WARN (else INFO) |
| `monitors.kernel.poll_interval_seconds` | `30` | How often `/proc/modules` is checked |
| `monitors.kernel.known_modules` | `[]` | Module names pre-approved beyond what `lsmod` seeds at startup |
| `monitors.tripwire.files` | (see below) | Honeypot files: a path, or `{path, owner, mode, content}` for bait with believable fake contents |
| `monitors.tripwire.create_missing` | `true` | Create decoy files that don't exist yet (empty unless `content`) |
| `monitors.tripwire.use_audit` | `true` | With ExecMonitor enabled, detect opens through auditd: exact process and user |
| `monitors.tripwire.allowed_readers` | `[]` | Audit mode: readers to ignore, `"comm"` or `"comm@user"` (prefix/glob), e.g. `"rsync@root"` |
| `monitors.docker.socket_path` | `/var/run/docker.sock` | Path to Docker socket |
| `monitors.docker.known_containers` | `[]` | Populate via `cop baseline show --table containers`; update when adding/removing containers |
| `monitors.auth.known_ssh_sources` | Tailscale CGNAT | Add your usual client IPs/CIDRs (e.g. the LAN) |
| `monitors.auth.restricted_login_users` | `[]` | SSH logins by these users are CRITICAL unless they match `login_windows` |
| `monitors.auth.login_windows` | `[]` | `{user, source, days: [sun], hours: [start, end)}` (UTC) when a restricted login is expected |
| `monitors.process.skip_known_container_processes` | `true` | New processes inside known containers don't alert (shell checks still apply) |
| `alerts.dedup_window_seconds` | `300` | Cooldown between alerts with the same rule and subject |
| `alerts.retention_days` | `90` | Alert history kept in the DB; `0` = forever |
| `monitors.exec.enabled` | `false` | ExecMonitor; needs the auditd rule below |
| `monitors.exec.public_containers` | `[]` | Internet-facing containers: app-started shells/downloaders are CRITICAL, and their processes are never exempt from new-process alerts |
| `monitors.exec.temp_exec_allow` | `[]` | Globs of programs allowed to run from `/tmp`, `/var/tmp`, `/dev/shm` |
| `ollama.enabled` | `false` | Enable local Ollama AI scoring |
| `ollama.url` | `http://localhost:11434/api/generate` | Ollama generate endpoint |
| `ollama.model` | `qwen3:1.7b` | Model to use (must be pulled in Ollama) |
| `ollama.timeout_seconds` | `60` | Per-request timeout; alerts fire even if Ollama is slow/down |
| `ollama.min_risk` | `0` | Suppress dispatch for alerts scored below this level; `0` disables the filter |
| `ollama.suppressed_comment_patterns` | `[]` | Suppress dispatch if Ollama comment matches any of these case-insensitive regex patterns |
| `telegram.enabled` | `false` | Enable Telegram bot sink |
| `telegram.bot_token` | `""` | From @BotFather |
| `telegram.chat_id` | `""` | Your personal or group chat ID (see below) |
| `telegram.allowed_user_ids` | `[]` | Telegram user IDs allowed to issue commands (empty = allow all) |
| `telegram.allowed_commands` | (see config) | Prefix whitelist for `/exec` |
| `telegram.confirm_destructive` | `true` | Require `YES` confirmation before `/exec` runs |

## CLI Reference

```
cop run                           Start daemon (foreground)
cop learn                         Add running processes to the baseline; re-snapshot ports and containers
cop baseline show [--table X]     Print baseline (processes/ports/containers/approvals/all)
cop baseline update               Re-snapshot baseline (alias for learn)
cop alerts [--limit N] [--severity CRITICAL|WARN|INFO]
cop status                        Baseline age, DB path, alert counts
```

Run `sudo cop learn && sudo systemctl restart cop` whenever you intentionally change the system (install new software, open a new port, add a container) to avoid false positives.

## Monitor Behaviour Notes

### ProcessMonitor
Kernel threads (ppid=2, `kthreadd` children such as `kworker/*`, `ksoftirqd/*`) are silently skipped — their names change dynamically and they cannot be meaningfully baselined. Everything else is compared against the baseline by `(name, exe, username)`, normalised so updates and per-client names don't look new: version numbers become `*` (`.../claude/versions/2.1.322` → `.../versions/*`) and a `[...]` suffix is dropped (`smbd[192.168.1.5]` → `smbd`).

- **Only new PIDs are inspected** each poll (exe, cmdline, user); processes already seen aren't re-read. Every new PID gets the reverse-shell check, even if its program is known (a reverse shell is almost always plain `bash`).
- **Seen once, known for good:** a new process alerts once and is then written to the baseline, so a weekly or daily job doesn't alert again after every cop restart. `cop learn` adds to the process baseline rather than replacing it, so "Mark Expected" approvals survive.
- **Container processes:** a process's container is read from `/proc/<pid>/cgroup`. Inside a known container (Docker baseline or `monitors.docker.known_containers`) that isn't in `monitors.exec.public_containers`, a new process is skipped, except that reverse-shell and suspicious-shell checks still apply; `docker exec` is covered by DockerMonitor. In an unknown container it alerts with `[container]` in the title.

### NetworkMonitor
Listening ports on any address are tracked except Tailscale (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) and link-local addresses, whose binds churn on their own. A port bound to a specific LAN address (e.g. `192.168.1.10:8090`) counts: it's as reachable as one on `0.0.0.0`. Loopback ports in the kernel's ephemeral range (`ip_local_port_range`) are ignored by default: those are short-lived callbacks (OAuth, IDE helpers). `baseline_ports_override` lists ports that always count as known.

Data volume tracking (`data_volume_anomaly`) and ResourceMonitor's bandwidth checks (`high_network_send`/`high_network_recv`) sum traffic across real external interfaces only — loopback (`lo`), Docker-internal interfaces (`docker*`, `br-*`, `veth*`), and tunnels and VM bridges (`tailscale*`, `wg*`, `virbr*`, `vnet*`) are excluded. Tunnel and VM traffic also crosses the physical interface (encrypted or NATed), so counting both doubles it; to subtract Tailscale's share (an exit node, backups pulled over Tailscale), add `tailscaled.service` to `trusted_systemd_units`. Without the Docker exclusion, a busy Docker host's container-to-container traffic (e.g. an app talking to its own database) gets counted the same as actual internet egress/ingress, producing false-positive spikes with no real bandwidth leaving the machine.

Legitimate heavy users (a media server, a torrent client, a file sync service) still put real traffic on the physical interface. So `data_volume_anomaly` alerts on **unexplained** outbound traffic: each 30 s poll, cop subtracts what the trusted sources moved in the same interval (`trusted_docker_containers` via `docker stats` NetIO, `trusted_systemd_units` via systemd's per-unit IP accounting) from the external-interface total. Only when what's left stays over `data_volume_threshold_mb` (MB/min) for `data_volume_sustained_seconds` does it alert, once per episode; it re-arms after the rate drops back under. The alert shows the total, the trusted share per source and the unexplained remainder. Per-connection detail (`ss -i -p`, sampled every 5 s to catch short-lived connections) is collected only once unexplained traffic has gone over the threshold, since the alert needs `data_volume_sustained_seconds` over it first; the rest of the time cop reads only interface and trusted-source counters (this cut cop's CPU use from ~3% to under 1%). Per-process lines show only measured bytes; what no open connection accounts for (closed sockets, UDP, forwarded traffic) is one separate "Not attributable" line, never guessed onto a process. Containers that share a network namespace (`network_mode: service:X`) report identical counters, so they're counted once.

Caveat: a container's `docker stats` NetIO includes its traffic to other containers, not just to the outside, so a trusted container that's chatty internally can hide some real external traffic while it's busy. Trust only containers whose traffic is mostly external, and don't trust an app's database-heavy container.

Inbound volume is off by default (`alert_on_inbound`): big downloads and streams to the box aren't a security signal on their own. The ResourceMonitor's raw rate alerts (`high_network_send`/`_recv`) are off by default too (`net_alerts_enabled`), since they can't subtract anything.

### FileMonitor
- **Directory paths** (`~/.ssh`, `/etc`, `/home`) are watched recursively.
- **Renames count at both ends.** `useradd`, `passwd`, `visudo`, `sed -i` and most editors write a temp file and rename it over the real one (`/etc/passwd+` → `/etc/passwd`), so a move is critical if either its source or destination is, and is only ignored if both are.
- Built-in `critical_paths`: `authorized_keys` (root, `~`, `/home/*`), `passwd`, `shadow`, `group`, `gshadow`, `sudoers`, `sudoers.d/*`, `sshd_config`, `sshd_config.d/*`, `ld.so.preload`, `pam.d/*`, `profile.d/*`, `bash.bashrc`, `environment`. Use `extra_critical_paths` to add to it.
- While apt/dpkg runs, non-critical events are skipped (`quiet_during_package_ops`); PackageMonitor reports the packages. Critical paths still alert.
- **File paths** (`/var/run/docker.sock`) are watched non-recursively on their parent directory, preventing Docker's containerd runtime files in `/var/run/containerd/` from generating noise.
- Docker containerd runtime files (names matching `{64-hex-id}-stdout` or `.{64-hex-id}.pid`) are suppressed regardless of where they appear.
- `ignore_patterns` filters by **filename only** (e.g. `*.tmp`). To silence an entire subdirectory inside a watched tree, use `ignore_paths` with the directory's full path — all events whose path starts with that prefix are dropped before alerting.
- File events are **attributed to containers**: on startup (and every 2 minutes) the monitor builds a map of all running container volume mounts. If a modified file's path falls under a container's mount, the container name is appended to the alert title — e.g. `File modified: settings.xml [mycontainer]`.

### DockerMonitor
Streams Docker events in a background thread. Detects: unknown containers starting, `docker exec` usage, privileged containers, image pulls, and restart loops. Reconnects automatically on Docker socket errors.

### AuthMonitor
Tails `/var/log/auth.log` from the end (does not replay history on startup). Handles log rotation by detecting inode changes. SSH brute-force detection uses a sliding window per source IP.

**Login windows:** for accounts that should only log in on a schedule (e.g. root, used only by a backup machine that pulls weekly), list them in `restricted_login_users` and describe when and from where they're expected in `login_windows`. Any other successful SSH login by them fires CRITICAL `ssh_login_outside_window`. Example: a stolen backup Pi pulling the whole disk midweek.
```yaml
auth:
  restricted_login_users: [root]
  login_windows:
    - {user: root, source: "100.64.0.10", days: [sun], hours: [9, 14]}   # UTC, [start, end)
```

### PersistenceMonitor
Polls cron directories and systemd unit directories every 30 seconds, comparing against an in-memory snapshot seeded at startup. Alerts on any new file appearing in a cron path; on any new `.service`, `.timer`, `.socket` or `.path` file in a systemd path (`new_systemd_unit`); on any new `*.conf` drop-in in a `<unit>.d/` directory (`new_systemd_dropin` — `systemctl edit`, `systemctl set-property` and overrides can change what a unit runs or as whom); and on edits to existing units and drop-ins (`systemd_unit_modified`). The default paths include `/etc/systemd/system.control` (where `set-property` writes) and user unit directories (`/root/.config/systemd/user`, `/home/*/.config/systemd/user`). `known_units` pre-approves a unit and its drop-ins.

### PackageMonitor
Sends **one alert per apt/dpkg run**, not one per package. It tails `/var/log/dpkg.log` from the end (so a plain `dpkg -i` counts too) and groups install/upgrade/remove lines until there's been no package activity for `summary_quiet_seconds` (60); unattended-upgrades' back-to-back apt sessions become one run. The summary (`package_activity`) gives the counts, the package names (up to 25 per kind) and who ran it, from the matching `/var/log/apt/history.log` entries (`Requested-By` and `Commandline`, or "unattended-upgrades"). A run that only upgrades is INFO, so it arrives silently; any install or removal makes it WARN.

### KernelMonitor
Polls `/proc/modules` every `poll_interval_seconds` (30). Modules loaded at startup, plus `known_modules`, are known; any other module that appears fires `kernel_module_loaded` once. (It used to tail `kern.log` for "module loaded", which only a few drivers print, so it missed nearly every load.)

### ExecMonitor
Polling `/proc` every 30 s can't see a command run through a hacked web app: `sh -c 'curl … | sh'` is over in milliseconds. ExecMonitor gets **every program start from the kernel**: an auditd rule logs `execve` under the key `cop_exec`, and cop tails `/var/log/audit/audit.log` (reading a rotated log from its start, so nothing is lost at rotation). Each event has the pid, parent pid, program, arguments and AppArmor label (`subj=docker-default` for container processes).

| Rule | Fires when |
|---|---|
| `container_suspicious_exec` (CRITICAL) | In a `public_containers` container, a shell, downloader (`curl`, `wget`, `nc`, `socat`, …) or inline interpreter (`python -c`, `perl -e`) is started **by the app**: walking up the parents, there's a process that isn't the container's init/supervisor (`tini`, `s6-*`, …), a shell, or `containerd-shim`/`runc`. Docker healthchecks and `docker exec` have `containerd-shim` as parent and don't count; DockerMonitor covers `docker exec`. |
| `exec_from_temp` (CRITICAL) | Any program run from `/tmp`, `/var/tmp` or `/dev/shm`, host or container: the usual place for a dropped payload. |
| `reverse_shell` (CRITICAL) | A shell whose stdin/stdout/stderr, or its parent's (Python's `pty.spawn` trick), are all one TCP/UDP socket. One alert per socket-holding process. A unix socketpair doesn't count. |
| `suspicious_shell_spawn` (CRITICAL) | On the host, a shell whose parent matches `monitors.process.suspicious_parent_names` (prefix: `python3` matches `python3.12`). |
| `audit_disabled` (CRITICAL) | Checked every 60 s: auditing is off, the `cop_exec` rule is gone, or the log is missing. |

**Limitation:** busybox shells (Alpine images) run their built-in commands without starting a new program, so after an app's first `sh -c` (which *is* caught), busybox `wget` etc. inside that shell aren't seen.

**Setup** (as root):
```bash
cat > /etc/audit/rules.d/cop.rules <<'RULES'
# runc starts for every container healthcheck; cop doesn't need them
-a never,exit -F arch=b64 -S execve -F exe=/usr/bin/runc
-a always,exit -F arch=b64 -S execve -k cop_exec
-a always,exit -F arch=b32 -S execve -k cop_exec
RULES
augenrules --load && auditctl -l
```
A busy Docker host starts a few programs a second (healthchecks), about 1 KB of log each, so raise auditd's rotation from the default 5×8 MB: `max_log_file = 50`, `num_logs = 8` in `/etc/audit/auditd.conf`, then `systemctl kill -s HUP auditd`. Then set `monitors.exec.enabled: true` and list your `public_containers`.

### TripwireMonitor

**Bait files work.** Automated and AI-driven attackers almost always open a file called `password.txt` (or `.env`, `.aws/credentials`) when they find one. A `files` entry can create such a file with believable, fake contents:
```yaml
tripwire:
  files:
    - "/root/.aws/credentials"
    - path: "/home/alice/password.txt"
      owner: alice
      mode: "600"
      content: |
        passwords - MOVE THESE INTO LASTPASS
        router admin   admin / (made-up password)
  allowed_readers: ["rsync@root", "smbd"]
```

**With auditd (ExecMonitor enabled, `use_audit: true`, the default)** each file gets an audit watch, `auditctl -w <file> -p rwa -k cop_tripwire`, added by cop at startup and re-added within a minute if a rule reload (`augenrules --load`) or anyone else removes it (WARN `tripwire_watches_restored`). Every open, write, rename or delete is logged by the kernel with the process, its user and login user, its command line and parent chain, so the alert says exactly who did it, e.g. *"opened by cat (pid 2580600, user andy) … Parents: bash < sshd"*. Reading extended attributes (what `ls -l`, Finder and Samba do when listing a folder) doesn't count. Before placing bait, check what legitimately reads files there (backups, search indexers, file shares, sync clients) and list those in `allowed_readers`; everything else alerts, including you opening it.

**Without auditd** it falls back to inotify:
Places watchdog watches on a list of honeypot files — files that no legitimate process should ever open. Any open fires an immediate CRITICAL alert. On startup, files that don't exist are created as empty decoys when `create_missing: true` (the default). The alert includes a best-effort process attribution by scanning `/proc/*/fd` for the accessing process at the moment the event fires — this frequently comes up empty for short-lived open/read/close patterns (e.g. a library auto-probing the file for credentials) since the accessor has often already closed the fd by the time the scan runs. Treat a hit with no attribution as inconclusive, not as evidence the check misfired: the alert itself is reliable even when the "by `<process>`" suffix is missing.

**Do not use `/root/.netrc` as a tripwire.** `wget` and some `apt`/HTTPS fetch paths consult `~/.netrc` by default on every request regardless of whether the target needs auth, so it fires from routine root-owned timers (`apt-daily.timer`, `apt-daily-upgrade.timer`, `motd-news.timer`) — confirmed in production on a live deployment: `tripwire_.netrc` fired ~35 times over four weeks with zero corroborating alerts (no new processes, no auth/network anomalies) and *never once* resolved a process via `/proc/*/fd` attribution, because these are quick open/read/close probes that finish before the scan runs. Since attribution never succeeds on this path, there's no process identity to allowlist either — the only fix is not watching that file. It was removed from the default `tripwire.files` list for this reason; `/root/.env` replaced it as the default third decoy. **The monitor now hard-refuses to arm any path whose basename is `.netrc`** regardless of what `tripwire.files` says — it logs a warning and skips the entry — so an older deployed `config.yaml` that still lists `/root/.netrc` will no longer produce these false positives (but you should still drop the stale entry from that config).

Good candidates are files that attackers commonly grep for but that don't exist on a typical server, and that no default-installed tool reads: `/root/.aws/credentials`, `/root/.gnupg/secring.gpg`, `/root/.env`. Only add real files (e.g. `/root/.ssh/id_rsa`) if you are certain no legitimate tool reads them — backup agents and ssh-agents do.

The `rule_id` is `tripwire_<filename>` (one per file), so dedup and cooldowns are tracked independently per tripwire.

## Alert Reference

| rule_id | Severity | Monitor | Trigger |
|---|---|---|---|
| `new_root_process` | CRITICAL | Process | Root process not in baseline |
| `suspicious_shell_spawn` | CRITICAL | Process | Shell spawned by web/MCP process |
| `reverse_shell` | CRITICAL | Exec, Process | Shell with stdio (or its parent's) on one network socket |
| `new_process` | INFO | Process | Any new non-kernel process not in baseline |
| `new_listen_port` | CRITICAL | Network | New port on any address except Tailscale/link-local (loopback ephemeral ports skipped) |
| `data_volume_anomaly` | WARN | Network | Unexplained outbound traffic (minus trusted containers/units) over threshold for the sustained period |
| `data_volume_anomaly_recv` | WARN | Network | Same for inbound; only with `alert_on_inbound: true` |
| `suspicious_outbound_port` | CRITICAL | Network | Established connection to a known C2/backdoor/mining port |
| `file_critical_modified` | CRITICAL | File | Write to authorized_keys, sudoers, sshd_config, ld.so.preload, pam.d, etc. |
| `file_created/modified/deleted/moved` | WARN | File | Change in watched path (title includes `[container]` if attributable) |
| `docker_unknown_container` | WARN | Docker | Container not in known_containers list |
| `docker_exec_into_container` | WARN | Docker | `docker exec` used |
| `docker_privileged_container` | CRITICAL | Docker | Container started with `--privileged` |
| `docker_image_pull` | INFO | Docker | Image pulled |
| `docker_restart_loop` | WARN | Docker | Container restarts > threshold in window |
| `ssh_brute_force` | CRITICAL | Auth | ≥5 SSH failures from same IP in 60s |
| `ssh_unknown_source` | WARN | Auth | SSH login from previously unseen IP |
| `ssh_login_outside_window` | CRITICAL | Auth | SSH login by a `restricted_login_users` account outside its `login_windows` |
| `unexpected_sudo` | WARN | Auth | sudo by user not in known_sudo_users |
| `sudo_usage` | INFO | Auth | Any sudo usage (audit trail) |
| `new_system_user` | CRITICAL | Auth | New user account created |
| `high_cpu_sustained` | WARN | Resource | Process >90% CPU for 120s |
| `high_memory` | WARN | Resource | System memory >85% |
| `high_network_send` | WARN | Resource | System send >50 Mbps; only with `net_alerts_enabled: true` |
| `high_network_recv` | WARN | Resource | System recv >100 Mbps; only with `net_alerts_enabled: true` |
| `new_cron_job` | CRITICAL | Persistence | New file appeared in a cron directory |
| `cron_job_modified` | WARN | Persistence | Existing cron file was modified |
| `new_systemd_unit` | CRITICAL | Persistence | New `.service`, `.timer`, `.socket` or `.path` file in a systemd directory |
| `new_systemd_dropin` | CRITICAL | Persistence | New `*.conf` drop-in in a `<unit>.d/` directory |
| `systemd_unit_modified` | WARN | Persistence | Existing unit or drop-in changed |
| `package_activity` | WARN / INFO | Package | One apt/dpkg run: WARN if anything was installed or removed, INFO if only upgrades |
| `kernel_module_loaded` | CRITICAL | Kernel | Module in `/proc/modules` that was not loaded at startup |
| `container_suspicious_exec` | CRITICAL | Exec | App in a public container started a shell/downloader/inline interpreter |
| `exec_from_temp` | CRITICAL | Exec | Program run from `/tmp`, `/var/tmp` or `/dev/shm` |
| `audit_disabled` | CRITICAL | Exec | Exec auditing off or its rule removed |
| `tripwire_<filename>` | CRITICAL | Tripwire | Honeypot file was read (one rule_id per file) |

## Secret Redaction

Before any alert is dispatched to ntfy or written to `alerts.jsonl`, cop scrubs `Bearer <token>` patterns from the alert message, title, and all string fields in the context (including `cmdline`). The token value is replaced with `[REDACTED]`; the `Bearer` keyword is kept so you can still see that a token was present.

This prevents API keys and auth tokens from appearing in push notifications or the on-disk log when tools like `curl` or `wget` run with Authorization headers.

## Ollama AI Scoring

When `ollama.enabled: true`, every non-deduplicated alert is scored by a local Ollama model before being dispatched to sinks. The model receives the alert severity, rule ID, title, and message, and returns:

| Field | Type | Description |
|---|---|---|
| `ollama_risk` | int 0–10 | 0 = benign, 10 = critical |
| `ollama_comment` | string | ≤15-word summary of why |

These fields are stamped into `alert.context` and appear in `alerts.jsonl`. If Ollama is unreachable or times out, no `ollama_risk` is set — the alert dispatches normally (fails open) with `ollama_comment: "Ollama Down"` in its context, and an error is logged. A scoring failure is never treated as a risk score of `0`, so a `min_risk` filter can't silently swallow an alert just because Ollama was slow or down.

The scoring prompt includes two context blocks prepended before the alert:

1. **Operator notes** — contents of `context.md` (notes you've appended via Telegram), prepended as background context.
2. **Recent event history** — the last `history_count` scored events (default: 10), oldest first. This lets the model recognise patterns such as a burst of anomalies preceding the current alert.

Requires Ollama running locally with the configured model pulled:
```bash
ollama pull qwen3:1.7b
```

### Suppression filters

Two optional filters can prevent low-signal alerts from reaching your sinks. Suppressed alerts are still recorded to the SQLite DB and `alerts.jsonl` for audit purposes — only the dispatch to ntfy, Telegram, and the log sink is skipped.

**Risk threshold** — set `min_risk` to drop any alert scored below that level:
```yaml
ollama:
  min_risk: 5   # discard risk 0–4; dispatch risk 5–10
```

**Comment patterns** — set `suppressed_comment_patterns` to a list of case-insensitive regex patterns; if the model's comment matches any of them the alert is suppressed:
```yaml
ollama:
  suppressed_comment_patterns:
    - "routine"
    - "legitimate"
    - "no malicious indicators"
```

Both filters are independent and either one alone can suppress an alert. Suppression only applies to alerts that were actually scored — if Ollama is unreachable or times out (`ollama_comment: "Ollama Down"`), the alert has no `ollama_risk` and is dispatched unfiltered rather than being suppressed.

### ntfy priority mapping

| Severity | ntfy Priority | Behavior |
|---|---|---|
| CRITICAL | 5 (max) | Vibration + pop-over notification |
| WARN | 4 (high) | Long vibration burst |
| INFO | 2 (low) | Silent, drawer only |

Startup (`✅ cop started`) and shutdown (`💤 cop stopped`) use priority 3 (default).

## Telegram Two-Way Alerting

Telegram replaces the one-way ntfy push with a full reply loop. Every alert arrives as a Telegram message with three inline buttons. INFO alerts (`new_process`, `sudo_usage`, upgrade-only `package_activity`, ...) are delivered silently, with no sound or vibration. The buttons keep working after a cop restart: each alert is stored with its button key, and cop looks it up in the alert history (kept `alerts.retention_days`) when it's no longer in memory.

```
🚨 New Listen Port Detected

Port 8888 (TCP) — python3 (PID 12345)
🤖😨😨😨 Risk: 7/10 — unexpected dev server, verify intent

[✅ Mark Expected]  [📝 Keep Watching]  [🔍 Details]
```

| Button / Command | What it does |
|---|---|
| `✅ Mark Expected` | Remembers the alert's subject so it won't fire again, where that's safe (table below); otherwise acknowledges it |
| `📝 Keep Watching` | Prompts for a free-text note, appends it to `context.md`, injected into future Ollama scoring prompts |
| `🔍 Details` | Sends the full `alert.context` dict as a code block |
| `/exec <command>` | Runs a whitelisted shell command and replies with stdout/stderr |
| `/health` | Returns a live snapshot: logged-in users, recent logins, sudo activity (24 h), top CPU/memory processes, Docker container stats (CPU, memory, net I/O — sorted by CPU), and active network traffic per process with send/receive rates and resolved remote hostnames |
| `/assessment` | Runs a full health gather, reads `context.md`, fetches the last `ollama.history_count` alert events, and asks Ollama for a free-text situational assessment: active threats, resource/container anomalies, and an overall risk verdict (Low / Medium / High / Critical). Requires `ollama.enabled: true`. |

### What "Mark Expected" does

| Alert | Mark Expected |
|---|---|
| `new_process`, `new_root_process` | Process added to the baseline (new processes are also remembered automatically after alerting once) |
| `new_listen_port` | Port added to the baseline |
| `suspicious_outbound_port` | That process may connect to that port |
| `docker_unknown_container` | Container added to the baseline |
| `docker_privileged_container`, `docker_exec_into_container` | That container may run privileged / be exec'd into |
| `ssh_unknown_source` | IP becomes a known SSH source |
| `file_created/modified/deleted/moved` | That exact path won't alert again (use `ignore_paths` for a folder) |
| `kernel_module_loaded` | Module approved, also after a reboot |
| `high_cpu_sustained` | That process name may use sustained high CPU |
| `container_suspicious_exec` | That command in that container won't alert again |
| `exec_from_temp` | That program path may run from a temp dir |
| `suspicious_shell_spawn` | That parent may start that shell |
| `file_critical_modified`, `tripwire_*`, `reverse_shell`, `audit_disabled` | **Acknowledged only**: these always alert |
| `new_systemd_unit/dropin`, `systemd_unit_modified`, cron | Acknowledged: the change is now in cop's snapshot (re-read from disk at start), so it alerts again only if the file changes again. `known_units` silences a unit for good |
| `ssh_login_outside_window`, `data_volume_anomaly`, `package_activity`, others | Acknowledged, with a pointer to the config setting that controls it |

Approvals that aren't baseline rows live in the `approvals` table: `sudo cop baseline show --table approvals`.

### Setup

**1. Create a bot via @BotFather**

Open Telegram, message `@BotFather`, send `/newbot`, follow the prompts. Copy the `bot_token` it gives you.

**2. Get your chat ID**

Message your new bot anything, then run:

```bash
curl -s "https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates" | python3 -m json.tool | grep '"id"'
```

Your chat ID is the `"id"` value nested under `"chat"` in the result.

**3. Add to config**

```yaml
telegram:
  enabled: true
  bot_token: "1234567890:ABCdef..."
  chat_id: "123456789"
  allowed_user_ids: [123456789]   # your Telegram user ID (from the same getUpdates output, under "from")
  allowed_commands:
    - "docker stop"
    - "docker restart"
    - "systemctl stop"
    - "kill"
  confirm_destructive: true
```

**4. Restart cop** — you should receive `✅ cop started` in the chat.

### `/exec` command

Run whitelisted shell commands directly from the chat:

```
/exec docker stop mycontainer
```

With `confirm_destructive: true` (default), cop replies with a confirmation prompt and waits for you to send `YES` before running. Any other reply cancels.

The `allowed_commands` list is **prefix-matched** — `"docker stop"` whitelists `docker stop mycontainer` but not `docker rm`.

### Operator notes and Ollama context

When you press `📝 Keep Watching` and send a note, it is appended to `~/.local/share/cop/context.md`:

```markdown
## 2026-05-03 14:32 — new_listen_port
Port 8888: normal python3 dev server. Keep watching for unusual traffic.
```

When `ollama.enabled: true`, this file is prepended to every scoring prompt as operator background context.

## Data Storage

When run as root, data lives under `/root/.local/share/cop/`:

```
/root/.local/share/cop/
├── baseline.db       SQLite: process/port/container baselines + alert history
├── alerts.jsonl      Rotating JSON-lines alert log (one record per line)
└── context.md        Operator notes appended via Telegram "Keep Watching" replies
```

SQLite tables: `process_baseline`, `port_baseline`, `container_baseline`, `resource_baseline`, `approvals`, `alert_history`, `ssh_sources`. `alert_history` holds alerts that were dispatched or filtered (not held-back repeats) and is pruned to `alerts.retention_days`.

## Troubleshooting

**Check recent alerts:**
```bash
sudo cop alerts --severity CRITICAL
journalctl -u cop -f
```

**False positives after system change:**
```bash
sudo cop learn
sudo systemctl restart cop
```

**FileMonitor not watching a path:**
```bash
# Check inotify limit (large watched trees can exhaust this)
cat /proc/sys/fs/inotify/max_user_watches
echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

**Docker monitor not connecting:**
```bash
ls -la /var/run/docker.sock   # must be accessible to root
```

**AuthMonitor permission denied:**
```bash
# cop must run as root, or add your user to the adm group
sudo usermod -aG adm $USER
```

## Manual Alert Triggers

Use these to verify cop is running and alerting correctly. Check `sudo cop alerts` or watch ntfy after each one.

### NetworkMonitor

**`new_listen_port` (CRITICAL)** — detected within 30 s:
```bash
nc -l 19999 &
# cleanup
kill %1
```

**`data_volume_anomaly` (WARN)** — unexplained outbound >100 MB/min, held for 5 min (`data_volume_sustained_seconds`); measured on real external interfaces only, minus trusted containers/units. For a quick test, set the sustained period to 0 and restart cop:
```bash
# needs a real remote endpoint, e.g. a second host on your LAN running: nc -l 9999 > /dev/null
dd if=/dev/zero bs=1M count=200 | nc <remote-host> 9999
```

### ResourceMonitor

**`high_cpu_sustained` (WARN)** — one process >90% CPU for 120 s; detected within ~15 s after the window fills:
```bash
timeout 130 python3 -c "while True: pass" &
```

**`high_network_send` (WARN)** / **`high_network_recv` (WARN)** — only with `net_alerts_enabled: true`. >50 Mbps send or >100 Mbps recv; measured on real external interfaces only — loopback and Docker interfaces (`docker*`, `br-*`, `veth*`) are excluded, so `localhost` no longer triggers it; detected within 15 s:
```bash
# with iperf3, against a second host on your LAN
iperf3 -s -D                       # on the remote host
iperf3 -c <remote-host> -t 30 -b 200M
pkill iperf3

# with nc (no iperf3 needed) — remote host runs: nc -l 9999 > /dev/null
dd if=/dev/zero bs=64k | nc <remote-host> 9999
```

### FileMonitor

**`file_critical_modified` (CRITICAL)** — write to any critical path; detected immediately:
```bash
touch ~/.ssh/authorized_keys
```

**`file_created` / `file_modified` / `file_deleted` (WARN)** — any change under a watched directory:
```bash
touch /etc/cop_test_trigger       # file_created
echo "# test" >> /etc/cop_test_trigger  # file_modified
rm /etc/cop_test_trigger          # file_deleted
```

### AuthMonitor

**`ssh_brute_force` (CRITICAL)** — 5+ SSH failures from the same IP within 60 s:
```bash
for i in {1..6}; do
  ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no fakeuser@localhost
done
```

**`sudo_usage` (INFO)** — any sudo invocation by a known user:
```bash
sudo id
```

**`unexpected_sudo` (WARN)** — sudo by a user not in `known_sudo_users`; requires a second user account on the machine:
```bash
sudo -u otheruser sudo id
```

### ProcessMonitor

**`new_root_process` (CRITICAL)** — a root process not in baseline; detected within 30 s:
```bash
sudo /usr/bin/sleep 300 &
sudo kill $!
```

**`suspicious_shell_spawn` (CRITICAL)** — shell spawned by python3/caddy/node (suspicious parent list):
```bash
python3 -c "import subprocess; subprocess.run(['bash', '-c', 'sleep 30'])"
```

**`reverse_shell` (CRITICAL)** — process with all stdio connected to the same network socket; detected within 30 s:
```bash
# Simulate a reverse shell — connect bash's stdio to a local socket
bash -c 'bash -i >& /dev/tcp/127.0.0.1/9001 0>&1' &
# cleanup
kill %1
```

**`new_process` (INFO)** — any non-root process not in baseline:
```bash
/usr/bin/sleep 300 &
kill %1
```

### PersistenceMonitor

**`new_cron_job` (CRITICAL)** — create a file in any cron directory; detected within 30 s:
```bash
echo "* * * * * root echo test" | sudo tee /etc/cron.d/cop_test
# cleanup
sudo rm /etc/cron.d/cop_test
```

**`cron_job_modified` (WARN)** — modify an existing cron file:
```bash
echo "# test" | sudo tee -a /etc/crontab
```

**`new_systemd_unit` (CRITICAL)** — drop a new unit file; detected within 30 s:
```bash
sudo cp /lib/systemd/system/ssh.service /etc/systemd/system/cop_test.service
# cleanup
sudo rm /etc/systemd/system/cop_test.service
```

**`suspicious_outbound_port` (CRITICAL)** — open a connection to a port on the suspicious list (e.g. 4444); detected within 30 s:
```bash
# In one terminal, listen on the suspicious port
nc -l 4444 &
# In another, connect to it
nc localhost 4444
```

### PackageMonitor

**`package_activity` (WARN)** — install any package; one summary about a minute after apt finishes:
```bash
sudo apt-get install -y sl
# cleanup (a second WARN summary, "1 removed")
sudo apt-get remove -y sl
```

### KernelMonitor

**`kernel_module_loaded` (CRITICAL)** — load any module not present at cop startup; detected within 30 s:
```bash
# Find a safe module that is not currently loaded
lsmod | grep dummy  # if not listed, it's unloaded
sudo modprobe dummy
# cleanup
sudo modprobe -r dummy
```

### ExecMonitor

**`exec_from_temp` (CRITICAL)**:
```bash
cp /bin/true /dev/shm/cop-test && /dev/shm/cop-test; rm /dev/shm/cop-test
```

**`container_suspicious_exec` (CRITICAL)** — add `cop-exec-test` to `public_containers` and restart cop first; use an image whose shell isn't busybox:
```bash
docker run --rm --name cop-exec-test --entrypoint python3 python:3-slim -c \
  "import subprocess,time; time.sleep(4); subprocess.run(['sh','-c','id']); time.sleep(4)"
```

### TripwireMonitor

**`tripwire_<filename>` (CRITICAL)** — read any honeypot file; detected immediately:
```bash
cat /root/.aws/credentials
```

### DockerMonitor

**`docker_exec_into_container` (WARN)**:
```bash
docker exec -it <any_running_container> id
```

**`docker_unknown_container` (WARN)**:
```bash
docker run --name cop_test_unknown alpine sleep 60
docker rm -f cop_test_unknown
```

**`docker_privileged_container` (CRITICAL)**:
```bash
docker run --rm --privileged --name cop_test_priv alpine sleep 10
```

**`docker_image_pull` (INFO)**:
```bash
docker pull alpine:latest
```

## TODO

- **Docker image digest tracking** — add `image_digest_baseline` table to SQLite. In `DockerMonitor.learn()`, record the RepoDigest of each running container's image. In `_handle_image_pull()`, compare new digest against baseline and alert `docker_image_digest_changed` WARN on mismatch. Guards against supply-chain compromise via updated images.
- **Auto Shutdown on Critical** — add an option to automatically shutdown either most processes, disconnect network, or shutdown the PC on Critical alerts.




## Extending

**Adding a new monitor:** subclass `BaseMonitor` (`cop/monitors/base.py`), implement `run()` and `learn()`, register in `cop/main.py:build_monitors()`.

**Adding a new alert sink:** subclass `AlertSink` (`cop/sinks/base.py`), implement `send()` and `close()`, add to the sinks list in `cop/main.py:run_daemon()`.

## License

MIT — see [LICENSE](LICENSE).
