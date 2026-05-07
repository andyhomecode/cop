# cop — Security Monitoring Daemon

A Python daemon that actively monitors a Linux machine for signs of compromise: unexpected processes, new listening ports, sensitive file changes, Docker anomalies, SSH brute-force, and resource abuse. Alerts are delivered via [ntfy.sh](https://ntfy.sh) and/or Telegram (with two-way reply support).

## Architecture

```
cop daemon (asyncio)
├── ProcessMonitor      — new/unexpected processes, root shells, suspicious spawns, reverse shells
├── NetworkMonitor      — new listening ports, outbound data volume, suspicious outbound ports
├── FileMonitor         — inotify on ~/.ssh, /etc, /home, docker.sock
├── DockerMonitor       — container events stream (start, exec, pull, restart loops)
├── AuthMonitor         — tail /var/log/auth.log (SSH brute force, unknown IPs, sudo)
├── ResourceMonitor     — sustained CPU spikes, memory, network bandwidth
├── PersistenceMonitor  — new cron jobs and systemd units (common persistence vectors)
├── PackageMonitor      — tail /var/log/dpkg.log for installs/removals
└── KernelMonitor       — tail /var/log/kern.log for unexpected module loads

Alert flow: monitor → AlertEngine (redact secrets → dedup + cooldown) → [Ollama scorer] → ntfy.sh + Telegram + alerts.jsonl
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

Copy `config.example.yaml` to `/root/.config/cop/config.yaml` and edit as needed. All fields are optional — defaults are conservative and suitable for most Linux hosts.

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
| `monitors.file.watch_paths` | `~/.ssh, /etc, /home, /var/run/docker.sock` | Add paths as needed |
| `monitors.file.ignore_paths` | `[]` | Path prefixes to silence entirely (e.g. cache directories inside a watched tree) |
| `monitors.network.baseline_ports_override` | `[]` | Ports that always count as known (never fire `new_listen_port`) |
| `monitors.network.data_volume_window_seconds` | `60` | Window over which outbound bytes are summed for anomaly detection |
| `monitors.network.suspicious_outbound_ports` | `[1080, 3333, 4444, ...]` | Ports that fire `suspicious_outbound_port` CRITICAL when any process connects to them |
| `monitors.network.trusted_outbound_process_names` | `[]` | Process names exempt from suspicious outbound port alerting |
| `monitors.persistence.cron_paths` | (all standard cron dirs) | Directories to watch for new/modified cron files |
| `monitors.persistence.systemd_paths` | `/etc/systemd/system, ...` | Directories to watch for new `.service`/`.timer` units |
| `monitors.persistence.known_units` | `[]` | Unit filenames pre-approved and excluded from `new_systemd_unit` alerts |
| `monitors.package.log_path` | `/var/log/dpkg.log` | Path to dpkg log |
| `monitors.package.ignored_packages` | `[]` | Package names to suppress entirely |
| `monitors.kernel.log_path` | `/var/log/kern.log` | Path to kernel log |
| `monitors.kernel.known_modules` | `[]` | Module names pre-approved beyond what `lsmod` seeds at startup |
| `monitors.docker.socket_path` | `/var/run/docker.sock` | Path to Docker socket |
| `monitors.docker.known_containers` | `[]` | Populate via `cop baseline show --table containers`; update when adding/removing containers |
| `monitors.auth.known_ssh_sources` | Tailscale CGNAT | Add your usual client IPs |
| `alerts.dedup_window_seconds` | `300` | Global cooldown between identical alerts |
| `ollama.enabled` | `false` | Enable local Ollama AI scoring |
| `ollama.url` | `http://localhost:11434/api/generate` | Ollama generate endpoint |
| `ollama.model` | `qwen3:1.7b` | Model to use (must be pulled in Ollama) |
| `ollama.timeout_seconds` | `60` | Per-request timeout; alerts fire even if Ollama is slow/down |
| `telegram.enabled` | `false` | Enable Telegram bot sink |
| `telegram.bot_token` | `""` | From @BotFather |
| `telegram.chat_id` | `""` | Your personal or group chat ID (see below) |
| `telegram.allowed_user_ids` | `[]` | Telegram user IDs allowed to issue commands (empty = allow all) |
| `telegram.allowed_commands` | (see config) | Prefix whitelist for `/exec` |
| `telegram.confirm_destructive` | `true` | Require `YES` confirmation before `/exec` runs |

## CLI Reference

```
cop run                           Start daemon (foreground)
cop learn                         Snapshot current state as baseline
cop baseline show [--table X]     Print baseline (processes/ports/containers/all)
cop baseline update               Re-snapshot baseline (alias for learn)
cop alerts [--limit N] [--severity CRITICAL|WARN|INFO]
cop status                        Baseline age, DB path, alert counts
```

Run `sudo cop learn && sudo systemctl restart cop` whenever you intentionally change the system (install new software, open a new port, add a container) to avoid false positives.

## Monitor Behaviour Notes

### ProcessMonitor
Kernel threads (ppid=2, `kthreadd` children such as `kworker/*`, `ksoftirqd/*`) are silently skipped — their names change dynamically and they cannot be meaningfully baselined. Everything else is compared against the baseline snapshot by `(name, exe, username)` tuple.

### NetworkMonitor
Only alertable addresses are tracked: `0.0.0.0`, `::`, and the entire `127.0.0.0/8` loopback range. Ports bound to Tailscale IPs, LAN-specific IPs, or other non-canonical addresses are silently ignored in both baseline and runtime — this prevents ephemeral Tailscale port churn from generating noise.

### FileMonitor
- **Directory paths** (`~/.ssh`, `/etc`, `/home`) are watched recursively.
- **File paths** (`/var/run/docker.sock`) are watched non-recursively on their parent directory, preventing Docker's containerd runtime files in `/var/run/containerd/` from generating noise.
- Docker containerd runtime files (names matching `{64-hex-id}-stdout` or `.{64-hex-id}.pid`) are suppressed regardless of where they appear.
- `ignore_patterns` filters by **filename only** (e.g. `*.tmp`). To silence an entire subdirectory inside a watched tree, use `ignore_paths` with the directory's full path — all events whose path starts with that prefix are dropped before alerting.
- File events are **attributed to containers**: on startup (and every 2 minutes) the monitor builds a map of all running container volume mounts. If a modified file's path falls under a container's mount, the container name is appended to the alert title — e.g. `File modified: settings.xml [mycontainer]`.

### DockerMonitor
Streams Docker events in a background thread. Detects: unknown containers starting, `docker exec` usage, privileged containers, image pulls, and restart loops. Reconnects automatically on Docker socket errors.

### AuthMonitor
Tails `/var/log/auth.log` from the end (does not replay history on startup). Handles log rotation by detecting inode changes. SSH brute-force detection uses a sliding window per source IP.

### PersistenceMonitor
Polls cron directories and systemd unit directories every 30 seconds, comparing against an in-memory snapshot seeded at startup. Alerts on any new file appearing in a cron path, and on any new `.service`, `.timer`, or `.socket` file in a systemd path. The `known_units` config list lets you pre-approve units installed by system packages (e.g. after a bulk `apt upgrade`) to avoid noise.

### PackageMonitor
Tails `/var/log/dpkg.log` from the end (does not replay history on startup). On startup, reads the existing log to build a set of known packages — so only packages installed *after* cop starts will fire `package_installed`. Handles log rotation via inode detection, same as AuthMonitor.

### KernelMonitor
Tails `/var/log/kern.log` and matches `module loaded` log lines. On startup, runs `lsmod` and seeds all currently-loaded modules as known — so only modules loaded *after* cop starts will fire `kernel_module_loaded`. Add frequently-loaded modules (e.g. from a kernel update) to `monitors.kernel.known_modules` to suppress expected loads.

## Alert Reference

| rule_id | Severity | Monitor | Trigger |
|---|---|---|---|
| `new_root_process` | CRITICAL | Process | Root process not in baseline |
| `suspicious_shell_spawn` | CRITICAL | Process | Shell spawned by web/MCP process |
| `reverse_shell` | CRITICAL | Process | Process with all stdio connected to same socket |
| `new_process` | INFO | Process | Any new non-kernel process not in baseline |
| `new_listen_port` | CRITICAL | Network | New port on alertable address |
| `data_volume_anomaly` | WARN | Network | Outbound data rate exceeds threshold |
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
| `unexpected_sudo` | WARN | Auth | sudo by user not in known_sudo_users |
| `sudo_usage` | INFO | Auth | Any sudo usage (audit trail) |
| `new_system_user` | CRITICAL | Auth | New user account created |
| `high_cpu_sustained` | WARN | Resource | Process >90% CPU for 120s |
| `high_memory` | WARN | Resource | System memory >85% |
| `high_network_send` | WARN | Resource | System send >50 Mbps |
| `high_network_recv` | WARN | Resource | System recv >100 Mbps |
| `new_cron_job` | CRITICAL | Persistence | New file appeared in a cron directory |
| `cron_job_modified` | WARN | Persistence | Existing cron file was modified |
| `new_systemd_unit` | CRITICAL | Persistence | New `.service`, `.timer`, or `.socket` file in a systemd directory |
| `package_installed` | WARN | Package | `apt`/`dpkg` installed a package |
| `package_removed` | WARN | Package | Package was removed |
| `package_upgraded` | INFO | Package | Package was upgraded |
| `kernel_module_loaded` | CRITICAL | Kernel | Kernel module loaded that was not present at startup |

## Secret Redaction

Before any alert is dispatched to ntfy or written to `alerts.jsonl`, cop scrubs `Bearer <token>` patterns from the alert message, title, and all string fields in the context (including `cmdline`). The token value is replaced with `[REDACTED]`; the `Bearer` keyword is kept so you can still see that a token was present.

This prevents API keys and auth tokens from appearing in push notifications or the on-disk log when tools like `curl` or `wget` run with Authorization headers.

## Ollama AI Scoring

When `ollama.enabled: true`, every non-deduplicated alert is scored by a local Ollama model before being dispatched to sinks. The model receives the alert severity, rule ID, title, and message, and returns:

| Field | Type | Description |
|---|---|---|
| `ollama_risk` | int 0–10 | 0 = benign, 10 = critical |
| `ollama_comment` | string | ≤15-word summary of why |

These fields are stamped into `alert.context` and appear in `alerts.jsonl`. If Ollama is unreachable or times out, the alert still fires with `ollama_risk: 0` and `ollama_comment: "Ollama Down"`, and an error is logged.

The scoring prompt includes two context blocks prepended before the alert:

1. **Operator notes** — contents of `context.md` (notes you've appended via Telegram), prepended as background context.
2. **Recent event history** — the last `history_count` scored events (default: 10), oldest first. This lets the model recognise patterns such as a burst of anomalies preceding the current alert.

Requires Ollama running locally with the configured model pulled:
```bash
ollama pull qwen3:1.7b
```

### ntfy priority mapping

| Severity | ntfy Priority | Behavior |
|---|---|---|
| CRITICAL | 5 (max) | Vibration + pop-over notification |
| WARN | 4 (high) | Long vibration burst |
| INFO | 2 (low) | Silent, drawer only |

Startup (`✅ cop started`) and shutdown (`💤 cop stopped`) use priority 3 (default).

## Telegram Two-Way Alerting

Telegram replaces the one-way ntfy push with a full reply loop. Every alert arrives as a Telegram message with three inline buttons:

```
🚨 New Listen Port Detected

Port 8888 (TCP) — python3 (PID 12345)
🤖😨😨😨 Risk: 7/10 — unexpected dev server, verify intent

[✅ Mark Expected]  [📝 Keep Watching]  [🔍 Details]
```

| Button / Command | What it does |
|---|---|
| `✅ Mark Expected` | Adds the alert's data to the baseline DB — alert won't fire again |
| `📝 Keep Watching` | Prompts for a free-text note, appends it to `context.md`, injected into future Ollama scoring prompts |
| `🔍 Details` | Sends the full `alert.context` dict as a code block |
| `/exec <command>` | Runs a whitelisted shell command and replies with stdout/stderr |
| `/health` | Returns a live snapshot: logged-in users, recent logins, sudo activity (24 h), top CPU/memory processes, Docker container stats (CPU, memory, net I/O — sorted by CPU), and active network traffic per process with send/receive rates and resolved remote hostnames |
| `/assessment` | Runs a full health gather, reads `context.md`, fetches the last `ollama.history_count` alert events, and asks Ollama for a free-text situational assessment: active threats, resource/container anomalies, and an overall risk verdict (Low / Medium / High / Critical). Requires `ollama.enabled: true`. |

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

SQLite tables: `process_baseline`, `port_baseline`, `container_baseline`, `resource_baseline`, `alert_history`, `ssh_sources`

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

**`data_volume_anomaly` (WARN)** — send >100 MB/min outbound; detected on next 30 s cycle:
```bash
nc -l 9999 > /dev/null &
dd if=/dev/zero bs=1M count=200 | nc localhost 9999
kill %1
```

### ResourceMonitor

**`high_cpu_sustained` (WARN)** — one process >90% CPU for 120 s; detected within ~15 s after the window fills:
```bash
timeout 130 python3 -c "while True: pass" &
```

**`high_network_send` (WARN)** / **`high_network_recv` (WARN)** — >50 Mbps send or >100 Mbps recv; loopback counts for both; detected within 15 s:
```bash
# with iperf3
iperf3 -s -D
iperf3 -c localhost -t 30 -b 200M
pkill iperf3

# with nc (no iperf3 needed)
nc -l 9999 > /dev/null &
dd if=/dev/zero bs=64k | nc localhost 9999
kill %1
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

**`package_installed` (WARN)** — install any package; detected immediately on the dpkg.log write:
```bash
sudo apt-get install -y sl
# cleanup
sudo apt-get remove -y sl
```

**`package_removed` (WARN)** — remove a package (same mechanism as install).

### KernelMonitor

**`kernel_module_loaded` (CRITICAL)** — load any module not present at cop startup; detected immediately on the kern.log write:
```bash
# Find a safe module that is not currently loaded
lsmod | grep dummy  # if not listed, it's unloaded
sudo modprobe dummy
# cleanup
sudo modprobe -r dummy
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

- **Credential file read detection** — add inotify `IN_ACCESS` watching on SSH private keys (`~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, etc.) using raw inotify via ctypes in `FileMonitor`. Alert `credential_file_read` CRITICAL when any process reads them. Currently cop is blind to file reads entirely.
- **Docker image digest tracking** — add `image_digest_baseline` table to SQLite. In `DockerMonitor.learn()`, record the RepoDigest of each running container's image. In `_handle_image_pull()`, compare new digest against baseline and alert `docker_image_digest_changed` WARN on mismatch. Guards against supply-chain compromise via updated images.
- **Auto Shutdown on Critical** -- add an option to automatically shutdown either most processes, disconnect network, or shutdown the PC on Critical alerts
- **AI Analysis** ✅ — Ollama scoring implemented; auto-remediation (shutdown, network isolation) not yet wired up.
- **Docker stats in /health** ✅ — `/health` now includes a 🐳 Containers section showing all running containers sorted by CPU%, with CPU%, memory usage, memory %, and cumulative net I/O.
- **`/assessment` command** ✅ — Telegram command that synthesizes health snapshot + `context.md` + last N alert events into a free-text Ollama situational assessment with an overall risk verdict.




## Extending

**Adding a new monitor:** subclass `BaseMonitor` (`cop/monitors/base.py`), implement `run()` and `learn()`, register in `cop/main.py:build_monitors()`.

**Adding a new alert sink:** subclass `AlertSink` (`cop/sinks/base.py`), implement `send()` and `close()`, add to the sinks list in `cop/main.py:run_daemon()`.
