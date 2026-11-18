from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class NtfyConfig:
    enabled: bool = True
    url: str = "https://ntfy.sh/your-cop-topic"
    token: str = ""
    timeout_seconds: int = 10


@dataclass
class LogSinkConfig:
    enabled: bool = True
    path: str = "~/.local/share/cop/alerts.jsonl"
    max_bytes: int = 10_485_760
    backup_count: int = 3


@dataclass
class ProcessMonitorConfig:
    enabled: bool = True
    suspicious_parent_names: list[str] = field(
        default_factory=lambda: ["caddy", "python3", "node"]
    )
    shell_names: list[str] = field(
        default_factory=lambda: ["bash", "sh", "zsh", "dash", "fish"]
    )
    ignored_process_names: list[str] = field(default_factory=list)
    # Processes inside a known container (by name, from the Docker baseline or
    # monitors.docker.known_containers) don't raise new_process/new_root_process.
    # Reverse-shell and suspicious-shell checks still apply to them.
    skip_known_container_processes: bool = True


@dataclass
class NetworkMonitorConfig:
    enabled: bool = True
    baseline_ports_override: list[int] = field(default_factory=list)
    # Loopback ports in the kernel's ephemeral range (ip_local_port_range) are
    # short-lived client callbacks (OAuth, IDE helpers), not services.
    ignore_loopback_ephemeral_ports: bool = True
    # Unexplained outbound MB/min (total minus trusted containers and units)
    # that must hold for data_volume_sustained_seconds before alerting.
    data_volume_threshold_mb: float = 100.0
    data_volume_sustained_seconds: int = 300
    # Inbound volume is rarely a security signal (downloads, streams to the
    # box), so data_volume_anomaly_recv is off unless asked for.
    alert_on_inbound: bool = False
    suspicious_outbound_ports: list[int] = field(
        default_factory=lambda: [
            1080,           # SOCKS proxy
            3333, 14444,    # mining pools
            4444,           # common backdoor / Metasploit default
            4899,           # Radmin
            5554,           # Metasploit
            6667, 6668, 6669,  # IRC (C2)
            9999,           # common backdoor
            31337,          # Back Orifice
        ]
    )
    trusted_outbound_process_names: list[str] = field(default_factory=list)
    trusted_docker_containers: list[str] = field(default_factory=list)
    # systemd units whose traffic is subtracted too (needs IPAccounting=yes on
    # the unit), e.g. dropboxd@dropboxsync.service.
    trusted_systemd_units: list[str] = field(default_factory=list)


@dataclass
class FileMonitorConfig:
    enabled: bool = True
    watch_paths: list[str] = field(
        default_factory=lambda: [
            "~/.ssh",
            "/root/.ssh",
            "/etc",
            "/home",
            "/var/run/docker.sock",  # watched non-recursively to avoid /var/run/containerd/ noise
        ]
    )
    ignore_patterns: list[str] = field(
        default_factory=lambda: ["*.swp", "*.tmp", "*~", ".dropbox", "*.pyc"]
    )
    ignore_paths: list[str] = field(default_factory=list)
    # Added to watch_paths / critical_paths, so a config can extend the
    # defaults without copying (and later drifting from) the whole list.
    extra_watch_paths: list[str] = field(default_factory=list)
    extra_critical_paths: list[str] = field(default_factory=list)
    # Non-critical /etc events while apt/dpkg runs are package churn, not
    # someone editing config; PackageMonitor reports the package activity.
    quiet_during_package_ops: bool = True
    alert_on_events: list[str] = field(
        default_factory=lambda: ["created", "modified", "deleted", "moved"]
    )
    critical_paths: list[str] = field(
        default_factory=lambda: [
            "~/.ssh/authorized_keys",
            "/root/.ssh/authorized_keys",
            "/home/*/.ssh/authorized_keys",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/gshadow",
            "/etc/sudoers",
            "/etc/sudoers.d/*",
            "/etc/ssh/sshd_config",
            "/etc/ssh/sshd_config.d/*",
            "/etc/ld.so.preload",
            "/etc/pam.d/*",
            "/etc/profile.d/*",
            "/etc/bash.bashrc",
            "/etc/environment",
            # systemd units and drop-ins: PersistenceMonitor (new_systemd_dropin)
        ]
    )


@dataclass
class DockerMonitorConfig:
    enabled: bool = True
    socket_path: str = "/var/run/docker.sock"
    known_containers: list[str] = field(default_factory=list)
    restart_count_threshold: int = 3
    restart_window_seconds: int = 300


@dataclass
class AuthMonitorConfig:
    enabled: bool = True
    log_path: str = "/var/log/auth.log"
    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 60
    known_ssh_sources: list[str] = field(
        default_factory=lambda: ["100.64.0.0/10", "127.0.0.1"]
    )
    known_sudo_users: list[str] = field(default_factory=lambda: ["root"])
    # Successful SSH logins by these users fire CRITICAL ssh_login_outside_window
    # unless they match an entry in login_windows. Empty = off.
    restricted_login_users: list[str] = field(default_factory=list)
    # Each: {user, source (IP or CIDR), days (mon..sun), hours [start, end) UTC}.
    login_windows: list[dict] = field(default_factory=list)


@dataclass
class ResourceMonitorConfig:
    enabled: bool = True
    cpu_threshold_percent: float = 90.0
    cpu_sustained_seconds: int = 120
    memory_threshold_percent: float = 85.0
    # high_network_send/recv: raw system-wide rate alerts. Off by default:
    # NetworkMonitor's data_volume_anomaly covers outbound with trusted
    # traffic subtracted, and these fire on every big download or stream.
    net_alerts_enabled: bool = False
    net_send_threshold_mbps: float = 50.0
    net_recv_threshold_mbps: float = 100.0
    check_interval_seconds: int = 15
    resource_whitelist: list[str] = field(default_factory=list)


@dataclass
class PersistenceMonitorConfig:
    enabled: bool = True
    cron_paths: list[str] = field(
        default_factory=lambda: [
            "/var/spool/cron/crontabs",
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
            "/etc/crontab",
        ]
    )
    systemd_paths: list[str] = field(
        default_factory=lambda: [
            "/etc/systemd/system",
            "/etc/systemd/system.control",
            "/usr/local/lib/systemd/system",
            "/root/.config/systemd/user",
            "/home/*/.config/systemd/user",
        ]
    )
    known_units: list[str] = field(default_factory=list)


@dataclass
class PackageMonitorConfig:
    enabled: bool = True
    log_path: str = "/var/log/dpkg.log"
    # Who ran each apt run (Commandline, Requested-By) is read from here
    apt_history_path: str = "/var/log/apt/history.log"
    # A run ends after this long with no dpkg activity; then one summary alert
    summary_quiet_seconds: int = 60
    # An install / removal makes the run's summary WARN (otherwise INFO, silent)
    alert_on_install: bool = True
    alert_on_remove: bool = True
    ignored_packages: list[str] = field(default_factory=list)


@dataclass
class KernelMonitorConfig:
    enabled: bool = True
    poll_interval_seconds: int = 30
    known_modules: list[str] = field(default_factory=list)


@dataclass
class TripwireMonitorConfig:
    enabled: bool = True
    files: list[str] = field(
        default_factory=lambda: [
            "/root/.aws/credentials",
            "/root/.gnupg/secring.gpg",
            "/root/.env",
        ]
    )
    # Entries are a path, or {path, owner, mode, content} for a bait file with
    # believable (fake) contents, e.g. a password.txt.
    # Create decoy files for entries that don't already exist (empty unless content)
    create_missing: bool = True
    # With ExecMonitor enabled: detect opens through auditd watches, which name
    # the process and user every time. Otherwise inotify (best-effort attribution).
    use_audit: bool = True
    # Readers to ignore (audit mode only): "comm" or "comm@user"; comm matches as
    # a prefix or glob. E.g. "rsync@root" for a backup, "smbd" for Samba.
    allowed_readers: list[str] = field(default_factory=list)


@dataclass
class ExecMonitorConfig:
    """Program starts from auditd. Needs an execve audit rule with audit_key,
    e.g. /etc/audit/rules.d/cop.rules (see README)."""
    enabled: bool = False
    audit_log: str = "/var/log/audit/audit.log"
    audit_key: str = "cop_exec"
    # Internet-facing containers: a shell/downloader started by the app in one
    # of these is CRITICAL, and ProcessMonitor never exempts their processes.
    public_containers: list[str] = field(default_factory=list)
    suspicious_commands: list[str] = field(default_factory=lambda: [
        "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp",
        "tftp", "ftp", "busybox", "base64", "xxd", "chmod", "nohup", "setsid",
        "crontab", "useradd", "passwd", "su", "sudo", "mkfifo", "id", "whoami",
    ])
    # Run with -c/-e (inline code), these count as suspicious too
    inline_interpreters: list[str] = field(default_factory=lambda: [
        "python", "python3", "perl", "ruby", "php", "node", "lua",
    ])
    # A container's own init/supervisors: shells under these are its scripts,
    # not the app's (globs). containerd-shim/runc parents (healthchecks,
    # docker exec) always count as infrastructure.
    container_infra_names: list[str] = field(default_factory=lambda: [
        "tini", "dumb-init", "docker-init", "catatonit", "init", "s6-*", "rc.init",
        "execlineb", "with-contenv", "supervisord", "runsv", "runsvdir",
    ])
    temp_dirs: list[str] = field(default_factory=lambda: ["/tmp/", "/var/tmp/", "/dev/shm/"])
    temp_exec_allow: list[str] = field(default_factory=list)  # globs on the exe path
    rules_check_interval_seconds: int = 60


@dataclass
class MonitorsConfig:
    process: ProcessMonitorConfig = field(default_factory=ProcessMonitorConfig)
    network: NetworkMonitorConfig = field(default_factory=NetworkMonitorConfig)
    file: FileMonitorConfig = field(default_factory=FileMonitorConfig)
    docker: DockerMonitorConfig = field(default_factory=DockerMonitorConfig)
    auth: AuthMonitorConfig = field(default_factory=AuthMonitorConfig)
    resource: ResourceMonitorConfig = field(default_factory=ResourceMonitorConfig)
    persistence: PersistenceMonitorConfig = field(default_factory=PersistenceMonitorConfig)
    package: PackageMonitorConfig = field(default_factory=PackageMonitorConfig)
    kernel: KernelMonitorConfig = field(default_factory=KernelMonitorConfig)
    tripwire: TripwireMonitorConfig = field(default_factory=TripwireMonitorConfig)
    exec: ExecMonitorConfig = field(default_factory=ExecMonitorConfig)


@dataclass
class GeneralConfig:
    data_dir: str = "~/.local/share/cop"
    log_level: str = "INFO"
    poll_interval_seconds: int = 30


@dataclass
class OllamaConfig:
    enabled: bool = False
    url: str = "http://localhost:11434/api/generate"
    model: str = "qwen3:1.7b"
    timeout_seconds: int = 60
    history_count: int = 10
    min_risk: int = 0
    suppressed_comment_patterns: list[str] = field(default_factory=list)


@dataclass
class AlertsConfig:
    dedup_window_seconds: int = 300
    rule_cooldowns: dict[str, int] = field(default_factory=dict)
    # Alert history older than this is deleted (at startup and daily). 0 = keep forever.
    retention_days: int = 90


@dataclass
class TelegramConfig:
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""
    allowed_user_ids: list[int] = field(default_factory=list)
    allowed_commands: list[str] = field(
        default_factory=lambda: ["docker stop", "docker restart", "systemctl stop", "kill"]
    )
    confirm_destructive: bool = True


@dataclass
class CopConfig:
    general: GeneralConfig = field(default_factory=GeneralConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    ntfy: NtfyConfig = field(default_factory=NtfyConfig)
    log_sink: LogSinkConfig = field(default_factory=LogSinkConfig)
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    monitors: MonitorsConfig = field(default_factory=MonitorsConfig)
    config_path: Path | None = None
    # Problems found while loading (unknown keys); logged and sent at startup.
    warnings: list[str] = field(default_factory=list)

    @property
    def data_path(self) -> Path:
        return Path(self.general.data_dir).expanduser()

    @property
    def db_path(self) -> Path:
        return self.data_path / "baseline.db"

    @property
    def log_path(self) -> Path:
        return Path(self.log_sink.path).expanduser()


def load_config(path: Path | None = None) -> CopConfig:
    """Load config YAML, falling back to defaults.

    Search order: explicit path → ~/.config/cop/config.yaml → /etc/cop/config.yaml
    """
    search: list[Path] = []
    if path:
        search.append(path)
    search += [
        Path("~/.config/cop/config.yaml").expanduser(),
        Path("/etc/cop/config.yaml"),
    ]

    raw: dict[str, Any] = {}
    found: Path | None = None
    for p in search:
        if p.exists():
            with open(p) as f:
                raw = yaml.safe_load(f) or {}
            found = p
            break

    config = _build_config(raw)
    config.config_path = found
    return config


_SECTIONS = {
    "general": GeneralConfig, "alerts": AlertsConfig, "ntfy": NtfyConfig,
    "log_sink": LogSinkConfig, "ollama": OllamaConfig, "telegram": TelegramConfig,
}
_MONITOR_SECTIONS = {
    "process": ProcessMonitorConfig, "network": NetworkMonitorConfig,
    "file": FileMonitorConfig, "docker": DockerMonitorConfig, "auth": AuthMonitorConfig,
    "resource": ResourceMonitorConfig, "persistence": PersistenceMonitorConfig,
    "package": PackageMonitorConfig, "kernel": KernelMonitorConfig,
    "tripwire": TripwireMonitorConfig, "exec": ExecMonitorConfig,
}


def _build_config(raw: dict[str, Any]) -> CopConfig:
    config = CopConfig()
    warnings = config.warnings
    for key, data in raw.items():
        if key in _SECTIONS:
            setattr(config, key, _apply(_SECTIONS[key](), data or {}, key, warnings))
        elif key == "monitors":
            monitors = MonitorsConfig()
            for mkey, mdata in (data or {}).items():
                if mkey in _MONITOR_SECTIONS:
                    setattr(monitors, mkey, _apply(_MONITOR_SECTIONS[mkey](), mdata or {}, f"monitors.{mkey}", warnings))
                else:
                    warnings.append(f"unknown config section monitors.{mkey} (ignored)")
            config.monitors = monitors
        else:
            warnings.append(f"unknown config section {key} (ignored)")
    return config


def _apply(obj: Any, data: dict, section: str = "", warnings: list[str] | None = None) -> Any:
    for key, val in data.items():
        if hasattr(obj, key):
            setattr(obj, key, val)
        elif warnings is not None:
            warnings.append(f"unknown config key {section}.{key} (ignored)")
    return obj
