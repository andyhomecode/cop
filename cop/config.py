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


@dataclass
class NetworkMonitorConfig:
    enabled: bool = True
    baseline_ports_override: list[int] = field(default_factory=list)
    trusted_cidrs: list[str] = field(
        default_factory=lambda: [
            "127.0.0.0/8",
            "::1/128",
            "100.64.0.0/10",
            "192.168.0.0/16",
            "10.0.0.0/8",
        ]
    )
    trusted_process_names: list[str] = field(
        default_factory=lambda: ["dropbox", "tailscaled", "systemd-resolved"]
    )
    data_volume_window_seconds: int = 60
    data_volume_threshold_mb: float = 100.0
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


@dataclass
class FileMonitorConfig:
    enabled: bool = True
    watch_paths: list[str] = field(
        default_factory=lambda: [
            "~/.ssh",
            "/etc",
            "/home",
            "/var/run/docker.sock",  # watched non-recursively to avoid /var/run/containerd/ noise
        ]
    )
    ignore_patterns: list[str] = field(
        default_factory=lambda: ["*.swp", "*.tmp", "*~", ".dropbox", "*.pyc"]
    )
    ignore_paths: list[str] = field(default_factory=list)
    alert_on_events: list[str] = field(
        default_factory=lambda: ["created", "modified", "deleted", "moved"]
    )
    critical_paths: list[str] = field(
        default_factory=lambda: [
            "~/.ssh/authorized_keys",
            "/home/*/.ssh/authorized_keys",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
            "/etc/ld.so.preload",
            "/etc/pam.d/common-auth",
            "/etc/pam.d/sshd",
            "/etc/pam.d/sudo",
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


@dataclass
class ResourceMonitorConfig:
    enabled: bool = True
    cpu_threshold_percent: float = 90.0
    cpu_sustained_seconds: int = 120
    memory_threshold_percent: float = 85.0
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
            "/usr/local/lib/systemd/system",
        ]
    )
    known_units: list[str] = field(default_factory=list)


@dataclass
class PackageMonitorConfig:
    enabled: bool = True
    log_path: str = "/var/log/dpkg.log"
    alert_on_install: bool = True
    alert_on_remove: bool = True
    ignored_packages: list[str] = field(default_factory=list)


@dataclass
class KernelMonitorConfig:
    enabled: bool = True
    log_path: str = "/var/log/kern.log"
    known_modules: list[str] = field(default_factory=list)


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


@dataclass
class AlertsConfig:
    dedup_window_seconds: int = 300
    rule_cooldowns: dict[str, int] = field(default_factory=dict)


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


def _build_config(raw: dict[str, Any]) -> CopConfig:
    config = CopConfig()
    if "general" in raw:
        config.general = _apply(GeneralConfig(), raw["general"])
    if "alerts" in raw:
        config.alerts = _apply(AlertsConfig(), raw["alerts"])
    if "ntfy" in raw:
        config.ntfy = _apply(NtfyConfig(), raw["ntfy"])
    if "log_sink" in raw:
        config.log_sink = _apply(LogSinkConfig(), raw["log_sink"])
    if "ollama" in raw:
        config.ollama = _apply(OllamaConfig(), raw["ollama"])
    if "telegram" in raw:
        config.telegram = _apply(TelegramConfig(), raw["telegram"])
    if "monitors" in raw:
        m = raw["monitors"]
        monitors = MonitorsConfig()
        if "process" in m:
            monitors.process = _apply(ProcessMonitorConfig(), m["process"])
        if "network" in m:
            monitors.network = _apply(NetworkMonitorConfig(), m["network"])
        if "file" in m:
            monitors.file = _apply(FileMonitorConfig(), m["file"])
        if "docker" in m:
            monitors.docker = _apply(DockerMonitorConfig(), m["docker"])
        if "auth" in m:
            monitors.auth = _apply(AuthMonitorConfig(), m["auth"])
        if "resource" in m:
            monitors.resource = _apply(ResourceMonitorConfig(), m["resource"])
        if "persistence" in m:
            monitors.persistence = _apply(PersistenceMonitorConfig(), m["persistence"])
        if "package" in m:
            monitors.package = _apply(PackageMonitorConfig(), m["package"])
        if "kernel" in m:
            monitors.kernel = _apply(KernelMonitorConfig(), m["kernel"])
        config.monitors = monitors
    return config


def _apply(obj: Any, data: dict) -> Any:
    for key, val in data.items():
        if hasattr(obj, key):
            setattr(obj, key, val)
    return obj
