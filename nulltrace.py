#!/usr/bin/env python3
# Developer : Sreeraj
# GitHub : https://github.com/s-r-e-e-r-a-j

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import time
try:
    import fcntl
except ImportError:
    fcntl = None

from argparse import ArgumentParser
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Sequence, Tuple
from urllib.error import URLError
from urllib.request import urlopen

TOR_CONFIG_BEGIN = "## BEGIN nulltrace"
TOR_CONFIG_END = "## END nulltrace"
TOR_CONFIG_MARKERS: Sequence[Tuple[str, str]] = (
    (TOR_CONFIG_BEGIN, TOR_CONFIG_END),
)
RUN_DIR = Path("/run/nulltrace")
STATE_FILE = RUN_DIR / "state.json"
IPTABLES_BACKUP = RUN_DIR / "iptables.v4.bak"
IP6TABLES_BACKUP = RUN_DIR / "iptables.v6.bak"


def get_config_home() -> Path:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        user_home = Path(f"/home/{sudo_user}")
        if user_home.exists():
            return user_home / ".config" / "nulltrace"
    return Path.home() / ".config" / "nulltrace"


CONFIG_HOME = get_config_home()
MAX_CONFIG_BYTES = 256 * 1024
MAX_EXCLUDED_ENTRIES = 32

TOR_USER_CANDIDATES = ("debian-tor", "_tor", "tor")
CONTROL_COOKIE_PATHS = (
    Path("/run/tor/control.authcookie"),
    Path("/var/run/tor/control.authcookie"),
    Path("/var/lib/tor/control.authcookie"),
)

IPV4_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
CIDR_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(25[0-5]|2[0-4]\d|[01]?\d\d?)/([0-9]|[1-2]\d|3[0-2])$"
)


def strip_tor_config_blocks(content: str) -> str:
    """Remove nulltrace blocks from torrc text."""
    lines = content.splitlines(keepends=True)
    filtered: List[str] = []
    skipping = False
    active_end: Optional[str] = None
    for line in lines:
        stripped = line.strip()
        if not skipping:
            matched = False
            for begin, end in TOR_CONFIG_MARKERS:
                if stripped == begin:
                    skipping = True
                    active_end = end
                    matched = True
                    break
            if not matched:
                filtered.append(line)
        elif stripped == active_end:
            skipping = False
            active_end = None
    return "".join(filtered)


def torrc_has_managed_block(content: str) -> bool:
    return any(begin in content for begin, _ in TOR_CONFIG_MARKERS)


def require_linux_root(action: str) -> None:
    if not hasattr(os, "geteuid"):
        raise OSError("nulltrace requires Linux")
    if os.geteuid() != 0:
        raise PermissionError(f"Root privileges required to {action}")


def resolve_config_path(filename: str) -> Path:
    """Restrict config files to ~/.config/nulltrace/ (relative names only)."""
    if not filename or filename != Path(filename).name:
        raise ValueError(
            "Config filename must be a plain name (e.g. myconfig.json), not a path"
        )
    config_home = get_config_home()
    config_home.mkdir(parents=True, exist_ok=True)
    resolved = (config_home / filename).resolve()
    config_root = str(config_home.resolve())
    if not str(resolved).startswith(config_root):
        raise ValueError("Config path must stay under ~/.config/nulltrace/")
    return resolved


@dataclass
class NetworkConfig:
    dns_port: str = "5353"
    tor_network: str = "10.192.0.0/10"
    localhost: str = "127.0.0.1"
    excluded_networks: List[str] = field(default_factory=list)
    excluded_ips: List[str] = field(
        default_factory=lambda: ["127.0.0.0/8"]
    )
    tor_port: str = "9041"
    tor_config: str = "/etc/tor/torrc"
    exit_country: Optional[str] = None


class nulltrace:
    def __init__(self, circuit_time: int = 3600, verbose: bool = False):
        self.config = NetworkConfig()
        self.circuit_time = circuit_time
        self.verbose = verbose
        self.mac_randomize = False
        self._spoofed_intf: Optional[str] = None
        self._tor_user: Optional[str] = None
        self.setup_logging(verbose)
        self.tor_config_content = self.generate_tor_config(self.circuit_time)

    @property
    def tor_user(self) -> str:
        if self._tor_user is None:
            self._tor_user = self.resolve_tor_user()
        return self._tor_user

    def setup_logging(self, verbose: bool) -> None:
        """Minimal logging: stderr only when --verbose; never logs IPs or DNS details."""
        self.logger = logging.getLogger("nulltrace")
        self.logger.handlers.clear()
        self.logger.propagate = False
        if not verbose:
            self.logger.addHandler(logging.NullHandler())
            self.logger.setLevel(logging.CRITICAL)
            return
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        self.logger.addHandler(handler)

    @staticmethod
    def is_valid_ip(value: str) -> bool:
        return bool(value and IPV4_RE.match(value.strip()))

    @staticmethod
    def is_valid_cidr(value: str) -> bool:
        return bool(value and CIDR_RE.match(value.strip()))

    @staticmethod
    def is_valid_port(value) -> bool:
        try:
            port = int(value)
            return 1 <= port <= 65535
        except (TypeError, ValueError):
            return False

    @staticmethod
    def is_valid_tor_config_path(path: str) -> bool:
        if not path or not path.startswith("/etc/tor/"):
            return False
        normalized = os.path.normpath(path)
        return normalized == path and ".." not in path.split(os.sep)

    def _limit_excluded_lists(self) -> None:
        total = len(self.config.excluded_networks) + len(self.config.excluded_ips)
        if total > MAX_EXCLUDED_ENTRIES:
            raise ValueError(
                f"Too many excluded networks (max {MAX_EXCLUDED_ENTRIES} total)"
            )

    def validate_network_config(self) -> None:
        if not self.is_valid_port(self.config.dns_port):
            raise ValueError(f"Invalid DNS port: {self.config.dns_port}")
        if not self.is_valid_port(self.config.tor_port):
            raise ValueError(f"Invalid Tor port: {self.config.tor_port}")
        if not self.is_valid_ip(self.config.localhost):
            raise ValueError(f"Invalid localhost address: {self.config.localhost}")
        if not self.is_valid_cidr(self.config.tor_network):
            raise ValueError(f"Invalid Tor network CIDR: {self.config.tor_network}")
        if not self.is_valid_tor_config_path(self.config.tor_config):
            raise ValueError(f"Invalid Tor config path: {self.config.tor_config}")
        if self.config.exit_country:
            if len(self.config.exit_country) != 2 or not self.config.exit_country.isalpha():
                raise ValueError(f"Invalid exit country code: {self.config.exit_country}")
        self._limit_excluded_lists()
        for network in self.config.excluded_networks + self.config.excluded_ips:
            if not self.is_valid_cidr(network):
                raise ValueError(f"Invalid excluded network CIDR: {network}")

    def validate_circuit_time(self, value: int) -> None:
        if not 60 <= value <= 86400:
            raise ValueError("Circuit time must be between 60 and 86400 seconds")

    def resolve_tor_user(self) -> str:
        for username in TOR_USER_CANDIDATES:
            result = subprocess.run(
                ["id", "-ur", username],
                capture_output=True,
                text=True,
                check=False,
            )
            uid = result.stdout.strip()
            if result.returncode == 0 and uid.isdigit():
                return uid
        raise RuntimeError(
            "Could not resolve Tor user (tried debian-tor, _tor, tor). Install Tor."
        )

    def generate_tor_config(self, circuit_time: int) -> str:
        config_block = (
            f"{TOR_CONFIG_BEGIN}\n"
            f"## Added by nulltrace for Tor routing\n"
            f"VirtualAddrNetwork {self.config.tor_network}\n"
            f"AutomapHostsOnResolve 1\n"
            f"TransPort {self.config.localhost}:{self.config.tor_port}\n"
            f"DNSPort {self.config.localhost}:{self.config.dns_port}\n"
            f"ControlPort 9051\n"
            f"CookieAuthentication 1\n"
            f"MaxCircuitDirtiness {circuit_time}\n"
        )
        if self.config.exit_country:
            config_block += f"ExitNodes {{{self.config.exit_country}}}\nStrictNodes 1\n"
        config_block += f"{TOR_CONFIG_END}\n"
        return config_block

    def _ensure_run_dir(self) -> None:
        RUN_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
        try:
            os.chmod(RUN_DIR, 0o755)
        except OSError:
            pass

    def _acquire_lock(self) -> None:
        self._ensure_run_dir()
        lock_path = RUN_DIR / "nulltrace.lock"
        self._lock_fd = open(lock_path, "w")
        if fcntl is None:
            return
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            try:
                self._lock_fd.close()
            except OSError:
                pass
            del self._lock_fd
            raise RuntimeError("Another instance of nulltrace is currently running. Please wait.")

    def _release_lock(self) -> None:
        if hasattr(self, "_lock_fd"):
            try:
                if fcntl is not None:
                    fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                self._lock_fd.close()
            except OSError:
                pass
            finally:
                if hasattr(self, "_lock_fd"):
                    del self._lock_fd

    def _secure_file(self, path: Path) -> None:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def _write_state(self, active: bool) -> None:
        self._ensure_run_dir()
        state = {
            "active": active,
            "iptables_v4": str(IPTABLES_BACKUP),
            "iptables_v6": str(IP6TABLES_BACKUP),
            "tor_backup": f"{self.config.tor_config}.nulltrace.bak",
            "tor_config": self.config.tor_config,
            "spoofed_intf": self._spoofed_intf,
        }
        STATE_FILE.write_text(json.dumps(state), encoding="utf-8")
        try:
            os.chmod(STATE_FILE, 0o644)
        except OSError:
            pass

    def _clear_state(self) -> None:
        if STATE_FILE.exists():
            STATE_FILE.unlink()

    def save_config(self, filename: str = "nulltrace_config.json") -> bool:
        try:
            path = resolve_config_path(filename)
        except ValueError as exc:
            print(f"[!] {exc}")
            return False

        if path.exists():
            print(f"[!] Configuration file '{path}' already exists and will be overwritten!")
            try:
                choice = input("    Continue? [y/N]: ").lower()
            except (EOFError, KeyboardInterrupt):
                print("\n[!] Save cancelled by user")
                return False
            if choice not in ("y", "yes"):
                print("[!] Save cancelled by user")
                return False

        try:
            config = {
                "version": "1.0",
                "circuit_time": self.circuit_time,
                "network_config": {
                    "dns_port": self.config.dns_port,
                    "tor_network": self.config.tor_network,
                    "localhost": self.config.localhost,
                    "excluded_networks": self.config.excluded_networks,
                    "excluded_ips": self.config.excluded_ips,
                    "tor_port": self.config.tor_port,
                    "tor_config": self.config.tor_config,
                    "exit_country": self.config.exit_country,
                },
                "last_saved": datetime.now().isoformat(),
            }
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(config, handle, indent=2)
            self._secure_file(path)
            sudo_user = os.environ.get("SUDO_USER")
            if sudo_user and sudo_user != "root":
                try:
                    import pwd
                    pw = pwd.getpwnam(sudo_user)
                    os.chown(path, pw.pw_uid, pw.pw_gid)
                except (KeyError, OSError, ImportError):
                    pass
            print(f"[+] Configuration saved to '{path}'")
            return True
        except OSError as exc:
            print(f"[!] Failed to save configuration: {exc}")
            return False

    def load_config(self, filename: str) -> bool:
        try:
            path = resolve_config_path(filename)
        except ValueError as exc:
            print(f"[!] {exc}")
            return False

        try:
            if path.stat().st_size > MAX_CONFIG_BYTES:
                raise ValueError(f"Config file exceeds {MAX_CONFIG_BYTES} bytes")
            with open(path, "r", encoding="utf-8") as handle:
                config = json.load(handle)

            if config.get("version") != "1.0":
                print(
                    f"[!] WARNING: Configuration version mismatch "
                    f"(expected 1.0, got {config.get('version')})"
                )
                try:
                    choice = input("    Continue anyway? [y/N]: ").lower()
                except (EOFError, KeyboardInterrupt):
                    return False
                if choice not in ("y", "yes"):
                    return False

            self.circuit_time = int(config["circuit_time"])
            self.validate_circuit_time(self.circuit_time)

            nc = config["network_config"]
            self.config.dns_port = str(nc["dns_port"])
            self.config.tor_network = nc["tor_network"]
            self.config.localhost = nc["localhost"]
            self.config.excluded_networks = list(nc["excluded_networks"])
            self.config.excluded_ips = list(nc["excluded_ips"])
            self.config.tor_port = str(nc["tor_port"])
            self.config.tor_config = nc["tor_config"]
            self.config.exit_country = nc.get("exit_country")
            self.validate_network_config()
            self.tor_config_content = self.generate_tor_config(self.circuit_time)
            print(f"[+] Configuration loaded from '{path}'")
            return True
        except FileNotFoundError:
            print(f"[!] Configuration file '{path}' not found")
            return False
        except json.JSONDecodeError:
            print(f"[!] Invalid JSON in configuration file '{path}'")
            return False
        except (KeyError, TypeError, ValueError, OSError) as exc:
            print(f"[!] Invalid configuration or read error: {exc}")
            return False

    def show_config(self) -> None:
        print("\n[*] Current Configuration")
        print("=" * 40)
        print(f"Config directory: {CONFIG_HOME}")
        print(f"Circuit Time: {self.circuit_time}s ({self.circuit_time // 60} minutes)")
        print(f"DNS Port: {self.config.dns_port}")
        print(f"Tor Port: {self.config.tor_port}")
        print(f"Tor Config Path: {self.config.tor_config}")
        print(f"Exit Country: {self.config.exit_country or 'Random'}")
        print(f"Tor Network: {self.config.tor_network}")
        print(f"Localhost: {self.config.localhost}")
        print("\nExcluded Networks:")
        for network in self.config.excluded_networks:
            print(f"  - {network}")
        print("\nExcluded IPs:")
        for ip in self.config.excluded_ips:
            print(f"  - {ip}")
        print("\nNote: Use --save [filename] to save this configuration")
        print("      Use --load [filename] to load a saved configuration")

    def check_tor_service(self) -> bool:
        if shutil.which("systemctl"):
            try:
                for svc in ("tor@default", "tor"):
                    result = subprocess.run(
                        ["systemctl", "is-active", svc],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if result.returncode == 0 and "exited" not in result.stdout:
                        return True
                    if result.returncode == 0 and svc == "tor":
                        return True
            except OSError:
                pass
        # Fallback for non-systemd environments (Alpine, Void, containers)
        for name in ("tor", "tor.real"):
            try:
                lookup = subprocess.run(
                    ["pgrep", "-x", name],
                    capture_output=True,
                    check=False,
                )
                if lookup.returncode == 0:
                    return True
            except OSError:
                pass
        return False

    def is_active(self) -> bool:
        for state_path in (STATE_FILE,):
            if not state_path.exists():
                continue
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
                if state.get("active"):
                    return True
            except (json.JSONDecodeError, OSError):
                continue
        return False

    def backup_iptables(self) -> None:
        self._ensure_run_dir()
        if not (IPTABLES_BACKUP.exists() and IPTABLES_BACKUP.stat().st_size > 0):
            with open(IPTABLES_BACKUP, "w", encoding="utf-8") as handle:
                subprocess.run(["iptables-save", "-c"], stdout=handle, check=True)
            self._secure_file(IPTABLES_BACKUP)
        if self._ip6tables_available() and not (IP6TABLES_BACKUP.exists() and IP6TABLES_BACKUP.stat().st_size > 0):
            try:
                with open(IP6TABLES_BACKUP, "w", encoding="utf-8") as handle:
                    subprocess.run(["ip6tables-save", "-c"], stdout=handle, check=True)
                self._secure_file(IP6TABLES_BACKUP)
            except (subprocess.CalledProcessError, FileNotFoundError):
                IP6TABLES_BACKUP.unlink(missing_ok=True)

    def restore_iptables(self, remove_backup: bool = True) -> None:
        restored_v4 = False
        v4_backup = next(
            (path for path in (IPTABLES_BACKUP,) if path.exists()),
            None,
        )
        if v4_backup is not None:
            subprocess.run(["iptables", "-F"], check=False)
            subprocess.run(["iptables", "-t", "nat", "-F"], check=False)
            subprocess.run(["iptables", "-t", "mangle", "-F"], check=False)
            subprocess.run(["iptables", "-t", "raw", "-F"], check=False)
            try:
                with open(v4_backup, "r", encoding="utf-8") as handle:
                    subprocess.run(["iptables-restore", "-c"], stdin=handle, check=True)
                restored_v4 = True
            except (subprocess.CalledProcessError, OSError) as exc:
                print(f"[!] iptables-restore failed: {exc}. Using fallback flush.")
            if restored_v4:
                if remove_backup:
                    v4_backup.unlink(missing_ok=True)
            else:
                failed_backup = v4_backup.with_suffix(".failed")
                try:
                    v4_backup.replace(failed_backup)
                    print(f"[!] Saved original IPv4 backup to {failed_backup} for manual recovery.")
                except OSError:
                    pass

        if not restored_v4:
            self._flush_iptables_v4()

        restored_v6 = False
        v6_backup = next(
            (path for path in (IP6TABLES_BACKUP,) if path.exists()),
            None,
        )
        if v6_backup is not None:
            subprocess.run(["ip6tables", "-F"], check=False)
            subprocess.run(["ip6tables", "-t", "nat", "-F"], check=False)
            subprocess.run(["ip6tables", "-t", "mangle", "-F"], check=False)
            subprocess.run(["ip6tables", "-t", "raw", "-F"], check=False)
            try:
                with open(v6_backup, "r", encoding="utf-8") as handle:
                    subprocess.run(["ip6tables-restore", "-c"], stdin=handle, check=True)
                restored_v6 = True
            except (subprocess.CalledProcessError, OSError) as exc:
                print(f"[!] ip6tables-restore failed: {exc}. Using fallback flush.")
            if restored_v6:
                if remove_backup:
                    v6_backup.unlink(missing_ok=True)
            else:
                failed_backup = v6_backup.with_suffix(".failed")
                try:
                    v6_backup.replace(failed_backup)
                    print(f"[!] Saved original IPv6 backup to {failed_backup} for manual recovery.")
                except OSError:
                    pass

        if not restored_v6 and self._ip6tables_available():
            self._flush_iptables_v6()

    def _ip6tables_available(self) -> bool:
        return shutil.which("ip6tables") is not None

    def _restore_ipv4_default(self) -> None:
        subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=False)
        subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], check=False)
        subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], check=False)

    def _flush_iptables_v4(self) -> None:
        subprocess.run(["iptables", "-F"], check=False)
        subprocess.run(["iptables", "-t", "nat", "-F"], check=False)
        subprocess.run(["iptables", "-t", "mangle", "-F"], check=False)
        subprocess.run(["iptables", "-t", "raw", "-F"], check=False)
        self._restore_ipv4_default()

    def _flush_iptables_v6(self) -> None:
        if self._ip6tables_available():
            subprocess.run(["ip6tables", "-F"], check=False)
            subprocess.run(["ip6tables", "-t", "nat", "-F"], check=False)
            subprocess.run(["ip6tables", "-t", "mangle", "-F"], check=False)
            subprocess.run(["ip6tables", "-t", "raw", "-F"], check=False)
            self._restore_ipv6_default()

    def _flush_iptables(self) -> None:
        self._flush_iptables_v4()
        self._flush_iptables_v6()

    def _restore_ipv6_default(self) -> None:
        subprocess.run(["ip6tables", "-P", "OUTPUT", "ACCEPT"], check=False)
        subprocess.run(["ip6tables", "-P", "INPUT", "ACCEPT"], check=False)
        subprocess.run(["ip6tables", "-P", "FORWARD", "ACCEPT"], check=False)

    def _tor_backup_paths(self) -> Tuple[str, ...]:
        return (
            f"{self.config.tor_config}.nulltrace.bak",
        )

    def _existing_tor_backup(self) -> Optional[str]:
        for path in self._tor_backup_paths():
            if os.path.exists(path):
                return path
        return None

    def backup_tor_config(self) -> None:
        if self._existing_tor_backup():
            return
        if os.path.exists(self.config.tor_config):
            backup_path = self._tor_backup_paths()[0]
            shutil.copy2(self.config.tor_config, backup_path)
            self._secure_file(Path(backup_path))

    def apply_tor_config(self) -> None:
        self.backup_tor_config()
        path = Path(self.config.tor_config)
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        if torrc_has_managed_block(existing):
            existing = strip_tor_config_blocks(existing)
        if existing and not existing.endswith("\n"):
            existing += "\n"
        path.write_text(existing + self.tor_config_content, encoding="utf-8")
        try:
            os.chmod(path, 0o644)
        except OSError:
            pass
        self._restart_tor()

    def restore_tor_config(self) -> None:
        backup_path = self._existing_tor_backup()
        if backup_path:
            shutil.copy2(backup_path, self.config.tor_config)
            os.remove(backup_path)
            other = [p for p in self._tor_backup_paths() if p != backup_path and os.path.exists(p)]
            for path in other:
                os.remove(path)
            self._restart_tor_no_check()
            return
        path = Path(self.config.tor_config)
        if not path.exists():
            return
        path.write_text(strip_tor_config_blocks(path.read_text(encoding="utf-8")), encoding="utf-8")
        self._restart_tor_no_check()

    def _restart_tor_no_check(self) -> None:
        if shutil.which("systemctl"):
            for svc in ("tor@default", "tor"):
                try:
                    result = subprocess.run(
                        ["systemctl", "restart", svc],
                        capture_output=True,
                        check=False,
                    )
                    if result.returncode == 0:
                        return
                except OSError:
                    pass
        for svc in ("tor@default", "tor"):
            try:
                result = subprocess.run(["service", svc, "restart"], capture_output=True, check=False)
                if result.returncode == 0:
                    return
            except OSError:
                pass

    def check_tor_ports(self) -> bool:
        if not self.check_tor_service():
            return False
        try:
            with socket.create_connection((self.config.localhost, int(self.config.tor_port)), timeout=1):
                pass
            # Verify DNSPort is bound by testing bind collision
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as test_sock:
                try:
                    test_sock.bind((self.config.localhost, int(self.config.dns_port)))
                    return False  # Port was unbound; Tor DNSPort is not listening
                except OSError:
                    pass  # Port is bound by Tor as expected
            return True
        except (OSError, ValueError):
            return False

    def _restart_tor(self) -> None:
        success = False
        last_err = ""
        for svc in ("tor@default", "tor"):
            try:
                result = subprocess.run(
                    ["systemctl", "restart", svc],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if result.returncode == 0:
                    success = True
                    break
                else:
                    last_err = result.stderr.strip() or result.stdout.strip()
            except OSError as exc:
                last_err = str(exc)

        if not success and not shutil.which("systemctl"):
            for svc in ("tor@default", "tor"):
                try:
                    result = subprocess.run(
                        ["service", svc, "restart"],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if result.returncode == 0:
                        success = True
                        break
                    else:
                        last_err = result.stderr.strip() or result.stdout.strip()
                except OSError as exc:
                    last_err = str(exc)

        if not success:
            raise RuntimeError(f"Failed to restart Tor: {last_err}")
        for _ in range(30):
            time.sleep(0.5)
            if self.check_tor_ports():
                return

        print("\n[!] FATAL: Tor failed to bind. Gathering diagnostic logs...")
        try:
            status = subprocess.run(["journalctl", "-u", "tor@default", "-n", "30", "--no-pager"], capture_output=True, text=True, check=False)
            print(status.stdout)
            if status.stderr:
                print(status.stderr)
        except OSError:
            pass

        raise RuntimeError(f"Tor failed to bind to port {self.config.tor_port} after 15 seconds")

    def _read_control_port(self) -> int:
        path = Path(self.config.tor_config)
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                match = re.match(r"^\s*ControlPort\s+(\d+)\s*$", line)
                if match:
                    port = int(match.group(1))
                    if self.is_valid_port(port):
                        return port
        return 9051

    def _tor_control_newnym(self) -> bool:
        cookie_path = next((p for p in CONTROL_COOKIE_PATHS if p.exists()), None)
        if cookie_path is None:
            return False
        port = self._read_control_port()
        try:
            cookie = cookie_path.read_bytes()
            with socket.create_connection(("127.0.0.1", port), timeout=8) as sock:
                auth = f"AUTHENTICATE {cookie.hex()}\r\n".encode()
                sock.sendall(auth)
                resp = sock.recv(256)
                if b"250" not in resp:
                    return False
                sock.sendall(b"SIGNAL NEWNYM\r\n")
                response = sock.recv(256)
                return b"250" in response
        except OSError:
            return False

    def _get_primary_interface(self) -> Optional[str]:
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, check=False
            )
            for line in result.stdout.splitlines():
                if "dev " in line:
                    parts = line.split("dev ")
                    if len(parts) > 1:
                        intf = parts[1].split()[0]
                        if not any(intf.startswith(prefix) for prefix in ("tun", "tap", "wg", "ppp")):
                            return intf
        except OSError:
            pass
        return None

    def _randomize_mac(self) -> None:
        if shutil.which("macchanger") is None:
            raise RuntimeError("macchanger is not installed but --mac-randomize was requested. Aborting.")
        intf = self._get_primary_interface()
        if not intf:
            raise RuntimeError("Could not determine primary network interface for MAC spoofing. Aborting.")
        
        print(f"[*] Randomizing MAC address for interface: {intf}...")
        try:
            subprocess.run(["ip", "link", "set", intf, "down"], check=True)
            subprocess.run(["macchanger", "-r", intf], check=True, capture_output=True)
            subprocess.run(["ip", "link", "set", intf, "up"], check=True)
            self._spoofed_intf = intf
            print("[+] MAC address randomized successfully. Renewing DHCP lease...")
            if shutil.which("dhclient"):
                subprocess.run(["dhclient", "-r", intf], capture_output=True, check=False)
                subprocess.run(["dhclient", intf], capture_output=True, check=False)
            elif shutil.which("nmcli"):
                subprocess.run(["nmcli", "device", "reapply", intf], capture_output=True, check=False)
            time.sleep(5)
        except subprocess.CalledProcessError as exc:
            subprocess.run(["ip", "link", "set", intf, "up"], check=False)
            raise RuntimeError(f"Failed to randomize MAC on {intf}. Aborting to prevent real MAC leak.") from exc

    def _restore_mac(self) -> None:
        if shutil.which("macchanger") is None:
            return
        intf = self._spoofed_intf
        if not intf:
            for state_path in (STATE_FILE,):
                if state_path.exists():
                    try:
                        state = json.loads(state_path.read_text(encoding="utf-8"))
                        intf = state.get("spoofed_intf")
                    except (json.JSONDecodeError, OSError):
                        pass
        if not intf:
            return
            
        print(f"[*] Restoring original MAC address for interface: {intf}...")
        try:
            subprocess.run(["ip", "link", "set", intf, "down"], check=True)
            subprocess.run(["macchanger", "-p", intf], check=True, capture_output=True)
            subprocess.run(["ip", "link", "set", intf, "up"], check=True)
            print("[+] Original MAC address restored. Renewing DHCP lease...")
            if shutil.which("dhclient"):
                subprocess.run(["dhclient", "-r", intf], capture_output=True, check=False)
                subprocess.run(["dhclient", intf], capture_output=True, check=False)
            elif shutil.which("nmcli"):
                subprocess.run(["nmcli", "device", "reapply", intf], capture_output=True, check=False)
            time.sleep(5)
        except subprocess.CalledProcessError as exc:
            print(f"[!] Failed to restore MAC on {intf}: {exc}")
            subprocess.run(["ip", "link", "set", intf, "up"], check=False)
    def setup_network_rules(self) -> None:
        require_linux_root("configure network routing")
        self._acquire_lock()
        try:
            if self.is_active():
                raise RuntimeError(
                    "nulltrace is already active. Run 'sudo nulltrace --stop' first."
                )

            self.validate_network_config()
            self.validate_circuit_time(self.circuit_time)

            if not self.check_tor_service():
                print("[*] Tor service is stopped. Attempting to start it automatically...")

            self.backup_iptables()
            if self.mac_randomize:
                self._randomize_mac()

            self.apply_tor_config()
            self._flush_iptables()
            self._apply_security_rules()
            self._apply_nat_rules()
            self._apply_connection_rules()
            self._apply_filter_rules()
            self._apply_ipv6_lockdown()
            self._write_state(active=True)
            print("[+] Privacy routing enabled (TCP/UDP/ICMP IPv4, IPv6 blocked)")
        except Exception:
            try:
                self.restore_iptables(remove_backup=False)
            except Exception:
                pass
            if self.mac_randomize:
                try:
                    self._restore_mac()
                except Exception:
                    pass
            self.restore_tor_config()
            self._clear_state()
            raise
        finally:
            self._release_lock()

    def stop_privacy_mode(self, force: bool = False) -> None:
        require_linux_root("restore network routing")
        self._acquire_lock()
        try:
            if not self.is_active() and not force:
                if IPTABLES_BACKUP.exists() or IP6TABLES_BACKUP.exists():
                    print(
                        "[!] State file missing but backup exists. "
                        "Use --force-stop to restore anyway."
                    )
                raise RuntimeError(
                    "nulltrace is not active. Use --force-stop to restore from backup if needed."
                )

            try:
                self._restore_mac()
            except Exception as exc:
                print(f"[!] Warning: Failed to restore MAC address: {exc}")

            try:
                self.restore_iptables(remove_backup=True)
            except Exception as exc:
                print(f"[!] Warning: Failed to restore iptables: {exc}")

            try:
                self.restore_tor_config()
            except Exception as exc:
                print(f"[!] Warning: Failed to restore Tor config: {exc}")

            self._clear_state()
            print("[!] Privacy mode deactivated")
        finally:
            self._release_lock()

    def _excluded_destinations(self) -> List[str]:
        return list(self.config.excluded_ips) + list(self.config.excluded_networks)

    def _apply_security_rules(self) -> None:
        security_rules = [
            [
                "iptables", "-I", "OUTPUT", "!", "-o", "lo", "!", "-d", self.config.localhost,
                "!", "-s", self.config.localhost, "-m", "owner", "!", "--uid-owner", self.tor_user,
                "-p", "tcp", "-m", "tcp", "--tcp-flags", "ACK,FIN", "ACK,FIN", "-j", "DROP",
            ],
            [
                "iptables", "-I", "OUTPUT", "!", "-o", "lo", "!", "-d", self.config.localhost,
                "!", "-s", self.config.localhost, "-m", "owner", "!", "--uid-owner", self.tor_user,
                "-p", "tcp", "-m", "tcp", "--tcp-flags", "ACK,RST", "ACK,RST", "-j", "DROP",
            ],
        ]
        for rule in security_rules:
            subprocess.run(rule, check=True)
        for net in self._excluded_destinations():
            subprocess.run(
                ["iptables", "-I", "OUTPUT", "-d", net, "-j", "ACCEPT"],
                check=True,
            )

    def _apply_nat_rules(self) -> None:
        # 1. Tor daemon bypass
        subprocess.run(
            [
                "iptables", "-t", "nat", "-A", "OUTPUT", "-m", "owner",
                "--uid-owner", self.tor_user, "-j", "RETURN",
            ],
            check=True,
        )
        # 2. Intercept ALL outbound UDP DNS (port 53) and redirect to Tor DNSPort
        # This MUST run before loopback and excluded networks bypass so queries to
        # 127.0.0.1:53 (e.g. from /etc/resolv.conf) are redirected to DNSPort!
        subprocess.run(
            [
                "iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp",
                "--dport", "53", "-j", "REDIRECT",
                "--to-ports", self.config.dns_port,
            ],
            check=True,
        )
        # 3. Bypass loopback interface
        subprocess.run(
            ["iptables", "-t", "nat", "-A", "OUTPUT", "-o", "lo", "-j", "RETURN"],
            check=True,
        )
        # 4. User-configured excluded LAN networks bypass
        for network in self._excluded_destinations():
            subprocess.run(
                ["iptables", "-t", "nat", "-A", "OUTPUT", "-d", network, "-j", "RETURN"],
                check=True,
            )
        # 5. All other outbound TCP redirected to Tor TransPort
        subprocess.run(
            [
                "iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp",
                "-j", "REDIRECT", "--to-ports", self.config.tor_port,
            ],
            check=True,
        )

    def _apply_connection_rules(self) -> None:
        # Handled in _apply_nat_rules in correct priority order
        pass

    def _apply_filter_rules(self) -> None:
        """Enforce strict default-deny egress and ingress firewall rules."""
        # Flush conntrack table if conntrack utility is present to sever pre-existing cleartext sockets
        if shutil.which("conntrack"):
            subprocess.run(["conntrack", "-F"], capture_output=True, check=False)

        for chain in ["OUTPUT", "INPUT", "FORWARD"]:
            subprocess.run(["iptables", "-P", chain, "DROP"], check=True)

        # Ingress stealth firewall
        subprocess.run(
            ["iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            check=True,
        )
        subprocess.run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=True)
        # Allow DHCP renewal inbound
        subprocess.run(
            ["iptables", "-A", "INPUT", "-p", "udp", "--sport", "67", "--dport", "68", "-j", "ACCEPT"],
            check=False,
        )
        # Allow inbound connections from explicitly excluded LAN networks
        for network in self.config.excluded_networks:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", network, "-j", "ACCEPT"],
                check=True,
            )
        subprocess.run(["iptables", "-A", "INPUT", "-j", "DROP"], check=True)

        # Egress: allow established/related, Tor daemon, loopback, and excluded destinations
        subprocess.run(
            ["iptables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            check=True,
        )
        subprocess.run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-A", "OUTPUT", "-d", "127.0.0.0/8", "-j", "ACCEPT"], check=True)
        subprocess.run(
            [
                "iptables", "-A", "OUTPUT", "-m", "owner",
                "--uid-owner", self.tor_user, "-j", "ACCEPT",
            ],
            check=True,
        )
        for network in self._excluded_destinations():
            subprocess.run(
                ["iptables", "-A", "OUTPUT", "-d", network, "-j", "ACCEPT"],
                check=True,
            )

        # Allow DHCP lease requests outbound
        subprocess.run(
            ["iptables", "-A", "OUTPUT", "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT"],
            check=False,
        )
        # Reject TCP port 53 to prevent hanging (Tor DNSPort is UDP-only)
        subprocess.run(
            ["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "REJECT", "--reject-with", "tcp-reset"],
            check=False,
        )
        # Block non-loopback UDP and ICMP to prevent leaks
        subprocess.run(
            ["iptables", "-A", "OUTPUT", "-p", "udp", "-j", "DROP"],
            check=True,
        )
        subprocess.run(
            ["iptables", "-A", "OUTPUT", "-p", "icmp", "-j", "DROP"],
            check=True,
        )
        # Fail-closed catch-all drop
        subprocess.run(["iptables", "-A", "OUTPUT", "-j", "DROP"], check=True)

    def _apply_ipv6_lockdown(self) -> None:
        if not self._ip6tables_available():
            print("[!] ip6tables not found; IPv6 leak protection unavailable")
            return
        subprocess.run(["ip6tables", "-F"], check=False)
        subprocess.run(["ip6tables", "-t", "nat", "-F"], check=False)
        subprocess.run(["ip6tables", "-t", "mangle", "-F"], check=False)
        for chain in ["OUTPUT", "INPUT", "FORWARD"]:
            subprocess.run(["ip6tables", "-P", chain, "DROP"], check=False)

        # Ingress: loopback, conntrack, and IPv6 Neighbor Discovery
        subprocess.run(["ip6tables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=False)
        subprocess.run(
            ["ip6tables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            check=False,
        )
        for icmp6_type in ("router-solicitation", "router-advertisement", "neighbor-solicitation", "neighbor-advertisement"):
            subprocess.run(["ip6tables", "-A", "INPUT", "-p", "ipv6-icmp", "--icmpv6-type", icmp6_type, "-j", "ACCEPT"], check=False)
        subprocess.run(["ip6tables", "-A", "INPUT", "-j", "DROP"], check=False)

        # Egress: loopback, conntrack, Tor daemon, and IPv6 Neighbor Discovery
        subprocess.run(["ip6tables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], check=False)
        subprocess.run(
            ["ip6tables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            check=False,
        )
        for icmp6_type in ("router-solicitation", "router-advertisement", "neighbor-solicitation", "neighbor-advertisement"):
            subprocess.run(["ip6tables", "-A", "OUTPUT", "-p", "ipv6-icmp", "--icmpv6-type", icmp6_type, "-j", "ACCEPT"], check=False)
        subprocess.run(
            [
                "ip6tables", "-A", "OUTPUT", "-m", "owner",
                "--uid-owner", self.tor_user, "-j", "ACCEPT",
            ],
            check=False,
        )
        # Reject non-Tor IPv6 egress with port-unreachable so dual-stack apps failover to IPv4 immediately
        subprocess.run(["ip6tables", "-A", "OUTPUT", "-j", "REJECT", "--reject-with", "icmp6-port-unreachable"], check=False)
        subprocess.run(["ip6tables", "-A", "FORWARD", "-j", "DROP"], check=False)
    def _resolv_conf_path(self) -> Path:
        path = Path("/etc/resolv.conf")
        if path.is_symlink():
            return path.resolve()
        return path

    def _check_resolv_conf_leaks(self) -> List[str]:
        issues = []
        path = self._resolv_conf_path()
        if not path.exists():
            return issues
        local_ok = {"127.0.0.1", "127.0.0.53", "::1"}
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line.startswith("nameserver"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                ns = parts[1]
                if ns in local_ok:
                    continue
                if self.is_valid_ip(ns) or ":" in ns:
                    issues.append(f"resolv.conf nameserver {ns} (not localhost)")
                elif "." in ns:
                    issues.append(f"resolv.conf nameserver {ns}")
        except OSError:
            pass
        return issues

    def run_dns_leak_test(self) -> None:
        print("[*] Checking local DNS configuration for potential leaks...")
        config_issues = self._check_resolv_conf_leaks()
        routing_active = self.is_active()

        if config_issues:
            print("[!] WARNING: DNS configuration issues found:")
            for issue in config_issues:
                print(f"    - {issue}")
            print("    Your OS is configured to use external DNS servers.")
            print("    While nulltrace's firewall blocks these leaks when active,")
            print("    you should change them to 127.0.0.1 for maximum safety.")
        else:
            print("[+] resolv.conf looks OK (no external DNS servers configured)")

        if not routing_active:
            print("[!] Privacy routing is currently INACTIVE (run: sudo nulltrace --start)")
        else:
            print("[+] Privacy routing is ACTIVE (All DNS traffic is forced through Tor)")

    def show_current_ip(self) -> None:
        for attempt in range(3):
            try:
                with urlopen("https://check.torproject.org/api/ip", timeout=10) as response:
                    data = json.loads(response.read().decode("utf-8"))
                ip = data.get("IP", "").strip()
                if not self.is_valid_ip(ip):
                    raise ValueError("Invalid IP in Tor check response")
                is_tor = data.get("IsTor", False)
                print(f"[+] Your IP: {ip}")
                print(f"[+] Tor exit: {'yes' if is_tor else 'no'}")
                return
            except (URLError, json.JSONDecodeError, ValueError, KeyError):
                time.sleep(3)
        raise RuntimeError("Could not determine IP address (is Tor running?)")

    def show_status(self) -> None:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            print("[!] WARNING: Status may be inaccurate without root privileges (cannot read state file).")
            print("    Run with 'sudo' for accurate routing status.")
        print("[*] nulltrace status")
        print(f"    Tor service: {'running' if self.check_tor_service() else 'stopped'}")
        print(f"    Privacy routing: {'active' if self.is_active() else 'inactive'}")
        try:
            self.show_current_ip()
        except RuntimeError as exc:
            print(f"    IP check: {exc}")

    def change_ip_address(self) -> None:
        require_linux_root("signal Tor for new identity")
        if self._tor_control_newnym():
            time.sleep(5)
            self.show_current_ip()
            return

        for name in ("tor", "tor.real"):
            result = subprocess.run(
                ["pkill", "-HUP", "-x", name],
                capture_output=True,
                check=False,
            )
            if result.returncode == 0:
                time.sleep(5)
                self.show_current_ip()
                return

        raise RuntimeError("Tor process not found to signal new identity")


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(
        description="nulltrace - Route system traffic through Tor",
    )
    parser.add_argument("-s", "--start", action="store_true", help="Start Tor routing")
    parser.add_argument("-x", "--stop", action="store_true", help="Stop Tor routing and restore rules")
    parser.add_argument(
        "--force-stop",
        action="store_true",
        help="Restore iptables/Tor even if state file says inactive",
    )
    parser.add_argument("-n", "--new-ip", action="store_true", help="Request new Tor identity")
    parser.add_argument("-i", "--ip", action="store_true", help="Show current public IP")
    parser.add_argument("-a", "--auto", action="store_true", help="Auto-change IP at intervals")
    parser.add_argument("-t", "--time", type=int, default=3600, help="Auto-change interval (seconds)")
    parser.add_argument(
        "--circuit-time",
        type=int,
        metavar="SEC",
        help="Tor MaxCircuitDirtiness (60-86400, used with --start)",
    )
    parser.add_argument("-c", "--exit-country", type=str, metavar="XX", help="2-letter ISO country code for Tor exit nodes (e.g., US, CH)")
    parser.add_argument("--mac-randomize", action="store_true", help="Randomize MAC address using macchanger during routing")
    parser.add_argument("--dnsleak", action="store_true", help="Run DNS leak test")
    parser.add_argument("--status", action="store_true", help="Show Tor and routing status")
    parser.add_argument(
        "--save",
        nargs="?",
        const="nulltrace_config.json",
        help="Save configuration under ~/.config/nulltrace/",
    )
    parser.add_argument(
        "--load",
        metavar="FILE",
        help="Load configuration from ~/.config/nulltrace/ (can be combined with --start or --auto)",
    )
    parser.add_argument("--show-config", action="store_true", help="Show current configuration")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging on stderr (off by default)",
    )
    return parser


def _select_action(args) -> Optional[str]:
    actions = {
        "save": args.save is not None,
        "show_config": args.show_config,
        "dnsleak": args.dnsleak,
        "status": args.status,
        "start": args.start,
        "stop": args.stop or args.force_stop,
        "ip": args.ip,
        "new_ip": args.new_ip,
        "auto": args.auto,
    }
    chosen = [name for name, enabled in actions.items() if enabled]
    if len(chosen) > 1:
        raise ValueError(
            f"Only one action allowed at a time (got: {', '.join('--' + c.replace('_', '-') for c in chosen)})"
        )
    return chosen[0] if chosen else None


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    circuit_time = args.circuit_time if args.circuit_time is not None else 3600

    try:
        action = _select_action(args)
    except ValueError as exc:
        print(f"[!] Error: {exc}")
        sys.exit(1)

    try:
        app = nulltrace(circuit_time=circuit_time, verbose=args.verbose)
    except RuntimeError as exc:
        print(f"[!] Error: {exc}")
        sys.exit(1)

    if args.load:
        if not app.load_config(args.load):
            sys.exit(1)
        if action is None:
            print("[+] Configuration loaded. Use --start to apply settings.")
            sys.exit(0)

    # CLI arguments override loaded config
    if args.circuit_time is not None:
        try:
            app.validate_circuit_time(args.circuit_time)
            app.circuit_time = args.circuit_time
            app.tor_config_content = app.generate_tor_config(app.circuit_time)
        except ValueError as exc:
            print(f"[!] Error: {exc}")
            sys.exit(1)

    if args.exit_country:
        if len(args.exit_country) != 2 or not args.exit_country.isalpha():
            print("[!] Error: Exit country must be a 2-letter ISO code")
            sys.exit(1)
        app.config.exit_country = args.exit_country.upper()
        app.tor_config_content = app.generate_tor_config(app.circuit_time)

    if args.mac_randomize:
        app.mac_randomize = True

    try:
        if action == "save":
            app.save_config(args.save)
            sys.exit(0)

        if action == "show_config":
            app.show_config()
            sys.exit(0)

        if action == "dnsleak":
            app.run_dns_leak_test()
            sys.exit(0)

        if action == "status":
            app.show_status()
            sys.exit(0)

        if action == "start":
            app.setup_network_rules()
        elif action == "stop":
            app.stop_privacy_mode(force=args.force_stop)
        elif action == "ip":
            app.show_current_ip()
        elif action == "new_ip":
            app.change_ip_address()
        elif action == "auto":
            if args.time <= 0 or args.time > 86400:
                raise ValueError("--time must be between 1 and 86400 seconds")
            if not app.is_active():
                app.setup_network_rules()
            print(f"[+] Auto IP switching enabled. Interval: {args.time} seconds")
            try:
                while True:
                    start = time.time()
                    try:
                        app.change_ip_address()
                    except RuntimeError as exc:
                        print(f"[!] IP rotation check warning: {exc}")
                    time.sleep(max(0, args.time - (time.time() - start)))
            except KeyboardInterrupt:
                print("\n[!] Stopped by user (routing remains active; use --stop to restore)")
        else:
            parser.print_help()
    except (PermissionError, OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"[!] Error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
