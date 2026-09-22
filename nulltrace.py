#!/usr/bin/env python3
# Developer : Sreeraj
# GitHub : https://github.com/s-r-e-e-r-a-j

import errno
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid

try:
    import fcntl
except ImportError:
    fcntl = None

from argparse import ArgumentParser
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
from urllib.error import URLError
from urllib.request import urlopen

# Markers and Paths
TOR_CONFIG_BEGIN = "## BEGIN nulltrace"
TOR_CONFIG_END = "## END nulltrace"
TOR_CONFIG_MARKERS: Sequence[Tuple[str, str]] = (
    (TOR_CONFIG_BEGIN, TOR_CONFIG_END),
)

# State and Runtime Directories
RUN_DIR = Path("/run/nulltrace")
PERSISTENT_DIR = Path("/var/lib/nulltrace")
STATE_FILE = PERSISTENT_DIR / "state.json"
RUN_STATE_FILE = RUN_DIR / "state.json"
LOCK_FILE = RUN_DIR / "nulltrace.lock"

# State Machine States (NT-004)
STATE_INACTIVE = "INACTIVE"
STATE_ACTIVATING = "ACTIVATING"
STATE_ACTIVE = "ACTIVE"
STATE_RESTORING = "RESTORING"
STATE_RESTORE_FAILED = "RESTORE_FAILED"

# Owned Custom Chain Names (NT-003)
CHAIN_FILTER_OUTPUT = "NULLTRACE_OUTPUT"
CHAIN_FILTER_INPUT = "NULLTRACE_INPUT"
CHAIN_FILTER_FORWARD = "NULLTRACE_FORWARD"
CHAIN_NAT_OUTPUT = "NULLTRACE_NAT_OUTPUT"
CHAIN_MANGLE_OUTPUT = "NULLTRACE_MANGLE_OUTPUT"
CHAIN_MANGLE_PREROUTING = "NULLTRACE_MANGLE_PREROUTING"

CHAIN_V6_OUTPUT = "NULLTRACE_V6_OUTPUT"
CHAIN_V6_INPUT = "NULLTRACE_V6_INPUT"
CHAIN_V6_FORWARD = "NULLTRACE_V6_FORWARD"
CHAIN_V6_MANGLE_OUTPUT = "NULLTRACE_V6_MANGLE_OUTPUT"
CHAIN_V6_MANGLE_PREROUTING = "NULLTRACE_V6_MANGLE_PREROUTING"

# Tor Connection Mark for Deterministic Conntrack Isolation (NT-002)
CONNMARK_TOR = "0x4e54"  # Hex for "NT"

# Trusted System Binary Directories (NT-006)
TRUSTED_BIN_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")


def resolve_trusted_binary(name: str) -> Optional[str]:
    """
    Resolve an executable strictly to a trusted system directory (NT-006).
    Rejects relative lookups through user-controlled PATH and path traversal attempts.
    """
    if not name or not isinstance(name, str):
        return None
    p = Path(name)
    if p.is_absolute():
        p_str = p.as_posix()
        for tdir in TRUSTED_BIN_DIRS:
            if p_str == f"{tdir}/{p.name}" and p.is_file() and os.access(p_str, os.X_OK):
                return p_str
        return None
    # If not an absolute path, must be a pure filename without path separators or traversal
    if p.name != name or "/" in name or "\\" in name or ".." in name:
        return None
    for directory in TRUSTED_BIN_DIRS:
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(str(candidate), os.X_OK):
            return str(candidate)
    return None


def require_trusted_binary(name: str) -> str:
    """Resolve binary in trusted directories or raise RuntimeError."""
    resolved = resolve_trusted_binary(name)
    if not resolved:
        raise RuntimeError(
            f"Required binary '{name}' not found in trusted system directories {TRUSTED_BIN_DIRS}"
        )
    return resolved


def run_trusted(
    cmd: Sequence[str],
    check: bool = True,
    capture_output: bool = True,
    text: bool = True,
    env: Optional[Dict[str, str]] = None,
    stdin=None,
    stdout=None,
    stderr=None,
    timeout: Optional[float] = None,
    input: Optional[Union[str, bytes]] = None,
) -> subprocess.CompletedProcess:
    """Execute a command using trusted binary lookup and sanitized PATH (NT-006)."""
    if not cmd:
        raise ValueError("Command sequence cannot be empty")

    bin_name = cmd[0]
    resolved_bin = resolve_trusted_binary(bin_name)
    actual_cmd = list(cmd)
    if resolved_bin:
        actual_cmd[0] = resolved_bin
    elif hasattr(os, "geteuid"):
        raise RuntimeError(
            f"Command '{bin_name}' cannot be resolved in trusted paths {TRUSTED_BIN_DIRS}"
        )

    clean_env = dict(env if env is not None else os.environ)
    clean_env["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"

    return subprocess.run(
        actual_cmd,
        check=check,
        capture_output=capture_output if stdout is None and stderr is None else False,
        text=text,
        env=clean_env,
        stdin=stdin,
        input=input,
        stdout=stdout,
        stderr=stderr,
        timeout=timeout,
    )


def atomic_write(
    path: Union[str, Path],
    content: Union[str, bytes],
    mode: int = 0o600,
    uid: Optional[int] = None,
    gid: Optional[int] = None,
) -> None:
    """Atomically write content to path using temporary file, fsync, and replace (NT-015)."""
    dest = Path(path).resolve()
    dest.parent.mkdir(parents=True, exist_ok=True)

    # Preserve ownership and permissions of existing file if not explicitly specified
    orig_stat = None
    try:
        if dest.exists():
            orig_stat = dest.stat()
    except OSError:
        pass

    target_uid = uid if uid is not None else (orig_stat.st_uid if orig_stat else None)
    target_gid = gid if gid is not None else (orig_stat.st_gid if orig_stat else None)

    is_text = isinstance(content, str)
    prefix = f".{dest.name}.tmp_"

    tf = tempfile.NamedTemporaryFile(
        mode="w" if is_text else "wb",
        dir=dest.parent,
        prefix=prefix,
        delete=False,
        encoding="utf-8" if is_text else None,
    )
    temp_path = Path(tf.name)
    try:
        try:
            tf.write(content)
            tf.flush()
            os.fsync(tf.fileno())
        finally:
            tf.close()
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    try:
        try:
            os.chmod(temp_path, mode)
        except OSError:
            pass
        if target_uid is not None or target_gid is not None:
            try:
                os.chown(
                    temp_path,
                    target_uid if target_uid is not None else -1,
                    target_gid if target_gid is not None else -1,
                )
            except (OSError, AttributeError):
                pass
        os.replace(temp_path, dest)
        if hasattr(os, "O_DIRECTORY") and hasattr(os, "fsync"):
            try:
                dir_fd = os.open(str(dest.parent), os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


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
MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


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
    if not filename or filename != Path(filename).name or "/" in filename or "\\" in filename or ".." in filename:
        raise ValueError(
            "Config filename must be a plain name (e.g. myconfig.json), not a path"
        )
    config_home = get_config_home()
    config_home.mkdir(parents=True, exist_ok=True)
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            import pwd
            pw = pwd.getpwnam(sudo_user)
            os.chown(config_home, pw.pw_uid, pw.pw_gid)
        except (KeyError, OSError, ImportError, AttributeError):
            pass
    resolved = (config_home / filename).resolve()
    try:
        resolved.relative_to(config_home.resolve())
    except ValueError:
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
        self._original_mac: Optional[str] = None
        self._tor_user: Optional[str] = None
        self._session_id: Optional[str] = None
        self._session_created_at: Optional[str] = None
        self._current_state: str = STATE_INACTIVE
        self._rollback_registered = False

        self.setup_logging(verbose)
        self.tor_config_content = self.generate_tor_config(self.circuit_time)

    @property
    def session_id(self) -> str:
        if self._session_id is None:
            self._session_id = uuid.uuid4().hex[:12]
        return self._session_id

    @property
    def tor_user(self) -> str:
        if self._tor_user is None:
            self._tor_user = self.resolve_tor_user()
        return self._tor_user

    def setup_logging(self, verbose: bool) -> None:
        """Minimal logging: stderr only when --verbose; never logs IPs or DNS queries."""
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
    def is_valid_loopback_ip(value: str) -> bool:
        """Validate that value is strictly a loopback address (NT-005)."""
        if not value or not isinstance(value, str):
            return False
        try:
            ip = ipaddress.ip_address(value.strip())
            return ip.is_loopback
        except ValueError:
            return False

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
        """
        Validate Tor config path is canonical, symlink-safe, and stays inside /etc/tor (NT-014).
        """
        if not path or not isinstance(path, str):
            return False
        try:
            p = Path(path).resolve(strict=False)
            if ".." in Path(path).parts:
                return False
            tor_dir = Path("/etc/tor").resolve(strict=False)
            if p == tor_dir:
                return False
            p.relative_to(tor_dir)
            return True
        except (ValueError, RuntimeError, OSError):
            return False

    def validate_tor_config_target(self, path: Union[str, Path]) -> Path:
        """
        Validate Tor config target path and integrity before privileged operations (NT-014):
        - Canonical, symlink-safe resolution inside /etc/tor/
        - Rejects symlink traversal escaping /etc/tor/
        - Verifies target file is not world-writable
        - Verifies target ownership (root or tor user) when run as root
        - Verifies target directory is not world-writable
        """
        if not path or not isinstance(path, (str, Path)):
            raise ValueError("Tor config path cannot be empty")
        path_str = str(path)
        if not self.is_valid_tor_config_path(path_str):
            raise ValueError(
                f"Tor config path '{path_str}' fails directory containment validation (must stay under /etc/tor/)"
            )

        p = Path(path).resolve(strict=False)

        # Check parent directory safety (POSIX permission and ownership checks)
        parent = p.parent
        if parent.exists() and hasattr(os, "getuid"):
            st_parent = parent.stat()
            if st_parent.st_mode & 0o002:
                raise ValueError(f"Insecure Tor config directory '{parent}': world-writable")
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                tor_uid = int(self.tor_user) if (hasattr(self, "_tor_user") and self._tor_user and self._tor_user.isdigit()) else None
                allowed_uids = {0}
                if tor_uid is not None:
                    allowed_uids.add(tor_uid)
                if st_parent.st_uid not in allowed_uids:
                    raise ValueError(
                        f"Insecure Tor config directory '{parent}': owned by untrusted UID {st_parent.st_uid}"
                    )

        # Check target file safety if it already exists (POSIX permission and ownership checks)
        if p.exists() and hasattr(os, "getuid"):
            st = p.stat()
            if st.st_mode & 0o002:
                raise ValueError(f"Insecure Tor config file '{p}': world-writable")
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                tor_uid = int(self.tor_user) if (hasattr(self, "_tor_user") and self._tor_user and self._tor_user.isdigit()) else None
                allowed_uids = {0}
                if tor_uid is not None:
                    allowed_uids.add(tor_uid)
                if st.st_uid not in allowed_uids:
                    raise ValueError(
                        f"Insecure Tor config file '{p}': owned by untrusted UID {st.st_uid}"
                    )
        return p

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
        # NT-005: Restrict listener address strictly to loopback
        if not self.is_valid_loopback_ip(self.config.localhost):
            raise ValueError(
                f"Invalid localhost address '{self.config.localhost}': must be a valid loopback IP (e.g. 127.0.0.1)"
            )
        if not self.is_valid_cidr(self.config.tor_network):
            raise ValueError(f"Invalid Tor network CIDR: {self.config.tor_network}")
        # NT-014: Symlink-safe Tor config path
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
        """Resolve tor daemon uid using trusted system binaries (NT-006)."""
        id_bin = resolve_trusted_binary("id")
        for username in TOR_USER_CANDIDATES:
            try:
                cmd = [id_bin or "id", "-ur", username]
                result = run_trusted(cmd, check=False)
                uid = result.stdout.strip()
                if result.returncode == 0 and uid.isdigit():
                    return uid
            except OSError:
                pass
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

    def _ensure_runtime_dirs(self) -> None:
        RUN_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
        PERSISTENT_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
        try:
            os.chmod(RUN_DIR, 0o755)
            os.chmod(PERSISTENT_DIR, 0o755)
        except OSError:
            pass

    def _acquire_lock(self) -> None:
        self._ensure_runtime_dirs()
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

    def _session_dir(self) -> Path:
        return PERSISTENT_DIR / f"session_{self.session_id}"

    def _load_session_metadata(self) -> Optional[Dict[str, Any]]:
        # 1. Look in persistent state file first to find active/current session ID
        for sf in (PERSISTENT_DIR / "state.json", RUN_DIR / "state.json"):
            if sf.exists():
                try:
                    state_info = json.loads(sf.read_text(encoding="utf-8"))
                    sid = state_info.get("session_id")
                    if sid:
                        meta_file = PERSISTENT_DIR / f"session_{sid}" / "metadata.json"
                        if meta_file.exists():
                            return json.loads(meta_file.read_text(encoding="utf-8"))
                    if state_info.get("state") in (STATE_ACTIVE, STATE_ACTIVATING, STATE_RESTORING, STATE_RESTORE_FAILED):
                        return state_info
                except (OSError, json.JSONDecodeError):
                    pass

        # 2. Look in persistent directory for sessions, sorted newest first
        if PERSISTENT_DIR.exists():
            candidates = sorted(
                PERSISTENT_DIR.glob("session_*"),
                key=lambda p: p.stat().st_mtime if p.exists() else 0,
                reverse=True,
            )
            for sdir_candidate in candidates:
                candidate_meta = sdir_candidate / "metadata.json"
                if candidate_meta.exists():
                    try:
                        data = json.loads(candidate_meta.read_text(encoding="utf-8"))
                        if data.get("state") in (STATE_ACTIVE, STATE_ACTIVATING, STATE_RESTORING, STATE_RESTORE_FAILED):
                            return data
                    except (OSError, json.JSONDecodeError):
                        pass

        # 3. Look in current session directory
        sdir = self._session_dir()
        meta_file = sdir / "metadata.json"
        if meta_file.exists():
            try:
                return json.loads(meta_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass

        return None

    def _persist_session_metadata(self) -> None:
        """Persist session metadata and recovery record (NT-010, NT-015)."""
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            return

        try:
            sdir = self._session_dir()
            sdir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(sdir, 0o700)
            except OSError:
                pass

            meta = {
                "session_id": self.session_id,
                "created_at": getattr(self, "_session_created_at", datetime.now().isoformat()),
                "tool_version": "2.0.0",
                "state": self._current_state,
                "spoofed_intf": self._spoofed_intf,
                "original_mac": self._original_mac,
                "mac_restored": getattr(self, "_mac_restored", False),
                "tor_config_path": self.config.tor_config,
                "tor_backup_path": str(sdir / "torrc.bak"),
                "tor_config_hash": getattr(self, "_tor_config_hash", None),
                "iptables_v4_backup": str(sdir / "iptables.v4.bak"),
                "iptables_v4_hash": getattr(self, "_iptables_v4_hash", None),
                "iptables_v6_backup": str(sdir / "iptables.v6.bak"),
                "iptables_v6_hash": getattr(self, "_iptables_v6_hash", None),
                "custom_chains": [
                    CHAIN_FILTER_OUTPUT, CHAIN_FILTER_INPUT, CHAIN_FILTER_FORWARD,
                    CHAIN_NAT_OUTPUT, CHAIN_MANGLE_OUTPUT, CHAIN_MANGLE_PREROUTING,
                    CHAIN_V6_OUTPUT, CHAIN_V6_INPUT, CHAIN_V6_FORWARD,
                    CHAIN_V6_MANGLE_OUTPUT, CHAIN_V6_MANGLE_PREROUTING,
                ],
                "failures": getattr(self, "_restore_failures", []),
            }

            meta_file = sdir / "metadata.json"
            atomic_write(meta_file, json.dumps(meta, indent=2), mode=0o600)
            self._write_state(self._current_state)
        except OSError:
            pass

    def _write_state(self, state: str) -> None:
        """Durable atomic write for runtime state files (NT-015)."""
        self._ensure_runtime_dirs()
        self._current_state = state

        payload = {
            "state": state,
            "active": (state == STATE_ACTIVE),
            "session_id": self.session_id,
            "session_dir": str(self._session_dir()),
            "spoofed_intf": self._spoofed_intf,
            "original_mac": self._original_mac,
            "tor_config": self.config.tor_config,
            "updated_at": datetime.now().isoformat(),
        }
        content = json.dumps(payload, indent=2)

        for dest in (PERSISTENT_DIR / "state.json", RUN_DIR / "state.json"):
            try:
                atomic_write(dest, content, mode=0o644)
            except OSError:
                pass

    def _set_state(self, new_state: str) -> None:
        self._current_state = new_state
        self._persist_session_metadata()

    def _get_current_state(self) -> str:
        if getattr(self, "_current_state", STATE_INACTIVE) != STATE_INACTIVE:
            return self._current_state
        meta = self._load_session_metadata()
        if meta:
            state = meta.get("state")
            if state in (STATE_ACTIVE, STATE_ACTIVATING, STATE_RESTORING, STATE_RESTORE_FAILED, STATE_INACTIVE):
                return state
            if meta.get("active"):
                return STATE_ACTIVE
        return getattr(self, "_current_state", STATE_INACTIVE)

    def is_active(self) -> bool:
        return self._get_current_state() == STATE_ACTIVE

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
            # NT-015: Use atomic durable write
            sudo_uid = None
            sudo_gid = None
            sudo_user = os.environ.get("SUDO_USER")
            if sudo_user and sudo_user != "root":
                try:
                    import pwd
                    pw = pwd.getpwnam(sudo_user)
                    sudo_uid = pw.pw_uid
                    sudo_gid = pw.pw_gid
                except (KeyError, OSError, ImportError):
                    pass
            atomic_write(path, json.dumps(config, indent=2), mode=0o600, uid=sudo_uid, gid=sudo_gid)
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

    def _control_tor_service(self, action: str) -> Tuple[bool, str]:
        """
        Tor service control: attempt systemctl, inspect exit code, fallback to service on failure (NT-012, NT-006).
        """
        errors: List[str] = []

        # 1. Attempt systemctl if available
        systemctl_bin = resolve_trusted_binary("systemctl")
        if systemctl_bin:
            for svc in ("tor@default", "tor"):
                try:
                    res = subprocess.run(
                        [systemctl_bin, action, svc],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if res.returncode == 0:
                        if action == "is-active":
                            if "active" in res.stdout.strip() and "exited" not in res.stdout:
                                return True, f"systemctl {action} {svc} succeeded"
                        else:
                            return True, f"systemctl {action} {svc} succeeded"
                    else:
                        err_text = res.stderr.strip() or res.stdout.strip() or f"code {res.returncode}"
                        errors.append(f"systemctl {action} {svc} failed: {err_text}")
                except OSError as exc:
                    errors.append(f"systemctl {action} {svc}: {exc}")
        else:
            errors.append("systemctl not found in trusted directories")

        # 2. Fallback to service utility (NT-012: triggers when systemctl returns non-zero, not just missing)
        service_bin = resolve_trusted_binary("service")
        if service_bin:
            for svc in ("tor@default", "tor"):
                try:
                    svc_action = "status" if action == "is-active" else action
                    res = subprocess.run(
                        [service_bin, svc, svc_action],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if res.returncode == 0:
                        return True, f"service {svc} {svc_action} succeeded"
                    else:
                        err_text = res.stderr.strip() or res.stdout.strip() or f"code {res.returncode}"
                        errors.append(f"service {svc} {svc_action} failed: {err_text}")
                except OSError as exc:
                    errors.append(f"service {svc} {svc_action}: {exc}")
        else:
            errors.append("service not found in trusted directories")

        # 3. For status check, fall back to pgrep
        if action == "is-active":
            pgrep_bin = resolve_trusted_binary("pgrep")
            if pgrep_bin:
                for proc_name in ("tor", "tor.real"):
                    try:
                        res = subprocess.run(
                            [pgrep_bin, "-x", proc_name],
                            capture_output=True,
                            check=False,
                        )
                        if res.returncode == 0:
                            return True, f"pgrep found active {proc_name} process"
                    except OSError:
                        pass

        return False, "; ".join(errors)

    def check_tor_service(self) -> bool:
        ok, _ = self._control_tor_service("is-active")
        return ok

    def _probe_dns_port(self, timeout: float = 2.0) -> bool:
        """
        Perform a protocol-level DNS query probe to verify Tor DNSPort is responding (NT-008).
        """
        try:
            tx_id = os.urandom(2)
            flags = b"\x01\x00"  # Standard query, recursion desired
            counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
            qname = b"\x05check\x0btorproject\x03org\x00"
            qtype_qclass = b"\x00\x01\x00\x01"  # Type A, Class IN
            packet = tx_id + flags + counts + qname + qtype_qclass

            port = int(self.config.dns_port)
            host = self.config.localhost
            family = socket.AF_INET6 if ":" in host else socket.AF_INET

            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (host, port))
                response, _ = sock.recvfrom(512)

            if len(response) < 12:
                return False
            resp_tx_id = response[:2]
            resp_flags = struct.unpack("!H", response[2:4])[0]
            is_response = bool(resp_flags & 0x8000)
            return (resp_tx_id == tx_id) and is_response
        except (OSError, socket.timeout, ValueError):
            return False

    def check_tor_ports(self) -> bool:
        """
        Verify both TransPort (TCP) and DNSPort (UDP protocol-level probe) are functional (NT-008).
        """
        if not self.check_tor_service():
            return False

        # TransPort TCP connect
        try:
            with socket.create_connection(
                (self.config.localhost, int(self.config.tor_port)), timeout=1.5
            ):
                pass
        except (OSError, ValueError):
            return False

        # DNSPort Protocol Probe (NT-008)
        if not self._probe_dns_port(timeout=2.0):
            time.sleep(0.5)
            if not self._probe_dns_port(timeout=2.5):
                return False
        return True

    def _restart_tor(self) -> None:
        """Restart Tor service and verify ports with protocol probe (NT-008, NT-012)."""
        ok, detail = self._control_tor_service("restart")
        if not ok:
            raise RuntimeError(f"Failed to restart Tor service: {detail}")

        for _ in range(30):
            time.sleep(0.5)
            if self.check_tor_ports():
                return

        raise RuntimeError(
            f"Tor failed health check (TransPort {self.config.tor_port} or DNSPort {self.config.dns_port} unreachable)"
        )

    def _restart_tor_no_check(self) -> None:
        self._control_tor_service("restart")

    def _check_ipv6_enabled(self) -> bool:
        """Check if IPv6 is enabled on the host (NT-001)."""
        try:
            test_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            test_sock.close()
        except OSError:
            return False

        disable_ipv6_path = Path("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        if disable_ipv6_path.exists():
            try:
                return disable_ipv6_path.read_text(encoding="utf-8").strip() == "0"
            except OSError:
                pass
        return True

    def _ip6tables_available(self) -> bool:
        return resolve_trusted_binary("ip6tables") is not None

    def backup_iptables(self) -> None:
        """Session-bound backup of existing host firewall rules (NT-010, NT-015)."""
        sdir = self._session_dir()
        sdir.mkdir(parents=True, exist_ok=True)
        v4_backup = sdir / "iptables.v4.bak"
        v6_backup = sdir / "iptables.v6.bak"

        iptables_save = require_trusted_binary("iptables-save")
        res_v4 = run_trusted([iptables_save, "-c"], check=True)
        atomic_write(v4_backup, res_v4.stdout, mode=0o600)
        self._iptables_v4_hash = hashlib.sha256(res_v4.stdout.encode()).hexdigest()

        if self._check_ipv6_enabled():
            ip6tables_save = resolve_trusted_binary("ip6tables-save")
            if not ip6tables_save:
                raise RuntimeError(
                    "IPv6 is enabled on host but ip6tables-save is missing. Aborting to prevent IPv6 leak."
                )
            res_v6 = run_trusted([ip6tables_save, "-c"], check=True)
            atomic_write(v6_backup, res_v6.stdout, mode=0o600)
            self._iptables_v6_hash = hashlib.sha256(res_v6.stdout.encode()).hexdigest()

    def backup_tor_config(self) -> None:
        """Session-bound backup of Tor configuration (NT-010, NT-014, NT-015)."""
        path = self.validate_tor_config_target(self.config.tor_config)
        sdir = self._session_dir()
        sdir.mkdir(parents=True, exist_ok=True)
        backup_path = sdir / "torrc.bak"

        if path.exists():
            clean_content = strip_tor_config_blocks(path.read_text(encoding="utf-8"))
            atomic_write(backup_path, clean_content, mode=0o644)
            self._tor_config_hash = hashlib.sha256(clean_content.encode()).hexdigest()
        else:
            atomic_write(backup_path, "", mode=0o644)
            self._tor_config_hash = hashlib.sha256(b"").hexdigest()

    def apply_tor_config(self) -> None:
        """Atomically update Tor configuration with nulltrace blocks (NT-014, NT-015)."""
        self.backup_tor_config()
        path = self.validate_tor_config_target(self.config.tor_config)
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        if torrc_has_managed_block(existing):
            existing = strip_tor_config_blocks(existing)
        if existing and not existing.endswith("\n"):
            existing += "\n"

        new_content = existing + self.tor_config_content
        atomic_write(path, new_content, mode=0o644)
        self._restart_tor()

    def restore_tor_config(self) -> None:
        """Restore Tor configuration from session backup (NT-010, NT-014, NT-015)."""
        sdir = self._session_dir()
        backup_path = sdir / "torrc.bak"
        path = self.validate_tor_config_target(self.config.tor_config)

        if backup_path.exists():
            content = strip_tor_config_blocks(backup_path.read_text(encoding="utf-8"))
            atomic_write(path, content, mode=0o644)
        elif path.exists():
            cleaned = strip_tor_config_blocks(path.read_text(encoding="utf-8"))
            atomic_write(path, cleaned, mode=0o644)

        self._restart_tor_no_check()

    def restore_iptables_from_backup(self) -> None:
        """
        Restore original host firewall rules from session backup using iptables-restore / ip6tables-restore (NT-004, NT-010).
        """
        sdir = self._session_dir()
        v4_backup = sdir / "iptables.v4.bak"
        v6_backup = sdir / "iptables.v6.bak"

        if not v4_backup.exists() and not v6_backup.exists():
            raise FileNotFoundError(f"No firewall backups found in session directory {sdir}")

        if v4_backup.exists():
            content_v4 = v4_backup.read_text(encoding="utf-8")
            iptables_restore = require_trusted_binary("iptables-restore")
            run_trusted([iptables_restore, "-c"], input=content_v4, check=True)

        if v6_backup.exists() and self._check_ipv6_enabled():
            content_v6 = v6_backup.read_text(encoding="utf-8")
            ip6tables_restore = require_trusted_binary("ip6tables-restore")
            run_trusted([ip6tables_restore, "-c"], input=content_v6, check=True)

    def _get_primary_interface(self) -> Optional[str]:
        """
        Determine the primary egress interface using kernel routing decision (NT-013).
        """
        ip_bin = resolve_trusted_binary("ip")
        if not ip_bin:
            return None

        virtual_prefixes = ("tun", "tap", "wg", "ppp", "lo", "docker", "virbr", "br-", "veth")

        # 1. Query kernel route decision for public destinations
        for probe in ("1.1.1.1", "8.8.8.8", "9.9.9.9"):
            try:
                res = run_trusted([ip_bin, "route", "get", probe], check=False)
                if res.returncode == 0:
                    tokens = res.stdout.split()
                    if "dev" in tokens:
                        idx = tokens.index("dev")
                        if idx + 1 < len(tokens):
                            intf = tokens[idx + 1]
                            if not any(intf.startswith(p) for p in virtual_prefixes):
                                return intf
            except OSError:
                pass

        # 2. Inspect default routes and check for ambiguity by metric
        try:
            res = run_trusted([ip_bin, "route", "show", "default"], check=False)
            candidates: List[Tuple[int, str]] = []
            for line in res.stdout.splitlines():
                tokens = line.split()
                if "dev" in tokens:
                    idx = tokens.index("dev")
                    if idx + 1 < len(tokens):
                        intf = tokens[idx + 1]
                        if not any(intf.startswith(p) for p in virtual_prefixes):
                            metric = 0
                            if "metric" in tokens:
                                m_idx = tokens.index("metric")
                                if m_idx + 1 < len(tokens) and tokens[m_idx + 1].isdigit():
                                    metric = int(tokens[m_idx + 1])
                            candidates.append((metric, intf))
            if candidates:
                candidates.sort(key=lambda x: x[0])
                lowest_metric = candidates[0][0]
                best_interfaces = list(dict.fromkeys(intf for m, intf in candidates if m == lowest_metric))
                if len(best_interfaces) == 1:
                    return best_interfaces[0]
                elif len(best_interfaces) > 1:
                    raise RuntimeError(
                        f"Ambiguous default egress interfaces with identical metric {lowest_metric}: {best_interfaces}. "
                        "Cannot deterministically select interface for MAC operations."
                    )
        except OSError:
            pass

        return None

    def _read_current_mac(self, intf: str) -> Optional[str]:
        """Read hardware MAC address directly from sysfs or ip link (NT-011)."""
        sysfs_path = Path(f"/sys/class/net/{intf}/address")
        if sysfs_path.exists():
            try:
                mac = sysfs_path.read_text(encoding="utf-8").strip().lower()
                if MAC_RE.match(mac):
                    return mac
            except OSError:
                pass

        ip_bin = resolve_trusted_binary("ip")
        if ip_bin:
            try:
                res = run_trusted([ip_bin, "link", "show", "dev", intf], check=False)
                if res.returncode == 0:
                    match = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", res.stdout)
                    if match:
                        mac = match.group(1).strip().lower()
                        if MAC_RE.match(mac):
                            return mac
            except OSError:
                pass
        return None

    def _renew_dhcp(self, intf: str) -> None:
        """Attempt to renew DHCP lease using available network tools."""
        dhclient_bin = resolve_trusted_binary("dhclient")
        nmcli_bin = resolve_trusted_binary("nmcli")
        if dhclient_bin:
            run_trusted([dhclient_bin, "-r", intf], check=False)
            run_trusted([dhclient_bin, intf], check=False)
        elif nmcli_bin:
            run_trusted([nmcli_bin, "device", "reapply", intf], check=False)

    def _randomize_mac(self) -> None:
        """Persist original hardware MAC and randomize using macchanger (NT-011)."""
        macchanger_bin = resolve_trusted_binary("macchanger")
        if not macchanger_bin:
            raise RuntimeError(
                "macchanger is not installed in trusted paths but --mac-randomize was requested. Aborting."
            )

        intf = self._get_primary_interface()
        if not intf:
            raise RuntimeError(
                "Could not determine primary network interface for MAC spoofing. Aborting."
            )

        original_mac = self._read_current_mac(intf)
        if not original_mac:
            raise RuntimeError(
                f"Could not read original hardware MAC for {intf}. Aborting to prevent permanent loss."
            )

        self._spoofed_intf = intf
        self._original_mac = original_mac
        self._persist_session_metadata()

        print(f"[*] Original MAC recorded: {original_mac} for interface: {intf}")
        print(f"[*] Randomizing MAC address for interface: {intf}...")

        ip_bin = require_trusted_binary("ip")
        try:
            run_trusted([ip_bin, "link", "set", intf, "down"], check=True)
            run_trusted([macchanger_bin, "-r", intf], check=True)
            run_trusted([ip_bin, "link", "set", intf, "up"], check=True)
            print("[+] MAC address randomized successfully. Renewing DHCP lease...")
            self._renew_dhcp(intf)
            time.sleep(4)
        except Exception as exc:
            run_trusted([ip_bin, "link", "set", intf, "up"], check=False)
            self._restore_mac()
            raise RuntimeError(f"Failed to randomize MAC on {intf}: {exc}. Reverted.") from exc

    def _restore_mac(self) -> None:
        """Restore original hardware MAC independently of macchanger (NT-011)."""
        intf = self._spoofed_intf
        original_mac = self._original_mac

        if not intf or not original_mac:
            meta = self._load_session_metadata()
            if meta:
                intf = intf or meta.get("spoofed_intf")
                original_mac = original_mac or meta.get("original_mac")

        if not intf or not original_mac:
            return

        print(f"[*] Restoring original MAC ({original_mac}) on interface {intf}...")
        ip_bin = require_trusted_binary("ip")

        try:
            run_trusted([ip_bin, "link", "set", intf, "down"], check=True)
            run_trusted([ip_bin, "link", "set", "dev", intf, "address", original_mac], check=True)
            run_trusted([ip_bin, "link", "set", intf, "up"], check=True)

            current_mac = self._read_current_mac(intf)
            if current_mac and current_mac.lower() != original_mac.lower():
                raise RuntimeError(
                    f"MAC verification mismatch: expected {original_mac}, actual {current_mac}"
                )

            print(f"[+] Original MAC {original_mac} verified restored.")
            self._renew_dhcp(intf)
            self._mac_restored = True
            self._persist_session_metadata()
        except Exception as exc:
            run_trusted([ip_bin, "link", "set", intf, "up"], check=False)
            raise RuntimeError(
                f"Failed to restore original MAC {original_mac} on {intf}: {exc}. "
                f"MANUAL ACTION: Run 'sudo ip link set dev {intf} address {original_mac}'"
            ) from exc

    def _excluded_destinations(self) -> List[str]:
        return list(self.config.excluded_ips) + list(self.config.excluded_networks)

    def _setup_custom_chains_v4(self) -> None:
        """
        Create and populate custom owned chains in filter, nat, and mangle tables (NT-003, NT-002, NT-009).
        Does NOT touch or flush base host tables!
        """
        iptables_bin = require_trusted_binary("iptables")

        # 1. NAT Table: Interception & Redirects
        # Create or flush custom NAT chain
        res = run_trusted([iptables_bin, "-t", "nat", "-N", CHAIN_NAT_OUTPUT], check=False)
        run_trusted([iptables_bin, "-t", "nat", "-F", CHAIN_NAT_OUTPUT], check=True)

        # Tor daemon bypass
        run_trusted([
            iptables_bin, "-t", "nat", "-A", CHAIN_NAT_OUTPUT,
            "-m", "owner", "--uid-owner", self.tor_user, "-j", "RETURN",
        ], check=True)

        # Intercept outbound UDP DNS (port 53) -> Tor DNSPort
        run_trusted([
            iptables_bin, "-t", "nat", "-A", CHAIN_NAT_OUTPUT,
            "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", self.config.dns_port,
        ], check=True)

        # NT-009: Outbound TCP DNS (port 53) bypass TransPort (it is rejected in filter)
        run_trusted([
            iptables_bin, "-t", "nat", "-A", CHAIN_NAT_OUTPUT,
            "-p", "tcp", "--dport", "53", "-j", "RETURN",
        ], check=True)

        # Loopback bypass
        run_trusted([
            iptables_bin, "-t", "nat", "-A", CHAIN_NAT_OUTPUT,
            "-o", "lo", "-j", "RETURN",
        ], check=True)

        # Excluded destinations bypass
        for net in self._excluded_destinations():
            run_trusted([
                iptables_bin, "-t", "nat", "-A", CHAIN_NAT_OUTPUT,
                "-d", net, "-j", "RETURN",
            ], check=True)

        # All other TCP redirected to Tor TransPort
        run_trusted([
            iptables_bin, "-t", "nat", "-A", CHAIN_NAT_OUTPUT,
            "-p", "tcp", "-j", "REDIRECT", "--to-ports", self.config.tor_port,
        ], check=True)

        # 2. Mangle Table: Conntrack Zone/Marking Isolation (NT-002)
        run_trusted([iptables_bin, "-t", "mangle", "-N", CHAIN_MANGLE_OUTPUT], check=False)
        run_trusted([iptables_bin, "-t", "mangle", "-F", CHAIN_MANGLE_OUTPUT], check=True)
        run_trusted([iptables_bin, "-t", "mangle", "-N", CHAIN_MANGLE_PREROUTING], check=False)
        run_trusted([iptables_bin, "-t", "mangle", "-F", CHAIN_MANGLE_PREROUTING], check=True)

        # Mark Tor daemon outbound flows and save connmark
        run_trusted([
            iptables_bin, "-t", "mangle", "-A", CHAIN_MANGLE_OUTPUT,
            "-m", "owner", "--uid-owner", self.tor_user, "-j", "MARK", "--set-mark", CONNMARK_TOR,
        ], check=True)
        run_trusted([
            iptables_bin, "-t", "mangle", "-A", CHAIN_MANGLE_OUTPUT,
            "-m", "mark", "--mark", CONNMARK_TOR, "-j", "CONNMARK", "--save-mark",
        ], check=True)

        # In PREROUTING, restore connmark so return packets for Tor have the mark
        run_trusted([
            iptables_bin, "-t", "mangle", "-A", CHAIN_MANGLE_PREROUTING,
            "-j", "CONNMARK", "--restore-mark",
        ], check=True)

        # 3. Filter Table: Strict Policy in Custom Chains
        for chain in (CHAIN_FILTER_OUTPUT, CHAIN_FILTER_INPUT, CHAIN_FILTER_FORWARD):
            run_trusted([iptables_bin, "-N", chain], check=False)
            run_trusted([iptables_bin, "-F", chain], check=True)

        # OUTPUT Rules:
        # Security drop for TCP teardown
        run_trusted([
            iptables_bin, "-A", CHAIN_FILTER_OUTPUT,
            "!", "-o", "lo", "!", "-d", self.config.localhost, "!", "-s", self.config.localhost,
            "-m", "owner", "!", "--uid-owner", self.tor_user,
            "-p", "tcp", "-m", "tcp", "--tcp-flags", "ACK,FIN", "ACK,FIN", "-j", "DROP",
        ], check=True)
        run_trusted([
            iptables_bin, "-A", CHAIN_FILTER_OUTPUT,
            "!", "-o", "lo", "!", "-d", self.config.localhost, "!", "-s", self.config.localhost,
            "-m", "owner", "!", "--uid-owner", self.tor_user,
            "-p", "tcp", "-m", "tcp", "--tcp-flags", "ACK,RST", "ACK,RST", "-j", "DROP",
        ], check=True)

        # Explicitly allowed egress
        run_trusted([iptables_bin, "-A", CHAIN_FILTER_OUTPUT, "-o", "lo", "-j", "ACCEPT"], check=True)
        run_trusted([iptables_bin, "-A", CHAIN_FILTER_OUTPUT, "-d", "127.0.0.0/8", "-j", "ACCEPT"], check=True)
        run_trusted([
            iptables_bin, "-A", CHAIN_FILTER_OUTPUT,
            "-m", "owner", "--uid-owner", self.tor_user, "-j", "ACCEPT",
        ], check=True)
        for net in self._excluded_destinations():
            run_trusted([iptables_bin, "-A", CHAIN_FILTER_OUTPUT, "-d", net, "-j", "ACCEPT"], check=True)

        # Allow DHCP requests outbound
        run_trusted([
            iptables_bin, "-A", CHAIN_FILTER_OUTPUT,
            "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT",
        ], check=False)

        # NT-009: Reject TCP port 53 with tcp-reset
        run_trusted([
            iptables_bin, "-A", CHAIN_FILTER_OUTPUT,
            "-p", "tcp", "--dport", "53", "-j", "REJECT", "--reject-with", "tcp-reset",
        ], check=True)

        # Block all other UDP and ICMP
        run_trusted([iptables_bin, "-A", CHAIN_FILTER_OUTPUT, "-p", "udp", "-j", "DROP"], check=True)
        run_trusted([iptables_bin, "-A", CHAIN_FILTER_OUTPUT, "-p", "icmp", "-j", "DROP"], check=True)

        # NT-002: Catch-all DROP in OUTPUT. Note: NO unconstrained ESTABLISHED,RELATED ACCEPT!
        # Pre-existing non-Tor TCP connections hit this DROP and cannot send data.
        run_trusted([iptables_bin, "-A", CHAIN_FILTER_OUTPUT, "-j", "DROP"], check=True)

        # INPUT Rules:
        run_trusted([iptables_bin, "-A", CHAIN_FILTER_INPUT, "-i", "lo", "-j", "ACCEPT"], check=True)
        # NT-002: Accept established packets ONLY if they belong to Tor (marked)
        run_trusted([
            iptables_bin, "-A", CHAIN_FILTER_INPUT,
            "-m", "mark", "--mark", CONNMARK_TOR, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
            "-j", "ACCEPT",
        ], check=True)
        # Allow DHCP lease renewal inbound
        run_trusted([
            iptables_bin, "-A", CHAIN_FILTER_INPUT,
            "-p", "udp", "--sport", "67", "--dport", "68", "-j", "ACCEPT",
        ], check=False)
        for net in self.config.excluded_networks:
            run_trusted([iptables_bin, "-A", CHAIN_FILTER_INPUT, "-s", net, "-j", "ACCEPT"], check=True)
        run_trusted([iptables_bin, "-A", CHAIN_FILTER_INPUT, "-j", "DROP"], check=True)

        # FORWARD Rules:
        run_trusted([iptables_bin, "-A", CHAIN_FILTER_FORWARD, "-j", "DROP"], check=True)

    def _setup_custom_chains_v6(self) -> None:
        """
        Fail-closed IPv6 lockdown using custom owned chains (NT-001, NT-002, NT-003).
        All commands use check=True and abort startup if any fails.
        """
        if not self._check_ipv6_enabled():
            return

        ip6tables_bin = resolve_trusted_binary("ip6tables")
        if not ip6tables_bin:
            raise RuntimeError(
                "IPv6 is enabled on host but ip6tables is missing. Aborting to prevent IPv6 leak."
            )

        # 1. Mangle Table: Conntrack Zone/Marking Isolation for Tor IPv6 (NT-002)
        run_trusted([ip6tables_bin, "-t", "mangle", "-N", CHAIN_V6_MANGLE_OUTPUT], check=False)
        run_trusted([ip6tables_bin, "-t", "mangle", "-F", CHAIN_V6_MANGLE_OUTPUT], check=True)
        run_trusted([ip6tables_bin, "-t", "mangle", "-N", CHAIN_V6_MANGLE_PREROUTING], check=False)
        run_trusted([ip6tables_bin, "-t", "mangle", "-F", CHAIN_V6_MANGLE_PREROUTING], check=True)

        # Mark Tor daemon outbound flows and save connmark
        run_trusted([
            ip6tables_bin, "-t", "mangle", "-A", CHAIN_V6_MANGLE_OUTPUT,
            "-m", "owner", "--uid-owner", self.tor_user, "-j", "MARK", "--set-mark", CONNMARK_TOR,
        ], check=True)
        run_trusted([
            ip6tables_bin, "-t", "mangle", "-A", CHAIN_V6_MANGLE_OUTPUT,
            "-m", "mark", "--mark", CONNMARK_TOR, "-j", "CONNMARK", "--save-mark",
        ], check=True)
        run_trusted([
            ip6tables_bin, "-t", "mangle", "-A", CHAIN_V6_MANGLE_PREROUTING,
            "-j", "CONNMARK", "--restore-mark",
        ], check=True)

        # 2. Filter Table
        for chain in (CHAIN_V6_OUTPUT, CHAIN_V6_INPUT, CHAIN_V6_FORWARD):
            run_trusted([ip6tables_bin, "-N", chain], check=False)
            run_trusted([ip6tables_bin, "-F", chain], check=True)

        # OUTPUT: allow loopback, ICMPv6 neighbor discovery, Tor daemon; reject all else
        run_trusted([ip6tables_bin, "-A", CHAIN_V6_OUTPUT, "-o", "lo", "-j", "ACCEPT"], check=True)
        for icmp6_type in ("router-solicitation", "router-advertisement", "neighbor-solicitation", "neighbor-advertisement"):
            run_trusted([
                ip6tables_bin, "-A", CHAIN_V6_OUTPUT,
                "-p", "ipv6-icmp", "--icmpv6-type", icmp6_type, "-j", "ACCEPT",
            ], check=True)
        run_trusted([
            ip6tables_bin, "-A", CHAIN_V6_OUTPUT,
            "-m", "owner", "--uid-owner", self.tor_user, "-j", "ACCEPT",
        ], check=True)
        run_trusted([
            ip6tables_bin, "-A", CHAIN_V6_OUTPUT,
            "-j", "REJECT", "--reject-with", "icmp6-port-unreachable",
        ], check=True)

        # INPUT: loopback, neighbor discovery, Tor replies
        run_trusted([ip6tables_bin, "-A", CHAIN_V6_INPUT, "-i", "lo", "-j", "ACCEPT"], check=True)
        for icmp6_type in ("router-solicitation", "router-advertisement", "neighbor-solicitation", "neighbor-advertisement"):
            run_trusted([
                ip6tables_bin, "-A", CHAIN_V6_INPUT,
                "-p", "ipv6-icmp", "--icmpv6-type", icmp6_type, "-j", "ACCEPT",
            ], check=True)
        # NT-002: Accept established packets ONLY if they belong to Tor daemon (marked)
        run_trusted([
            ip6tables_bin, "-A", CHAIN_V6_INPUT,
            "-m", "mark", "--mark", CONNMARK_TOR, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
            "-j", "ACCEPT",
        ], check=True)
        run_trusted([ip6tables_bin, "-A", CHAIN_V6_INPUT, "-j", "DROP"], check=True)

        # FORWARD
        run_trusted([ip6tables_bin, "-A", CHAIN_V6_FORWARD, "-j", "DROP"], check=True)

    def _activate_jump_rules(self) -> None:
        """Atomically insert jumps to custom chains at top of base chains (NT-003)."""
        iptables_bin = require_trusted_binary("iptables")

        # Flush kernel conntrack table if conntrack tool is present (NT-002)
        conntrack_bin = resolve_trusted_binary("conntrack")
        if conntrack_bin:
            run_trusted([conntrack_bin, "-F"], check=False)

        # Insert jumps in top of chains
        run_trusted([iptables_bin, "-I", "OUTPUT", "1", "-j", CHAIN_FILTER_OUTPUT], check=True)
        run_trusted([iptables_bin, "-I", "INPUT", "1", "-j", CHAIN_FILTER_INPUT], check=True)
        run_trusted([iptables_bin, "-I", "FORWARD", "1", "-j", CHAIN_FILTER_FORWARD], check=True)

        run_trusted([iptables_bin, "-t", "nat", "-I", "OUTPUT", "1", "-j", CHAIN_NAT_OUTPUT], check=True)
        run_trusted([iptables_bin, "-t", "mangle", "-I", "OUTPUT", "1", "-j", CHAIN_MANGLE_OUTPUT], check=True)
        run_trusted([iptables_bin, "-t", "mangle", "-I", "PREROUTING", "1", "-j", CHAIN_MANGLE_PREROUTING], check=True)

        if self._check_ipv6_enabled():
            ip6tables_bin = resolve_trusted_binary("ip6tables")
            if not ip6tables_bin:
                raise RuntimeError(
                    "IPv6 is enabled on host but ip6tables is missing. Aborting to prevent IPv6 leak."
                )
            run_trusted([ip6tables_bin, "-I", "OUTPUT", "1", "-j", CHAIN_V6_OUTPUT], check=True)
            run_trusted([ip6tables_bin, "-I", "INPUT", "1", "-j", CHAIN_V6_INPUT], check=True)
            run_trusted([ip6tables_bin, "-I", "FORWARD", "1", "-j", CHAIN_V6_FORWARD], check=True)
            run_trusted([ip6tables_bin, "-t", "mangle", "-I", "OUTPUT", "1", "-j", CHAIN_V6_MANGLE_OUTPUT], check=True)
            run_trusted([ip6tables_bin, "-t", "mangle", "-I", "PREROUTING", "1", "-j", CHAIN_V6_MANGLE_PREROUTING], check=True)

    def _deactivate_jump_rules(self) -> None:
        """Remove top-level jump rules to owned custom chains (NT-003)."""
        iptables_bin = resolve_trusted_binary("iptables")
        if iptables_bin:
            # Delete jumps in reverse order
            for _ in range(5):
                run_trusted([iptables_bin, "-D", "OUTPUT", "-j", CHAIN_FILTER_OUTPUT], check=False)
                run_trusted([iptables_bin, "-D", "INPUT", "-j", CHAIN_FILTER_INPUT], check=False)
                run_trusted([iptables_bin, "-D", "FORWARD", "-j", CHAIN_FILTER_FORWARD], check=False)

                run_trusted([iptables_bin, "-t", "nat", "-D", "OUTPUT", "-j", CHAIN_NAT_OUTPUT], check=False)
                run_trusted([iptables_bin, "-t", "mangle", "-D", "OUTPUT", "-j", CHAIN_MANGLE_OUTPUT], check=False)
                run_trusted([iptables_bin, "-t", "mangle", "-D", "PREROUTING", "-j", CHAIN_MANGLE_PREROUTING], check=False)

        ip6tables_bin = resolve_trusted_binary("ip6tables")
        if ip6tables_bin:
            for _ in range(5):
                run_trusted([ip6tables_bin, "-D", "OUTPUT", "-j", CHAIN_V6_OUTPUT], check=False)
                run_trusted([ip6tables_bin, "-D", "INPUT", "-j", CHAIN_V6_INPUT], check=False)
                run_trusted([ip6tables_bin, "-D", "FORWARD", "-j", CHAIN_V6_FORWARD], check=False)
                run_trusted([ip6tables_bin, "-t", "mangle", "-D", "OUTPUT", "-j", CHAIN_V6_MANGLE_OUTPUT], check=False)
                run_trusted([ip6tables_bin, "-t", "mangle", "-D", "PREROUTING", "-j", CHAIN_V6_MANGLE_PREROUTING], check=False)

    def _destroy_custom_chains(self) -> None:
        """Flush and delete owned custom chains (NT-003)."""
        iptables_bin = resolve_trusted_binary("iptables")
        if iptables_bin:
            for chain in (CHAIN_FILTER_OUTPUT, CHAIN_FILTER_INPUT, CHAIN_FILTER_FORWARD):
                run_trusted([iptables_bin, "-F", chain], check=False)
                run_trusted([iptables_bin, "-X", chain], check=False)
            run_trusted([iptables_bin, "-t", "nat", "-F", CHAIN_NAT_OUTPUT], check=False)
            run_trusted([iptables_bin, "-t", "nat", "-X", CHAIN_NAT_OUTPUT], check=False)
            run_trusted([iptables_bin, "-t", "mangle", "-F", CHAIN_MANGLE_OUTPUT], check=False)
            run_trusted([iptables_bin, "-t", "mangle", "-X", CHAIN_MANGLE_OUTPUT], check=False)
            run_trusted([iptables_bin, "-t", "mangle", "-F", CHAIN_MANGLE_PREROUTING], check=False)
            run_trusted([iptables_bin, "-t", "mangle", "-X", CHAIN_MANGLE_PREROUTING], check=False)

        ip6tables_bin = resolve_trusted_binary("ip6tables")
        if ip6tables_bin:
            for chain in (CHAIN_V6_OUTPUT, CHAIN_V6_INPUT, CHAIN_V6_FORWARD):
                run_trusted([ip6tables_bin, "-F", chain], check=False)
                run_trusted([ip6tables_bin, "-X", chain], check=False)
            run_trusted([ip6tables_bin, "-t", "mangle", "-F", CHAIN_V6_MANGLE_OUTPUT], check=False)
            run_trusted([ip6tables_bin, "-t", "mangle", "-X", CHAIN_V6_MANGLE_OUTPUT], check=False)
            run_trusted([ip6tables_bin, "-t", "mangle", "-F", CHAIN_V6_MANGLE_PREROUTING], check=False)
            run_trusted([ip6tables_bin, "-t", "mangle", "-X", CHAIN_V6_MANGLE_PREROUTING], check=False)

    def _verify_firewall_teardown(self) -> None:
        """Verify that all owned custom chains and jump rules have been removed (NT-003, NT-004)."""
        iptables_bin = resolve_trusted_binary("iptables")
        remaining: List[str] = []
        if iptables_bin:
            for table in ("filter", "nat", "mangle"):
                try:
                    res = run_trusted([iptables_bin, "-t", table, "-S"], check=False)
                    if res.returncode == 0:
                        for line in res.stdout.splitlines():
                            if any(c in line for c in (CHAIN_FILTER_OUTPUT, CHAIN_FILTER_INPUT, CHAIN_FILTER_FORWARD,
                                                       CHAIN_NAT_OUTPUT, CHAIN_MANGLE_OUTPUT, CHAIN_MANGLE_PREROUTING)):
                                remaining.append(f"IPv4 {table}: {line.strip()}")
                except OSError:
                    pass

        ip6tables_bin = resolve_trusted_binary("ip6tables")
        if ip6tables_bin:
            for table in ("filter", "mangle"):
                try:
                    res = run_trusted([ip6tables_bin, "-t", table, "-S"], check=False)
                    if res.returncode == 0:
                        for line in res.stdout.splitlines():
                            if any(c in line for c in (CHAIN_V6_OUTPUT, CHAIN_V6_INPUT, CHAIN_V6_FORWARD,
                                                       CHAIN_V6_MANGLE_OUTPUT, CHAIN_V6_MANGLE_PREROUTING)):
                                remaining.append(f"IPv6 {table}: {line.strip()}")
                except OSError:
                    pass

        if remaining:
            raise RuntimeError(f"Firewall custom rules or jumps remain active: {'; '.join(remaining[:5])}")

    def _rollback_startup(self) -> None:
        """Cleanly rollback all changes if startup fails at any point (NT-001, NT-003, NT-004)."""
        failures: List[str] = []
        try:
            self._deactivate_jump_rules()
            self._destroy_custom_chains()
            self._verify_firewall_teardown()
        except Exception as exc:
            failures.append(f"Rollback firewall teardown failed: {exc}")

        if self.mac_randomize:
            try:
                self._restore_mac()
            except Exception as exc:
                failures.append(f"Rollback MAC restoration failed: {exc}")

        try:
            self.restore_tor_config()
        except Exception as exc:
            failures.append(f"Rollback Tor config restoration failed: {exc}")

        if failures:
            self._restore_failures = failures
            self._set_state(STATE_RESTORE_FAILED)
            print("[!] CRITICAL: Rollback encountered errors. System marked RESTORE_FAILED.")
            for f in failures:
                print(f"    - {f}")
        else:
            self._restore_failures = []
            self._set_state(STATE_INACTIVE)

    def setup_network_rules(self) -> None:
        """
        Transactional activation of nulltrace privacy routing (NT-001, NT-002, NT-003, NT-004).
        """
        require_linux_root("configure network routing")
        self._acquire_lock()
        try:
            existing = self._load_session_metadata()
            current_state = self._get_current_state()
            if current_state in (STATE_ACTIVE, STATE_ACTIVATING, STATE_RESTORING) or (
                existing and existing.get("state") in (STATE_ACTIVE, STATE_ACTIVATING, STATE_RESTORING)
            ):
                raise RuntimeError(
                    f"nulltrace is already active or in an uncleaned state ({current_state}). "
                    "Run 'sudo nulltrace --stop' first."
                )
            if current_state == STATE_RESTORE_FAILED or (existing and existing.get("state") == STATE_RESTORE_FAILED):
                raise RuntimeError(
                    "nulltrace is in RESTORE_FAILED state from a previous run. "
                    "Run 'sudo nulltrace --stop' or recover manually before starting."
                )

            self.validate_network_config()
            self.validate_circuit_time(self.circuit_time)

            self._session_created_at = datetime.now().isoformat()
            self._set_state(STATE_ACTIVATING)

            # Signal handler for clean rollback on interruption (NT-003)
            def _sig_handler(signum, frame):
                print(f"\n[!] Interrupted by signal {signum}. Rolling back...")
                self._rollback_startup()
                sys.exit(128 + signum)

            signal.signal(signal.SIGINT, _sig_handler)
            signal.signal(signal.SIGTERM, _sig_handler)

            print("[*] Backing up network and Tor configuration...")
            self.backup_iptables()

            if self.mac_randomize:
                self._randomize_mac()

            print("[*] Applying Tor configuration...")
            self.apply_tor_config()

            print("[*] Constructing transactional firewall chains...")
            self._setup_custom_chains_v4()
            self._setup_custom_chains_v6()

            print("[*] Activating privacy routing...")
            self._activate_jump_rules()

            # Mark state ACTIVE only after complete verification
            self._set_state(STATE_ACTIVE)
            print("[+] Privacy routing enabled (TCP transparent proxy, UDP/53 DNS to Tor, IPv6 blocked)")
        except Exception:
            print("\n[!] Startup failure encountered. Executing fail-closed rollback...")
            self._rollback_startup()
            raise
        finally:
            self._release_lock()

    def stop_privacy_mode(self, force: bool = False) -> None:
        """
        Teardown state machine: ACTIVE -> RESTORING -> INACTIVE or RESTORE_FAILED (NT-004).
        Never clears state if any restoration step fails; preserves recovery artifacts.
        """
        require_linux_root("restore network routing")
        self._acquire_lock()
        try:
            current_state = self._get_current_state()
            existing = self._load_session_metadata()

            if (
                current_state not in (STATE_ACTIVE, STATE_ACTIVATING, STATE_RESTORING, STATE_RESTORE_FAILED)
                and not force
                and not (existing and existing.get("state") in (STATE_ACTIVE, STATE_ACTIVATING, STATE_RESTORING, STATE_RESTORE_FAILED))
            ):
                raise RuntimeError(
                    "nulltrace is not active. Use --force-stop to restore from backup if needed."
                )

            self._set_state(STATE_RESTORING)
            failures: List[str] = []

            # 1. Restore MAC (NT-011)
            try:
                self._restore_mac()
            except Exception as exc:
                msg = f"MAC address restoration failed: {exc}"
                print(f"[!] {msg}")
                failures.append(msg)

            # 2. Deactivate and destroy firewall custom chains (NT-003, NT-004)
            try:
                self._deactivate_jump_rules()
                self._destroy_custom_chains()
                self._verify_firewall_teardown()
            except Exception as exc:
                msg = f"Firewall custom chain teardown failed: {exc}"
                print(f"[!] {msg}")
                failures.append(msg)
                # Attempt restore from session backup if custom teardown was incomplete
                print(f"[!] Attempting iptables restore from session backup...")
                try:
                    self.restore_iptables_from_backup()
                except Exception as restore_exc:
                    print(f"[!] Firewall backup restoration failed: {restore_exc}")

            # 3. Restore Tor configuration (NT-014, NT-015)
            try:
                self.restore_tor_config()
            except Exception as exc:
                msg = f"Tor configuration restoration failed: {exc}"
                print(f"[!] {msg}")
                failures.append(msg)

            if failures:
                self._restore_failures = failures
                self._set_state(STATE_RESTORE_FAILED)
                print("\n[!] CRITICAL: Restoration failed on one or more components.")
                print("    System state marked RESTORE_FAILED. Backups have been preserved.")
                for f in failures:
                    print(f"    - {f}")
                print(f"    Recovery record saved: {self._session_dir() / 'metadata.json'}")
                raise RuntimeError(f"Teardown incomplete ({len(failures)} failures). State: RESTORE_FAILED.")

            # Complete success: mark INACTIVE
            self._restore_failures = []
            self._set_state(STATE_INACTIVE)
            print("[+] Privacy mode deactivated successfully. System networking restored.")
        finally:
            self._release_lock()

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
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line.startswith("nameserver"):
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                ns = parts[1]
                if self.is_valid_loopback_ip(ns) or ns in ("127.0.0.53",):
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
        current_state = self._get_current_state()

        if config_issues:
            print("[!] WARNING: External DNS servers configured in resolv.conf:")
            for issue in config_issues:
                print(f"    - {issue}")
            print("    When nulltrace is active, UDP queries are transparently forced to Tor DNSPort.")
            print("    For defense-in-depth, configure /etc/resolv.conf nameserver to 127.0.0.1.")
        else:
            print("[+] resolv.conf looks OK (no external nameservers found)")

        # Verify DNSPort responsiveness
        if self._probe_dns_port():
            print("[+] Tor DNSPort is responding correctly to DNS queries.")
        else:
            print("[!] Tor DNSPort is not responding to DNS queries.")

        if current_state != STATE_ACTIVE:
            print("[!] Privacy routing is currently INACTIVE (run: sudo nulltrace --start)")
        else:
            print("[+] Privacy routing is ACTIVE (All DNS UDP traffic is forced through Tor)")

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
            print("[!] Note: Run with 'sudo' for complete privileged state verification.")

        current_state = self._get_current_state()
        tor_running = self.check_tor_service()
        tor_ports_ok = self.check_tor_ports() if tor_running else False

        print("\n[*] nulltrace Status")
        print(f"    Session State: {current_state}")
        print(f"    Tor Service: {'running' if tor_running else 'stopped'}")
        print(f"    Tor Ports (TransPort/DNSPort): {'healthy' if tor_ports_ok else 'unhealthy/unreachable'}")
        print(f"    Privacy Routing: {'active' if current_state == STATE_ACTIVE else 'inactive'}")

        if current_state in (STATE_ACTIVATING, STATE_RESTORING):
            print(f"\n[!] WARNING: System is in intermediate session state: {current_state}!")
            print("    This indicates a previous run crashed or was interrupted.")
            print("    RECOVERY: Run 'sudo nulltrace --stop' or 'sudo nulltrace --recover' to restore networking.")
            return

        if current_state == STATE_RESTORE_FAILED:
            print("\n[!] CRITICAL: System is in RESTORE_FAILED state!")
            meta = self._load_session_metadata()
            if meta and meta.get("failures"):
                print("    Failed components during last stop attempt:")
                for f in meta["failures"]:
                    print(f"      - {f}")
            print("    RECOVERY: Run 'sudo nulltrace --stop' or 'sudo nulltrace --recover' to retry restoration.")
            return

        if current_state == STATE_ACTIVE:
            try:
                self.show_current_ip()
            except RuntimeError as exc:
                print(f"    IP check: {exc}")

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

    def change_ip_address(self) -> None:
        require_linux_root("signal Tor for new identity")
        if self._tor_control_newnym():
            time.sleep(5)
            self.show_current_ip()
            return

        pkill_bin = resolve_trusted_binary("pkill")
        if pkill_bin:
            for name in ("tor", "tor.real"):
                res = run_trusted([pkill_bin, "-HUP", "-x", name], check=False)
                if res.returncode == 0:
                    time.sleep(5)
                    self.show_current_ip()
                    return

        raise RuntimeError("Tor process not found to signal new identity")


def build_parser() -> ArgumentParser:
    parser = ArgumentParser(
        description="nulltrace - Route system traffic through Tor with hardened fail-closed security",
    )
    parser.add_argument("-s", "--start", action="store_true", help="Start Tor routing")
    parser.add_argument("-x", "--stop", action="store_true", help="Stop Tor routing and restore rules")
    parser.add_argument(
        "--force-stop",
        action="store_true",
        help="Force teardown even if state file reports inactive",
    )
    parser.add_argument(
        "--recover",
        action="store_true",
        help="Recover system state from persistent metadata and session backups",
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
        help="Load configuration from ~/.config/nulltrace/",
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
        "stop": args.stop or args.force_stop or args.recover,
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
            success = app.save_config(args.save)
            sys.exit(0 if success else 1)

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
            app.stop_privacy_mode(force=args.force_stop or args.recover)
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
                print("\n[!] Auto loop interrupted by user.")
                try:
                    choice = input("[?] Restore normal networking now? [Y/n]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    choice = "y"
                if choice not in ("n", "no"):
                    app.stop_privacy_mode()
                else:
                    print("[*] Privacy routing remains ACTIVE. To restore later, run: sudo nulltrace --stop")
        else:
            parser.print_help()
    except (PermissionError, OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"[!] Error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
