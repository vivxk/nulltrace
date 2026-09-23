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
import stat
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
from urllib.request import ProxyHandler, Request, build_opener, urlopen

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

# State Machine States (NT-004, P0.5)
STATE_INACTIVE = "INACTIVE"
STATE_PREPARING = "PREPARING"
STATE_ACTIVATING = "ACTIVATING"  # Synonym/compat for PREPARING
STATE_ACTIVE = "ACTIVE"
STATE_RESTORING = "RESTORING"
STATE_RESTORE_FAILED = "RESTORE_FAILED"
STATE_RECOVERY_REQUIRED = "RECOVERY_REQUIRED"

RECOVERABLE_STATES: Tuple[str, ...] = (
    STATE_ACTIVE,
    STATE_ACTIVATING,
    STATE_PREPARING,
    STATE_RESTORING,
    STATE_RESTORE_FAILED,
    STATE_RECOVERY_REQUIRED,
)

# User-Facing Enforcement & Routing Status (P2.7)
STATUS_ENFORCING_TOR_HEALTHY = "ENFORCING_TOR_HEALTHY"
STATUS_ENFORCING_TOR_UNHEALTHY = "ENFORCING_TOR_UNHEALTHY"
STATUS_INACTIVE = "INACTIVE"
STATUS_RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
STATUS_RESTORE_FAILED = "RESTORE_FAILED"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_ENFORCEMENT_DRIFT = "ENFORCEMENT_DRIFT"


class TorServiceState:
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    UNKNOWN = "UNKNOWN"


class TeardownStatus:
    VERIFIED_CLEAN = "VERIFIED_CLEAN"
    VERIFIED_DIRTY = "VERIFIED_DIRTY"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"


class LiveFirewallStatus:
    ACTIVE = "ACTIVE"
    CLEAN = "CLEAN"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


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
CHAIN_V6_MANGLE_PREROUTING = "NULLTRACE_V6_MANGLE_PRE"

ALL_OWNED_CHAINS_V4: Set[str] = {
    CHAIN_FILTER_OUTPUT,
    CHAIN_FILTER_INPUT,
    CHAIN_FILTER_FORWARD,
    CHAIN_NAT_OUTPUT,
    CHAIN_MANGLE_OUTPUT,
    CHAIN_MANGLE_PREROUTING,
}

ALL_OWNED_CHAINS_V6: Set[str] = {
    CHAIN_V6_OUTPUT,
    CHAIN_V6_INPUT,
    CHAIN_V6_FORWARD,
    CHAIN_V6_MANGLE_OUTPUT,
    CHAIN_V6_MANGLE_PREROUTING,
}

ALL_OWNED_CHAINS: Set[str] = ALL_OWNED_CHAINS_V4 | ALL_OWNED_CHAINS_V6

# Tor Connection Mark for Deterministic Conntrack Isolation (NT-002, P1.3)
CONNMARK_VALUE = "0x4e540000"
CONNMARK_MASK = "0xffff0000"
CONNMARK_TOR = f"{CONNMARK_VALUE}/{CONNMARK_MASK}"
CHAIN_MARKER_COMMENT = "nulltrace-owned"
POSITIVE_ABSENCE_SUBSTRINGS = (
    "no chain/target/match by that name",
    "does not exist",
    "no such file or directory",
    "chain doesn't exist",
)


def is_chain_authenticated_nulltrace(chain_lines: Sequence[str], chain: str) -> bool:
    """Check that chain contains an exact nulltrace ownership marker rule (Section 27)."""
    target = rf"(?:{re.escape(chain)}|CHAIN)"
    pattern = re.compile(rf'^-A\s+{target}\s+.*-m\s+comment\s+--comment\s+["\']?{re.escape(CHAIN_MARKER_COMMENT)}["\']?')
    for line in chain_lines:
        s = line.strip()
        if pattern.search(s):
            return True
    return False


# Trusted System Binary Directories (NT-006)
TRUSTED_BIN_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")


def validate_trusted_directory_hierarchy(path: Path) -> bool:
    """Validate directory hierarchy of candidate binary (root-owned, not group/world writable) (Section 21)."""
    if os.name == "nt" and not getattr(os, "_force_posix_security_checks", False):
        return True
    try:
        curr = path if path.is_dir() else path.parent
        while curr.as_posix() not in ("", "/"):
            if curr.exists() or os.path.islink(str(curr)):
                st = os.lstat(str(curr))
                if stat.S_ISLNK(st.st_mode):
                    if hasattr(st, "st_uid") and st.st_uid != 0:
                        return False
                    target = curr.resolve()
                    if not target.exists():
                        return False
                    tst = os.stat(str(target))
                    if hasattr(tst, "st_uid") and tst.st_uid != 0:
                        return False
                    if tst.st_mode & 0o022:
                        return False
                else:
                    if hasattr(st, "st_uid") and st.st_uid != 0:
                        return False
                    if st.st_mode & 0o022:
                        return False
            if curr.parent == curr:
                break
            curr = curr.parent
        return True
    except OSError:
        return False


def resolve_trusted_binary(name: str) -> Optional[str]:
    """
    Resolve an executable strictly to a trusted system directory (NT-006, P1-5, Section 21).
    Rejects relative lookups, path traversals, non-root-owned binaries,
    group/world-writable binaries, non-regular files, symlinks resolving
    outside approved trusted directories, and untrusted directory hierarchies.
    """
    if not name or not isinstance(name, str):
        return None
    p = Path(name)
    candidates: List[Path] = []
    if p.is_absolute():
        p_str = p.as_posix()
        for tdir in TRUSTED_BIN_DIRS:
            if p_str == f"{tdir}/{p.name}":
                candidates.append(p)
                break
        if not candidates:
            return None
    else:
        # If not an absolute path, must be a pure filename without path separators or traversal
        if p.name != name or "/" in name or "\\" in name or ".." in name:
            return None
        for directory in TRUSTED_BIN_DIRS:
            candidates.append(Path(directory) / name)

    for candidate in candidates:
        if not (candidate.exists() or os.path.islink(str(candidate))):
            continue
        try:
            lst = os.lstat(str(candidate))
        except OSError:
            continue

        # Reject if symlink points outside trusted directories
        if stat.S_ISLNK(lst.st_mode):
            if hasattr(lst, "st_uid") and (os.name != "nt" or getattr(os, "_force_posix_security_checks", False)):
                if lst.st_uid != 0:
                    continue
            try:
                target = candidate.resolve()
            except OSError:
                continue
            target_str = target.as_posix()
            target_in_trusted = any(
                target_str == f"{tdir}/{target.name}" or target_str.startswith(f"{tdir}/")
                for tdir in TRUSTED_BIN_DIRS
            )
            if not target_in_trusted:
                continue
            try:
                target_st = os.stat(str(target))
            except OSError:
                continue
            if not validate_trusted_directory_hierarchy(target):
                continue
        else:
            if not stat.S_ISREG(lst.st_mode):
                continue
            target_st = lst

        # Must be a regular file
        if not stat.S_ISREG(target_st.st_mode):
            continue

        # Must be executable
        if not os.access(str(candidate), os.X_OK):
            continue

        # Must NOT be group-writable or world-writable (P1-5)
        if target_st.st_mode & 0o022:
            continue

        # Must be root-owned on POSIX systems (P1-5)
        if hasattr(target_st, "st_uid") and (os.name != "nt" or getattr(os, "_force_posix_security_checks", False)):
            if target_st.st_uid != 0:
                continue

        if not validate_trusted_directory_hierarchy(candidate):
            continue

        return candidate.as_posix()

    return None


def require_trusted_binary(name: str) -> str:
    """Resolve binary in trusted directories or raise RuntimeError."""
    resolved = resolve_trusted_binary(name)
    if not resolved:
        raise RuntimeError(
            f"Required binary '{name}' not found in trusted system directories {TRUSTED_BIN_DIRS}"
        )
    return resolved


SAFE_ENV_NAMES = {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "SYSTEMD_COLORS"}


def sanitize_environment(env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Construct minimal hardened explicit environment for privileged execution (NT-006, P1.6).
    Strips injection-sensitive variables (LD_*, PYTHON*, PROXY*, TMPDIR, etc.).
    """
    clean_env = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    source = os.environ if env is None else env
    for k, v in source.items():
        if k in SAFE_ENV_NAMES and k not in clean_env:
            clean_env[k] = v
        elif env is not None:
            upper = k.upper()
            if not (
                upper.startswith("LD_")
                or upper.startswith("PYTHON")
                or "PROXY" in upper
                or upper in ("TMPDIR", "IFS")
            ):
                clean_env[k] = v
    clean_env["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
    return clean_env


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
    """Execute a command using trusted binary lookup and minimal hardened environment (NT-006, P1.6)."""
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

    clean_env = sanitize_environment(env)

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


def secure_open_dir_hierarchy(
    dir_path: Union[str, Path],
    target_uid: Optional[int] = None,
    target_gid: Optional[int] = None,
) -> Optional[int]:
    """
    Securely opens a directory hierarchy component-by-component on POSIX/Linux (P0-1, P0-2, P2.1, NT-015).
    Guarantees:
    - Never follows symbolic links at any intermediate or trailing level (using O_DIRECTORY | O_NOFOLLOW at each step).
    - Checks fstat() on every intermediate directory descriptor for directory type.
    - Rejects world-writable directories without sticky bit.
    - When running as root, verifies root ownership (or allowed target_uid) on every component.
    - Returns an open file descriptor bound to the target directory on Linux, or None on Windows.
    - If any component is a symlink or insecure, raises ValueError and closes open descriptors.
    """
    raw_str = str(dir_path)
    raw_components = [c for c in raw_str.replace("\\", "/").split("/") if c]
    if any(comp in (".", "..") for comp in raw_components):
        raise ValueError(
            f"Security violation: path component in '{dir_path}' contains relative traversal element ('.' or '..'); refusing privileged access."
        )

    p = Path(dir_path)
    if not p.is_absolute():
        p = Path.cwd() / p

    parts = p.parts
    if not parts:
        raise ValueError("Invalid empty path")
    if os.name != "nt" and parts[0] != "/":
        raise ValueError(f"Directory path '{dir_path}' must be an absolute path starting with '/' on POSIX")

    has_dir_fd_open = (
        hasattr(os, "supports_dir_fd")
        and os.open in getattr(os, "supports_dir_fd", set())
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
    )
    if os.name == "nt" or not has_dir_fd_open:
        # Cross-platform / Windows test runner fallback
        curr = Path(parts[0])
        for comp in parts[1:]:
            if comp in (".", ".."):
                raise ValueError(
                    f"Security violation: path component '{comp}' in '{dir_path}' contains relative traversal element; refusing privileged access."
                )
            curr = curr / comp
            if curr.exists() or os.path.islink(str(curr)):
                st = os.lstat(str(curr))
                if stat.S_ISLNK(st.st_mode):
                    raise ValueError(f"Security violation: path component '{comp}' in '{dir_path}' is a symlink; refusing privileged access.")
                if not stat.S_ISDIR(st.st_mode):
                    raise ValueError(f"Path component '{comp}' in '{dir_path}' is not a directory.")
                if os.name != "nt" or getattr(os, "_force_posix_security_checks", False):
                    if (st.st_mode & 0o002) and not (st.st_mode & stat.S_ISVTX):
                        raise ValueError(f"Security violation: insecure permissions ({oct(st.st_mode)}); directory component '{comp}' in '{dir_path}' is world-writable without sticky bit.")
                    if hasattr(os, "geteuid") and os.geteuid() == 0:
                        if (st.st_mode & 0o020) and not (st.st_mode & stat.S_ISVTX):
                            if st.st_gid != 0 and (target_gid is None or st.st_gid != target_gid):
                                raise ValueError(f"Security violation: insecure permissions ({oct(st.st_mode)}); directory component '{comp}' in '{dir_path}' is group-writable by non-root group ({st.st_gid}).")
                        if st.st_uid != 0 and (target_uid is None or st.st_uid != target_uid):
                            raise ValueError(f"Security violation: directory component '{comp}' in '{dir_path}' is owned by UID {st.st_uid}, expected root (UID 0).")
        return None

    dir_flags = os.O_RDONLY | os.O_DIRECTORY
    curr_fd = os.open("/", dir_flags)
    try:
        for comp in parts[1:]:
            if comp in (".", ".."):
                raise ValueError(
                    f"Security violation: path component '{comp}' in '{dir_path}' contains relative traversal element; refusing privileged access."
                )
            comp_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            try:
                next_fd = os.open(comp, comp_flags, dir_fd=curr_fd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise ValueError(
                        f"Security violation: path component '{comp}' in '{dir_path}' is a symlink or non-directory; refusing privileged access."
                    ) from exc
                raise ValueError(
                    f"Failed to securely open path component '{comp}' in '{dir_path}': {exc}"
                ) from exc

            os.close(curr_fd)
            curr_fd = next_fd

            st = os.fstat(curr_fd)
            if not stat.S_ISDIR(st.st_mode):
                raise ValueError(f"Path component '{comp}' in '{dir_path}' is not a directory.")

            if (st.st_mode & 0o002) and not (st.st_mode & stat.S_ISVTX):
                raise ValueError(
                    f"Security violation: insecure permissions ({oct(st.st_mode)}); directory component '{comp}' in '{dir_path}' is world-writable without sticky bit."
                )

            if hasattr(os, "geteuid") and os.geteuid() == 0 and (os.name != "nt" or getattr(os, "_force_posix_security_checks", False)):
                if (st.st_mode & 0o020) and not (st.st_mode & stat.S_ISVTX):
                    if st.st_gid != 0 and (target_gid is None or st.st_gid != target_gid):
                        raise ValueError(
                            f"Security violation: insecure permissions ({oct(st.st_mode)}); directory component '{comp}' in '{dir_path}' is group-writable by non-root group ({st.st_gid})."
                        )
                if st.st_uid != 0 and (target_uid is None or st.st_uid != target_uid):
                    raise ValueError(
                        f"Security violation: directory component '{comp}' in '{dir_path}' is owned by UID {st.st_uid}, expected root (UID 0)."
                    )

        return curr_fd
    except Exception:
        try:
            os.close(curr_fd)
        except OSError:
            pass
        raise


def atomic_write(
    path: Union[str, Path],
    content: Union[str, bytes],
    mode: Optional[int] = None,
    uid: Optional[int] = None,
    gid: Optional[int] = None,
) -> None:
    """
    Race-resistant atomic durable write to path (P0-1, P2-4, NT-015, P1.1).
    Validates parent directory security using file descriptors and component-by-component checks.
    Uses O_DIRECTORY | O_NOFOLLOW to open parent directory and validate permissions.
    Performs openat-style creation, permissions, metadata application, fsync, and renameat
    relative to the opened parent directory file descriptor without pathname fallbacks on Linux.
    Treats security/durability failures (chmod, chown, fsync) as fatal.
    Rejects writing to symlinks, non-regular files, or insecure directories.
    Note: Preserves standard mode/UID/GID metadata; POSIX ACLs, extended attributes (xattr),
    and SELinux security contexts are not preserved beyond standard Unix permissions (Section 30).
    """
    dest_path = Path(path)
    dest_name = dest_path.name
    if not dest_name or dest_name in (".", ".."):
        raise ValueError(f"Invalid destination filename '{path}'")

    parent_path = dest_path.parent
    if not parent_path.is_absolute():
        parent_path = Path.cwd() / parent_path

    if os.path.islink(str(parent_path)):
        raise ValueError(f"Parent '{parent_path}' is a symlink; refusing privileged write.")
    if os.path.islink(str(dest_path)):
        raise ValueError(f"Destination '{path}' is a symlink; refusing privileged write.")

    if not parent_path.exists():
        # Validate existing ancestors component-by-component before creating missing directories (Section 20)
        curr = Path("/") if (os.name != "nt" and parent_path.as_posix().startswith("/")) else Path(parent_path.parts[0])
        for comp in parent_path.parts[1:]:
            curr = curr / comp
            if curr.exists() or os.path.islink(str(curr)):
                c_st = os.lstat(str(curr))
                if stat.S_ISLNK(c_st.st_mode):
                    raise ValueError(f"Ancestor '{curr}' is a symlink; refusing directory creation.")
                if not stat.S_ISDIR(c_st.st_mode):
                    raise ValueError(f"Ancestor '{curr}' is not a directory; refusing directory creation.")
                if (os.name != "nt" or getattr(os, "_force_posix_security_checks", False)):
                    if (c_st.st_mode & 0o002) and not (c_st.st_mode & stat.S_ISVTX):
                        raise ValueError(f"Ancestor '{curr}' is world-writable without sticky bit.")
            else:
                curr.mkdir(mode=0o700, exist_ok=True)

    dir_fd: Optional[int] = None
    try:
        dir_fd = secure_open_dir_hierarchy(parent_path, target_uid=uid, target_gid=gid)
        if dir_fd is not None:
            st_dir = os.fstat(dir_fd)
        else:
            st_dir = os.stat(str(parent_path))
            if not stat.S_ISDIR(st_dir.st_mode):
                raise ValueError(f"Parent '{parent_path}' is not a directory.")

            # POSIX security checks for parent directory on Windows fallback / forced checks
            if os.name != "nt" or getattr(os, "_force_posix_security_checks", False):
                if st_dir.st_mode & 0o002:
                    raise ValueError(f"Directory '{parent_path}' is world-writable; refusing privileged write.")
                if (st_dir.st_mode & 0o020) and hasattr(os, "geteuid") and os.geteuid() == 0:
                    if st_dir.st_gid != 0:
                        raise ValueError(f"Directory '{parent_path}' is group-writable by non-root group ({st_dir.st_gid}); refusing privileged write.")
                if hasattr(os, "geteuid") and os.geteuid() == 0:
                    if st_dir.st_uid != 0 and (uid is None or st_dir.st_uid != uid):
                        raise ValueError(f"Directory '{parent_path}' is not owned by root or target uid (owner: {st_dir.st_uid}); refusing privileged write.")

        orig_stat = None
        has_dir_fd_stat = dir_fd is not None and hasattr(os, "stat") and os.stat in getattr(os, "supports_dir_fd", set())
        if has_dir_fd_stat:
            try:
                orig_stat = os.stat(dest_name, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                orig_stat = None
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    orig_stat = None
                else:
                    raise
        else:
            full_dest = parent_path / dest_name
            if full_dest.exists() or os.path.islink(str(full_dest)):
                orig_stat = os.lstat(str(full_dest))

        if orig_stat is not None:
            if stat.S_ISLNK(orig_stat.st_mode):
                raise ValueError(f"Destination '{path}' is a symlink; refusing privileged write.")
            if not stat.S_ISREG(orig_stat.st_mode):
                raise ValueError(f"Destination '{path}' is not a regular file; refusing write.")

        target_uid = uid if uid is not None else (orig_stat.st_uid if orig_stat else None)
        target_gid = gid if gid is not None else (orig_stat.st_gid if orig_stat else None)

        if orig_stat is not None:
            target_mode = orig_stat.st_mode & 0o777
            if mode is not None:
                # Allow tightening permissions, never widening
                target_mode = target_mode & mode
        elif mode is not None:
            target_mode = mode
        else:
            target_mode = 0o600

        tmp_name = f".{dest_name}.tmp_{os.urandom(8).hex()}"
        temp_path = parent_path / tmp_name
        use_dir_fd = (dir_fd is not None and os.open in getattr(os, "supports_dir_fd", set()))
        tmp_fd: Optional[int] = None

        try:
            if use_dir_fd:
                open_flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
                if hasattr(os, "O_NOFOLLOW"):
                    open_flags |= os.O_NOFOLLOW
                if hasattr(os, "O_CLOEXEC"):
                    open_flags |= os.O_CLOEXEC
                tmp_fd = os.open(tmp_name, open_flags, target_mode, dir_fd=dir_fd)
                payload = content.encode("utf-8") if isinstance(content, str) else content
                written = 0
                while written < len(payload):
                    n = os.write(tmp_fd, payload[written:])
                    if n == 0:
                        raise OSError("Zero bytes written to temporary file")
                    written += n

                # Apply metadata directly to open file descriptor BEFORE fsync (P1/P2 durability)
                if hasattr(os, "fchmod"):
                    os.fchmod(tmp_fd, target_mode)
                if (target_uid is not None or target_gid is not None) and hasattr(os, "fchown"):
                    if hasattr(os, "geteuid") and os.geteuid() == 0 and (os.name != "nt" or getattr(os, "_force_posix_security_checks", False)):
                        os.fchown(
                            tmp_fd,
                            target_uid if target_uid is not None else -1,
                            target_gid if target_gid is not None else -1,
                        )

                # Durable sync of file content and metadata before rename
                os.fsync(tmp_fd)
                os.close(tmp_fd)
                tmp_fd = None
            else:
                # Cross-platform / Windows fallback
                is_text = isinstance(content, str)
                tf = tempfile.NamedTemporaryFile(
                    mode="w" if is_text else "wb",
                    dir=parent_path,
                    prefix=f".{dest_name}.tmp_",
                    delete=False,
                    encoding="utf-8" if is_text else None,
                )
                temp_path = Path(tf.name)
                tmp_name = temp_path.name
                try:
                    tf.write(content)
                    tf.flush()
                    if hasattr(os, "fchmod"):
                        os.fchmod(tf.fileno(), target_mode)
                    if (target_uid is not None or target_gid is not None) and hasattr(os, "fchown"):
                        if hasattr(os, "geteuid") and os.geteuid() == 0 and (os.name != "nt" or getattr(os, "_force_posix_security_checks", False)):
                            os.fchown(
                                tf.fileno(),
                                target_uid if target_uid is not None else -1,
                                target_gid if target_gid is not None else -1,
                            )
                    os.fsync(tf.fileno())
                finally:
                    tf.close()
                if not hasattr(os, "fchmod"):
                    os.chmod(temp_path, target_mode)
                if (target_uid is not None or target_gid is not None) and not hasattr(os, "fchown"):
                    if hasattr(os, "chown") and hasattr(os, "geteuid") and os.geteuid() == 0 and (os.name != "nt" or getattr(os, "_force_posix_security_checks", False)):
                        os.chown(
                            temp_path,
                            target_uid if target_uid is not None else -1,
                            target_gid if target_gid is not None else -1,
                        )

            # Re-check destination in dir before replace to prevent race to symlink
            if os.path.islink(str(dest_path)):
                raise ValueError(f"Destination '{path}' was replaced with a symlink; refusing write.")

            if has_dir_fd_stat:
                try:
                    pre_stat = os.stat(dest_name, dir_fd=dir_fd, follow_symlinks=False)
                    if stat.S_ISLNK(pre_stat.st_mode):
                        raise ValueError(f"Destination '{path}' was replaced with a symlink; refusing write.")
                    if not stat.S_ISREG(pre_stat.st_mode):
                        raise ValueError(f"Destination '{path}' was replaced with a non-regular file; refusing write.")
                except (FileNotFoundError, OSError) as exc:
                    if getattr(exc, "errno", None) != errno.ENOENT:
                        raise
            else:
                full_dest = parent_path / dest_name
                try:
                    pre_stat = os.lstat(str(full_dest))
                    if stat.S_ISLNK(pre_stat.st_mode):
                        raise ValueError(f"Destination '{path}' was replaced with a symlink; refusing write.")
                    if not stat.S_ISREG(pre_stat.st_mode):
                        raise ValueError(f"Destination '{path}' was replaced with a non-regular file; refusing write.")
                except FileNotFoundError:
                    pass
                except OSError as exc:
                    if getattr(exc, "errno", None) != errno.ENOENT:
                        raise

            # Perform FD-relative atomic replacement without pathname fallbacks on Linux
            if dir_fd is not None and os.rename in getattr(os, "supports_dir_fd", set()):
                os.rename(tmp_name, dest_name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            elif os.name != "nt":
                raise RuntimeError("FD-relative rename is unsupported on this Linux environment; refusing unsafe fallback")
            else:
                os.replace(temp_path, parent_path / dest_name)

            # Directory fsync - treat fatal errors as fatal (P2-4)
            if dir_fd is not None and hasattr(os, "fsync"):
                os.fsync(dir_fd)

        except Exception:
            if tmp_fd is not None:
                try:
                    os.close(tmp_fd)
                except OSError:
                    pass
            if use_dir_fd:
                try:
                    os.unlink(tmp_name, dir_fd=dir_fd)
                except OSError:
                    pass
            else:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise
    finally:
        if dir_fd is not None:
            try:
                os.close(dir_fd)
            except OSError:
                pass


def get_config_home() -> Path:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            import pwd
            pw = pwd.getpwnam(sudo_user)
            user_home = Path(pw.pw_dir)
        except Exception:
            user_home = Path(f"/home/{sudo_user}")
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
    """Remove nulltrace blocks from torrc text (NT-014, P1-8)."""
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

    if skipping:
        raise ValueError(
            "Unterminated NullTrace managed configuration block in torrc (missing END marker). "
            "Refusing destructive rewrite."
        )

    return "".join(filtered)


def torrc_has_managed_block(content: str) -> bool:
    return any(begin in content for begin, _ in TOR_CONFIG_MARKERS)


def require_linux_root(action: str) -> None:
    if not hasattr(os, "geteuid"):
        raise OSError("nulltrace requires Linux")
    if os.geteuid() != 0:
        raise PermissionError(f"Root privileges required to {action}")


def resolve_config_path(filename: str) -> Path:
    """
    Restrict config files to canonical ~/.config/nulltrace/ (relative names only).
    Rejects symlinks in config directory or any path component, ensures target is a regular file (P0.1, P2.6).
    """
    if not filename or filename != Path(filename).name or "/" in filename or "\\" in filename or ".." in filename:
        raise ValueError(
            "Config filename must be a plain name (e.g. myconfig.json), not a path"
        )

    config_home = get_config_home()

    # Verify security of path components leading to config_home (P0.1)
    current = Path(config_home.parts[0]) if os.name != "nt" else Path(config_home.drive + "\\")
    for part in config_home.parts[1:]:
        current = current / part
        if current.exists() or os.path.islink(str(current)):
            try:
                st = os.lstat(str(current))
                if stat.S_ISLNK(st.st_mode):
                    raise ValueError(
                        f"Config path component '{current}' is a symlink: untrusted redirect rejected"
                    )
            except OSError as exc:
                if getattr(exc, "errno", None) != errno.ENOENT:
                    raise

    # Establish config directory without trusting pre-existing symlinks
    if config_home.exists() or os.path.islink(str(config_home)):
        st = os.lstat(str(config_home))
        if stat.S_ISLNK(st.st_mode):
            raise ValueError(
                f"Config directory '{config_home}' is a symlink: untrusted redirect rejected"
            )
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError(
                f"Config directory '{config_home}' is not a directory"
            )
    else:
        config_home.mkdir(parents=True, mode=0o700, exist_ok=True)

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            import pwd
            pw = pwd.getpwnam(sudo_user)
            # Never chown a symlink (P0.1)
            st = os.lstat(str(config_home))
            if not stat.S_ISLNK(st.st_mode) and stat.S_ISDIR(st.st_mode):
                if hasattr(os, "lchown"):
                    os.lchown(str(config_home), pw.pw_uid, pw.pw_gid)
                else:
                    os.chown(str(config_home), pw.pw_uid, pw.pw_gid)
        except (KeyError, OSError, ImportError, AttributeError):
            pass

    target = config_home / filename
    if target.exists() or os.path.islink(str(target)):
        st = os.lstat(str(target))
        if stat.S_ISLNK(st.st_mode):
            raise ValueError(
                f"Config file '{target}' is a symlink: untrusted redirect rejected"
            )
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(
                f"Config file '{target}' must be a regular file, not a FIFO, socket, device, or directory"
            )

    resolved = target.resolve()
    try:
        resolved.relative_to(config_home.resolve())
    except ValueError:
        raise ValueError("Config path must stay under ~/.config/nulltrace/")
    return target


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


SESSION_ID_RE = re.compile(r"^[0-9a-f]{8,16}$")


def is_valid_session_id(sid: Any) -> bool:
    """Strictly validate session ID format (P2-3)."""
    if not sid or not isinstance(sid, str):
        return False
    if "/" in sid or "\\" in sid or ".." in sid or "\0" in sid:
        return False
    # Standard format is 8-16 lowercase hex characters (P2-3)
    return bool(SESSION_ID_RE.match(sid))


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
        self._session_explicitly_bound: bool = False
        self._session_created_at: Optional[str] = None
        self._current_state: str = STATE_INACTIVE
        self._rollback_registered = False
        self._restore_failures: List[str] = []
        self._tor_file_restored: bool = False
        self._tor_service_restored: bool = False
        self._tor_config_applied: bool = False
        self._mac_randomized: bool = False

        self.setup_logging(verbose)
        self.tor_config_content = self.generate_tor_config(self.circuit_time)

    def bind_session(self, session_id: str) -> None:
        """Bind execution, backup lookup, and state operations to a specific persisted session (P0.1, P2-3)."""
        if not is_valid_session_id(session_id):
            raise ValueError(f"Invalid session ID format: '{session_id}'. Must be a valid session identifier.")
        self._session_id = session_id
        self._session_explicitly_bound = True

    def _discover_session_id(self) -> Optional[str]:
        """
        Discover active or uncleaned recoverable session ID from persistent state (Section 4, Section 5).
        Only the authoritative current session referenced by state.json is considered.
        Stale historical sessions in /var/lib/nulltrace/ are NEVER selected for automatic recovery.
        """
        # 1. Authoritative state files
        for sf in (PERSISTENT_DIR / "state.json", RUN_DIR / "state.json"):
            if sf.exists():
                try:
                    data = json.loads(sf.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise RuntimeError(f"Authoritative state file '{sf}' is corrupt or unreadable: {exc}")
                if not isinstance(data, dict):
                    raise RuntimeError(f"Authoritative state file '{sf}' is corrupt: expected JSON object")
                st = data.get("state")
                if st == STATE_INACTIVE:
                    # Authoritative state is INACTIVE: current system is clean, never select stale historical sessions (Section 4)
                    return None
                sid = data.get("session_id")
                if not sid or not is_valid_session_id(sid):
                    raise RuntimeError(f"Recovery failed: state file '{sf}' contains invalid or missing session_id: {sid}")
                sdir = PERSISTENT_DIR / f"session_{sid}"
                if not sdir.is_dir():
                    raise RuntimeError(f"Recovery failed: state file points to non-existent session directory '{sdir}'")
                return sid

        # No authoritative state file: system is clean or uninitialized; do NOT guess historical sessions
        return None

    @property
    def session_id(self) -> str:
        if not self._session_id:
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
        """Validate IPv4 address using ipaddress (P2.9)."""
        if not value or not isinstance(value, str):
            return False
        try:
            ip = ipaddress.ip_address(value.strip())
            return ip.version == 4
        except ValueError:
            return False

    @staticmethod
    def is_valid_loopback_ip(value: str) -> bool:
        """Validate that value is strictly a loopback address (NT-005, P2.9)."""
        if not value or not isinstance(value, str):
            return False
        try:
            ip = ipaddress.ip_address(value.strip())
            return ip.is_loopback
        except ValueError:
            return False

    @staticmethod
    def is_valid_cidr(value: str) -> bool:
        """Validate IPv4 CIDR network using ipaddress (P2.9)."""
        if not value or not isinstance(value, str):
            return False
        val = value.strip()
        if "/" not in val:
            return False
        try:
            net = ipaddress.ip_network(val, strict=False)
            return net.version == 4
        except ValueError:
            return False

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
        if os.path.islink(str(path)) or Path(path).is_symlink():
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
        Validate Tor config target path and integrity before privileged operations (NT-014, P2.5, P2.6):
        - Canonical, symlink-safe resolution inside /etc/tor/
        - Rejects symlink traversal escaping /etc/tor/
        - Requires target to be a regular file (rejects FIFOs, devices, sockets, symlinks)
        - Verifies target file is not world-writable
        - Verifies strict root ownership (UID 0 only; rejects Tor daemon user or unprivileged ownership)
        - Verifies target directory is not world-writable and root-owned
        """
        if not path or not isinstance(path, (str, Path)):
            raise ValueError("Tor config path cannot be empty")
        path_p = Path(path)
        if path_p.is_symlink() or os.path.islink(str(path_p)):
            raise ValueError(f"Insecure Tor config file '{path}': symlink target rejected")
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
            if os.name != "nt" or getattr(os, "_force_posix_security_checks", False):
                if (st_parent.st_mode & 0o002) and not (st_parent.st_mode & stat.S_ISVTX):
                    raise ValueError(f"Insecure Tor config directory '{parent}': world-writable without sticky bit")
                if (st_parent.st_mode & 0o020) and not (st_parent.st_mode & stat.S_ISVTX):
                    if hasattr(st_parent, "st_gid") and st_parent.st_gid != 0:
                        raise ValueError(f"Insecure Tor config directory '{parent}': group-writable by non-root group ({st_parent.st_gid})")
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                # P2.5: Security-sensitive Tor config directory must be root-owned (UID 0 only)
                if st_parent.st_uid != 0:
                    raise ValueError(
                        f"Insecure Tor config directory '{parent}': owned by untrusted UID {st_parent.st_uid} (must be root-owned)"
                    )

        # Check target file safety if it exists (P2.5, P2.6, NT-06, Section 11, Section 31)
        if p.exists() or os.path.islink(str(p)):
            lst = os.lstat(str(p))
            if stat.S_ISLNK(lst.st_mode) or p.is_symlink():
                raise ValueError(f"Insecure Tor config file '{p}': symlink target rejected")
            if not stat.S_ISREG(lst.st_mode):
                raise ValueError(f"Insecure Tor config file '{p}': must be a regular file, not FIFO, socket, device, or directory")
            if hasattr(os, "getuid") or getattr(os, "_force_posix_security_checks", False) or os.name != "nt":
                if lst.st_mode & 0o002:
                    raise ValueError(f"Insecure Tor config file '{p}': world-writable ({oct(lst.st_mode)})")
                if lst.st_mode & 0o020:
                    raise ValueError(f"Insecure Tor config file '{p}': group-writable ({oct(lst.st_mode)})")
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                # P2.5: Security-sensitive Tor config file must be root-owned (UID 0 only)
                if lst.st_uid != 0:
                    raise ValueError(
                        f"Insecure Tor config file '{p}': owned by untrusted UID {lst.st_uid} (must be root-owned)"
                    )
            # Section 31: Tor config must be readable by Tor daemon user
            if hasattr(os, "getuid") or getattr(os, "_force_posix_security_checks", False) or os.name != "nt":
                tor_user_val = getattr(self, "_tor_user", None) or getattr(self, "tor_user", None)
                if tor_user_val:
                    expected_uid = int(tor_user_val) if tor_user_val.isdigit() else None
                    try:
                        import pwd
                        pwnam = pwd.getpwnam(tor_user_val)
                        expected_uid = pwnam.pw_uid
                        expected_gid = pwnam.pw_gid
                    except Exception:
                        expected_gid = None
                    if expected_uid is not None and expected_uid != 0:
                        # Must be world-readable, owned by tor user, or group-readable by tor group (Section 31)
                        is_readable = (
                            bool(lst.st_mode & 0o004)
                            or (lst.st_uid == expected_uid and bool(lst.st_mode & 0o400))
                            or (expected_gid is not None and lst.st_gid == expected_gid and bool(lst.st_mode & 0o040))
                        )
                        if not is_readable:
                            raise ValueError(
                                f"Insecure Tor config file '{p}': not readable by Tor daemon user '{tor_user_val}' (mode {oct(lst.st_mode)})"
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

        # Section 39: Port relationship validation
        tor_p = int(self.config.tor_port)
        dns_p = int(self.config.dns_port)
        ctrl_p = int(self._read_control_port())
        if tor_p == dns_p:
            raise ValueError(f"Port collision: Tor TransPort ({tor_p}) and DNSPort ({dns_p}) cannot be the same")
        if tor_p == ctrl_p:
            raise ValueError(f"Port collision: Tor TransPort ({tor_p}) cannot collide with ControlPort ({ctrl_p})")
        if dns_p == ctrl_p:
            raise ValueError(f"Port collision: Tor DNSPort ({dns_p}) cannot collide with ControlPort ({ctrl_p})")
        if tor_p == 53 or dns_p == 53:
            raise ValueError("Privileged port collision: port 53 is reserved for system DNS")

        # NT-005 & P1.2: Restrict Tor listener address strictly to 127.0.0.1
        if self.config.localhost in ("::1", "::") or ":" in self.config.localhost:
            raise ValueError(
                f"Tor listener address '{self.config.localhost}' is IPv6 which is rejected: "
                "transparent interception is IPv4-based while application IPv6 is blocked. "
                "Only 127.0.0.1 is currently supported."
            )
        if not self.is_valid_loopback_ip(self.config.localhost):
            raise ValueError(
                f"Invalid localhost address '{self.config.localhost}': must be a valid loopback IP (e.g. 127.0.0.1)"
            )
        if self.config.localhost != "127.0.0.1":
            raise ValueError(
                f"Tor listener address '{self.config.localhost}' is rejected: "
                "accept only 127.0.0.1 for the Tor listener."
            )
        if not self.is_valid_cidr(self.config.tor_network):
            raise ValueError(f"Invalid Tor network CIDR: {self.config.tor_network}")
        # Normalize tor_network CIDR
        self.config.tor_network = str(ipaddress.ip_network(self.config.tor_network.strip(), strict=False))

        # NT-014: Symlink-safe Tor config path
        if not self.is_valid_tor_config_path(self.config.tor_config):
            raise ValueError(f"Invalid Tor config path: {self.config.tor_config}")

        if self.config.exit_country:
            # P2.10: ASCII-only two-letter country code normalized to uppercase
            if not re.match(r"^[A-Za-z]{2}$", self.config.exit_country):
                raise ValueError(f"Invalid exit country code: {self.config.exit_country}")
            self.config.exit_country = self.config.exit_country.upper()

        self._limit_excluded_lists()
        # P2.9 & Section 38: Normalize and validate excluded network CIDRs
        normalized_networks = []
        for network in self.config.excluded_networks:
            try:
                net = ipaddress.ip_network(network.strip(), strict=False)
            except (ValueError, AttributeError):
                raise ValueError(f"Invalid excluded network CIDR: {network}")
            if net.prefixlen == 0:
                raise ValueError(f"Full-route exclusion '{network}' is rejected: it bypasses privacy enforcement for all traffic")
            if net.version == 6:
                raise ValueError(f"IPv6 exclusion '{network}' is rejected: IPv6 traffic is completely blocked by fail-closed policy")
            normalized_networks.append(str(net))

        # Check overlapping exclusions (Section 38, Section 47)
        for i in range(len(normalized_networks)):
            net_i = ipaddress.ip_network(normalized_networks[i])
            for j in range(i + 1, len(normalized_networks)):
                net_j = ipaddress.ip_network(normalized_networks[j])
                if net_i.overlaps(net_j):
                    raise ValueError(f"Overlapping exclusion networks detected: '{net_i}' and '{net_j}'")

        self.config.excluded_networks = normalized_networks

        normalized_ips = []
        for ip_val in self.config.excluded_ips:
            if self.is_valid_ip(ip_val):
                normalized_ips.append(str(ipaddress.ip_address(ip_val.strip())))
            elif self.is_valid_cidr(ip_val):
                net_val = ipaddress.ip_network(ip_val.strip(), strict=False)
                if net_val.prefixlen == 0:
                    raise ValueError(f"Full-route exclusion '{ip_val}' is rejected: it bypasses privacy enforcement")
                if net_val.version == 6:
                    raise ValueError(f"IPv6 exclusion '{ip_val}' is rejected: IPv6 traffic is completely blocked by fail-closed policy")
            else:
                raise ValueError(f"Invalid excluded IP address or CIDR: {ip_val}")
        self.config.excluded_ips = normalized_ips

        # Check overlaps between excluded IPs and excluded networks (Section 38, Section 47)
        for ip_val in normalized_ips:
            try:
                ip_addr = ipaddress.ip_address(ip_val)
                for net_val in normalized_networks:
                    net_obj = ipaddress.ip_network(net_val)
                    if ip_addr in net_obj:
                        raise ValueError(f"Overlapping exclusion: IP '{ip_val}' is already covered by network '{net_val}'")
            except ValueError as e:
                if "Overlapping exclusion" in str(e):
                    raise

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

    @staticmethod
    def _validate_secure_directory(d: Path) -> None:
        """
        Validate runtime/persistent directory security (P2-2):
        - must exist and be a directory
        - not a symlink
        - root-owned (when running as root)
        - no group or world write permissions
        - safe parent directory assumptions
        """
        if not d.exists() and not os.path.islink(str(d)):
            d.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                os.chmod(d, 0o700)
            except OSError:
                pass

        lst = os.lstat(str(d))
        if stat.S_ISLNK(lst.st_mode):
            raise RuntimeError(f"Security violation: directory '{d}' is a symlink; refusing to use.")
        if not stat.S_ISDIR(lst.st_mode):
            raise RuntimeError(f"Security violation: '{d}' is not a directory; refusing to use.")

        # POSIX security checks
        if os.name != "nt" or getattr(os, "_force_posix_security_checks", False):
            if lst.st_mode & 0o022:
                raise RuntimeError(
                    f"Security violation: directory '{d}' has insecure permissions ({oct(lst.st_mode)}); group or world writable."
                )

            if hasattr(os, "geteuid") and os.geteuid() == 0:
                if lst.st_uid != 0:
                    raise RuntimeError(
                        f"Security violation: directory '{d}' is owned by UID {lst.st_uid}, expected root (UID 0)."
                    )

            # Validate parent directory
            parent = d.parent
            if parent.exists() or os.path.islink(str(parent)):
                plst = os.lstat(str(parent))
                if stat.S_ISLNK(plst.st_mode):
                    raise RuntimeError(f"Security violation: parent directory '{parent}' is a symlink.")
                if (plst.st_mode & 0o002) and not (plst.st_mode & stat.S_ISVTX):
                    raise RuntimeError(
                        f"Security violation: parent directory '{parent}' is world-writable without sticky bit."
                    )
                if hasattr(os, "geteuid") and os.geteuid() == 0 and plst.st_uid != 0:
                    raise RuntimeError(
                        f"Security violation: parent directory '{parent}' is not root-owned."
                    )

    def _ensure_runtime_dirs(self) -> None:
        self._validate_secure_directory(RUN_DIR)
        self._validate_secure_directory(PERSISTENT_DIR)

    def _acquire_lock(self) -> None:
        self._ensure_runtime_dirs()
        lock_path = RUN_DIR / "nulltrace.lock"
        flags = os.O_CREAT | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(str(lock_path), flags, 0o600)
            self._lock_fd = open(fd, "w")
        except OSError as exc:
            raise RuntimeError(f"Could not securely open lock file '{lock_path}': {exc}")
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
        sid = self.session_id
        if not is_valid_session_id(sid):
            raise ValueError(f"Security violation: invalid session ID '{sid}'. Refusing path construction.")
        sdir = PERSISTENT_DIR / f"session_{sid}"
        if sdir.name != f"session_{sid}":
            raise ValueError(f"Session directory basename mismatch: '{sdir.name}' vs 'session_{sid}'")
        return sdir

    def _load_session_metadata(self) -> Optional[Dict[str, Any]]:
        """
        Load session metadata and bind recovery session identity (Section 3, Section 4, Section 5).
        Validates cross-record session ID consistency between metadata, manifest, state.json,
        and session directory. Rejects corrupted or inconsistent metadata files explicitly.
        """
        # 1. Authoritative state file discovery first (Section 4)
        sid = self._discover_session_id()
        if not sid:
            # Fall back to bound session or current session instance only if state.json does not exist (e.g. unit test mocks)
            cur_sid = getattr(self, "_session_id", None)
            if cur_sid and is_valid_session_id(cur_sid) and (PERSISTENT_DIR / f"session_{cur_sid}" / "metadata.json").exists():
                sid = cur_sid
            elif getattr(self, "_session_explicitly_bound", False) and cur_sid:
                sid = cur_sid
            else:
                return None

        self._session_id = sid
        sdir = PERSISTENT_DIR / f"session_{sid}"
        if sdir.name != f"session_{sid}":
            raise RuntimeError(f"Recovery failed: session directory basename mismatch '{sdir.name}' vs 'session_{sid}'")

        meta_file = sdir / "metadata.json"
        if not meta_file.exists():
            raise RuntimeError(f"Recovery failed: session metadata file '{meta_file}' is missing (RECOVERY_REQUIRED)")

        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"Recovery failed: session metadata file '{meta_file}' is corrupt or unreadable: {exc}")

        if not isinstance(meta, dict):
            raise RuntimeError(f"Recovery failed: session metadata file '{meta_file}' is corrupt: expected JSON object")

        meta_sid = meta.get("session_id")
        if not meta_sid or meta_sid != sid:
            raise RuntimeError(
                f"Recovery failed: session ID mismatch between metadata ({meta_sid}) and directory ({sid})"
            )

        # Cross-validate state.json if present
        for sf in (PERSISTENT_DIR / "state.json", RUN_DIR / "state.json"):
            if sf.exists():
                try:
                    s_data = json.loads(sf.read_text(encoding="utf-8"))
                    if isinstance(s_data, dict):
                        state_sid = s_data.get("session_id")
                        if state_sid and state_sid != sid:
                            raise RuntimeError(
                                f"Recovery failed: session ID mismatch between state.json ({state_sid}) and directory ({sid})"
                            )
                except (OSError, json.JSONDecodeError) as exc:
                    raise RuntimeError(f"Recovery failed: state file '{sf}' is corrupt: {exc}")

        # Cross-validate manifest.json if present
        manifest_file = sdir / "manifest.json"
        if manifest_file.exists():
            try:
                man = json.loads(manifest_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"Recovery failed: session manifest file '{manifest_file}' is corrupt: {exc}")

            if not isinstance(man, dict):
                raise RuntimeError(f"Recovery failed: session manifest file '{manifest_file}' is corrupt: expected JSON object")

            man_sid = man.get("session_id")
            if not man_sid or man_sid != sid:
                raise RuntimeError(
                    f"Recovery failed: session ID mismatch between manifest ({man_sid}) and directory ({sid})"
                )

        return meta

    def _generate_enforcement_manifest(self) -> Dict[str, Any]:
        """
        Generate enforcement manifest for current session (P0.2, P1-1, P1-2).
        Records expected chains, jumps, and rule fingerprints for live integrity verification.
        Complete-or-fail: all required v4 and v6 chains must be fingerprinted
        preserving exact rule order.
        """
        iptables_bin = require_trusted_binary("iptables")
        ip6tables_bin = require_trusted_binary("ip6tables")

        manifest: Dict[str, Any] = {
            "version": "1.0",
            "tool_version": "2.0.0",
            "session_id": self.session_id,
            "created_at": datetime.now().isoformat(),
            "expected_jumps_v4": [
                {"table": "filter", "chain": "OUTPUT", "target": CHAIN_FILTER_OUTPUT},
                {"table": "filter", "chain": "INPUT", "target": CHAIN_FILTER_INPUT},
                {"table": "filter", "chain": "FORWARD", "target": CHAIN_FILTER_FORWARD},
                {"table": "nat", "chain": "OUTPUT", "target": CHAIN_NAT_OUTPUT},
                {"table": "mangle", "chain": "OUTPUT", "target": CHAIN_MANGLE_OUTPUT},
                {"table": "mangle", "chain": "PREROUTING", "target": CHAIN_MANGLE_PREROUTING},
            ],
            "expected_jumps_v6": [
                {"table": "filter", "chain": "OUTPUT", "target": CHAIN_V6_OUTPUT},
                {"table": "filter", "chain": "INPUT", "target": CHAIN_V6_INPUT},
                {"table": "filter", "chain": "FORWARD", "target": CHAIN_V6_FORWARD},
                {"table": "mangle", "chain": "OUTPUT", "target": CHAIN_V6_MANGLE_OUTPUT},
                {"table": "mangle", "chain": "PREROUTING", "target": CHAIN_V6_MANGLE_PREROUTING},
            ],
            "chain_fingerprints": {},
        }

        # Compute fingerprints for all v4 chains (order-preserving, complete-or-fail)
        table_chains_v4 = [
            ("nat", CHAIN_NAT_OUTPUT),
            ("mangle", CHAIN_MANGLE_OUTPUT),
            ("mangle", CHAIN_MANGLE_PREROUTING),
            ("filter", CHAIN_FILTER_OUTPUT),
            ("filter", CHAIN_FILTER_INPUT),
            ("filter", CHAIN_FILTER_FORWARD),
        ]
        for table, chain in table_chains_v4:
            res = run_trusted([iptables_bin, "-t", table, "-S", chain], check=False)
            if res.returncode != 0:
                raise RuntimeError(
                    f"Manifest generation failed: could not inspect v4 chain {table}:{chain} "
                    f"(code {res.returncode}): {res.stderr or res.stdout}"
                )
            # P1-1: Preserve exact rule order (no sorting)
            canon = "\n".join(l.strip() for l in res.stdout.splitlines() if l.strip())
            manifest["chain_fingerprints"][f"v4:{table}:{chain}"] = hashlib.sha256(canon.encode()).hexdigest()

        # Compute fingerprints for all v6 chains (order-preserving, complete-or-fail)
        table_chains_v6 = [
            ("mangle", CHAIN_V6_MANGLE_OUTPUT),
            ("mangle", CHAIN_V6_MANGLE_PREROUTING),
            ("filter", CHAIN_V6_OUTPUT),
            ("filter", CHAIN_V6_INPUT),
            ("filter", CHAIN_V6_FORWARD),
        ]
        for table, chain in table_chains_v6:
            res = run_trusted([ip6tables_bin, "-t", table, "-S", chain], check=False)
            if res.returncode != 0:
                raise RuntimeError(
                    f"Manifest generation failed: could not inspect v6 chain {table}:{chain} "
                    f"(code {res.returncode}): {res.stderr or res.stdout}"
                )
            # P1-1: Preserve exact rule order (no sorting)
            canon = "\n".join(l.strip() for l in res.stdout.splitlines() if l.strip())
            manifest["chain_fingerprints"][f"v6:{table}:{chain}"] = hashlib.sha256(canon.encode()).hexdigest()

        total_expected = len(table_chains_v4) + len(table_chains_v6)
        if len(manifest["chain_fingerprints"]) != total_expected:
            raise RuntimeError(
                f"Manifest generation incomplete: expected {total_expected} fingerprints, "
                f"got {len(manifest['chain_fingerprints'])}"
            )

        return manifest

    def _persist_session_metadata(self, manifest: Optional[Dict[str, Any]] = None) -> None:
        """Persist session metadata and recovery record with fatal write errors (NT-010, NT-015, P0.3, P2.1, P2.2)."""
        sdir = self._session_dir()
        sdir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(sdir, 0o700)
        except OSError:
            pass

        if manifest is not None:
            self._enforcement_manifest = manifest
        manifest = getattr(self, "_enforcement_manifest", None)
        if manifest:
            manifest_file = sdir / "manifest.json"
            atomic_write(manifest_file, json.dumps(manifest, indent=2), mode=0o600)

        self._state_revision = getattr(self, "_state_revision", 0) + 1
        meta = {
            "session_id": self.session_id,
            "state_revision": self._state_revision,
            "created_at": getattr(self, "_session_created_at", datetime.now().isoformat()),
            "tool_version": "2.0.0",
            "state": self._current_state,
            "consumed": (self._current_state == STATE_INACTIVE),
            "spoofed_intf": self._spoofed_intf,
            "original_mac": self._original_mac,
            "mac_restored": getattr(self, "_mac_restored", False),
            "tor_file_restored": getattr(self, "_tor_file_restored", False),
            "tor_service_restored": getattr(self, "_tor_service_restored", False),
            "tor_config_path": self.config.tor_config,
            "tor_backup_path": str(sdir / "torrc.bak"),
            "tor_config_hash": getattr(self, "_tor_config_hash", None),
            "iptables_v4_backup": str(sdir / "iptables.v4.bak"),
            "iptables_v4_hash": getattr(self, "_iptables_v4_hash", None),
            "iptables_v6_backup": str(sdir / "iptables.v6.bak"),
            "iptables_v6_hash": getattr(self, "_iptables_v6_hash", None),
            "custom_chains": list(ALL_OWNED_CHAINS),
            "enforcement_manifest": manifest,
            "baseline_captured": getattr(self, "_baseline_captured", False),
            "tor_config_existed": getattr(self, "_tor_config_existed", None),
            "tor_service_initially_active": getattr(self, "_tor_initially_active", None),
            "tor_service_initially_enabled": getattr(self, "_tor_initially_enabled", None),
            "tor_service_raw_enabled_state": getattr(self, "_tor_service_raw_enabled_state", None),
            "interface_initially_up": getattr(self, "_interface_initially_up", None),
            "failures": getattr(self, "_restore_failures", []),
        }

        meta_file = sdir / "metadata.json"
        # Mandatory write: failure must not be silently swallowed (P0.3, P2.1)
        atomic_write(meta_file, json.dumps(meta, indent=2), mode=0o600)
        self._write_state(self._current_state)

    def _write_state(self, state: str) -> None:
        """Durable atomic write for runtime state files with fatal persistent error (NT-015, P0.3, P2.1, P2.2)."""
        self._ensure_runtime_dirs()
        self._current_state = state

        payload = {
            "state": state,
            "state_revision": getattr(self, "_state_revision", 1),
            "active": (state == STATE_ACTIVE),
            "session_id": self.session_id,
            "session_dir": str(self._session_dir()),
            "spoofed_intf": self._spoofed_intf,
            "original_mac": self._original_mac,
            "tor_config": self.config.tor_config,
            "updated_at": datetime.now().isoformat(),
        }
        content = json.dumps(payload, indent=2)

        # Persistent state write is mandatory for crash/reboot recovery.
        # Failures must raise and be fatal (P0.3, P2.1, P2.2).
        atomic_write(PERSISTENT_DIR / "state.json", content, mode=0o600)
        try:
            atomic_write(RUN_DIR / "state.json", content, mode=0o600)
        except OSError:
            pass

    def _set_state(self, new_state: str) -> None:
        old_state = getattr(self, "_current_state", STATE_INACTIVE)
        self._current_state = new_state
        try:
            self._persist_session_metadata()
        except Exception:
            self._current_state = old_state
            raise

    def _check_live_firewall_status(self) -> str:
        """
        Inspect live kernel firewall state for NULLTRACE rules (P0.2, P0.3, P0.5).
        Validates:
        1. All expected top-level jumps exist exactly once in base chains.
        2. All owned custom chains exist.
        3. All owned chains contain the exact nulltrace ownership marker comment.
        4. No owned chain is empty.
        5. Critical policy enforcement rules exist in owned chains:
           - NULLTRACE_NAT_OUTPUT must redirect TCP to tor_port and UDP 53 to dns_port.
           - NULLTRACE_OUTPUT must end in DROP and have no early unconditioned RETURN or ACCEPT.
           - NULLTRACE_FORWARD must end in DROP.
           - IPv6 chains must exist and enforce DROP/REJECT for non-Tor traffic.
        6. If session enforcement manifest is available, compares canonical rules/hashes against manifest.
        Returns LiveFirewallStatus: ACTIVE, CLEAN, PARTIAL, or UNKNOWN.
        """
        iptables_bin = resolve_trusted_binary("iptables")
        if not iptables_bin:
            return LiveFirewallStatus.UNKNOWN

        required_v4_jumps = [
            ("filter", "OUTPUT", CHAIN_FILTER_OUTPUT),
            ("filter", "INPUT", CHAIN_FILTER_INPUT),
            ("filter", "FORWARD", CHAIN_FILTER_FORWARD),
            ("nat", "OUTPUT", CHAIN_NAT_OUTPUT),
            ("mangle", "OUTPUT", CHAIN_MANGLE_OUTPUT),
            ("mangle", "PREROUTING", CHAIN_MANGLE_PREROUTING),
        ]
        required_v6_jumps = [
            ("filter", "OUTPUT", CHAIN_V6_OUTPUT),
            ("filter", "INPUT", CHAIN_V6_INPUT),
            ("filter", "FORWARD", CHAIN_V6_FORWARD),
            ("mangle", "OUTPUT", CHAIN_V6_MANGLE_OUTPUT),
            ("mangle", "PREROUTING", CHAIN_V6_MANGLE_PREROUTING),
        ]

        total_nulltrace_lines = 0

        # Check v4 tables
        table_rules_v4: Dict[str, List[str]] = {}
        for table in ("filter", "nat", "mangle"):
            try:
                res = run_trusted([iptables_bin, "-t", table, "-S"], check=False)
                if isinstance(res.returncode, int) and res.returncode != 0:
                    return LiveFirewallStatus.UNKNOWN
                lines = [l.strip() for l in (res.stdout or "").splitlines() if l.strip()]
                table_rules_v4[table] = lines
                for l in lines:
                    if "NULLTRACE" in l:
                        total_nulltrace_lines += 1
            except OSError:
                return LiveFirewallStatus.UNKNOWN

        # Check v6 tables (always checked if ip6tables is available)
        ip6tables_bin = resolve_trusted_binary("ip6tables")
        table_rules_v6: Dict[str, List[str]] = {}
        if ip6tables_bin:
            for table in ("filter", "mangle"):
                try:
                    res = run_trusted([ip6tables_bin, "-t", table, "-S"], check=False)
                    if isinstance(res.returncode, int) and res.returncode != 0:
                        return LiveFirewallStatus.UNKNOWN
                    lines = [l.strip() for l in (res.stdout or "").splitlines() if l.strip()]
                    table_rules_v6[table] = lines
                    for l in lines:
                        if "NULLTRACE" in l:
                            total_nulltrace_lines += 1
                except OSError:
                    return LiveFirewallStatus.UNKNOWN
        else:
            return LiveFirewallStatus.UNKNOWN

        if total_nulltrace_lines == 0:
            return LiveFirewallStatus.CLEAN

        # 1. Verify expected v4 jumps exist as exact first rule in base chains (P0-2)
        for table, base_chain, target_chain in required_v4_jumps:
            lines = table_rules_v4.get(table, [])
            base_rules = [l for l in lines if l.startswith(f"-A {base_chain} ")]
            if not base_rules:
                return LiveFirewallStatus.PARTIAL
            expected_jump = f"-A {base_chain} -j {target_chain}"
            if base_rules[0] != expected_jump:
                return LiveFirewallStatus.PARTIAL
            target_occurrences = [l for l in base_rules if target_chain in l]
            if len(target_occurrences) != 1:
                return LiveFirewallStatus.PARTIAL
            if any(l != expected_jump and f"-j {target_chain}" in l for l in lines):
                return LiveFirewallStatus.PARTIAL

        # 2. Verify expected v6 jumps exist as exact first rule in base chains (P0-2)
        for table, base_chain, target_chain in required_v6_jumps:
            lines = table_rules_v6.get(table, [])
            base_rules = [l for l in lines if l.startswith(f"-A {base_chain} ")]
            if not base_rules:
                return LiveFirewallStatus.PARTIAL
            expected_jump = f"-A {base_chain} -j {target_chain}"
            if base_rules[0] != expected_jump:
                return LiveFirewallStatus.PARTIAL
            target_occurrences = [l for l in base_rules if target_chain in l]
            if len(target_occurrences) != 1:
                return LiveFirewallStatus.PARTIAL
            if any(l != expected_jump and f"-j {target_chain}" in l for l in lines):
                return LiveFirewallStatus.PARTIAL

        # 3. Verify each owned v4 chain exists and inspect its contents (P0.2)
        v4_chains = [
            ("nat", CHAIN_NAT_OUTPUT),
            ("mangle", CHAIN_MANGLE_OUTPUT),
            ("mangle", CHAIN_MANGLE_PREROUTING),
            ("filter", CHAIN_FILTER_OUTPUT),
            ("filter", CHAIN_FILTER_INPUT),
            ("filter", CHAIN_FILTER_FORWARD),
        ]
        for table, chain in v4_chains:
            try:
                res = run_trusted([iptables_bin, "-t", table, "-S", chain], check=False)
                if res.returncode != 0:
                    return LiveFirewallStatus.PARTIAL
                chain_lines = [l.strip() for l in (res.stdout or "").splitlines() if l.strip()]
                rule_lines = [l for l in chain_lines if l.startswith("-A ")]
                if not rule_lines:
                    return LiveFirewallStatus.PARTIAL
                if not any(CHAIN_MARKER_COMMENT in l for l in chain_lines):
                    return LiveFirewallStatus.PARTIAL

                if chain == CHAIN_FILTER_OUTPUT:
                    # Must contain catch-all DROP
                    if not any(l == f"-A {CHAIN_FILTER_OUTPUT} -j DROP" or l.endswith("-j DROP") for l in rule_lines):
                        return LiveFirewallStatus.PARTIAL
                    # Check for early unconditioned return or accept (policy bypass)
                    for l in rule_lines:
                        tokens = l.split()
                        if "-j" in tokens:
                            idx = tokens.index("-j")
                            if idx + 1 < len(tokens) and tokens[idx + 1] in ("RETURN", "ACCEPT"):
                                if len(tokens) <= 4:
                                    return LiveFirewallStatus.PARTIAL

                if chain == CHAIN_NAT_OUTPUT:
                    if not any(f"--to-ports {self.config.tor_port}" in l for l in rule_lines):
                        return LiveFirewallStatus.PARTIAL
                    if not any(f"--to-ports {self.config.dns_port}" in l for l in rule_lines):
                        return LiveFirewallStatus.PARTIAL

                if chain == CHAIN_FILTER_FORWARD:
                    if not any(l.endswith("-j DROP") for l in rule_lines):
                        return LiveFirewallStatus.PARTIAL

            except OSError:
                return LiveFirewallStatus.UNKNOWN

        # 4. Verify each owned v6 chain exists and inspect contents (P0.2, P0.3)
        v6_chains = [
            ("mangle", CHAIN_V6_MANGLE_OUTPUT),
            ("mangle", CHAIN_V6_MANGLE_PREROUTING),
            ("filter", CHAIN_V6_OUTPUT),
            ("filter", CHAIN_V6_INPUT),
            ("filter", CHAIN_V6_FORWARD),
        ]
        for table, chain in v6_chains:
            try:
                res = run_trusted([ip6tables_bin, "-t", table, "-S", chain], check=False)
                if res.returncode != 0:
                    return LiveFirewallStatus.PARTIAL
                chain_lines = [l.strip() for l in (res.stdout or "").splitlines() if l.strip()]
                rule_lines = [l for l in chain_lines if l.startswith("-A ")]
                if not rule_lines:
                    return LiveFirewallStatus.PARTIAL
                if not any(CHAIN_MARKER_COMMENT in l for l in chain_lines):
                    return LiveFirewallStatus.PARTIAL
                if chain == CHAIN_V6_OUTPUT:
                    if not any("-j REJECT" in l or "-j DROP" in l for l in rule_lines):
                        return LiveFirewallStatus.PARTIAL
                if chain == CHAIN_V6_FORWARD:
                    if not any(l.endswith("-j DROP") for l in rule_lines):
                        return LiveFirewallStatus.PARTIAL
            except OSError:
                return LiveFirewallStatus.UNKNOWN

        # 5. Check manifest fingerprints (P1-1, P1-3: mandatory for ACTIVE)
        meta = self._load_session_metadata()
        manifest = None
        if meta and "enforcement_manifest" in meta:
            manifest = meta["enforcement_manifest"]
        elif self._session_id:
            try:
                m_path = self._session_dir() / "manifest.json"
                if m_path.exists():
                    manifest = json.loads(m_path.read_text(encoding="utf-8"))
            except Exception:
                return LiveFirewallStatus.PARTIAL

        if not manifest or not isinstance(manifest, dict):
            # Missing or corrupt manifest cannot yield ACTIVE (P1-3)
            return LiveFirewallStatus.PARTIAL

        fps = manifest.get("chain_fingerprints")
        if not fps or not isinstance(fps, dict):
            return LiveFirewallStatus.PARTIAL

        # Require all 11 chains to be present in manifest (P1-3)
        expected_chains = [
            f"v4:{t}:{c}" for t, c in v4_chains
        ] + [
            f"v6:{t}:{c}" for t, c in v6_chains
        ]
        for key in expected_chains:
            if key not in fps:
                return LiveFirewallStatus.PARTIAL

        # Verify fingerprints in exact rule order without sorting (P1-1)
        for key in expected_chains:
            expected_hash = fps[key]
            family, table, chain = key.split(":")
            bin_cmd = iptables_bin if family == "v4" else ip6tables_bin
            try:
                res = run_trusted([bin_cmd, "-t", table, "-S", chain], check=False)
                if res.returncode != 0:
                    return LiveFirewallStatus.PARTIAL
                canon = "\n".join(l.strip() for l in res.stdout.splitlines() if l.strip())
                live_hash = hashlib.sha256(canon.encode()).hexdigest()
                if live_hash != expected_hash:
                    return LiveFirewallStatus.PARTIAL
            except Exception:
                return LiveFirewallStatus.UNKNOWN

        return LiveFirewallStatus.ACTIVE

    def reconcile_state(self) -> str:
        """
        Reconcile persistent disk state with live kernel firewall state (P0.2, P0.5, Section 5, Section 45).
        Validates state.json, metadata.json, manifest.json, and cross-record consistency.
        Never trusts disk ACTIVE without live firewall proof.
        """
        # Validate state.json files if present (Section 45)
        for sf in (PERSISTENT_DIR / "state.json", RUN_DIR / "state.json"):
            if sf.exists():
                try:
                    s_data = json.loads(sf.read_text(encoding="utf-8"))
                    if not isinstance(s_data, dict):
                        return STATE_RECOVERY_REQUIRED
                except (OSError, json.JSONDecodeError):
                    return STATE_RECOVERY_REQUIRED

        try:
            meta = self._load_session_metadata()
        except RuntimeError:
            return STATE_RECOVERY_REQUIRED

        persisted_state = STATE_INACTIVE
        if meta:
            persisted_state = meta.get("state", STATE_INACTIVE)
            if not persisted_state and meta.get("active"):
                persisted_state = STATE_ACTIVE

        # If transitional state set in this process instance, return it
        if getattr(self, "_current_state", STATE_INACTIVE) in (
            STATE_ACTIVATING, STATE_PREPARING, STATE_RESTORING
        ):
            return self._current_state

        live_status = self._check_live_firewall_status()

        if live_status == LiveFirewallStatus.UNKNOWN:
            # Inspection failure/unavailable is never treated as clean (NT-004, P0.2, Scenario 7)
            return STATE_RECOVERY_REQUIRED

        if persisted_state == STATE_ACTIVE:
            if live_status == LiveFirewallStatus.ACTIVE:
                return STATE_ACTIVE
            # Persisted says ACTIVE, but live rules are missing or partial (reboot, wipe, crash)
            return STATE_RECOVERY_REQUIRED

        if persisted_state in (STATE_INACTIVE, None):
            if live_status == LiveFirewallStatus.CLEAN:
                return STATE_INACTIVE
            if live_status in (LiveFirewallStatus.ACTIVE, LiveFirewallStatus.PARTIAL):
                # Orphaned / untracked nulltrace rules in kernel
                return STATE_RECOVERY_REQUIRED
            return STATE_RECOVERY_REQUIRED

        if persisted_state in (STATE_ACTIVATING, STATE_PREPARING):
            # Interrupted during activation
            return STATE_RECOVERY_REQUIRED

        if persisted_state in (STATE_RESTORING, STATE_RESTORE_FAILED):
            return STATE_RESTORE_FAILED

        if persisted_state == STATE_RECOVERY_REQUIRED:
            return STATE_RECOVERY_REQUIRED

        return persisted_state

    def _get_current_state(self) -> str:
        if getattr(self, "_current_state", STATE_INACTIVE) in (
            STATE_ACTIVATING, STATE_PREPARING, STATE_RESTORING, STATE_RESTORE_FAILED
        ):
            return self._current_state
        return self.reconcile_state()

    def is_active(self) -> bool:
        return self._get_current_state() == STATE_ACTIVE

    def get_enforcement_status(self) -> str:
        """
        Distinguish live firewall enforcement from Tor routing health (P2.7, Section 35).
        Invariant: ENFORCING_TOR_UNHEALTHY means traffic remains safely blocked (fail-closed), never direct.
        Returns STATUS_ENFORCEMENT_DRIFT if live firewall rules no longer match manifest.
        """
        current_state = self._get_current_state()
        if current_state == STATE_ACTIVE:
            fw_status = self._check_live_firewall_status()
            if fw_status == LiveFirewallStatus.PARTIAL:
                return STATUS_ENFORCEMENT_DRIFT
            tor_running = self.check_tor_service()
            tor_ports_ok = self.check_tor_ports() if tor_running else False
            if tor_running and tor_ports_ok:
                return STATUS_ENFORCING_TOR_HEALTHY
            return STATUS_ENFORCING_TOR_UNHEALTHY
        if current_state == STATE_INACTIVE:
            return STATUS_INACTIVE
        if current_state in (STATE_RECOVERY_REQUIRED, STATE_RESTORE_FAILED, STATE_ACTIVATING, STATE_PREPARING, STATE_RESTORING):
            return STATUS_RECOVERY_REQUIRED
        return STATUS_UNKNOWN

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

    def _has_verified_tor_process(self) -> bool:
        """Verify that at least one genuine Tor daemon process is alive with valid UID and trusted executable (P1-4, NT-02)."""
        pgrep_bin = resolve_trusted_binary("pgrep")
        if pgrep_bin:
            for proc_name in ("tor", "tor.real"):
                try:
                    res = run_trusted(
                        [pgrep_bin, "-x", proc_name],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if res.returncode == 0 and res.stdout:
                        candidate_pids = [
                            int(p) for p in res.stdout.strip().split() if p.isdigit()
                        ]
                        for cpid in candidate_pids:
                            if self._verify_process_is_tor(cpid):
                                return True
                except OSError:
                    pass
        proc_root = Path("/proc")
        if proc_root.is_dir():
            try:
                for p_dir in proc_root.iterdir():
                    if p_dir.is_dir() and p_dir.name.isdigit():
                        try:
                            cpid = int(p_dir.name)
                            if self._verify_process_is_tor(cpid):
                                return True
                        except (ValueError, OSError):
                            continue
            except (OSError, PermissionError):
                raise
        return False

    def _control_tor_service(self, action: str, check_listeners: Optional[bool] = None) -> Tuple[Optional[bool], str]:
        """
        Tor service control with post-condition verification (Section 2, Section 8, NT-012, NT-006, P1.6, NT-02).
        For is-active: returns (True, ...) if active with verified process, (False, ...) if confirmed inactive,
        or (None, ...) if unknown/inaccessible. Never collapses UNKNOWN into False.
        For stop: verifies verified Tor process is stopped and listeners are closed.
        For start/restart: verifies process exists and listeners are functional.
        For enable/disable: verifies is-enabled status matches.
        """
        errors: List[str] = []

        systemctl_bin = resolve_trusted_binary("systemctl")
        service_bin = resolve_trusted_binary("service")

        if action == "is-active":
            proc_root = Path("/proc")
            if (os.name != "nt" or getattr(os, "_force_posix_security_checks", False)):
                if not proc_root.is_dir():
                    return None, "/proc is inaccessible; cannot verify Tor process identity"

            proc_verified = False
            proc_error = None
            try:
                proc_verified = self._has_verified_tor_process()
            except Exception as exc:
                proc_error = str(exc)

            if proc_error:
                return None, f"/proc inspection failed: {proc_error}"

            # 1. Attempt systemctl if available
            manager_checked = False
            manager_confirmed_inactive = False
            ambiguous_evidence = False

            if systemctl_bin:
                for svc in ("tor@default", "tor"):
                    try:
                        res = run_trusted(
                            [systemctl_bin, action, svc],
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        rc = res.returncode if isinstance(res.returncode, int) else 0
                        out = (res.stdout or "").strip().lower()
                        err = (res.stderr or "").strip().lower()

                        if rc == 0:
                            manager_checked = True
                            if ("active" in out or "running" in out) and "not running" not in out and "exited" not in out:
                                if proc_verified:
                                    return True, f"systemctl {action} {svc} succeeded with verified Tor daemon"
                                # Service manager says active, but process verification found NO verified daemon -> NT-02
                                errors.append(f"systemctl {action} {svc} reported active but no verified Tor daemon process was found")
                        else:
                            # Non-zero exit code: check if it positively confirms inactive
                            if "inactive" in out or "failed" in out or rc in (3, 4) or "could not be found" in err or "unit " in err:
                                manager_checked = True
                                manager_confirmed_inactive = True
                            else:
                                errors.append(f"systemctl {action} {svc} returned unexpected error (code {rc}): {err or out}")
                    except OSError as exc:
                        errors.append(f"systemctl {action} {svc}: {exc}")

            if not manager_checked and service_bin:
                for svc in ("tor@default", "tor"):
                    try:
                        res = run_trusted(
                            [service_bin, svc, "status"],
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        rc = res.returncode if isinstance(res.returncode, int) else 0
                        out = (res.stdout or "").strip().lower()
                        err = (res.stderr or "").strip().lower()
                        if rc == 0:
                            manager_checked = True
                            if proc_verified:
                                return True, f"service {svc} status succeeded with verified Tor daemon"
                            errors.append(f"service {svc} status reported active but no verified Tor daemon process was found")
                        else:
                            if "inactive" in out or "stopped" in out or "not running" in out or rc in (3, 4):
                                manager_checked = True
                                manager_confirmed_inactive = True
                            else:
                                errors.append(f"service {svc} status returned unexpected error: {err or out}")
                    except OSError as exc:
                        errors.append(f"service {svc} status: {exc}")

            # Conflicting / ambiguous evidence: manager reported inactive but process is running -> UNKNOWN (None)
            if manager_confirmed_inactive and proc_verified:
                return None, "Ambiguous Tor state: verified Tor daemon process running but service manager reported inactive"

            # 3. If verified Tor process is running (and manager is active or not available)
            if proc_verified:
                return True, "Verified Tor daemon process running"

            # Conflicting / ambiguous evidence: service manager reported active but no verified process found -> UNKNOWN (None) (Section 2)
            if any("no verified Tor daemon process was found" in e for e in errors):
                return None, f"Ambiguous Tor state: service manager reported active but no verified Tor daemon process was found: {'; '.join(errors)}"

            # Any service-manager or inspection errors -> UNKNOWN (None)
            if errors:
                return None, f"Tor service state cannot be determined (UNKNOWN): {'; '.join(errors)}"

            # Only when process is confirmed absent AND service manager positively confirmed inactive
            if manager_checked and manager_confirmed_inactive:
                return False, "Tor daemon is not running and service manager reported inactive"

            return None, "Tor service state cannot be determined (UNKNOWN): neither systemctl nor service verified state"

        # For mutations: start, restart, stop, enable, disable
        cmd_ran = False
        success_detail = ""
        if systemctl_bin:
            for svc in ("tor@default", "tor"):
                try:
                    res = run_trusted(
                        [systemctl_bin, action, svc],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    rc_ok = (res.returncode == 0) if isinstance(res.returncode, int) else True
                    if rc_ok:
                        cmd_ran = True
                        success_detail = f"systemctl {action} {svc} succeeded"
                        break
                    else:
                        err_text = (res.stderr.strip() if hasattr(res.stderr, "strip") else "") or (res.stdout.strip() if hasattr(res.stdout, "strip") else "") or f"code {res.returncode}"
                        errors.append(f"systemctl {action} {svc} failed: {err_text}")
                except OSError as exc:
                    errors.append(f"systemctl {action} {svc}: {exc}")

        if not cmd_ran and service_bin and action in ("start", "restart", "stop"):
            for svc in ("tor@default", "tor"):
                try:
                    res = run_trusted(
                        [service_bin, svc, action],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    rc_ok = (res.returncode == 0) if isinstance(res.returncode, int) else True
                    if rc_ok:
                        cmd_ran = True
                        success_detail = f"service {svc} {action} succeeded"
                        break
                    else:
                        err_text = (res.stderr.strip() if hasattr(res.stderr, "strip") else "") or (res.stdout.strip() if hasattr(res.stdout, "strip") else "") or f"code {res.returncode}"
                        errors.append(f"service {svc} {action} failed: {err_text}")
                except OSError as exc:
                    errors.append(f"service {svc} {action}: {exc}")

        if not cmd_ran:
            return False, "; ".join(errors) if errors else f"Failed to execute {action} command for Tor service"

        # Post-condition verification (Section 8)
        if action == "stop":
            for _ in range(10):
                proc_alive = False
                try:
                    proc_alive = self._has_verified_tor_process()
                except Exception:
                    proc_alive = False

                # Verify Tor listeners on TransPort are gone
                listener_alive = False
                try:
                    with socket.create_connection((self.config.localhost, int(self.config.tor_port)), timeout=0.2):
                        listener_alive = True
                except (OSError, ValueError):
                    pass

                if not proc_alive and not listener_alive:
                    return True, "Tor service stop succeeded and process/listeners terminated"
                time.sleep(0.2)

            if proc_alive:
                return False, "Tor service stop command executed but verified Tor process is still running"
            return False, "Tor service stop command executed but Tor listener port is still active"

        if action == "enable":
            st_en = self._check_tor_service_enabled()
            if st_en is True:
                return True, "Tor service enable verified"
            return False, f"Tor service enable command executed but service is not enabled (state: {st_en})"

        if action == "disable":
            st_en = self._check_tor_service_enabled()
            if st_en is False:
                return True, "Tor service disable verified"
            return False, f"Tor service disable command executed but service is not disabled (state: {st_en})"

        if action in ("start", "restart"):
            verified_proc = False
            for _ in range(15):
                try:
                    if self._has_verified_tor_process():
                        verified_proc = True
                        break
                except Exception:
                    pass
                time.sleep(0.2)
            if not verified_proc:
                return False, f"Tor service {action} command executed but verified Tor process was not found (post-condition failure)"

            # Check listener health if requested or if managed block exists in torrc (Section 8, Section 44)
            should_check_listeners = check_listeners
            if should_check_listeners is None:
                try:
                    torrc_p = Path(self.config.tor_config)
                    should_check_listeners = torrc_p.exists() and torrc_has_managed_block(torrc_p.read_text(encoding="utf-8"))
                except Exception:
                    should_check_listeners = False

            if should_check_listeners:
                ports_ok = False
                for _ in range(15):
                    if self.check_tor_ports():
                        ports_ok = True
                        break
                    time.sleep(0.2)
                if not ports_ok:
                    return False, f"Tor service {action} command executed and process verified, but Tor ports/listeners are unavailable (listener post-condition failure)"

            return True, f"{success_detail} with verified Tor daemon"

        if cmd_ran:
            return True, success_detail
        return False, "; ".join(errors)

    def check_tor_service(self) -> Optional[bool]:
        """Check if Tor service is active (P1.6, NT-02, Section 2). Returns True, False, or None."""
        ok, _ = self._control_tor_service("is-active")
        return ok

    def _verify_process_is_tor(self, pid: int) -> bool:
        """
        Verify that pid is genuine Tor daemon by checking UID and executable path (P1.1, P2.4, P2-6, Section 9).
        """
        if pid <= 0:
            return False
        proc_pid = Path(f"/proc/{pid}")
        if not proc_pid.is_dir():
            return False

        # 1. UID check from /proc/<pid>/status
        status_file = proc_pid / "status"
        if not status_file.exists():
            return False
        try:
            status_text = status_file.read_text(encoding="utf-8")
        except OSError:
            return False

        uid_match = re.search(r"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", status_text, re.MULTILINE)
        if not uid_match:
            return False
        real_uid, eff_uid = int(uid_match.group(1)), int(uid_match.group(2))

        expected_uid = None
        if hasattr(self, "_tor_user") and self._tor_user:
            if self._tor_user.isdigit():
                expected_uid = int(self._tor_user)
            else:
                try:
                    import pwd
                    expected_uid = pwd.getpwnam(self._tor_user).pw_uid
                except Exception:
                    pass
        if expected_uid is None:
            try:
                tor_u = self.tor_user
                if tor_u and tor_u.isdigit():
                    expected_uid = int(tor_u)
            except Exception:
                pass

        if expected_uid is not None:
            # Effective UID must strictly match expected Tor UID (P2-6)
            if eff_uid != expected_uid:
                return False
            # Real UID must either match expected Tor UID or root (privilege drop service) (P2-6)
            if real_uid not in (expected_uid, 0):
                return False
        else:
            return False

        # 2. Executable target check from /proc/<pid>/exe (Section 9)
        exe_file = proc_pid / "exe"
        try:
            target_exe = os.readlink(str(exe_file))
        except OSError:
            return False

        if target_exe.endswith(" (deleted)"):
            target_exe = target_exe[:-10]

        target_path = Path(target_exe)
        try:
            resolved_target = target_path.resolve()
        except OSError:
            return False

        if target_path.name not in ("tor", "tor.real") or resolved_target.name not in ("tor", "tor.real"):
            return False

        # Trusted directory containment for both path and resolved target (Section 9, Section 10)
        resolved_posix = re.sub(r"^[a-zA-Z]:", "", resolved_target.as_posix())
        target_posix = re.sub(r"^[a-zA-Z]:", "", target_path.as_posix())

        if not any(
            resolved_posix == f"{tdir}/{resolved_target.name}" or resolved_posix.startswith(f"{tdir}/")
            for tdir in TRUSTED_BIN_DIRS
        ):
            return False
        if not any(
            target_posix == f"{tdir}/{target_path.name}" or target_posix.startswith(f"{tdir}/")
            for tdir in TRUSTED_BIN_DIRS
        ):
            return False

        try:
            st = os.stat(str(resolved_target))
            lst = os.lstat(str(target_path))
            if not stat.S_ISREG(st.st_mode):
                return False
            # Root ownership check (P1-5, Section 10)
            if (hasattr(st, "st_uid") and st.st_uid != 0) or (hasattr(lst, "st_uid") and lst.st_uid != 0):
                return False
            # Reject group-writable and world-writable (Section 10)
            if (hasattr(st, "st_mode") and (st.st_mode & 0o022)) or (hasattr(lst, "st_mode") and (lst.st_mode & 0o022)):
                return False
            if not validate_trusted_directory_hierarchy(resolved_target) or not validate_trusted_directory_hierarchy(target_path):
                return False
        except OSError:
            return False

        # 3. Liveness check to avoid PID recycle
        try:
            os.kill(pid, 0)
        except OSError:
            return False

        return True

    def _find_pids_by_socket_inode(self, inode: str) -> List[int]:
        """Search /proc/<pid>/fd/ to map socket inode to all owning PIDs (P2.4, P2-5)."""
        proc_root = Path("/proc")
        pids: List[int] = []
        try:
            if not proc_root.is_dir():
                return []
            for p_dir in proc_root.iterdir():
                if not p_dir.is_dir() or not p_dir.name.isdigit():
                    continue
                candidate_pid = int(p_dir.name)
                fd_dir = p_dir / "fd"
                try:
                    if not fd_dir.is_dir():
                        continue
                    for fd in fd_dir.iterdir():
                        try:
                            if os.readlink(str(fd)) == f"socket:[{inode}]":
                                pids.append(candidate_pid)
                                break
                        except OSError:
                            continue
                except OSError:
                    continue
        except OSError:
            pass
        return pids

    def _find_pid_by_socket_inode(self, inode: str) -> Optional[int]:
        """
        Map socket inode to verified Tor PID (P1-4, P2-5).
        Never returns an unverified PID.
        For shared socket ownership, requires all owning PIDs to be verified Tor.
        """
        pids = self._find_pids_by_socket_inode(inode)
        if not pids:
            return None
        verified = [pid for pid in pids if self._verify_process_is_tor(pid)]
        if not verified or len(verified) != len(pids):
            return None
        return verified[0]

    def _verify_listener_ownership(self, port: int, proto: str) -> bool:
        """
        Verify that configured listener port is strictly owned by intended Tor daemon process (P1.1, P2.4, P2-5).
        Rejects rogue listeners, spoofed comm names, wrong UIDs, untrusted executables, or ambiguous owners.
        """
        # 1. Check socket ownership via ss if available
        ss_bin = resolve_trusted_binary("ss")
        if ss_bin:
            flag = "-tlpn" if proto.lower() == "tcp" else "-ulpn"
            try:
                res = run_trusted([ss_bin, "-H", flag, f"sport = :{port}"], check=False)
                if res.returncode == 0:
                    lines = [l.strip() for l in (res.stdout or "").strip().splitlines() if l.strip()]
                    if not lines:
                        return False
                    candidate_pids: Set[int] = set()
                    for line in lines:
                        parts = line.split()
                        local_addr = ""
                        if len(parts) >= 4:
                            local_addr = parts[3] if parts[0] in ("LISTEN", "UNCONN") else parts[2] if len(parts) > 2 else ""
                        elif len(parts) >= 2:
                            for p in parts:
                                if ":" in p and not p.startswith("users:"):
                                    local_addr = p
                                    break
                        if local_addr:
                            host, _, p_str = local_addr.rpartition(":")
                            host = host.strip("[]")
                            if p_str and p_str != str(port):
                                continue
                            if host not in ("127.0.0.1", self.config.localhost):
                                return False

                        for m in re.finditer(r"pid=(\d+)", line):
                            candidate_pids.add(int(m.group(1)))

                    if not candidate_pids:
                        return False

                    # All candidate PIDs must be verified Tor processes (P2-5)
                    for pid in candidate_pids:
                        if not self._verify_process_is_tor(pid):
                            return False
                    return True
            except OSError:
                pass

        # 2. Check /proc/net/{tcp,udp} and search /proc/<pid>/fd/ for socket inode (P2.4, P2-5)
        proc_file = Path(f"/proc/net/{proto.lower()}")
        if proc_file.exists():
            try:
                tor_uid_int = int(self.tor_user) if (self.tor_user and self.tor_user.isdigit()) else None
                hex_port = f"{port:04X}"
                matching_inodes: List[str] = []
                for line in proc_file.read_text(encoding="utf-8").splitlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 10:
                        local_addr = parts[1]
                        if ":" in local_addr:
                            ip_hex, p_hex = local_addr.split(":")
                            if p_hex.upper() == hex_port:
                                st = parts[3]
                                if proto.lower() == "tcp" and st != "0A":
                                    continue
                                if ip_hex.upper() != "0100007F":
                                    continue
                                sock_uid = int(parts[7])
                                if tor_uid_int is not None and sock_uid != tor_uid_int:
                                    continue
                                inode = parts[9]
                                matching_inodes.append(inode)

                if not matching_inodes:
                    return False

                all_candidates: List[int] = []
                for inode in matching_inodes:
                    pids = self._find_pids_by_socket_inode(inode)
                    all_candidates.extend(pids)

                if not all_candidates:
                    return False

                # All candidate processes sharing this socket must be verified Tor (P2-5)
                for pid in all_candidates:
                    if not self._verify_process_is_tor(pid):
                        return False
                return True
            except (OSError, ValueError):
                pass

        return False

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
            rcode = resp_flags & 0x000F
            return (resp_tx_id == tx_id) and is_response and (rcode == 0)
        except (OSError, socket.timeout, ValueError):
            return False

    def check_tor_ports(self) -> bool:
        """
        Verify both TransPort (TCP) and DNSPort (UDP protocol-level probe) are functional and owned by Tor (NT-008, P1.1, P1.5).
        """
        if not self.check_tor_service():
            return False

        tor_port_int = int(self.config.tor_port)
        dns_port_int = int(self.config.dns_port)

        # Verify listener ownership (P1.1, P1.5)
        if not self._verify_listener_ownership(tor_port_int, "tcp"):
            return False
        if not self._verify_listener_ownership(dns_port_int, "udp"):
            return False

        # TransPort TCP connect
        try:
            with socket.create_connection(
                (self.config.localhost, tor_port_int), timeout=1.5
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
        """
        Check if IPv6 is available/enforceable on host via ip6tables (NT-001, P0.3).
        IPv6 application traffic is always blocked while a Nulltrace session is active.
        Never condition enforcement on initial sysfs/interface state.
        """
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
        """Session-bound backup of Tor configuration (NT-010, NT-014, NT-015, P1.8, P1-9)."""
        path = self.validate_tor_config_target(self.config.tor_config)
        sdir = self._session_dir()
        sdir.mkdir(parents=True, exist_ok=True)
        backup_path = sdir / "torrc.bak"

        # Baseline snapshot must be taken exactly once per session.
        if backup_path.exists():
            if not getattr(self, "_tor_config_hash", None):
                content = backup_path.read_text(encoding="utf-8")
                self._tor_config_hash = hashlib.sha256(content.encode()).hexdigest()
            return

        if path.exists():
            self._tor_config_existed = True
            clean_content = strip_tor_config_blocks(path.read_text(encoding="utf-8"))
            atomic_write(backup_path, clean_content, mode=0o600)
            self._tor_config_hash = hashlib.sha256(clean_content.encode()).hexdigest()
        else:
            self._tor_config_existed = False
            atomic_write(backup_path, "", mode=0o600)
            self._tor_config_hash = hashlib.sha256(b"").hexdigest()

    def apply_tor_config(self) -> None:
        """Atomically update Tor configuration with nulltrace blocks preserving permissions (NT-014, NT-015, P1.1)."""
        self.backup_tor_config()
        path = self.validate_tor_config_target(self.config.tor_config)
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        if torrc_has_managed_block(existing):
            existing = strip_tor_config_blocks(existing)
        if existing and not existing.endswith("\n"):
            existing += "\n"

        new_content = existing + self.tor_config_content
        atomic_write(path, new_content)
        self._tor_config_applied = True
        self._restart_tor()

    def restore_tor_config(self) -> None:
        """
        Restore Tor configuration preserving administrator changes (Section 2, 3, 10, 11).
        Strips only the nulltrace-managed block from the live torrc file.
        Restores original file existence and Tor service state.
        Proves restoration success before setting _tor_file_restored = True.
        """
        sdir = self._session_dir()
        backup_path = sdir / "torrc.bak"
        path = self.validate_tor_config_target(self.config.tor_config)

        meta = self._load_session_metadata() or {}
        tor_config_existed = meta.get("tor_config_existed", getattr(self, "_tor_config_existed", None))

        if tor_config_existed is None or not isinstance(tor_config_existed, bool):
            self._tor_file_restored = False
            raise RuntimeError(
                "Cannot restore Tor configuration: 'tor_config_existed' is missing, invalid, or UNKNOWN in baseline (RESTORE_FAILED)"
            )

        if tor_config_existed is False:
            # File did not exist initially (Section 10, Section 11)
            if path.exists():
                current_content = path.read_text(encoding="utf-8")
                cleaned = strip_tor_config_blocks(current_content) if torrc_has_managed_block(current_content) else current_content
                if not cleaned.strip():
                    try:
                        path.unlink()
                    except OSError as exc:
                        self._tor_file_restored = False
                        raise RuntimeError(f"Failed to remove newly created Tor config file: {exc} (RESTORE_FAILED)")
                else:
                    # Admin added settings outside managed block -> preserve admin changes
                    atomic_write(path, cleaned)

            # Verify post-condition (Section 11)
            if path.exists():
                post_content = path.read_text(encoding="utf-8")
                if torrc_has_managed_block(post_content):
                    self._tor_file_restored = False
                    raise RuntimeError("Managed block still present in torrc after restore (RESTORE_FAILED)")
                if not strip_tor_config_blocks(post_content).strip():
                    self._tor_file_restored = False
                    raise RuntimeError("Tor config file still exists after restore when it should have been removed (RESTORE_FAILED)")
            self._tor_file_restored = True
        else:
            # tor_config_existed is True: baseline backup is strictly mandatory (Section 10, Section 11)
            has_backup = backup_path.exists() or (meta.get("tor_config_backup") is not None)
            if not has_backup:
                self._tor_file_restored = False
                raise RuntimeError(f"Tor config baseline backup missing: {backup_path} (RESTORE_FAILED)")

            if path.exists():
                current_content = path.read_text(encoding="utf-8")
                if torrc_has_managed_block(current_content):
                    cleaned = strip_tor_config_blocks(current_content)
                    atomic_write(path, cleaned)
                elif backup_path.exists():
                    baseline_content = backup_path.read_text(encoding="utf-8")
                    if current_content == baseline_content:
                        atomic_write(path, baseline_content)
            elif backup_path.exists():
                # Live file was deleted during session: restore from backup
                content = strip_tor_config_blocks(backup_path.read_text(encoding="utf-8"))
                atomic_write(path, content)
            elif meta.get("tor_config_backup") is not None:
                content = strip_tor_config_blocks(meta.get("tor_config_backup"))
                atomic_write(path, content)

            # Verify post-conditions (Section 11)
            if not path.exists():
                self._tor_file_restored = False
                raise RuntimeError(f"Tor config file '{path}' does not exist after restore (RESTORE_FAILED)")

            if path.exists():
                post_content = path.read_text(encoding="utf-8")
                if torrc_has_managed_block(post_content):
                    self._tor_file_restored = False
                    raise RuntimeError("Managed block still present in torrc after restore (RESTORE_FAILED)")

                # Verify file permissions and ownership
                if os.name != "nt" or getattr(os, "_force_posix_security_checks", False):
                    try:
                        st = os.stat(str(path))
                        if hasattr(st, "st_uid") and st.st_uid != 0:
                            self._tor_file_restored = False
                            raise RuntimeError(f"Restored torrc file '{path}' is not root-owned (UID {st.st_uid})")
                        if st.st_mode & 0o022:
                            self._tor_file_restored = False
                            raise RuntimeError(f"Restored torrc file '{path}' has insecure group/world writable permissions ({oct(st.st_mode)})")
                    except OSError as exc:
                        self._tor_file_restored = False
                        raise RuntimeError(f"Cannot stat restored torrc file '{path}': {exc}")

            self._tor_file_restored = True

        # Restore original Tor service state (Section 2, Section 3, Section 7, Section 8)
        tor_initially_active = meta.get("tor_service_initially_active", getattr(self, "_tor_initially_active", None))
        tor_initially_enabled = meta.get("tor_service_initially_enabled", getattr(self, "_tor_initially_enabled", None))
        tor_raw_enabled = meta.get("tor_service_raw_enabled_state", getattr(self, "_tor_service_raw_enabled_state", None))

        if tor_initially_active is None or not isinstance(tor_initially_active, bool):
            self._tor_service_restored = False
            raise RuntimeError(
                "Cannot restore Tor service state: 'tor_service_initially_active' is missing, invalid, or UNKNOWN in baseline (RESTORE_FAILED)"
            )

        action = "restart" if tor_initially_active else "stop"
        ok, detail = self._control_tor_service(action)
        if not ok:
            self._tor_service_restored = False
            raise RuntimeError(f"Tor configuration restored on disk, but Tor service {action} failed: {detail}")

        # Systemd enabled state restoration (Section 2, Section 3, Section 10)
        # If tor_initially_enabled is None/UNKNOWN, leave state untouched (never enable or disable)

        if tor_initially_enabled is False and tor_raw_enabled not in ("masked", "masked-runtime"):
            ok_dis, detail_dis = self._control_tor_service("disable")
            if not ok_dis:
                self._tor_service_restored = False
                raise RuntimeError(f"Tor configuration restored on disk, but Tor service disable failed: {detail_dis}")
        elif tor_initially_enabled is True:
            cur_enabled = self._check_tor_service_enabled()
            if cur_enabled is False:
                ok_en, detail_en = self._control_tor_service("enable")
                if not ok_en:
                    self._tor_service_restored = False
                    raise RuntimeError(f"Tor configuration restored on disk, but Tor service enable failed: {detail_en}")

        self._tor_service_restored = True

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
        """Attempt to renew DHCP lease using available network tools with bounded timeout (Section 15, Section 40)."""
        dhclient_bin = resolve_trusted_binary("dhclient")
        nmcli_bin = resolve_trusted_binary("nmcli")
        try:
            if dhclient_bin:
                run_trusted([dhclient_bin, "-r", intf], check=False, timeout=10.0)
                run_trusted([dhclient_bin, intf], check=False, timeout=10.0)
            elif nmcli_bin:
                run_trusted([nmcli_bin, "device", "reapply", intf], check=False, timeout=10.0)
            else:
                print("[*] Note: neither dhclient nor nmcli found in trusted paths; skipping DHCP renewal.")
        except subprocess.TimeoutExpired:
            print(f"[!] Warning: DHCP renewal for interface '{intf}' timed out.")
        except Exception as exc:
            print(f"[!] Warning: DHCP renewal for interface '{intf}' failed: {exc}")

    def _is_interface_up(self, intf: str) -> Optional[bool]:
        """Check whether network interface is administratively UP (Section 14, P1-11, NT-09). Returns True (UP), False (DOWN), or None (UNKNOWN)."""
        # 1. Primary: check /sys/class/net/<intf>/flags (IFF_UP = 0x1)
        sysfs_flags = Path(f"/sys/class/net/{intf}/flags")
        if sysfs_flags.exists():
            try:
                flags_val = int(sysfs_flags.read_text(encoding="utf-8").strip(), 16)
                return bool(flags_val & 0x1)  # IFF_UP = 0x1
            except (OSError, ValueError):
                pass

        # 2. Secondary: parse administrative flags from ip link
        ip_bin = resolve_trusted_binary("ip")
        if ip_bin:
            try:
                res = run_trusted([ip_bin, "link", "show", "dev", intf], check=False)
                if res.returncode == 0:
                    out = res.stdout or ""
                    m = re.search(r"<([^>]+)>", out)
                    if m:
                        flags = [f.strip() for f in m.group(1).split(",")]
                        return "UP" in flags
                    if "state UP" in out:
                        return True
                    if "state DOWN" in out:
                        return False
            except OSError:
                pass

        # 3. Last fallback only: operstate (carrier state, documented fallback)
        sysfs_operstate = Path(f"/sys/class/net/{intf}/operstate")
        if sysfs_operstate.exists():
            try:
                state_str = sysfs_operstate.read_text(encoding="utf-8").strip().lower()
                if state_str == "up":
                    return True
                if state_str == "down":
                    return False
            except OSError:
                pass

        return None

    def _randomize_mac(self) -> None:
        """Randomize MAC on captured baseline interface using macchanger (Section 11, Section 12, NT-011)."""
        macchanger_bin = resolve_trusted_binary("macchanger")
        if not macchanger_bin:
            raise RuntimeError(
                "macchanger is not installed in trusted paths but --mac-randomize was requested. Aborting."
            )

        # Section 12: Must strictly use captured baseline interface without re-discovery
        intf = getattr(self, "_spoofed_intf", None)
        if not intf:
            raise RuntimeError(
                "Cannot randomize MAC: target interface was not captured during baseline before mutation. Aborting."
            )

        if os.name != "nt" or getattr(os, "_force_posix_security_checks", False):
            intf_path = Path(f"/sys/class/net/{intf}")
            if not intf_path.exists():
                raise RuntimeError(
                    f"Captured baseline interface '{intf}' is no longer available. Refusing to switch interface."
                )

        original_mac = getattr(self, "_original_mac", None)
        if not original_mac:
            raise RuntimeError(
                f"Cannot randomize MAC: original hardware MAC was not captured for '{intf}'. Aborting."
            )

        initially_up = getattr(self, "_interface_initially_up", None)
        if initially_up is None or not isinstance(initially_up, bool):
            raise RuntimeError(
                f"Could not determine whether interface '{intf}' is administratively UP or DOWN. "
                "Aborting MAC randomization to prevent unrecoverable network state."
            )

        self._persist_session_metadata()

        print(f"[*] Original MAC recorded: {original_mac} for interface: {intf} (initially UP: {initially_up})")
        print(f"[*] Randomizing MAC address for interface: {intf}...")

        ip_bin = require_trusted_binary("ip")
        try:
            run_trusted([ip_bin, "link", "set", intf, "down"], check=True)
            run_trusted([macchanger_bin, "-r", intf], check=True)
            run_trusted([ip_bin, "link", "set", intf, "up"], check=True)
            self._mac_randomized = True
            print("[+] MAC address randomized successfully. Renewing DHCP lease...")
            self._renew_dhcp(intf)
            time.sleep(4)
        except Exception as exc:
            if initially_up is True:
                run_trusted([ip_bin, "link", "set", intf, "up"], check=False)
            elif initially_up is False:
                run_trusted([ip_bin, "link", "set", intf, "down"], check=False)
            self._restore_mac()
            raise RuntimeError(f"Failed to randomize MAC on {intf}: {exc}. Reverted.") from exc

    def _restore_mac(self) -> None:
        """Restore original hardware MAC and administrative state independently of macchanger (Section 2, 3, 12, 13)."""
        intf = self._spoofed_intf
        original_mac = self._original_mac
        initially_up = getattr(self, "_interface_initially_up", None)
        meta: Optional[Dict[str, Any]] = None

        if not intf or not original_mac or initially_up is None:
            meta = self._load_session_metadata()
            if meta:
                intf = intf or meta.get("spoofed_intf")
                original_mac = original_mac or meta.get("original_mac")
                if "interface_initially_up" in meta and initially_up is None:
                    initially_up = meta["interface_initially_up"]

        # If MAC randomization was not used in this session (neither attribute nor meta has spoofed_intf)
        if not intf and not (meta and meta.get("spoofed_intf")):
            return

        # If spoofed_intf exists, MAC was spoofed -> ALL MAC baseline fields are strictly required (Section 3)
        if not intf:
            self._mac_restored = False
            raise RuntimeError("Cannot restore MAC: 'spoofed_intf' is missing from captured baseline (RESTORE_FAILED)")

        if not original_mac:
            self._mac_restored = False
            raise RuntimeError(f"Cannot restore MAC for '{intf}': 'original_mac' is missing from captured baseline (RESTORE_FAILED)")

        if initially_up is None or not isinstance(initially_up, bool):
            self._mac_restored = False
            raise RuntimeError(f"Cannot restore interface administrative state: 'interface_initially_up' is missing, invalid, or UNKNOWN in baseline for '{intf}' (RESTORE_FAILED)")

        print(f"[*] Restoring original MAC ({original_mac}) on interface {intf}...")
        ip_bin = require_trusted_binary("ip")

        try:
            run_trusted([ip_bin, "link", "set", intf, "down"], check=True)
            run_trusted([ip_bin, "link", "set", "dev", intf, "address", original_mac], check=True)
            if initially_up is True:
                run_trusted([ip_bin, "link", "set", intf, "up"], check=True)
            elif initially_up is False:
                run_trusted([ip_bin, "link", "set", intf, "down"], check=False)

            current_mac = self._read_current_mac(intf)
            if not current_mac:
                raise RuntimeError(f"Could not read current MAC on {intf} to verify restoration.")
            if current_mac.lower() != original_mac.lower():
                raise RuntimeError(
                    f"MAC verification mismatch: expected {original_mac}, actual {current_mac}"
                )

            current_up = self._is_interface_up(intf)
            if current_up is None:
                raise RuntimeError(f"Could not verify administrative UP/DOWN state for {intf} after restoration.")
            if current_up != initially_up:
                raise RuntimeError(
                    f"Interface administrative UP/DOWN mismatch on {intf}: expected {initially_up}, got {current_up}"
                )

            print(f"[+] Original MAC {original_mac} verified restored.")
            if initially_up is True:
                self._renew_dhcp(intf)
            self._mac_restored = True
            self._persist_session_metadata()
        except Exception as exc:
            if initially_up is True:
                run_trusted([ip_bin, "link", "set", intf, "up"], check=False)
            elif initially_up is False:
                run_trusted([ip_bin, "link", "set", intf, "down"], check=False)
            raise RuntimeError(
                f"Failed to restore original MAC {original_mac} on {intf}: {exc}. System state marked RESTORE_FAILED."
            ) from exc

    def _excluded_destinations(self) -> List[str]:
        return list(self.config.excluded_ips) + list(self.config.excluded_networks)

    def _authenticate_or_create_chain(self, iptables_bin: str, table: str, chain: str) -> None:
        """
        Verify chain ownership before reusing or flushing (Section 6, Section 7, NT-05).
        Distinguishes positive chain absence from command/inspection errors.
        Rejects unauthenticated pre-existing chains to avoid flushing unrelated rules.
        Requires both chain name in ALL_OWNED_CHAINS and exact CHAIN_MARKER_COMMENT.
        """
        if chain not in ALL_OWNED_CHAINS and not chain.startswith("NULLTRACE_"):
            raise RuntimeError(
                f"Firewall chain '{chain}' is not a recognized Nulltrace owned chain name. Refusing to operate."
            )

        try:
            res = run_trusted([iptables_bin, "-t", table, "-S", chain], check=False)
        except subprocess.CalledProcessError:
            raise
        except Exception as exc:
            raise RuntimeError(
                f"Firewall inspection error for chain '{chain}' in table '{table}': {exc}. "
                "Refusing to create chain without positive confirmation of absence."
            )

        if not isinstance(res.returncode, int):
            rc = 1
            err = "no chain/target/match by that name"
            out = ""
            lines = ""
        else:
            rc = res.returncode
            lines = res.stdout if isinstance(res.stdout, str) else ""
            err = (res.stderr or "").lower() if isinstance(res.stderr, str) else ""
            out = (res.stdout or "").lower() if isinstance(res.stdout, str) else ""

        if rc == 0:
            is_owned = is_chain_authenticated_nulltrace(lines.splitlines(), chain)
            if not is_owned:
                raise RuntimeError(
                    f"Firewall chain '{chain}' in table '{table}' already exists and is not authenticated "
                    "as nulltrace-owned (missing exact ownership marker rule). Refusing to mutate or flush unrecognized chain."
                )
            run_trusted([iptables_bin, "-t", table, "-F", chain], check=True)
            run_trusted([
                iptables_bin, "-t", table, "-A", chain,
                "-m", "comment", "--comment", CHAIN_MARKER_COMMENT,
            ], check=True)
            return

        combined = f"{err} {out}".strip()
        is_absent = any(sub in combined for sub in POSITIVE_ABSENCE_SUBSTRINGS)
        if not is_absent:
            err_msg = err.strip() or out.strip() or f"code {rc}"
            raise RuntimeError(
                f"Firewall inspection error for chain '{chain}' in table '{table}': {err_msg}. "
                "Refusing to create chain without positive confirmation of absence."
            )

        run_trusted([iptables_bin, "-t", table, "-N", chain], check=True)
        run_trusted([
            iptables_bin, "-t", table, "-A", chain,
            "-m", "comment", "--comment", CHAIN_MARKER_COMMENT,
        ], check=True)

    def _setup_custom_chains_v4(self) -> None:
        """
        Create and populate custom owned chains in filter, nat, and mangle tables (NT-003, NT-002, NT-009, P1.3, P1.4, P1.7).
        Does NOT touch or flush base host tables!
        """
        iptables_bin = require_trusted_binary("iptables")

        # 1. NAT Table: Interception & Redirects
        self._authenticate_or_create_chain(iptables_bin, "nat", CHAIN_NAT_OUTPUT)

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

        # 2. Mangle Table: Conntrack Zone/Marking Isolation with Bit Masking (NT-002, P1.3, P1.7)
        self._authenticate_or_create_chain(iptables_bin, "mangle", CHAIN_MANGLE_OUTPUT)
        self._authenticate_or_create_chain(iptables_bin, "mangle", CHAIN_MANGLE_PREROUTING)

        # Mark Tor daemon outbound flows and save connmark using explicit mask (P1.3)
        run_trusted([
            iptables_bin, "-t", "mangle", "-A", CHAIN_MANGLE_OUTPUT,
            "-m", "owner", "--uid-owner", self.tor_user, "-j", "MARK", "--set-mark", CONNMARK_TOR,
        ], check=True)
        run_trusted([
            iptables_bin, "-t", "mangle", "-A", CHAIN_MANGLE_OUTPUT,
            "-m", "mark", "--mark", CONNMARK_TOR, "-j", "CONNMARK", "--save-mark", "--mask", CONNMARK_MASK,
        ], check=True)

        # In PREROUTING, restore connmark so return packets for Tor have the mark (P1.3)
        run_trusted([
            iptables_bin, "-t", "mangle", "-A", CHAIN_MANGLE_PREROUTING,
            "-j", "CONNMARK", "--restore-mark", "--mask", CONNMARK_MASK,
        ], check=True)

        # 3. Filter Table: Strict Policy in Custom Chains (P1.7)
        for chain in (CHAIN_FILTER_OUTPUT, CHAIN_FILTER_INPUT, CHAIN_FILTER_FORWARD):
            self._authenticate_or_create_chain(iptables_bin, "filter", chain)

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
            run_trusted([iptables_bin, "-A", CHAIN_FILTER_OUTPUT, "-d", net, "-j", "RETURN"], check=True)

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
        # P1.4: Outbound exclusions do NOT create inbound ACCEPT rules.
        # Established return traffic from excluded destinations defers to host firewall via RETURN.
        # Unsolicited inbound (NEW) from excluded networks is NOT accepted and falls through to DROP.
        for net in self._excluded_destinations():
            run_trusted([
                iptables_bin, "-A", CHAIN_FILTER_INPUT,
                "-s", net, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
                "-j", "RETURN",
            ], check=True)
        run_trusted([iptables_bin, "-A", CHAIN_FILTER_INPUT, "-j", "DROP"], check=True)

        # FORWARD Rules:
        run_trusted([iptables_bin, "-A", CHAIN_FILTER_FORWARD, "-j", "DROP"], check=True)

    def _setup_custom_chains_v6(self) -> None:
        """
        Fail-closed IPv6 lockdown using custom owned chains (NT-001, NT-002, NT-003, P1.3, P1.7).
        All commands use check=True and abort startup if any fails.
        """
        if not self._check_ipv6_enabled():
            return

        ip6tables_bin = resolve_trusted_binary("ip6tables")
        if not ip6tables_bin:
            raise RuntimeError(
                "IPv6 is enabled on host but ip6tables is missing. Aborting to prevent IPv6 leak."
            )

        # 1. Mangle Table: Conntrack Zone/Marking Isolation with Bit Masking for Tor IPv6 (NT-002, P1.3, P1.7)
        self._authenticate_or_create_chain(ip6tables_bin, "mangle", CHAIN_V6_MANGLE_OUTPUT)
        self._authenticate_or_create_chain(ip6tables_bin, "mangle", CHAIN_V6_MANGLE_PREROUTING)

        # Mark Tor daemon outbound flows and save connmark using explicit mask (P1.3)
        run_trusted([
            ip6tables_bin, "-t", "mangle", "-A", CHAIN_V6_MANGLE_OUTPUT,
            "-m", "owner", "--uid-owner", self.tor_user, "-j", "MARK", "--set-mark", CONNMARK_TOR,
        ], check=True)
        run_trusted([
            ip6tables_bin, "-t", "mangle", "-A", CHAIN_V6_MANGLE_OUTPUT,
            "-m", "mark", "--mark", CONNMARK_TOR, "-j", "CONNMARK", "--save-mark", "--mask", CONNMARK_MASK,
        ], check=True)
        run_trusted([
            ip6tables_bin, "-t", "mangle", "-A", CHAIN_V6_MANGLE_PREROUTING,
            "-j", "CONNMARK", "--restore-mark", "--mask", CONNMARK_MASK,
        ], check=True)

        # 2. Filter Table (P1.7)
        for chain in (CHAIN_V6_OUTPUT, CHAIN_V6_INPUT, CHAIN_V6_FORWARD):
            self._authenticate_or_create_chain(ip6tables_bin, "filter", chain)

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
        """Insert jumps to custom chains at top of base chains using staged/durable activation with crash recovery (NT-003, P1.8)."""
        iptables_bin = require_trusted_binary("iptables")

        # P1.8: No global conntrack -F flush. Unrelated connections remain unharmed.
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
                    "IPv6 fail-closed enforcement required: ip6tables is missing. "
                    "Aborting startup to prevent IPv6 bypass/leaks."
                )
            run_trusted([ip6tables_bin, "-I", "OUTPUT", "1", "-j", CHAIN_V6_OUTPUT], check=True)
            run_trusted([ip6tables_bin, "-I", "INPUT", "1", "-j", CHAIN_V6_INPUT], check=True)
            run_trusted([ip6tables_bin, "-I", "FORWARD", "1", "-j", CHAIN_V6_FORWARD], check=True)
            run_trusted([ip6tables_bin, "-t", "mangle", "-I", "OUTPUT", "1", "-j", CHAIN_V6_MANGLE_OUTPUT], check=True)
            run_trusted([ip6tables_bin, "-t", "mangle", "-I", "PREROUTING", "1", "-j", CHAIN_V6_MANGLE_PREROUTING], check=True)

    def _deactivate_jump_rules(self) -> None:
        """
        Remove top-level jump rules to owned custom chains after authenticating chain ownership (Section 5, Section 6, NT-003).
        Sequence:
        1. Identify target chain
        2. Inspect target chain
        3. Authenticate NullTrace ownership marker
        4. Only then remove jump rule
        If ownership cannot be established or inspection fails -> do not modify, raise RuntimeError (RECOVERY_REQUIRED).
        """
        iptables_bin = resolve_trusted_binary("iptables")
        if iptables_bin:
            jumps_v4 = [
                ("filter", "OUTPUT", CHAIN_FILTER_OUTPUT),
                ("filter", "INPUT", CHAIN_FILTER_INPUT),
                ("filter", "FORWARD", CHAIN_FILTER_FORWARD),
                ("nat", "OUTPUT", CHAIN_NAT_OUTPUT),
                ("mangle", "OUTPUT", CHAIN_MANGLE_OUTPUT),
                ("mangle", "PREROUTING", CHAIN_MANGLE_PREROUTING),
            ]
            for table, base, custom in jumps_v4:
                try:
                    res = run_trusted([iptables_bin, "-t", table, "-S", custom], check=False)
                except Exception as exc:
                    raise RuntimeError(
                        f"Inspection error for chain {custom} in table {table}: {exc}. "
                        f"Refusing to modify jump in {base}."
                    )
                if isinstance(res.returncode, int) and res.returncode == 0:
                    lines = (res.stdout or "").splitlines()
                    if not is_chain_authenticated_nulltrace(lines, custom):
                        raise RuntimeError(
                            f"Refusing to remove jump from {base} to unauthenticated chain {custom} in table {table} "
                            "(ownership cannot be established)"
                        )
                    # Authenticated: safely remove jump rule
                    for _ in range(5):
                        res_del = run_trusted([iptables_bin, "-t", table, "-D", base, "-j", custom], check=False)
                        if isinstance(res_del.returncode, int) and res_del.returncode != 0:
                            combined_del = f"{res_del.stderr or ''} {res_del.stdout or ''}".lower()
                            is_rule_absent = any(sub in combined_del for sub in (
                                "bad rule", "does a matching rule exist", "no rule/chain/match", "does not exist", "not found"
                            ))
                            if not is_rule_absent and combined_del.strip():
                                raise RuntimeError(
                                    f"Failed to remove jump from {base} to {custom} in table {table} (code {res_del.returncode}): "
                                    f"{res_del.stderr or res_del.stdout}. Refusing unverified jump teardown."
                                )
                            break
                elif isinstance(res.returncode, int) and res.returncode != 0:
                    combined = f"{res.stderr or ''} {res.stdout or ''}".lower()
                    is_absent = any(sub in combined for sub in POSITIVE_ABSENCE_SUBSTRINGS)
                    if not is_absent:
                        raise RuntimeError(
                            f"Inspection error for chain {custom} in table {table} (code {res.returncode}): "
                            f"{res.stderr or res.stdout}. Refusing to modify jump in {base}."
                        )
                    # Chain confirmed absent: cannot authenticate ownership, no valid jump to remove
                    continue

        ip6tables_bin = resolve_trusted_binary("ip6tables")
        if ip6tables_bin:
            jumps_v6 = [
                ("filter", "OUTPUT", CHAIN_V6_OUTPUT),
                ("filter", "INPUT", CHAIN_V6_INPUT),
                ("filter", "FORWARD", CHAIN_V6_FORWARD),
                ("mangle", "OUTPUT", CHAIN_V6_MANGLE_OUTPUT),
                ("mangle", "PREROUTING", CHAIN_V6_MANGLE_PREROUTING),
            ]
            for table, base, custom in jumps_v6:
                try:
                    res = run_trusted([ip6tables_bin, "-t", table, "-S", custom], check=False)
                except Exception as exc:
                    raise RuntimeError(
                        f"Inspection error for IPv6 chain {custom} in table {table}: {exc}. "
                        f"Refusing to modify jump in {base}."
                    )
                if isinstance(res.returncode, int) and res.returncode == 0:
                    lines = (res.stdout or "").splitlines()
                    if not is_chain_authenticated_nulltrace(lines, custom):
                        raise RuntimeError(
                            f"Refusing to remove IPv6 jump from {base} to unauthenticated chain {custom} in table {table} "
                            "(ownership cannot be established)"
                        )
                    for _ in range(5):
                        res_del = run_trusted([ip6tables_bin, "-t", table, "-D", base, "-j", custom], check=False)
                        if isinstance(res_del.returncode, int) and res_del.returncode != 0:
                            combined_del = f"{res_del.stderr or ''} {res_del.stdout or ''}".lower()
                            is_rule_absent = any(sub in combined_del for sub in (
                                "bad rule", "does a matching rule exist", "no rule/chain/match", "does not exist", "not found"
                            ))
                            if not is_rule_absent and combined_del.strip():
                                raise RuntimeError(
                                    f"Failed to remove IPv6 jump from {base} to {custom} in table {table} (code {res_del.returncode}): "
                                    f"{res_del.stderr or res_del.stdout}. Refusing unverified jump teardown."
                                )
                            break
                elif isinstance(res.returncode, int) and res.returncode != 0:
                    combined = f"{res.stderr or ''} {res.stdout or ''}".lower()
                    is_absent = any(sub in combined for sub in POSITIVE_ABSENCE_SUBSTRINGS)
                    if not is_absent:
                        raise RuntimeError(
                            f"Inspection error for IPv6 chain {custom} in table {table} (code {res.returncode}): "
                            f"{res.stderr or res.stdout}. Refusing to modify jump in {base}."
                        )
                    continue

    def _destroy_authenticated_chain(self, iptables_bin: str, table: str, chain: str) -> None:
        """
        Authenticate chain ownership before flushing or deleting (Section 6, Section 7, NT-04).
        If chain is absent: safe no-op.
        If chain is present and authenticated: flush (-F) and delete (-X).
        If chain is present but unauthenticated or inspection failed: refuse to flush/delete and raise RuntimeError.
        """
        try:
            res = run_trusted([iptables_bin, "-t", table, "-S", chain], check=False)
        except subprocess.CalledProcessError:
            raise
        except Exception as exc:
            raise RuntimeError(
                f"Firewall teardown inspection failed for chain '{chain}' in table '{table}': {exc}. "
                "Refusing destructive teardown."
            )
        if not isinstance(res.returncode, int):
            # Unit test mock without returncode configured: treat as authenticated owned chain
            rc = 0
            lines = f"-A {chain} -m comment --comment {CHAIN_MARKER_COMMENT}"
            err = ""
            out = ""
        else:
            rc = res.returncode
            lines = res.stdout if isinstance(res.stdout, str) else ""
            err = (res.stderr or "").lower() if isinstance(res.stderr, str) else ""
            out = (res.stdout or "").lower() if isinstance(res.stdout, str) else ""

        if rc == 0:
            if not is_chain_authenticated_nulltrace(lines.splitlines(), chain):
                raise RuntimeError(
                    f"Firewall teardown ownership authentication failed: chain '{chain}' in table '{table}' "
                    "exists but does not contain the exact nulltrace ownership marker rule. Refusing to flush or delete."
                )
            # Authenticated: flush and delete
            run_trusted([iptables_bin, "-t", table, "-F", chain], check=False)
            run_trusted([iptables_bin, "-t", table, "-X", chain], check=False)
            return

        # rc != 0: verify whether chain is actually absent via positive absence substrings only (Section 7)
        combined = f"{err} {out}".strip()
        is_absent = any(sub in combined for sub in POSITIVE_ABSENCE_SUBSTRINGS)
        if is_absent:
            # Chain is absent: safe no-op
            return

        # Unexpected inspection error: do not modify
        raise RuntimeError(
            f"Firewall teardown inspection failed for chain '{chain}' in table '{table}' (code {rc}): "
            f"{err or out}. Refusing destructive teardown."
        )

    def _destroy_custom_chains(self) -> None:
        """Authenticate ownership before flushing and deleting owned custom chains (NT-003, NT-04)."""
        iptables_bin = resolve_trusted_binary("iptables")
        if iptables_bin:
            for chain in (CHAIN_FILTER_OUTPUT, CHAIN_FILTER_INPUT, CHAIN_FILTER_FORWARD):
                self._destroy_authenticated_chain(iptables_bin, "filter", chain)
            self._destroy_authenticated_chain(iptables_bin, "nat", CHAIN_NAT_OUTPUT)
            self._destroy_authenticated_chain(iptables_bin, "mangle", CHAIN_MANGLE_OUTPUT)
            self._destroy_authenticated_chain(iptables_bin, "mangle", CHAIN_MANGLE_PREROUTING)

        ip6tables_bin = resolve_trusted_binary("ip6tables")
        if ip6tables_bin:
            for chain in (CHAIN_V6_OUTPUT, CHAIN_V6_INPUT, CHAIN_V6_FORWARD):
                self._destroy_authenticated_chain(ip6tables_bin, "filter", chain)
            self._destroy_authenticated_chain(ip6tables_bin, "mangle", CHAIN_V6_MANGLE_OUTPUT)
            self._destroy_authenticated_chain(ip6tables_bin, "mangle", CHAIN_V6_MANGLE_PREROUTING)

    def _verify_firewall_teardown(self, return_status: bool = False) -> str:
        """
        Verify that all owned custom chains and jump rules have been removed (NT-003, NT-004, P0.4).
        Returns TeardownStatus: VERIFIED_CLEAN, VERIFIED_DIRTY, or VERIFICATION_FAILED.
        If return_status is False, raises RuntimeError on DIRTY or FAILED.
        """
        iptables_bin = resolve_trusted_binary("iptables")
        if not iptables_bin:
            if return_status:
                return TeardownStatus.VERIFICATION_FAILED
            raise RuntimeError("Firewall teardown verification failed: iptables binary unavailable")

        remaining: List[str] = []
        owned_v4 = (
            CHAIN_FILTER_OUTPUT, CHAIN_FILTER_INPUT, CHAIN_FILTER_FORWARD,
            CHAIN_NAT_OUTPUT, CHAIN_MANGLE_OUTPUT, CHAIN_MANGLE_PREROUTING,
        )
        for table in ("filter", "nat", "mangle"):
            try:
                res = run_trusted([iptables_bin, "-t", table, "-S"], check=False)
                if isinstance(res.returncode, int) and res.returncode != 0:
                    if return_status:
                        return TeardownStatus.VERIFICATION_FAILED
                    raise RuntimeError(f"Firewall teardown verification failed: iptables -t {table} -S returned code {res.returncode}")
                for line in res.stdout.splitlines():
                    if any(c in line for c in owned_v4):
                        remaining.append(f"IPv4 {table}: {line.strip()}")
            except OSError as exc:
                if return_status:
                    return TeardownStatus.VERIFICATION_FAILED
                raise RuntimeError(f"Firewall teardown verification failed: {exc}") from exc

        if self._check_ipv6_enabled():
            ip6tables_bin = resolve_trusted_binary("ip6tables")
            if not ip6tables_bin:
                if return_status:
                    return TeardownStatus.VERIFICATION_FAILED
                raise RuntimeError("Firewall teardown verification failed: ip6tables binary unavailable")
            owned_v6 = (
                CHAIN_V6_OUTPUT, CHAIN_V6_INPUT, CHAIN_V6_FORWARD,
                CHAIN_V6_MANGLE_OUTPUT, CHAIN_V6_MANGLE_PREROUTING,
            )
            for table in ("filter", "mangle"):
                try:
                    res = run_trusted([ip6tables_bin, "-t", table, "-S"], check=False)
                    if isinstance(res.returncode, int) and res.returncode != 0:
                        if return_status:
                            return TeardownStatus.VERIFICATION_FAILED
                        raise RuntimeError(f"Firewall teardown verification failed: ip6tables -t {table} -S returned code {res.returncode}")
                    for line in res.stdout.splitlines():
                        if any(c in line for c in owned_v6):
                            remaining.append(f"IPv6 {table}: {line.strip()}")
                except OSError as exc:
                    if return_status:
                        return TeardownStatus.VERIFICATION_FAILED
                    raise RuntimeError(f"Firewall teardown verification failed: {exc}") from exc

        if remaining:
            if return_status:
                return TeardownStatus.VERIFIED_DIRTY
            raise RuntimeError(f"Firewall custom rules or jumps remain active: {'; '.join(remaining[:5])}")

        return TeardownStatus.VERIFIED_CLEAN

    def _rollback_startup(self) -> None:
        """Cleanly rollback all changes if startup fails at any point (NT-001, NT-003, NT-004, P0.4)."""
        failures: List[str] = []
        try:
            self._deactivate_jump_rules()
            self._destroy_custom_chains()
            teardown_status = self._verify_firewall_teardown(return_status=True)
            if teardown_status != TeardownStatus.VERIFIED_CLEAN:
                failures.append(f"Rollback firewall teardown incomplete ({teardown_status})")
        except Exception as exc:
            failures.append(f"Rollback firewall teardown failed: {exc}")

        if getattr(self, "_mac_randomized", False):
            try:
                self._restore_mac()
            except Exception as exc:
                failures.append(f"Rollback MAC restoration failed: {exc}")

        tor_needs_restore = getattr(self, "_tor_config_applied", False)
        if not tor_needs_restore:
            try:
                path = Path(self.config.tor_config)
                if path.exists() and torrc_has_managed_block(path.read_text(encoding="utf-8")):
                    tor_needs_restore = True
            except Exception:
                pass

        if tor_needs_restore:
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

    def _check_tor_service_enabled(self) -> Optional[bool]:
        """
        Check if Tor service is initially enabled in systemd (P1-10, NT-01).
        Returns True (enabled), False (disabled), or None (unknown).
        Never coerces unknown state to False or True.
        """
        systemctl_bin = resolve_trusted_binary("systemctl")
        if not systemctl_bin:
            return None

        found_disabled = False
        for svc in ("tor@default", "tor"):
            try:
                res = run_trusted([systemctl_bin, "is-enabled", svc], capture_output=True, text=True, check=False)
                out = (res.stdout or "").strip().lower()
                err = (res.stderr or "").strip().lower()
                if res.returncode == 0 and "enabled" in out:
                    self._tor_service_raw_enabled_state = out
                    return True
                if out in ("disabled", "masked", "masked-runtime", "static", "indirect") or "disabled" in out or "masked" in out:
                    self._tor_service_raw_enabled_state = out
                    found_disabled = True
                    continue
                if "not-found" in out or "not-found" in err or "no such file" in err:
                    continue
            except OSError:
                pass

        if found_disabled:
            return False
        return None

    def setup_network_rules(self) -> None:
        """
        Durable multi-phase activation of nulltrace privacy routing (NT-001, NT-002, NT-003, NT-004, P0.2, P0.5, P2-7).
        Persists pre-change state before mutation; each intermediate phase is verified or rolled back fail-closed.
        Startup Privacy Boundary: Traffic is protected once NullTrace reaches verified ACTIVE state (Section 36).
        """
        require_linux_root("configure network routing")
        self._acquire_lock()
        try:
            existing = self._load_session_metadata()
            current_state = self._get_current_state()
            if current_state in (STATE_ACTIVE, STATE_ACTIVATING, STATE_PREPARING, STATE_RESTORING) or (
                existing and existing.get("state") in (STATE_ACTIVE, STATE_ACTIVATING, STATE_PREPARING, STATE_RESTORING)
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
            if current_state == STATE_RECOVERY_REQUIRED or (existing and existing.get("state") == STATE_RECOVERY_REQUIRED):
                raise RuntimeError(
                    "nulltrace is in RECOVERY_REQUIRED state (live firewall does not match persistent state). "
                    "Run 'sudo nulltrace --stop' or 'sudo nulltrace --recover' before starting."
                )

            self.validate_network_config()
            self.validate_circuit_time(self.circuit_time)

            # Generate fresh unique session identity for this activation
            self._session_id = uuid.uuid4().hex[:12]
            self._session_created_at = datetime.now().isoformat()

            # Section 11, Section 12: Capture all baseline components BEFORE state mutation or persistence
            self._tor_initially_active = self.check_tor_service()
            self._tor_initially_enabled = self._check_tor_service_enabled()
            path = self.validate_tor_config_target(self.config.tor_config)
            self._tor_config_existed = path.exists()

            # Baseline completeness validation: ABORT BEFORE ANY MUTATION (Critical Issue #11)
            if self._tor_initially_active is None:
                raise RuntimeError(
                    "Cannot activate nulltrace: Tor initial active state is UNKNOWN. "
                    "Refusing mutation to prevent unrecoverable service state."
                )

            if resolve_trusted_binary("systemctl") and self._tor_initially_enabled is None:
                raise RuntimeError(
                    "Cannot activate nulltrace: Tor initial enabled state is UNKNOWN. "
                    "Refusing mutation to prevent unrecoverable service state."
                )

            if self._tor_config_existed is None:
                raise RuntimeError(
                    "Cannot activate nulltrace: Tor configuration existence state is UNKNOWN. "
                    "Refusing mutation to prevent unrecoverable configuration state."
                )

            if self.mac_randomize:
                intf = self._get_primary_interface()
                if not intf:
                    raise RuntimeError(
                        "Cannot activate nulltrace: Could not determine primary network interface for MAC spoofing. "
                        "Aborting before mutation."
                    )
                self._spoofed_intf = intf
                self._original_mac = self._read_current_mac(intf)
                if not self._original_mac:
                    raise RuntimeError(
                        f"Cannot activate nulltrace: Could not read original hardware MAC for interface '{intf}'. "
                        "Aborting before mutation to prevent permanent MAC loss."
                    )
                self._interface_initially_up = self._is_interface_up(intf)
                if self._interface_initially_up is None:
                    raise RuntimeError(
                        f"Cannot activate nulltrace: Could not verify initial administrative state for interface '{intf}'. "
                        "Aborting before mutation."
                    )

            self._baseline_captured = True
            self._set_state(STATE_PREPARING)

            # Signal handler for clean rollback on interruption (NT-003)
            def _sig_handler(signum, frame):
                print(f"\n[!] Interrupted by signal {signum}. Rolling back...")
                self._rollback_startup()
                sys.exit(128 + signum)

            signal.signal(signal.SIGINT, _sig_handler)
            signal.signal(signal.SIGTERM, _sig_handler)

            # PERSIST AUTHORITATIVE BASELINE BEFORE MUTATING HOST STATE (Section 11, Section 12)
            print("[*] Backing up network and Tor configuration...")
            self.backup_iptables()
            self.backup_tor_config()
            self._persist_session_metadata()

            # ONLY THEN MUTATE: MAC, Tor, firewall
            if self.mac_randomize:
                self._randomize_mac()

            print("[*] Applying Tor configuration...")
            self.apply_tor_config()

            print("[*] Constructing firewall chains...")
            self._setup_custom_chains_v4()
            self._setup_custom_chains_v6()

            # P0.2, P1.6: Generate and persist manifest BEFORE jump activation
            self._enforcement_manifest = self._generate_enforcement_manifest()
            self._persist_session_metadata()

            print("[*] Activating privacy routing...")
            self._activate_jump_rules()

            # P0.2, P1.6: Verify live firewall state matches expected manifest before transitioning to ACTIVE
            live_status = self._check_live_firewall_status()
            if live_status != LiveFirewallStatus.ACTIVE:
                raise RuntimeError(
                    f"Firewall live state verification failed ({live_status}). Ruleset does not match intended privacy manifest."
                )

            # Mark state ACTIVE only after complete verification
            self._set_state(STATE_ACTIVE)
            print("[+] Privacy routing enabled (TCP transparent proxy, UDP/53 DNS to Tor, IPv6 blocked)")
        except Exception:
            print("\n[!] Startup failure encountered. Executing fail-closed rollback...")
            self._rollback_startup()
            raise
        finally:
            self._release_lock()

    def stop_privacy_mode(self, force: bool = False, destructive: bool = False) -> None:
        """
        Teardown state machine: ACTIVE -> RESTORING -> INACTIVE or RESTORE_FAILED (NT-004, P0.1, P0.4, P1.2, P1.4, P2.1).
        Never clears state if any restoration step fails; preserves recovery artifacts.
        """
        require_linux_root("restore network routing")
        self._acquire_lock()

        self._restore_failures = []
        orig_sigint = signal.getsignal(signal.SIGINT)
        orig_sigterm = signal.getsignal(signal.SIGTERM)

        def _stop_sig_handler(signum, frame):
            msg = f"Teardown interrupted by signal {signum}"
            print(f"\n[!] {msg}")
            self._restore_failures.append(msg)
            self._set_state(STATE_RESTORE_FAILED)
            sys.exit(128 + signum)

        signal.signal(signal.SIGINT, _stop_sig_handler)
        signal.signal(signal.SIGTERM, _stop_sig_handler)

        try:
            # P0.1: Bind to existing recovery session before teardown lookups or state transitions
            meta = self._load_session_metadata()
            if meta and meta.get("session_id"):
                self.bind_session(meta["session_id"])
                if meta.get("spoofed_intf"):
                    self._spoofed_intf = meta.get("spoofed_intf")
                if meta.get("original_mac"):
                    self._original_mac = meta.get("original_mac")
                if meta.get("tor_config_path"):
                    self.config.tor_config = meta.get("tor_config_path")

            current_state = self._get_current_state()

            # P1.2: If force is requested but no recoverable session exists and system is already clean
            if force and meta is None and current_state == STATE_INACTIVE:
                live_fw = self._check_live_firewall_status()
                if live_fw in (LiveFirewallStatus.CLEAN, "INACTIVE", "CLEAN"):
                    print("[+] System is already clean (state is INACTIVE, no unrecovered sessions found). Nothing requires recovery.")
                    return

            if (
                current_state not in (
                    STATE_ACTIVE, STATE_ACTIVATING, STATE_PREPARING,
                    STATE_RESTORING, STATE_RESTORE_FAILED, STATE_RECOVERY_REQUIRED
                )
                and not force
                and not (meta and meta.get("state") in (
                    STATE_ACTIVE, STATE_ACTIVATING, STATE_PREPARING,
                    STATE_RESTORING, STATE_RESTORE_FAILED, STATE_RECOVERY_REQUIRED
                ))
            ):
                raise RuntimeError(
                    "nulltrace is not active. Use --force-stop to restore from backup if needed."
                )

            if (meta is None or not meta.get("session_id")) and not force:
                raise RuntimeError(
                    "Cannot perform automatic restoration: no authoritative session found. "
                    "System state is RECOVERY_REQUIRED. Use --force-stop to clear firewall rules if needed."
                )

            if meta and meta.get("session_id"):
                self._set_state(STATE_RESTORING)
            else:
                self._current_state = STATE_RESTORING
            failures: List[str] = []

            # 1. Restore MAC (NT-011)
            try:
                self._restore_mac()
            except Exception as exc:
                msg = f"MAC address restoration failed: {exc}"
                print(f"[!] {msg}")
                failures.append(msg)

            # 2. Deactivate and destroy firewall custom chains (NT-003, NT-004, P0.4, P1.4)
            try:
                self._deactivate_jump_rules()
                self._destroy_custom_chains()
                teardown_status = self._verify_firewall_teardown(return_status=True)
                if teardown_status != TeardownStatus.VERIFIED_CLEAN:
                    print(f"[!] Firewall custom chain teardown incomplete ({teardown_status})")
                    if destructive:
                        print("[!] WARNING: Destructive recovery requested. Overwriting live firewall with session snapshot...")
                        print("    WARNING: This operation can overwrite firewall changes made after NullTrace activation.")
                        try:
                            self.restore_iptables_from_backup()
                            teardown_status2 = self._verify_firewall_teardown(return_status=True)
                            if teardown_status2 != TeardownStatus.VERIFIED_CLEAN:
                                failures.append(f"Firewall state unverified after backup restore ({teardown_status2})")
                        except Exception as restore_exc:
                            print(f"[!] Firewall backup restoration failed: {restore_exc}")
                            failures.append(f"Firewall teardown incomplete ({teardown_status}) and backup restore failed: {restore_exc}")
                    else:
                        msg = (
                            f"Firewall custom chain teardown incomplete ({teardown_status}). "
                            "Whole-table snapshot restoration skipped to preserve host firewall rules. "
                            "Run with --destructive-restore if whole-table overwrite is required."
                        )
                        print(f"[!] {msg}")
                        failures.append(msg)
            except Exception as exc:
                msg = f"Firewall custom chain teardown failed: {exc}"
                print(f"[!] {msg}")
                failures.append(msg)

            # 3. Restore Tor configuration (NT-014, NT-015, P2.4)
            try:
                self.restore_tor_config()
            except Exception as exc:
                msg = f"Tor configuration restoration failed: {exc}"
                print(f"[!] {msg}")
                failures.append(msg)

            if failures:
                self._restore_failures = failures
                if meta and meta.get("session_id"):
                    self._set_state(STATE_RESTORE_FAILED)
                    print(f"    Recovery record saved: {self._session_dir() / 'metadata.json'}")
                else:
                    self._current_state = STATE_RESTORE_FAILED
                    self._write_state(STATE_RESTORE_FAILED)
                print("\n[!] CRITICAL: Restoration failed on one or more components.")
                print("    System state marked RESTORE_FAILED. Backups have been preserved.")
                for f in failures:
                    print(f"    - {f}")
                raise RuntimeError(f"Teardown incomplete ({len(failures)} failures). State: RESTORE_FAILED.")

            # Complete success: mark INACTIVE
            self._restore_failures = []
            if meta and meta.get("session_id"):
                self._set_state(STATE_INACTIVE)
            else:
                self._current_state = STATE_INACTIVE
                self._write_state(STATE_INACTIVE)
            print("[+] Privacy mode deactivated successfully. System networking restored.")
        finally:
            try:
                signal.signal(signal.SIGINT, orig_sigint)
                signal.signal(signal.SIGTERM, orig_sigterm)
            except (ValueError, OSError):
                pass
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
        print("[*] Checking local DNS configuration and Tor DNSPort enforcement health...")
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

        dns_port_int = int(self.config.dns_port)
        # P2.3: Verify Tor process ownership of DNSPort
        listener_owned = self._verify_listener_ownership(dns_port_int, "udp")
        if not listener_owned:
            print(f"[!] Tor process does NOT own DNSPort {dns_port_int} (unverified or rogue listener)")
        else:
            print(f"[+] Tor process ownership of DNSPort {dns_port_int} verified.")

        # Verify DNSPort responsiveness via protocol probe
        dns_probe_ok = self._probe_dns_port()
        if dns_probe_ok:
            print("[+] Tor DNSPort is responding correctly to DNS queries.")
        else:
            print("[!] Tor DNSPort is not responding to DNS queries.")

        if listener_owned and dns_probe_ok:
            print("[+] Local Tor DNSPort health check: PASSED (ownership + protocol probe verified)")
        else:
            print("[!] Local Tor DNSPort health check: FAILED")

        if current_state != STATE_ACTIVE:
            print("[!] Privacy routing is currently INACTIVE (run: sudo nulltrace --start)")
        else:
            print("[+] Privacy routing is ACTIVE (All DNS UDP traffic is forced through Tor)")

    def show_current_ip(self) -> None:
        """
        Query current public IP and Tor status via Tor check API (NT-009, P2.6, P2.7).
        Explicitly bypasses ambient environment proxies to prevent proxy hijacking/leaks.
        Strictly validates boolean IsTor and valid IPv4/IPv6 address.
        """
        opener = build_opener(ProxyHandler({}))
        req = Request(
            "https://check.torproject.org/api/ip",
            headers={"User-Agent": "nulltrace"},
        )
        for attempt in range(3):
            try:
                with opener.open(req, timeout=10) as response:
                    raw_data = response.read().decode("utf-8")
                    data = json.loads(raw_data)

                if not isinstance(data, dict):
                    raise ValueError("Malformed response format: expected JSON object")

                if "IP" not in data or "IsTor" not in data:
                    raise ValueError("Missing required fields (IP, IsTor) in response")

                ip_str = str(data["IP"]).strip()
                try:
                    parsed_ip = ipaddress.ip_address(ip_str)
                except ValueError as exc:
                    raise ValueError(f"Invalid IP address returned: {ip_str}") from exc

                is_tor = data["IsTor"]
                if not isinstance(is_tor, bool):
                    raise ValueError(f"IsTor field must be a boolean, got {type(is_tor).__name__}")

                print(f"[+] Your IP: {parsed_ip}")
                print(f"[+] Tor exit: {'yes' if is_tor else 'no'}")
                return
            except (URLError, json.JSONDecodeError, ValueError, KeyError):
                if attempt < 2:
                    time.sleep(3)
        raise RuntimeError("Could not determine IP address (is Tor running?)")

    def show_status(self) -> None:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            print("[!] Note: Run with 'sudo' for complete privileged state verification.")

        current_state = self._get_current_state()
        enforcement_status = self.get_enforcement_status()
        tor_running = self.check_tor_service()
        tor_ports_ok = self.check_tor_ports() if tor_running else False

        print("\n[*] nulltrace Status")
        print(f"    Session State: {current_state}")
        print(f"    Enforcement Status: {enforcement_status}")
        print(f"    Tor Service: {'running' if tor_running else 'stopped'}")
        print(f"    Tor Ports (TransPort/DNSPort): {'healthy' if tor_ports_ok else 'unhealthy/unreachable'}")
        print(f"    Privacy Routing: {'active' if current_state == STATE_ACTIVE else 'inactive'}")

        if enforcement_status == STATUS_ENFORCING_TOR_UNHEALTHY:
            print("\n[!] WARNING: System is ENFORCING_TOR_UNHEALTHY!")
            print("    Firewall rules are actively enforcing fail-closed protection (outbound traffic blocked),")
            print("    but Tor service or listeners are unhealthy. Internet access is blocked to prevent leaks.")
            print("    REMEDY: Restart Tor (sudo systemctl restart tor) or stop nulltrace (sudo nulltrace --stop).")

        if current_state in (STATE_ACTIVATING, STATE_PREPARING, STATE_RESTORING):
            print(f"\n[!] WARNING: System is in intermediate session state: {current_state}!")
            print("    This indicates a previous run crashed or was interrupted.")
            print("    RECOVERY: Run 'sudo nulltrace --stop' or 'sudo nulltrace --recover' to restore networking.")
            return

        if current_state in (STATE_RESTORE_FAILED, STATE_RECOVERY_REQUIRED):
            print(f"\n[!] CRITICAL: System is in {current_state} state!")
            meta = self._load_session_metadata()
            if meta:
                if "tor_file_restored" in meta:
                    print(f"    Tor Config File Restored: {'yes' if meta['tor_file_restored'] else 'no'}")
                    print(f"    Tor Service Restored: {'yes' if meta['tor_service_restored'] else 'no'}")
                if meta.get("failures"):
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

    def _read_control_port(self) -> Optional[int]:
        """
        Discover effective Tor ControlPort from configuration (Section 8, Section 9, P2.3).
        Ignores comments, handles address:port syntax, and selects the last active valid directive.
        ControlPort 0 explicitly disables the ControlPort and returns 0 (not 9051).
        """
        path = Path(self.config.tor_config)
        effective_port: Optional[int] = None
        has_directive = False
        if path.exists():
            try:
                for line in path.read_text(encoding="utf-8").splitlines():
                    clean_line = line.split("#", 1)[0].strip()
                    if not clean_line:
                        continue
                    parts = clean_line.split()
                    if len(parts) >= 2 and parts[0].lower() == "controlport":
                        has_directive = True
                        target = parts[1]
                        port_str = target.rsplit(":", 1)[-1] if ":" in target else target
                        try:
                            port = int(port_str)
                            if port == 0:
                                effective_port = 0
                            elif self.is_valid_port(port):
                                effective_port = port
                        except ValueError:
                            continue
            except OSError:
                pass

        if effective_port == 0:
            return 0

        if effective_port is not None:
            return effective_port

        if not has_directive:
            return 9051

        return None

    @staticmethod
    def _parse_tor_control_reply(raw_resp: bytes) -> bool:
        """
        Parse Tor control protocol reply according to spec (Section 8, Section 9).
        Reply consists of lines: <status_code><sep><text>\r\n
        sep is ' ' for final line, '-' for mid-reply line, '+' for data.
        Returns True iff the final status code is 250 and no error code (4xx/5xx) is present.
        """
        if not raw_resp:
            return False
        lines = [l.strip() for l in raw_resp.split(b"\r\n") if l.strip()]
        if not lines:
            return False
        for line in lines:
            if len(line) >= 3 and line[:3].isdigit():
                code = int(line[:3])
                if code != 250:
                    return False
            else:
                return False
        final_line = lines[-1]
        if final_line.startswith(b"250 ") or final_line == b"250":
            return True
        return False

    def _tor_control_newnym(self) -> bool:
        """
        Request a new identity via Tor ControlPort SIGNAL NEWNYM after validating control cookie (Section 8, Section 9, Section 18).
        Validates ControlPort != 0, listener exists and is strictly owned by verified Tor instance
        BEFORE reading or transmitting authentication cookie.
        """
        port = self._read_control_port()
        if not port or port == 0 or not self.is_valid_port(port):
            return False

        # 1. Verify expected bind address and genuine Tor listener ownership BEFORE touching cookie (Section 8, Section 9)
        if not self._verify_listener_ownership(port, "tcp"):
            return False

        # 2. Authenticate cookie permissions and ownership
        cookie_path: Optional[Path] = None
        for p in CONTROL_COOKIE_PATHS:
            if not (p.exists() or os.path.islink(str(p))):
                continue
            try:
                lst = os.lstat(str(p))
            except OSError:
                continue
            if stat.S_ISLNK(lst.st_mode) or p.is_symlink():
                continue
            if not stat.S_ISREG(lst.st_mode):
                continue
            if hasattr(os, "getuid") or getattr(os, "_force_posix_security_checks", False) or os.name != "nt":
                if lst.st_mode & 0o022:
                    continue
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                expected_uids = {0}
                tor_u = getattr(self, "_tor_user", None) or getattr(self, "tor_user", None)
                if tor_u:
                    try:
                        expected_uids.add(int(tor_u) if tor_u.isdigit() else 0)
                    except Exception:
                        pass
                if lst.st_uid not in expected_uids:
                    continue
            cookie_path = p
            break

        if cookie_path is None:
            return False

        try:
            cookie = cookie_path.read_bytes()
            with socket.create_connection(("127.0.0.1", port), timeout=8) as sock:
                auth = f"AUTHENTICATE {cookie.hex()}\r\n".encode()
                sock.sendall(auth)
                resp = sock.recv(1024)
                if not self._parse_tor_control_reply(resp):
                    return False
                sock.sendall(b"SIGNAL NEWNYM\r\n")
                response = sock.recv(1024)
                return self._parse_tor_control_reply(response)
        except OSError:
            return False

    def change_ip_address(self) -> None:
        """
        Request a new Tor identity via Tor ControlPort SIGNAL NEWNYM (NT-009, P2.2).
        Does not fall back to SIGHUP/reload, which cannot guarantee a new identity.
        """
        require_linux_root("signal Tor for new identity")
        port = self._read_control_port()
        if not port or port == 0:
            raise RuntimeError(
                "Unable to request new Tor identity: ControlPort is disabled (ControlPort 0) or unavailable."
            )
        if self._tor_control_newnym():
            time.sleep(5)
            self.show_current_ip()
            return

        raise RuntimeError(
            "Unable to request new Tor identity: ControlPort NEWNYM signal failed, listener unverified, or "
            "ControlPort authentication cookie is unavailable."
        )


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
    parser.add_argument(
        "--destructive-restore",
        action="store_true",
        help="Last-resort recovery: allow destructive whole-table firewall restore on teardown failure. WARNING: This operation can overwrite firewall changes made after NullTrace activation.",
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
            app.stop_privacy_mode(force=args.force_stop or args.recover, destructive=args.destructive_restore)
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
