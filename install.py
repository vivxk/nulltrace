#!/usr/bin/env python3
import argparse
import errno
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Union

TRUSTED_BIN_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")


def resolve_trusted_binary(name: str) -> Optional[str]:
    """
    Resolve binary strictly to a trusted system directory (NT-006, P1-5).
    Rejects relative lookups, path traversals, non-root-owned binaries,
    group/world-writable binaries, non-regular files, and symlinks resolving
    outside approved trusted directories.
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
        else:
            if not stat.S_ISREG(lst.st_mode):
                continue
            target_st = lst

        if not stat.S_ISREG(target_st.st_mode):
            continue

        if not os.access(str(candidate), os.X_OK):
            continue

        if target_st.st_mode & 0o022:
            continue

        if hasattr(target_st, "st_uid") and (os.name != "nt" or getattr(os, "_force_posix_security_checks", False)):
            if target_st.st_uid != 0:
                continue

        return candidate.as_posix()

    return None


def require_trusted_binary(name: str) -> str:
    """Resolve binary in trusted directories or raise SystemExit."""
    resolved = resolve_trusted_binary(name)
    if not resolved:
        print(f"[!] Required binary '{name}' not found in trusted directories {TRUSTED_BIN_DIRS}")
        sys.exit(1)
    return resolved


SAFE_ENV_NAMES = {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "SYSTEMD_COLORS"}


def sanitize_environment(env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Construct minimal hardened explicit environment for privileged execution (NT-006, P1.6)."""
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
) -> subprocess.CompletedProcess:
    """Execute command using trusted path resolution and minimal hardened environment (NT-006, P1.6)."""
    if not cmd:
        raise ValueError("Command cannot be empty")
    bin_name = cmd[0]
    resolved = resolve_trusted_binary(bin_name)
    actual_cmd = list(cmd)
    if resolved:
        actual_cmd[0] = resolved
    elif hasattr(os, "geteuid"):
        print(f"[!] Untrusted or missing binary '{bin_name}'")
        sys.exit(1)

    clean_env = sanitize_environment(env)

    return subprocess.run(
        actual_cmd,
        check=check,
        capture_output=capture_output,
        text=text,
        env=clean_env,
    )


def check_root():
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        print("[!] This script must be run as root")
        sys.exit(1)


def check_dependencies():
    missing = []
    for cmd in ["tor", "iptables", "ip6tables"]:
        if resolve_trusted_binary(cmd) is None:
            missing.append(cmd)

    if missing:
        print(f"[!] Installation aborted. Missing required system dependencies: {', '.join(missing)}")
        print("    Please install them (e.g., sudo apt install tor iptables ip6tables)")
        sys.exit(1)

    if resolve_trusted_binary("macchanger") is None:
        print("[*] Optional dependency 'macchanger' not found in trusted paths.")
        print("    You will not be able to use the --mac-randomize feature.")
        print("    To enable it, install macchanger (e.g., sudo apt install macchanger)")


def secure_open_dir_hierarchy(
    dir_path: Union[str, Path],
    target_uid: Optional[int] = 0,
    target_gid: Optional[int] = 0,
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
            f"Security violation: path component in '{dir_path}' contains relative traversal element ('.' or '..'); refusing install."
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
                    f"Security violation: path component '{comp}' in '{dir_path}' contains relative traversal element; refusing install."
                )
            curr = curr / comp
            if curr.exists() or os.path.islink(str(curr)):
                st = os.lstat(str(curr))
                if stat.S_ISLNK(st.st_mode):
                    raise ValueError(f"Ancestor directory '{curr}' is a symlink; refusing install.")
                if not stat.S_ISDIR(st.st_mode):
                    raise ValueError(f"Ancestor '{curr}' is not a directory.")
                if os.name != "nt" or getattr(os, "_force_posix_security_checks", False):
                    if (st.st_mode & 0o022) and not (st.st_mode & stat.S_ISVTX):
                        raise ValueError(f"Directory '{curr}' has insecure permissions ({oct(st.st_mode)}); group/world writable.")
                    if hasattr(os, "geteuid") and os.geteuid() == 0:
                        if st.st_uid != 0 and (target_uid is None or st.st_uid != target_uid):
                            raise ValueError(f"Directory '{curr}' is owned by UID {st.st_uid}, expected root (UID 0).")
        return None

    dir_flags = os.O_RDONLY | os.O_DIRECTORY
    curr_fd = os.open("/", dir_flags)
    try:
        for comp in parts[1:]:
            if comp in (".", ".."):
                raise ValueError(
                    f"Security violation: path component '{comp}' in '{dir_path}' contains relative traversal element; refusing install."
                )
            comp_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            try:
                next_fd = os.open(comp, comp_flags, dir_fd=curr_fd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise ValueError(
                        f"Security violation: path component '{comp}' in '{dir_path}' is a symlink or non-directory; refusing install."
                    ) from exc
                raise ValueError(
                    f"Failed to securely open path component '{comp}' in '{dir_path}': {exc}"
                ) from exc

            os.close(curr_fd)
            curr_fd = next_fd

            st = os.fstat(curr_fd)
            if not stat.S_ISDIR(st.st_mode):
                raise ValueError(f"Path component '{comp}' in '{dir_path}' is not a directory.")

            if (st.st_mode & 0o022) and not (st.st_mode & stat.S_ISVTX):
                raise ValueError(
                    f"Directory '{comp}' has insecure permissions ({oct(st.st_mode)}); group/world writable."
                )

            if hasattr(os, "geteuid") and os.geteuid() == 0 and (os.name != "nt" or getattr(os, "_force_posix_security_checks", False)):
                if st.st_uid != 0 and (target_uid is None or st.st_uid != target_uid):
                    raise ValueError(
                        f"Directory '{comp}' is owned by UID {st.st_uid}, expected root (UID 0)."
                    )

        return curr_fd
    except Exception:
        try:
            os.close(curr_fd)
        except OSError:
            pass
        raise


def secure_deploy_file(
    source_content: Union[str, bytes],
    target_path: Path,
    mode: int = 0o755,
) -> None:
    """
    Secure atomic installation of a privileged system file (P0-1, P1-5, P2-8).
    Validates ancestor directories (root-owned, not group/world-writable, not symlinks).
    Uses openat-style creation with O_CREAT | O_EXCL | O_NOFOLLOW via parent dir_fd.
    Applies mode, root ownership, fsync durability, and renameat replacement.
    """
    dest_path = Path(target_path)
    parent_dir = dest_path.parent
    if not parent_dir.is_absolute():
        parent_dir = Path.cwd() / parent_dir

    if os.name == "nt" and not getattr(os, "_force_posix_security_checks", False):
        parent_dir.mkdir(parents=True, exist_ok=True)
        tmp = parent_dir / f".{dest_path.name}.tmp_{os.urandom(6).hex()}"
        if isinstance(source_content, str):
            tmp.write_text(source_content, encoding="utf-8")
        else:
            tmp.write_bytes(source_content)
        os.replace(tmp, dest_path)
        return

    if dest_path.is_symlink() or os.path.islink(str(dest_path)):
        raise ValueError(f"Target path '{dest_path}' is an untrusted symlink; refusing install.")
    if parent_dir.is_symlink() or os.path.islink(str(parent_dir)):
        raise ValueError(f"Target directory '{parent_dir}' is an untrusted symlink; refusing install.")

    dir_fd = secure_open_dir_hierarchy(parent_dir, target_uid=0, target_gid=0)
    if dir_fd is None:
        parent_dir.mkdir(parents=True, exist_ok=True)
        tmp = parent_dir / f".{dest_path.name}.tmp_{os.urandom(6).hex()}"
        if isinstance(source_content, str):
            tmp.write_text(source_content, encoding="utf-8")
        else:
            tmp.write_bytes(source_content)
        os.replace(tmp, dest_path)
        return

    tmp_name = f".{dest_path.name}.tmp_{os.urandom(8).hex()}"
    tmp_fd: Optional[int] = None
    try:
        st_dir = os.fstat(dir_fd)
        if not stat.S_ISDIR(st_dir.st_mode):
            raise ValueError(f"Parent '{parent_dir}' is not a directory.")
        if os.name != "nt" or getattr(os, "_force_posix_security_checks", False):
            if hasattr(os, "geteuid") and os.geteuid() == 0 and st_dir.st_uid != 0:
                raise ValueError(f"Directory '{parent_dir}' is not root-owned.")
            if st_dir.st_mode & 0o022:
                raise ValueError(f"Directory '{parent_dir}' is group or world writable.")

        dest_name = dest_path.name
        try:
            dest_st = os.stat(dest_name, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISLNK(dest_st.st_mode):
                raise ValueError(f"Destination '{dest_path}' is a symlink; refusing install.")
            if not stat.S_ISREG(dest_st.st_mode):
                raise ValueError(f"Destination '{dest_path}' is not a regular file; refusing install.")
        except (FileNotFoundError, OSError) as exc:
            if getattr(exc, "errno", None) != errno.ENOENT and not isinstance(exc, FileNotFoundError):
                raise

        open_flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        tmp_fd = os.open(tmp_name, open_flags, mode, dir_fd=dir_fd)
        payload = source_content.encode("utf-8") if isinstance(source_content, str) else source_content
        written = 0
        while written < len(payload):
            n = os.write(tmp_fd, payload[written:])
            if n == 0:
                raise OSError("Zero bytes written during install")
            written += n

        if hasattr(os, "fchmod"):
            os.fchmod(tmp_fd, mode)
        if hasattr(os, "fchown") and hasattr(os, "geteuid") and os.geteuid() == 0:
            os.fchown(tmp_fd, 0, 0)
        os.fsync(tmp_fd)
        os.close(tmp_fd)
        tmp_fd = None

        try:
            pre_st = os.stat(dest_name, dir_fd=dir_fd, follow_symlinks=False)
            if stat.S_ISLNK(pre_st.st_mode):
                raise ValueError(f"Destination '{dest_path}' was replaced with a symlink; refusing install.")
        except (FileNotFoundError, OSError) as exc:
            if getattr(exc, "errno", None) != errno.ENOENT and not isinstance(exc, FileNotFoundError):
                raise

        if os.rename in getattr(os, "supports_dir_fd", set()):
            os.rename(tmp_name, dest_name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        else:
            raise RuntimeError("FD-relative rename unsupported on Linux")

        if hasattr(os, "fsync"):
            os.fsync(dir_fd)

    except Exception:
        if tmp_fd is not None:
            try:
                os.close(tmp_fd)
            except OSError:
                pass
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
        except (OSError, UnboundLocalError):
            pass
        raise
    finally:
        os.close(dir_fd)


def install_nulltrace():
    check_dependencies()
    try:
        source = Path(__file__).resolve().parent / "nulltrace.py"
        if not source.is_file():
            print(f"[!] nulltrace.py not found beside installer: {source}")
            sys.exit(1)

        share_dir = Path("/usr/share/nulltrace")
        if not share_dir.exists():
            share_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
            if hasattr(os, "chmod"):
                os.chmod(str(share_dir), 0o755)

        secure_deploy_file(source.read_bytes(), share_dir / "nulltrace.py", mode=0o755)

        python3_bin = resolve_trusted_binary("python3") or "/usr/bin/python3"
        launcher_content = f"""#!/bin/sh
exec {python3_bin} /usr/share/nulltrace/nulltrace.py "$@"
"""
        secure_deploy_file(launcher_content, Path("/usr/bin/nulltrace"), mode=0o755)

        print("[+] nulltrace installed successfully")
        print("[+] You can now use the 'nulltrace' command")

    except Exception as e:
        print(f"[!] Installation failed: {str(e)}")
        sys.exit(1)


class FirewallInspectionResult:
    CLEAN = "CLEAN"
    ACTIVE = "ACTIVE"
    UNKNOWN = "UNKNOWN"


def inspect_live_nulltrace_rules() -> str:
    """
    Tri-state inspection of live iptables/ip6tables rulesets (P1.5, P1-7):
    - CLEAN: binaries ran successfully and no NULLTRACE chains or rules exist in any table.
    - ACTIVE: binaries ran successfully and NULLTRACE chains or rules exist.
    - UNKNOWN: iptables or ip6tables binary missing, unusable, or inspection command errored.
    """
    iptables_bin = resolve_trusted_binary("iptables")
    ip6tables_bin = resolve_trusted_binary("ip6tables")
    if not iptables_bin or not ip6tables_bin:
        return FirewallInspectionResult.UNKNOWN

    found_active = False
    all_tables = ("filter", "nat", "mangle", "raw", "security")

    for table in all_tables:
        try:
            res = run_trusted([iptables_bin, "-t", table, "-S"], check=False)
            if res.returncode != 0:
                err = (res.stderr or "").lower()
                if "table does not exist" in err or "no such file or directory" in err or "protocol not supported" in err:
                    continue
                return FirewallInspectionResult.UNKNOWN
            for line in res.stdout.splitlines():
                if "NULLTRACE" in line:
                    found_active = True
        except Exception:
            return FirewallInspectionResult.UNKNOWN

    for table in all_tables:
        try:
            res = run_trusted([ip6tables_bin, "-t", table, "-S"], check=False)
            if res.returncode != 0:
                err = (res.stderr or "").lower()
                if "table does not exist" in err or "no such file or directory" in err or "protocol not supported" in err:
                    continue
                return FirewallInspectionResult.UNKNOWN
            for line in res.stdout.splitlines():
                if "NULLTRACE" in line:
                    found_active = True
        except Exception:
            return FirewallInspectionResult.UNKNOWN

    if found_active:
        return FirewallInspectionResult.ACTIVE
    return FirewallInspectionResult.CLEAN


def has_live_nulltrace_rules() -> bool:
    """Inspect live iptables/ip6tables rulesets for NULLTRACE chains or jump rules (P1.5, P2.5)."""
    return inspect_live_nulltrace_rules() == FirewallInspectionResult.ACTIVE


def routing_may_be_active() -> bool:
    """
    Check if nulltrace routing is active via live firewall inspection or persisted state (P1.5, P2.5).
    """
    # 1. Inspect live firewall rules first (P1.5, P2.5)
    if has_live_nulltrace_rules():
        return True

    # 2. Inspect state files
    candidates = [
        Path("/var/lib/nulltrace/state.json"),
        Path("/run/nulltrace/state.json"),
    ]
    pdir = Path("/var/lib/nulltrace")
    if pdir.exists():
        candidates.extend(pdir.glob("session_*/metadata.json"))

    for p in candidates:
        if p.exists():
            try:
                import json
                data = json.loads(p.read_text(encoding="utf-8"))
                if data.get("state") in (
                    "ACTIVE", "ACTIVATING", "PREPARING", "RESTORING",
                    "RESTORE_FAILED", "RECOVERY_REQUIRED"
                ) or data.get("active"):
                    return True
            except Exception:
                return True
    return False


def uninstall_nulltrace(
    purge: bool = False,
    interactive: bool = True,
    emergency_flush: bool = False,
):
    """
    Safely uninstall nulltrace without destructive table flushes (NT-007, NT-006, P1.5, P2.5).
    Never clears unrelated host firewall rules by default.
    Aborts immediately if live firewall inspection returns UNKNOWN.
    """
    fw_status = inspect_live_nulltrace_rules()
    if fw_status == FirewallInspectionResult.UNKNOWN:
        print("[!] ERROR: Live firewall state cannot be verified (iptables unavailable or inspection failed).")
        print("    Uninstallation aborted to prevent leaving orphaned live rules or unrecoverable firewall state.")
        sys.exit(1)

    if routing_may_be_active():
        print("[!] nulltrace routing appears to be active or uncleaned.")
        print("    Attempting to safely restore network rules via nulltrace --force-stop...")

        python3_bin = resolve_trusted_binary("python3") or "python3"
        installed_script = Path("/usr/share/nulltrace/nulltrace.py")
        restore_ok = False

        # Section 8.1: Do not execute a local source checkout as root during uninstall
        is_installed_valid = False
        if installed_script.exists():
            try:
                st = os.lstat(str(installed_script))
                if stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode):
                    if hasattr(os, "geteuid") and os.geteuid() == 0:
                        if st.st_uid == 0 and not (st.st_mode & 0o022):
                            is_installed_valid = True
                    else:
                        is_installed_valid = True
            except OSError:
                is_installed_valid = False

        if is_installed_valid:
            try:
                res = run_trusted([python3_bin, str(installed_script), "--force-stop"], check=False)
                post_status = inspect_live_nulltrace_rules()
                if post_status == FirewallInspectionResult.UNKNOWN:
                    print("[!] ERROR: Post-stop firewall inspection failed (UNKNOWN).")
                    print("    Uninstallation aborted to protect system networking.")
                    sys.exit(1)
                if res.returncode == 0 and post_status == FirewallInspectionResult.CLEAN:
                    restore_ok = True
                    print("[+] Network rules and Tor configuration restored successfully.")
                else:
                    err_msg = res.stderr.strip() or res.stdout.strip()
                    if post_status == FirewallInspectionResult.ACTIVE:
                        err_msg = "Live NULLTRACE firewall rules still detected after stop attempt."
                    print(f"[!] nulltrace --force-stop failed (code {res.returncode}): {err_msg}")
            except Exception as exc:
                print(f"[!] Failed to execute stop procedure: {exc}")
        else:
            print("[!] Trusted installed recovery script '/usr/share/nulltrace/nulltrace.py' is missing or untrusted.")
            print("    Refusing to execute local untrusted checkout as root.")

        if not restore_ok:
            # NT-007: Do not destroy host firewall by default.
            print("\n[!] WARNING: Automatic restoration failed.")
            print("    To prevent destroying unrelated firewall policies (e.g. UFW, Docker, host rules),")
            print("    nulltrace WILL NOT automatically flush all firewall tables.")
            print("    Recovery artifacts and backups have been preserved in /var/lib/nulltrace/.")

            if not emergency_flush:
                if interactive:
                    print("\n[?] Do you want to invoke an EMERGENCY flush of ALL firewall tables?")
                    print("    WARNING: This will wipe ALL iptables/ip6tables rules on this machine,")
                    print("    potentially breaking Docker, UFW, and host security!")
                    try:
                        confirm = input("    Type 'DESTROY-FIREWALL' to proceed with emergency wipe: ").strip()
                    except (EOFError, KeyboardInterrupt):
                        confirm = ""
                    if confirm != "DESTROY-FIREWALL":
                        print("[!] Emergency wipe rejected. Uninstallation aborted to protect firewall state.")
                        sys.exit(1)
                        return
                else:
                    print("[!] Uninstallation aborted. Run with --emergency-flush-all-rules to force wipe.")
                    sys.exit(1)
                    return

            # Only executed if explicitly requested and confirmed (P2-8)
            print("[!] Executing emergency firewall table wipe as requested...")
            iptables_bin = resolve_trusted_binary("iptables")
            ip6tables_bin = resolve_trusted_binary("ip6tables")
            netfilter_tables = ("filter", "nat", "mangle", "raw", "security")
            flush_errors: List[str] = []

            if not iptables_bin or not ip6tables_bin:
                flush_errors.append("iptables or ip6tables binary missing from trusted system directories")

            if iptables_bin:
                for table in netfilter_tables:
                    rf = run_trusted([iptables_bin, "-t", table, "-F"], check=False)
                    if rf.returncode != 0:
                        err = (rf.stderr or "").lower()
                        if not ("table does not exist" in err or "no such file or directory" in err or "protocol not supported" in err):
                            flush_errors.append(f"iptables -t {table} -F failed (code {rf.returncode})")
                    rx = run_trusted([iptables_bin, "-t", table, "-X"], check=False)
                    if rx.returncode != 0:
                        err = (rx.stderr or "").lower()
                        if not ("table does not exist" in err or "no such file or directory" in err or "protocol not supported" in err):
                            flush_errors.append(f"iptables -t {table} -X failed (code {rx.returncode})")
                for chain in ["OUTPUT", "INPUT", "FORWARD"]:
                    rp = run_trusted([iptables_bin, "-P", chain, "ACCEPT"], check=False)
                    if rp.returncode != 0:
                        flush_errors.append(f"iptables -P {chain} ACCEPT failed (code {rp.returncode})")

            if ip6tables_bin:
                for table in netfilter_tables:
                    rf = run_trusted([ip6tables_bin, "-t", table, "-F"], check=False)
                    if rf.returncode != 0:
                        err = (rf.stderr or "").lower()
                        if not ("table does not exist" in err or "no such file or directory" in err or "protocol not supported" in err):
                            flush_errors.append(f"ip6tables -t {table} -F failed (code {rf.returncode})")
                    rx = run_trusted([ip6tables_bin, "-t", table, "-X"], check=False)
                    if rx.returncode != 0:
                        err = (rx.stderr or "").lower()
                        if not ("table does not exist" in err or "no such file or directory" in err or "protocol not supported" in err):
                            flush_errors.append(f"ip6tables -t {table} -X failed (code {rx.returncode})")
                for chain in ["OUTPUT", "INPUT", "FORWARD"]:
                    rp = run_trusted([ip6tables_bin, "-P", chain, "ACCEPT"], check=False)
                    if rp.returncode != 0:
                        flush_errors.append(f"ip6tables -P {chain} ACCEPT failed (code {rp.returncode})")

            if flush_errors:
                print("[!] ERROR: One or more emergency flush commands failed:")
                for e in flush_errors:
                    print(f"    - {e}")

            # P1-6: Verify live firewall state is CLEAN before removing recovery tooling
            post_emergency_status = inspect_live_nulltrace_rules()
            if flush_errors or post_emergency_status != FirewallInspectionResult.CLEAN:
                print(f"[!] ERROR: Emergency firewall flush could not verify clean firewall state (status: {post_emergency_status}).")
                print("    NullTrace recovery tooling (/usr/share/nulltrace, /usr/bin/nulltrace) retained.")
                print("    Uninstallation aborted to prevent leaving unrecoverable orphaned firewall rules.")
                sys.exit(1)

            print("[+] Emergency firewall flush complete and clean firewall state verified.")

    try:
        for path in (
            "/usr/share/nulltrace",
            "/usr/bin/nulltrace",
        ):
            if os.path.isdir(path):
                shutil.rmtree(path)
            elif os.path.isfile(path):
                os.remove(path)
        print("[+] nulltrace program files removed successfully.")
    except Exception as e:
        print(f"[!] Uninstallation failed during file removal: {str(e)}")
        sys.exit(1)

    do_purge = purge
    if interactive and not do_purge:
        try:
            choice = input("[?] Do you want to wipe all saved configurations in ~/.config/ and recovery state? [y/N]: ").lower()
        except (EOFError, KeyboardInterrupt):
            choice = "n"
        if choice in ["y", "yes"]:
            do_purge = True

    if do_purge:
        cfg_dirs = [
            Path.home() / ".config" / "nulltrace",
            Path("/var/lib/nulltrace"),
            Path("/run/nulltrace"),
        ]
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user and sudo_user != "root":
            cfg_dirs.append(Path(f"/home/{sudo_user}") / ".config" / "nulltrace")
        for cfg in cfg_dirs:
            if cfg.exists():
                try:
                    if cfg.is_dir():
                        shutil.rmtree(cfg)
                    else:
                        cfg.unlink()
                    print(f"[+] Purged: {cfg}")
                except Exception as e:
                    print(f"[!] Failed to purge {cfg}: {e}")
        print("[+] All configurations and session data purged.")


def main():
    parser = argparse.ArgumentParser(description="Installer and uninstaller for nulltrace")
    parser.add_argument("--install", action="store_true", help="Install nulltrace non-interactively")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall nulltrace non-interactively")
    parser.add_argument("--purge", action="store_true", help="Purge config files during uninstallation")
    parser.add_argument(
        "--emergency-flush-all-rules",
        action="store_true",
        help="Opt-in emergency fallback to wipe all firewall tables (filter, nat, mangle, raw, security) if stop fails (destructive)",
    )

    args, unknown = parser.parse_known_args()

    check_root()

    if args.install:
        install_nulltrace()
        sys.exit(0)

    if args.uninstall:
        uninstall_nulltrace(
            purge=args.purge,
            interactive=False,
            emergency_flush=args.emergency_flush_all_rules,
        )
        sys.exit(0)

    # Interactive mode fallback
    while True:
        try:
            choice = input(
                "[+] To install press (Y), to uninstall press (N), to exit press (Q) >> "
            ).lower()
        except (EOFError, KeyboardInterrupt):
            print("\n[+] Exiting...")
            sys.exit(0)

        if choice in ["y", "yes"]:
            install_nulltrace()
            break
        elif choice in ["n", "no"]:
            uninstall_nulltrace(
                purge=args.purge,
                interactive=True,
                emergency_flush=args.emergency_flush_all_rules,
            )
            break
        elif choice in ["q", "quit"]:
            print("[+] Exiting...")
            sys.exit(0)
        else:
            print("[!] Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
