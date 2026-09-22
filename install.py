#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence

TRUSTED_BIN_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")


def resolve_trusted_binary(name: str) -> Optional[str]:
    """Resolve binary strictly to a trusted system directory (NT-006)."""
    if not name or not isinstance(name, str):
        return None
    p = Path(name)
    if p.is_absolute():
        p_str = p.as_posix()
        for tdir in TRUSTED_BIN_DIRS:
            if p_str == f"{tdir}/{p.name}" and p.is_file() and os.access(p_str, os.X_OK):
                return p_str
        return None
    if p.name != name or "/" in name or "\\" in name or ".." in name:
        return None
    for directory in TRUSTED_BIN_DIRS:
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(str(candidate), os.X_OK):
            return str(candidate)
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


def install_nulltrace():
    check_dependencies()
    try:
        source = Path(__file__).resolve().parent / "nulltrace.py"
        if not source.is_file():
            print(f"[!] nulltrace.py not found beside installer: {source}")
            sys.exit(1)

        os.makedirs("/usr/share/nulltrace", mode=0o755, exist_ok=True)
        shutil.copy2(source, "/usr/share/nulltrace/nulltrace.py")
        os.chmod("/usr/share/nulltrace/nulltrace.py", 0o755)

        python3_bin = resolve_trusted_binary("python3") or "/usr/bin/python3"
        launcher_content = f"""#!/bin/sh
exec {python3_bin} /usr/share/nulltrace/nulltrace.py "$@"
"""
        target_launcher = Path("/usr/bin/nulltrace")
        temp_launcher = Path("/usr/bin/.nulltrace.launcher.tmp")
        temp_launcher.write_text(launcher_content, encoding="utf-8")
        os.chmod(temp_launcher, 0o755)
        os.replace(temp_launcher, target_launcher)

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
    Tri-state inspection of live iptables/ip6tables rulesets (P1.5):
    - CLEAN: binaries ran successfully and no NULLTRACE chains or rules exist.
    - ACTIVE: binaries ran successfully and NULLTRACE chains or rules exist.
    - UNKNOWN: iptables binary missing or command errored.
    """
    iptables_bin = resolve_trusted_binary("iptables")
    if not iptables_bin:
        return FirewallInspectionResult.UNKNOWN

    found_active = False
    for table in ("filter", "nat", "mangle"):
        try:
            res = run_trusted([iptables_bin, "-t", table, "-S"], check=False)
            if res.returncode != 0:
                return FirewallInspectionResult.UNKNOWN
            for line in res.stdout.splitlines():
                if "NULLTRACE" in line:
                    found_active = True
        except Exception:
            return FirewallInspectionResult.UNKNOWN

    ip6tables_bin = resolve_trusted_binary("ip6tables")
    if ip6tables_bin:
        for table in ("filter", "mangle"):
            try:
                res = run_trusted([ip6tables_bin, "-t", table, "-S"], check=False)
                if res.returncode != 0:
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
        script_path = "/usr/share/nulltrace/nulltrace.py"
        if not os.path.exists(script_path):
            script_path = str(Path(__file__).resolve().parent / "nulltrace.py")

        restore_ok = False
        try:
            res = run_trusted([python3_bin, script_path, "--force-stop"], check=False)
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
                else:
                    print("[!] Uninstallation aborted. Run with --emergency-flush-all-rules to force wipe.")
                    sys.exit(1)

            # Only executed if explicitly requested and confirmed
            print("[!] Executing emergency firewall table wipe as requested...")
            iptables_bin = resolve_trusted_binary("iptables")
            ip6tables_bin = resolve_trusted_binary("ip6tables")
            if iptables_bin:
                run_trusted([iptables_bin, "-F"], check=False)
                run_trusted([iptables_bin, "-t", "nat", "-F"], check=False)
                run_trusted([iptables_bin, "-t", "mangle", "-F"], check=False)
                for chain in ["OUTPUT", "INPUT", "FORWARD"]:
                    run_trusted([iptables_bin, "-P", chain, "ACCEPT"], check=False)
            if ip6tables_bin:
                run_trusted([ip6tables_bin, "-F"], check=False)
                run_trusted([ip6tables_bin, "-t", "mangle", "-F"], check=False)
                for chain in ["OUTPUT", "INPUT", "FORWARD"]:
                    run_trusted([ip6tables_bin, "-P", chain, "ACCEPT"], check=False)
            print("[+] Emergency firewall flush complete.")

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
        help="Opt-in emergency fallback to wipe all firewall tables if stop fails (destructive)",
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
