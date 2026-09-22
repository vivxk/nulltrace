import os
import sys
import shutil
import argparse
import subprocess
from pathlib import Path

def check_root():
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        print("[!] This script must be run as root")
        sys.exit(1)

def check_dependencies():
    missing = []
    for cmd in ["tor", "iptables", "ip6tables"]:
        if shutil.which(cmd) is None:
            missing.append(cmd)
    
    if missing:
        print(f"[!] Installation aborted. Missing required system dependencies: {', '.join(missing)}")
        print("    Please install them (e.g., sudo apt install tor iptables ip6tables)")
        sys.exit(1)

    if shutil.which("macchanger") is None:
        print("[*] Optional dependency 'macchanger' not found.")
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

        launcher_content = """#!/bin/sh
exec python3 /usr/share/nulltrace/nulltrace.py "$@"
"""
        with open("/usr/bin/nulltrace", "w", encoding="utf-8") as handle:
            handle.write(launcher_content)
        os.chmod("/usr/bin/nulltrace", 0o755)

        print("[+] nulltrace installed successfully")
        print("[+] You can now use the 'nulltrace' command")

    except Exception as e:
        print(f"[!] Installation failed: {str(e)}")
        sys.exit(1)

def routing_may_be_active():
    candidates = (
        Path("/run/nulltrace/state.json"),
        Path("/run/nulltrace/iptables.v4.bak"),
    )
    return any(path.exists() for path in candidates)

def uninstall_nulltrace(purge: bool = False, interactive: bool = True):
    if routing_may_be_active():
        print("[!] nulltrace routing appears to be active.")
        print("    Attempting to automatically restore network rules...")
        try:
            # We use the python script directly in case the launcher is compromised or partially deleted
            script_path = "/usr/share/nulltrace/nulltrace.py"
            if not os.path.exists(script_path):
                script_path = "nulltrace" # Fallback to global path
            res = subprocess.run(["python3", script_path, "--force-stop"], check=False)
            if res.returncode != 0:
                raise RuntimeError(f"nulltrace --force-stop returned exit code {res.returncode}")
            print("[+] Network rules restored successfully.")
        except Exception as e:
            print(f"[!] Warning: Failed to automatically stop nulltrace: {e}")
            if interactive:
                try:
                    choice = input("    Attempt fail-safe firewall flush (sets default policies to ACCEPT)? [y/N]: ").lower()
                except (EOFError, KeyboardInterrupt):
                    choice = "n"
                if choice not in ("y", "yes"):
                    print("[!] Skipping firewall flush.")
                    print("[!] Uninstall cancelled")
                    return
            print("    [+] Attempting manual fail-safe firewall flush...")
            subprocess.run(["iptables", "-F"], check=False)
            subprocess.run(["iptables", "-t", "nat", "-F"], check=False)
            for chain in ["OUTPUT", "INPUT", "FORWARD"]:
                subprocess.run(["iptables", "-P", chain, "ACCEPT"], check=False)
            if shutil.which("ip6tables"):
                subprocess.run(["ip6tables", "-F"], check=False)
                for chain in ["OUTPUT", "INPUT", "FORWARD"]:
                    subprocess.run(["ip6tables", "-P", chain, "ACCEPT"], check=False)
            print("    [+] Firewall fail-safe complete. Network rules cleared.")
            
            if interactive:
                try:
                    choice = input("    Continue uninstall anyway? [y/N]: ").lower()
                except (EOFError, KeyboardInterrupt):
                    choice = "n"
                if choice not in ("y", "yes"):
                    print("[!] Uninstall cancelled")
                    return
            else:
                print("[!] Proceeding with uninstall despite cleanup failure (CLI mode).")

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
            choice = input("[?] Do you want to wipe all saved configurations in ~/.config/? [y/N]: ").lower()
        except (EOFError, KeyboardInterrupt):
            choice = "n"
        if choice in ["y", "yes"]:
            do_purge = True
    
    if do_purge:
        cfg_dirs = [Path.home() / ".config" / "nulltrace"]
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user and sudo_user != "root":
            cfg_dirs.append(Path(f"/home/{sudo_user}") / ".config" / "nulltrace")
        for cfg in cfg_dirs:
            if cfg.exists():
                try:
                    shutil.rmtree(cfg)
                    print(f"[+] Purged configuration directory: {cfg}")
                except Exception as e:
                    print(f"[!] Failed to purge {cfg}: {e}")
        print("[+] All configurations purged.")

def main():
    parser = argparse.ArgumentParser(description="Installer for nulltrace")
    parser.add_argument("--install", action="store_true", help="Install nulltrace non-interactively")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall nulltrace non-interactively")
    parser.add_argument("--purge", action="store_true", help="Purge config files during uninstallation")
    
    # We parse known args so that if no arguments are provided, it doesn't fail but falls back to interactive
    args, unknown = parser.parse_known_args()

    check_root()

    if args.install:
        install_nulltrace()
        sys.exit(0)
    
    if args.uninstall:
        uninstall_nulltrace(purge=args.purge, interactive=False)
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
            uninstall_nulltrace(purge=args.purge, interactive=True)
            break
        elif choice in ["q", "quit"]:
            print("[+] Exiting...")
            sys.exit(0)
        else:
            print("[!] Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
