# nulltrace

**Advanced Privacy Tool with Hardened Transparent Tor Proxying**

nulltrace routes system traffic through the Tor network on Linux using iptables transparent proxying. It enforces strict egress filtering, isolated connection tracking, transactional owned firewall chains, and fail-closed IPv6 protection.

![nulltrace](https://img.shields.io/badge/Privacy-Enhanced-brightgreen)
![Security](https://img.shields.io/badge/Security-Hardened-red)
![Platform](https://img.shields.io/badge/Platform-Linux-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)

---

## 🚀 Key Security Architecture

### ✅ Transactional & Non-Destructive Firewall Architecture
- **Owned & Authenticated Chains**: All nulltrace firewall rules reside inside owned chains (`NULLTRACE_OUTPUT`, `NULLTRACE_INPUT`, `NULLTRACE_FORWARD`, `NULLTRACE_NAT_OUTPUT`, `NULLTRACE_MANGLE_*`, and `NULLTRACE_V6_*`), each authenticated with ownership markers (`nulltrace-owned`) before mutation or reuse.
- **Atomic Activation Without Global Flushes**: Nulltrace never flushes host firewall tables (`iptables -F`) nor does it wipe global connection tracking state (`conntrack -F`). Unrelated policies from UFW, Docker, VPNs, or administrator configurations remain completely untouched. Rules are activated via atomic priority-1 jump insertions.
- **Fail-Closed Rollback**: If any rule fails during startup or if the process receives SIGINT/SIGTERM, nulltrace triggers an immediate rollback that removes jump rules and deletes custom chains.

### ✅ Egress Lockdown, Masked Marks & Conntrack Isolation
- **Connection Tracking & Namespaced Marks**: Pre-existing direct TCP connections cannot bypass Tor. Nulltrace isolates Tor daemon flows using a 16-bit masked CONNMARK (`0x4e540000/0xffff0000`), ensuring unrelated packet marks used by host VPNs, QoS, or policy routing survive unmolested.
- **Strict Default Deny & No Accidental Inbound Allow**: Filter table chains drop all unauthorized outgoing/incoming traffic. Outbound destination exclusions remain strictly outbound; excluding an outbound subnet never opens an inbound ACCEPT hole in the host firewall.
- **Inbound Stealth Firewall**: Blocks unsolicited inbound probes on public networks while maintaining DHCP and loopback operation.

### ✅ Protocol-Accurate DNS Policy & Tor Listener Verification
- **UDP Port 53 Redirection**: Outbound UDP DNS queries are intercepted in NAT and redirected to Tor's `DNSPort` (default port 5353).
- **TCP Port 53 Reset**: Outbound TCP DNS (port 53) is explicitly rejected with `tcp-reset` at the packet filter level and bypassed in NAT. Tor's DNSPort operates over UDP; wire-format DNS is never sent to TransPort.
- **Process & Protocol Verification**: Startup verifies that Tor `DNSPort` actively responds to real DNS query packets and verifies socket/listener ownership via `ss` and socket UIDs matching the intended Tor daemon.
- **IPv4-Only Listener Policy**: The Tor listener address is strictly restricted to `127.0.0.1`. IPv6 listener binding (`::1`) is rejected until native IPv6 transparent interception is implemented.

### ✅ Fail-Closed IPv6 Policy
- **Blocked, Not Proxied**: Until full IPv6 transparent proxying is available, all IPv6 application traffic is strictly blocked (`check=True` on all `ip6tables` operations).
- **Hard Startup Verification**: If IPv6 is enabled on the host and `ip6tables` fails or is absent, startup aborts immediately. Dual-stack systems fail closed rather than leaking over IPv6.

### ✅ Crash/Reboot-Safe State Machine & Durable Recovery
- **Enforcement Truth Over Disk State**: Disk state describes recovery intent; live kernel rules prove protection. Persisted `ACTIVE` state without live firewall rules (e.g. after host reboot or crash) is automatically reconciled to `RECOVERY_REQUIRED`, preventing false active reports.
- **Cross-Process Session Binding**: Every activation session receives a unique session ID (`session_<id>`). A fresh `--stop` or `--recover` process automatically discovers and binds to the active session directory and restores its exact backups.
- **Explicit Lifecycle States**: Full state machine transitions through `INACTIVE` -> `PREPARING` -> `ACTIVE` -> `RESTORING` -> `INACTIVE`, `RESTORE_FAILED`, or `RECOVERY_REQUIRED`.
- **Tri-State Teardown Verification**: Teardown verification distinguishes between clean removal (`VERIFIED_CLEAN`), remaining rules (`VERIFIED_DIRTY`), and inspection errors (`VERIFICATION_FAILED`). Recovery state is never deleted unless teardown is proven clean.
- **Durable Atomic Writes**: All configuration, state, and backup files are written using temporary files, fsync, and atomic replacement, preserving existing restrictive permissions (e.g. 0600 or 0640 for `torrc`).
- **Execution Hardening**: Privileged operations execute in a minimal sanitized environment (stripping `LD_*`, `PYTHON*`, `*PROXY*`, and `TMPDIR`) with trusted binary resolution.
- **Deterministic Identity Rotation**: `--new-ip` requires definitive Tor ControlPort `SIGNAL NEWNYM` authentication and never falls back to `pkill -HUP`.
- **Proxy-Safe IP Checks**: `--ip` status queries bypass ambient proxy variables and enforce strict type and address parsing for IPv4 and IPv6 exit nodes.

---

## 📋 Requirements

- **Linux Distribution**: Ubuntu, Debian, Kali Linux, Parrot OS, Arch Linux, Alpine, etc.
- **Python 3.8+**
- **Tor Service**: Installed and configured
- **Root Access**: Required for network configuration and packet filtering
- **Dependencies**: `iptables`, `ip6tables`, Tor (Optional: `macchanger` for MAC randomization)

---

## 🔧 Installation

### Method 1: Installer Script

```bash
# 1. Clone repository
git clone https://github.com/vivxk/nulltrace.git
cd nulltrace

# 2. Run installer as root
sudo python3 install.py

# Options:
#   Press Y to install
#   Press N to safely uninstall
#   Press Q to exit
```

### Method 2: Manual Setup

```bash
# 1. Install dependencies
sudo apt update
sudo apt install tor iptables ip6tables

# 2. Copy files to system directories
sudo mkdir -p /usr/share/nulltrace
sudo cp nulltrace.py /usr/share/nulltrace/
sudo chmod 755 /usr/share/nulltrace/nulltrace.py

# 3. Create launcher
cat << 'EOF' | sudo tee /usr/bin/nulltrace > /dev/null
#!/bin/sh
exec /usr/bin/python3 /usr/share/nulltrace/nulltrace.py "$@"
EOF
sudo chmod 755 /usr/bin/nulltrace
```

---

## 📖 Usage

### Basic Commands

```bash
# Start nulltrace (route system traffic through Tor)
sudo nulltrace --start

# Stop nulltrace and restore normal networking
sudo nulltrace --stop

# Show current public IP and Tor exit status
nulltrace --ip

# Request new Tor identity (new IP)
sudo nulltrace --new-ip

# Show detailed status (service, ports, routing, session state)
nulltrace --status
```

### Advanced Options

```bash
# Start with MAC address randomization on the primary egress interface
sudo nulltrace --start --mac-randomize

# Auto-rotate Tor IP every 15 minutes (900 seconds)
sudo nulltrace --auto --time 900

# Specify exit node country code (e.g., Switzerland)
sudo nulltrace --start --exit-country CH

# Run DNS leak check (checks resolv.conf and tests Tor DNSPort responsiveness)
nulltrace --dnsleak

# Set Tor circuit lifetime (seconds)
sudo nulltrace --start --circuit-time 1800
```

### Option Reference Table

| Option | Short Form | Description | Example |
|---|---|---|---|
| `--start` | `-s` | Start Tor transparent proxying | `sudo nulltrace --start` |
| `--stop` | `-x` | Teardown routing and restore system state | `sudo nulltrace --stop` |
| `--force-stop` | | Force teardown even if state file is inactive | `sudo nulltrace --force-stop` |
| `--recover` | | Recover system state from persistent metadata & backups | `sudo nulltrace --recover` |
| `--status` | | Display status and session diagnostics | `nulltrace --status` |
| `--ip` | `-i` | Check public IP via Tor check API | `nulltrace --ip` |
| `--new-ip` | `-n` | Request new Tor identity | `sudo nulltrace --new-ip` |
| `--auto` | `-a` | Auto-rotate identity at intervals | `sudo nulltrace --auto --time 600` |
| `--time <sec>` | `-t` | Interval for `--auto` in seconds | `--time 600` |
| `--circuit-time <sec>` | | Set Tor MaxCircuitDirtiness | `--circuit-time 1800` |
| `--mac-randomize` | | Randomize egress interface MAC address | `sudo nulltrace --start --mac-randomize` |
| `--exit-country <cc>` | `-c` | 2-letter ISO country code for exit node | `sudo nulltrace --start --exit-country IS` |
| `--dnsleak` | | Test DNS configuration and DNSPort health | `nulltrace --dnsleak` |
| `--save [file]` | | Save settings under `~/.config/nulltrace/` | `nulltrace --save myconfig.json` |
| `--load [file]` | | Load settings from `~/.config/nulltrace/` | `nulltrace --load myconfig.json` |
| `--show-config` | | Display current configuration | `nulltrace --show-config` |
| `--verbose` | | Enable debug messages on stderr | `nulltrace --verbose --status` |

---

## 🛡️ Recovery & Troubleshooting

### Crash Recovery & `RESTORE_FAILED`
If a stop operation is interrupted or encounters an error:
1. The session state is marked `RESTORE_FAILED` or `RECOVERY_REQUIRED`.
2. Backups and recovery metadata are preserved in `/var/lib/nulltrace/session_<id>/`.
3. To recover, run:
   ```bash
   sudo nulltrace --recover
   # or
   sudo nulltrace --stop
   ```
4. If manual intervention is required, inspect `/var/lib/nulltrace/session_<id>/metadata.json` for backed-up configurations and original hardware MAC addresses.

### Non-Destructive Uninstallation
To uninstall nulltrace without damaging unrelated firewall rules:
```bash
sudo python3 install.py --uninstall
```
*Note: Uninstallation attempts clean restoration first. If stop fails, it preserves recovery records and exits non-zero rather than indiscriminately wiping the host firewall.*

---

## 📜 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
