# nulltrace

**Advanced Privacy Tool with Enhanced Security Features**

nulltrace routes system traffic through the Tor network on Linux using iptables transparent proxying. It includes DNS leak checks, tight egress rules, and safe backup/restore around network and Tor configuration changes.

![nulltrace](https://img.shields.io/badge/Privacy-Enhanced-brightgreen)
![Security](https://img.shields.io/badge/Security-Fixed-red)
![Platform](https://img.shields.io/badge/Platform-Linux-blue)

---

## 🚀 New Features in nulltrace

### ✅ Security Enhancements
- **Command Injection Protection**: Validates inputs; subprocess uses argv lists (no shell)
- **DNS Leak Detection**: `resolv.conf` checks and sample `dig` lookups
- **Full egress lockdown**: All TCP via Tor, DNS UDP redirected, other UDP/ICMP blocked, IPv6 blocked
- **Atomic Operations**: Backup/restore in `/run/nulltrace/` with safe start/stop guards

### ✅ Improved Functionality
- **Enhanced DNS Leak Test**: `resolv.conf` + resolver samples (no third-party logging)
- **Better Error Handling**: Rollback on failed start; no backup overwrite on re-start
- **Input Validation**: Config limited to `~/.config/nulltrace/`
- **Tor NEWNYM**: Control port when available, HUP fallback

### ✅ Additional Features
- **Comprehensive Status**: Tor service and routing status (`--status`)
- **Minimal Logging**: No log files by default; optional `--verbose` on stderr only

---

## 📋 Requirements

- **Linux Distribution**: Ubuntu, Debian, Kali Linux, Parrot OS, etc.
- **Python 3.6+**
- **Tor Service**: Must be installed and running
- **Root Access**: Required for installation and network configuration
- **Dependencies**: `iptables`, `ip6tables`, Tor systemd service (Optional: `macchanger` for MAC randomization)

---

## 🔧 Installation

### Method 1: Manual Installation (Recommended)

```bash
# 1. Clone or download the repository
git clone https://github.com/vivxk/nulltrace.git
cd nulltrace

# 2. Run the installation script as root
sudo python3 install.py

# 3. Follow the prompts:
#    - Press Y to install
#    - Press N to uninstall existing version
#    - Press Q to exit
```

### Method 2: Manual Setup

```bash
# 1. Copy files to system locations
sudo mkdir -p /usr/share/nulltrace
sudo cp nulltrace.py /usr/share/nulltrace/
sudo chmod +x /usr/share/nulltrace/nulltrace.py

# 2. Create launcher script
echo '#!/bin/sh' | sudo tee /usr/bin/nulltrace > /dev/null
echo 'exec python3 /usr/share/nulltrace/nulltrace.py "$@"' | sudo tee -a /usr/bin/nulltrace > /dev/null
sudo chmod +x /usr/bin/nulltrace

# 3. Install dependencies
sudo apt update
sudo apt install tor iptables ip6tables
```

---

## 📖 Usage

### Basic Commands

```bash
# Start nulltrace (route all traffic through Tor)
sudo nulltrace --start

# Stop nulltrace and restore normal networking
sudo nulltrace --stop

# Show current Tor IP
nulltrace --ip

# Get a new Tor IP address
sudo nulltrace --new-ip

# Show detailed status
nulltrace --status
```

### Advanced Features

```bash
# Auto-rotate IP every 30 minutes
sudo nulltrace --auto --time 1800

# Test for DNS leaks
nulltrace --dnsleak

# Set custom circuit lifetime (default: 3600 seconds)
sudo nulltrace --start --circuit-time 1800
```

### Complete Option Reference

| Option | Short Form | Description | Example |
|--------|------------|-------------|---------|
| `--start` | `-s` | Start routing traffic through Tor | `sudo nulltrace --start` |
| `--stop` | `-x` | Stop Tor routing and restore backups | `sudo nulltrace --stop` |
| `--force-stop` | | Restore from backup if state file is missing | `sudo nulltrace --force-stop` |
| `--ip` | `-i` | Show current Tor IP (Tor check API) | `nulltrace --ip` |
| `--new-ip` | `-n` | Request new Tor identity/IP | `sudo nulltrace --new-ip` |
| `--auto` | `-a` | Auto-change IP at intervals | `sudo nulltrace --auto` |
| `--time <sec>` | `-t` | Set auto-change interval | `--time 300` (5 min) |
| `--circuit-time <sec>` | | Set Tor circuit lifetime | `--circuit-time 1800` |
| `--status` | | Show detailed status | `nulltrace --status` |
| `--dnsleak` | | Test for DNS leaks | `nulltrace --dnsleak` |
| `--verbose` | | Debug messages on stderr | `nulltrace --verbose --status` |
| `--mac-randomize` | | Randomize physical MAC address | `sudo nulltrace --start --mac-randomize` |
| `--exit-country <cc>` | | Force Tor exit node to specific country | `sudo nulltrace --start --exit-country us` |
| `--save [file]` | | Save configuration to file | `nulltrace --save myconfig.json` |
| `--load [file]` | | Load configuration from file | `nulltrace --load myconfig.json` |
| `--show-config` | | Show current configuration | `nulltrace --show-config` |

---

### Configuration Management

nulltrace supports persistent configuration to save and restore your settings:

```bash
# Save current configuration
nulltrace --save

# Save with custom filename
nulltrace --save my_settings.json

# Load saved configuration
nulltrace --load my_settings.json

# Show current configuration
nulltrace --show-config
```

**Configuration includes:**
- Circuit time settings
- Network configuration (ports, excluded networks/IPs)
- All customizable parameters

**Note:** Configuration is entirely optional and never loads automatically. Saved files live in `~/.config/nulltrace/`.

---

## 🛡️ Security Features

### Command Injection Protection
- Validates domain names and IPs with strict regex
- All subprocess calls use argument lists (no shell)

### Traffic Isolation
- **TCP**: all outbound TCP NAT-redirected to Tor TransPort
- **DNS**: UDP and TCP port 53 aggressively redirected to Tor DNSPort
- **Inbound Stealth Firewall**: `INPUT` chain locked down to drop all unrequested inbound probes, making you invisible on public Wi-Fi
- **Other UDP / ICMP**: dropped (except loopback, Tor user, excluded LAN CIDRs)
- **IPv6**: blocked via ip6tables while active using safe, non-destructive rules

### Privilege Management
- Requires root only for `--start`, `--stop`, `--force-stop`, `--new-ip`, and `--auto`
- `--ip`, `--dnsleak`, and `--status` run without root

### Atomic Operations
- Backs up IPv4/IPv6 iptables to `/run/nulltrace/` before changes
- Refuses `--start` if already active (preserves pristine backups)
- Failed start restores rules but keeps backup for `--force-stop`

---

## 📊 Examples

### Start with Custom Circuit Time
```bash
sudo nulltrace --start --circuit-time 900
# Circuits will expire after 15 minutes
```

### Auto-Rotate IP Every 10 Minutes
```bash
sudo nulltrace --auto --time 600
# Press Ctrl+C to stop
```

### Comprehensive Status Check
```bash
nulltrace --status
# Shows: Tor service status, routing status, current IP
```

### DNS Leak Test
```bash
nulltrace --dnsleak
# Tests multiple DNS resolvers and checks for leaks
```

---

## 🔍 Troubleshooting

### Common Issues

**Tor service not running:**
```bash
sudo systemctl start tor
sudo systemctl enable tor
```

**Permission denied:**
```bash
# Use sudo with all commands that modify network settings
sudo nulltrace --start
```

**DNS issues:**
```bash
# Test DNS leak detection
nulltrace --dnsleak

# If leaks detected, restart the setup
sudo nulltrace --stop
sudo nulltrace --start
```

**Debug output (optional):**
```bash
nulltrace --verbose --status
```

---

## 📝 Logging

nulltrace does **not** write log files by default (privacy-focused). Use `--verbose` for debug messages on stderr only. IPs and DNS queries are not logged.

---

## 🚫 Disclaimer

**Ethical Use Only:**
- This tool is for privacy, security research, and educational purposes
- Do not use for illegal activities
- Respect terms of service of networks you access
- The authors are not responsible for misuse

**Legal Considerations:**
- Using Tor may be restricted in some jurisdictions
- Some websites may block Tor exit nodes
- Your ISP may have policies about Tor usage

---

## 🔄 Uninstallation

```bash
# Run the uninstaller directly
sudo python3 install.py --uninstall
```
*Note: The uninstaller features an elite "Anti-Brick" Hard Flush failsafe to mathematically guarantee your firewall is cleared, even if the python script encounters an execution error.*

---

## 📚 Technical Details

### How It Works
1. **Configuration**: Appends marked block to `/etc/tor/torrc` (TransPort, DNSPort, circuit time)
2. **Network Rules**: Backs up iptables, applies NAT + filter rules, blocks IPv6 egress
3. **DNS Routing**: Redirects UDP/53 to Tor; blocks other UDP
4. **IP Rotation**: `SIGNAL NEWNYM` via Tor control port, or HUP fallback
5. **Restore on stop**: iptables and Tor config revert from backups

### Files Modified
- `/etc/tor/torrc` - Tor configuration (nulltrace block)
- `/etc/tor/torrc.nulltrace.bak` - One-time backup of original config
- `/run/nulltrace/iptables.v4.bak` - IPv4 iptables backup while active
- `/run/nulltrace/iptables.v6.bak` - IPv6 iptables backup (if available)
- `/run/nulltrace/state.json` - active session marker
- `~/.config/nulltrace/` - user JSON settings only

### Network Changes
- NAT: Tor user bypass, DNS redirect, excluded LAN, all TCP → TransPort
- filter: allow Tor/LAN/TCP, drop other UDP and ICMP
- ip6tables: default DROP on OUTPUT while active

---

## 📅 Planned Features / TODO (Under Research)

The following advanced anti-forensics features have been proposed and are currently under research for future implementation:

*   **Memory Locking (`mlockall`)**: Pinning the `nulltrace` process memory to physical RAM to prevent any sensitive configuration data or routing states from being written to disk via the Linux Swap file.
*   **Swap Disablement (`swapoff -a`)**: System-wide, temporary disablement of the Linux Swap partition during active routing to guarantee a 100% amnesic session in the event of a physical hardware seizure.
*   **Persistent Lockdown (Boot Kill-Switch)**: An optional setting to permanently modify default iptables to DROP all traffic on boot, enforcing a fail-closed environment where internet access is physically impossible unless `nulltrace` is actively running.
*   **Pluggable Transports (`obfs4`)**: Support for Tor bridge obfuscation to evade Deep Packet Inspection (DPI) and bypass ISP-level Tor blocking.
*   **Native `nftables` Migration (Architecture)**: As modern Linux distributions deprecate `iptables`, a future refactor to dynamically generate `nftables` rulesets or interact via the Netlink API will ensure long-term, future-proof routing compatibility.

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:
- Fork the repository
- Create a feature branch
- Submit pull requests
- Report issues with detailed information

---

## 📜 License

This project is licensed under the MIT License. See the LICENSE file for details.

---

## 📞 Support

For issues, questions, or suggestions:
- Check the GitHub issues page
- Review the documentation
- Use `nulltrace --verbose` for stderr debug output

---

**Stay Private, Stay Secure! 🔒**
