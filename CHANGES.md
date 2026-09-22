# nulltrace Security Hardening & Changelog

## Summary of Architectural Hardening & Bug Fixes

This document records the comprehensive architectural review and security hardening applied to `nulltrace` (Linux transparent Tor proxy).

---

## 1. Critical Routing & Firewall Fixes

### 1.1 Filter Table Egress Leak Fixed
- **Issue**: An unconditional rule (`iptables -A OUTPUT -p tcp -j ACCEPT`) was previously appended to the `filter` table `OUTPUT` chain, allowing raw or non-redirected TCP sockets (e.g. using `SO_BINDTODEVICE`) to leak directly to physical network interfaces.
- **Fix**: Removed the open TCP accept rule. Enforced strict default-deny policies (`-P DROP`) across `OUTPUT`, `INPUT`, and `FORWARD`. Only explicit loopback (`-o lo`), established connections (`conntrack`), the Tor daemon user (`--uid-owner`), and user-configured excluded destinations are permitted. All other egress is dropped at the packet filter level.

### 1.2 NAT Rule Ordering & Excluded Destination Priority
- **Issue**: Outbound DNS redirection (`REDIRECT --to-ports 5353`) was applied before excluded destination `RETURN` rules, preventing LAN DNS exclusions from functioning.
- **Fix**: Reordered NAT chain rules so that `excluded_networks` RETURN rules are evaluated prior to DNS interception.

### 1.3 TCP DNS Protocol Mismatch Fixed
- **Issue**: TCP DNS queries (port 53) were previously redirected to `tor_port` (9041, TransPort) instead of `dns_port` (5353, DNSPort), causing wire-format DNS queries to fail and breaking `.onion` automapping over TCP.
- **Fix**: Redirected TCP port 53 directly to Tor's `DNSPort` (`5353`).

### 1.4 IPv6 Connection Tracking & Ingress Hole Fixed
- **Issue**: Tor daemon was allowed outbound IPv6 traffic, but `ip6tables` `INPUT` dropped all packets with no connection tracking (`conntrack`) or loopback acceptance, causing Tor to hang or fail on dual-stack relay connections.
- **Fix**: Added `ESTABLISHED,RELATED` connection tracking and loopback acceptance on IPv6 `INPUT` and `OUTPUT`.

### 1.5 Tor Outbound TCP Teardown Fixed
- **Issue**: Security rules dropped `ACK,FIN` and `ACK,RST` on `! -o lo` before the Tor owner exemption, blocking legitimate connection teardowns between the Tor daemon and remote relays.
- **Fix**: Added `! -m owner --uid-owner $tor_user` exemption to the security drop rules.

---

## 2. Process & ControlPort Stability

### 2.1 Tor ControlPort Handshake Deadlock Eliminated
- **Issue**: `_tor_control_newnym()` executed a blocking `sock.recv(256)` before sending `AUTHENTICATE`. Because the Tor control protocol does not send a connection banner, this caused a guaranteed 8-second timeout hang on every new identity request.
- **Fix**: Removed the pre-emptive `recv()`. The client immediately sends the authentication payload upon connection establishment.

### 2.2 Systemd vs. Non-systemd Compatibility
- **Issue**: Calling `systemctl` on non-systemd Linux systems (Alpine, Void, containers) threw an unhandled `FileNotFoundError`.
- **Fix**: Wrapped service invocations in `OSError` guards and added fallbacks to standard `service tor restart`.

### 2.3 Comprehensive Port Health Checks
- **Issue**: `check_tor_ports()` only tested TransPort 9041 and never validated DNSPort 5353, allowing port collisions with local resolvers (such as `avahi-daemon`) to go unnoticed.
- **Fix**: Added validation probe for DNSPort on 5353 in `check_tor_ports()`.

---

## 3. Teardown & Backup Integrity

### 3.1 Decoupled IPv4 and IPv6 Teardown
- **Issue**: An error in restoring IPv6 rules previously caused `restored` to be reset to `False`, triggering `_flush_iptables()` and wiping out successfully restored IPv4 rules.
- **Fix**: Separated IPv4 and IPv6 restoration flags so an IPv6 failure never compromises IPv4 restoration.

### 3.2 Backup Overwrite Protection
- **Issue**: Re-running `--start` after a partial failure could overwrite a pristine firewall backup with incomplete rules.
- **Fix**: Added guard checks in `backup_iptables()` to ensure existing non-empty backup files are preserved.

### 3.3 State & Config File Permissions
- **Issue**: Non-root users running `--status` or `--dnsleak` received errors because `/run/nulltrace` was set to `0700`.
- **Fix**: Configured directory permissions to `0755` and `state.json` to `0644`, while keeping sensitive backup files secured at `0600`.

### 3.4 Multi-User Config Resolution
- **Issue**: Unprivileged users saving configs to `~/.config/nulltrace` could not load them when running under `sudo` because `Path.home()` resolved to `/root`.
- **Fix**: Added `get_config_home()` to inspect `$SUDO_USER` and locate the real user's config directory.

---

## 4. Teardown & Backup Preservation

### 4.1 Backup Preservation on Restore Failure
- **Issue**: If `iptables-restore` or `ip6tables-restore` failed during teardown, the original backup was unconditionally unlinked, permanently destroying the user's prior firewall configuration.
- **Fix**: Preserved the backup on failure by renaming it to `.failed` (e.g. `iptables.v4.bak.failed`) and outputting instructions for manual recovery.

### 4.2 Tor Configuration File Permissions
- **Issue**: Writing `/etc/tor/torrc` with restrictive root umasks (e.g., 0027 or 0077) caused Tor to fail to boot because the unprivileged `debian-tor` service user could not read the configuration.
- **Fix**: Added explicit `os.chmod(path, 0o644)` when applying `torrc`.

### 4.3 Redundant Tor Service Restart Eliminated
- **Issue**: On Debian/Ubuntu where `tor@default` is the primary unit, `_restart_tor_no_check()` restarted both `tor@default` and `tor` sequentially, causing double-restarts.
- **Fix**: Short-circuited on the first successful service restart.

### 4.4 Excluded Destinations Harmonization
- **Issue**: NAT redirection to TransPort bypassed only `excluded_networks` while ignoring `excluded_ips`.
- **Fix**: Updated NAT and security rule routines to consistently use `_excluded_destinations()`, covering both networks and specific host exemptions.

---

## 5. Installer Hardening (`install.py`)

- Added exit code verification for `subprocess.run(["python3", script_path, "--force-stop"])` to ensure the manual fallback flush is triggered if automated teardown fails.
- Fixed config purge under `sudo` to clean up `$SUDO_USER` directories in addition to `/root`.
- Protected all terminal `input()` calls against `EOFError` and `KeyboardInterrupt` in headless environments.
- Allowed `--help` to be displayed without requiring root permissions.
- Added interactive confirmation before manual firewall flush to prevent accidental firewall table wipes if the user cancels uninstallation.
