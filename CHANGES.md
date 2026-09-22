# nulltrace Security Hardening & Remediation Changelog

## Architectural Remediation & Security Overhaul (Tickets NT-001 through NT-016)

This document details the comprehensive security remediation executed to guarantee the privacy invariant that all system traffic is either provably Tor-routed or blocked.

---

### NT-001 (P0): Fail-Closed IPv6 Lockdown
- **Issue**: Previously, `_apply_ipv6_lockdown()` ran `ip6tables` commands with `check=False` and swallowed failures, allowing sessions to claim active status while IPv6 leaked traffic in cleartext.
- **Remediation**:
  - Implemented strict fail-closed enforcement: all `ip6tables` commands execute with `check=True`.
  - Added startup pre-flight check: if IPv6 is enabled on the host and `ip6tables` is missing or fails, startup aborts immediately and triggers rollback before any state is marked active.
  - Defined IPv6 policy as "blocked, not transparently proxied" across application traffic.

### NT-002 (P0): Conntrack Flow Isolation & Tor Connection Marking
- **Issue**: Pre-existing direct TCP connections established prior to activation remained in kernel connection tracking tables and were accepted by an unconstrained `OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT` rule, bypassing Tor.
- **Remediation**:
  - Removed unconditional `ESTABLISHED,RELATED -j ACCEPT` rules from external egress interfaces.
  - In `mangle` table, added rules to mark Tor daemon outbound traffic with `CONNMARK_TOR` (`0x4e54`) and save the connmark.
  - Restricted established connection acceptance in `INPUT` to packets matching `CONNMARK_TOR`.
  - In `OUTPUT`, all application egress must route via loopback or match explicit Tor/excluded destination rules; any pre-existing cleartext socket hits the default DROP rule.
  - Added `conntrack -F` flush when utility is present, while ensuring deterministic isolation even when conntrack tools are absent.

### NT-003 (P0): Transactional Owned Chains & Atomic Activation
- **Issue**: Startup flushed the host's entire firewall tables (`iptables -F`), wiping out unrelated firewall managers (UFW, Docker, firewalld, host admin rules) and leaving the host in an ambiguous state if interrupted.
- **Remediation**:
  - Replaced destructive table-wide flushes with owned custom chains: `NULLTRACE_OUTPUT`, `NULLTRACE_INPUT`, `NULLTRACE_FORWARD`, `NULLTRACE_NAT_OUTPUT`, `NULLTRACE_MANGLE_OUTPUT`, `NULLTRACE_MANGLE_PREROUTING`, and IPv6 equivalents `NULLTRACE_V6_*`.
  - Rules are populated inside custom chains first; activation occurs atomically by inserting priority-1 jump rules from base chains.
  - Registered signal handlers (`SIGINT`, `SIGTERM`) during startup to perform clean fail-closed rollback.
  - Host firewall tables and existing rules remain completely untouched.

### NT-004 (P0): Strict Teardown State Machine
- **Issue**: `stop_privacy_mode()` caught exceptions, printed warnings, cleared state files, and reported inactive even when MAC, firewall, or Tor restoration failed.
- **Remediation**:
  - Implemented a 5-state teardown state machine: `INACTIVE` -> `ACTIVATING` -> `ACTIVE` -> `RESTORING` -> `INACTIVE` or `RESTORE_FAILED`.
  - If any restoration step fails during teardown, the session is marked `RESTORE_FAILED`, backups and metadata are preserved, and a non-zero exit code is returned.
  - Status reports prominent diagnostics and recovery instructions when in `RESTORE_FAILED` state.

### NT-005 (P1): Restrict Tor Listener Address to Loopback
- **Issue**: `is_valid_ip()` allowed arbitrary IP addresses (such as `0.0.0.0` or LAN IPs) for `localhost`, exposing Tor TransPort and DNSPort to the local network.
- **Remediation**:
  - Replaced generic IP validation with `is_valid_loopback_ip()`, using `ipaddress.ip_address(val).is_loopback`.
  - Enforced that `config.localhost` strictly accepts loopback addresses (`127.0.0.1`, `::1`, `127.0.0.0/8`). Rejected `0.0.0.0`, LAN, and WAN addresses.

### NT-006 (P1): Eliminate PATH-Dependent Root Command Execution
- **Issue**: Root subprocesses were executed using bare command names, allowing binary hijacking if an untrusted directory preceded system paths in `PATH`.
- **Remediation**:
  - Implemented `resolve_trusted_binary()` and `run_trusted()` in both `nulltrace.py` and `install.py`.
  - Resolved all privileged executables strictly to trusted system directories (`/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`).
  - Sanitized the environment `PATH` to trusted directories on all subprocess calls.

### NT-007 (P1): Non-Destructive Uninstaller Safety
- **Issue**: `install.py` previously executed a hard flush (`iptables -F`, `iptables -P ACCEPT`) if stopping nulltrace failed, destroying host security policies.
- **Remediation**:
  - Removed destructive fail-open flushes from the default uninstallation flow.
  - Uninstallation now halts and preserves recovery artifacts if automatic restoration fails.
  - Added an explicit, opt-in `--emergency-flush-all-rules` flag with interactive confirmation for intentional disaster recovery only.

### NT-008 (P1): Tor-Specific DNSPort Protocol Health Checks
- **Issue**: `check_tor_ports()` checked DNSPort health by trying to bind UDP socket to port 5353; any arbitrary process listening on 5353 (e.g. mDNS/avahi) was mistakenly treated as healthy Tor.
- **Remediation**:
  - Implemented `_probe_dns_port()`: sends an actual standard DNS query packet over UDP to `(localhost, dns_port)` and verifies a valid DNS response with matching transaction ID and QR bit.
  - Port collisions with non-Tor processes fail health checks.

### NT-009 (P1): Aligned TCP DNS Policy & TransPort Protection
- **Issue**: Documentation claimed TCP DNS was redirected to DNSPort, while NAT redirected TCP to TransPort and filter rules rejected TCP/53.
- **Remediation**:
  - Added explicit bypass for TCP port 53 in NAT (`-p tcp --dport 53 -j RETURN`), ensuring wire-format DNS is never sent to TransPort.
  - Enforced filter rejection (`-p tcp --dport 53 -j REJECT --reject-with tcp-reset`) to prevent hangs and DNS leaks.
  - Synchronized `README.md` and documentation to accurately describe UDP redirection and TCP reset.

### NT-010 (P1): Session-Bound Backups & Stale Backup Prevention
- **Issue**: Backup files in `/run/nulltrace/` were reused across runs, allowing stale snapshots to overwrite newer host configurations during a later stop.
- **Remediation**:
  - Tied every activation to a unique session ID (`session_<id>`).
  - Stored backups and recovery records in persistent storage (`/var/lib/nulltrace/session_<id>/`).
  - Prohibited starting a new session if an uncleaned or failed session exists; required clean restoration first.

### NT-011 (P1): MAC Address Persistence & Independent Restoration
- **Issue**: MAC restoration depended solely on `macchanger -p`, failing if macchanger was uninstalled or failed.
- **Remediation**:
  - Read original hardware MAC from sysfs (`/sys/class/net/<intf>/address`) or `ip link` prior to modification.
  - Persisted original MAC address in session metadata.
  - Restored MAC using `ip link set dev <intf> address <mac>` independently of macchanger.

### NT-012 (P2): Tor Service Fallback on Command Exit Code
- **Issue**: Tor service control tried `systemctl` and only fell back to `service` if `systemctl` binary did not exist. On systems where `systemctl` failed with non-zero exit code (e.g. containers, chroots, broken systemd), `service` was never attempted.
- **Remediation**:
  - Implemented `_control_tor_service()`: inspects exit codes and stderr; falls back to `service` whenever `systemctl` returns non-zero.
  - Structured failure diagnostics returned if both mechanisms fail.

### NT-013 (P2): Deterministic Egress Interface Selection via `ip route get`
- **Issue**: `_get_primary_interface()` parsed `ip route show default` and took the first text line, leading to incorrect interface selection on multi-homed or policy-routed systems.
- **Remediation**:
  - Used `ip route get <probe_ip>` to query the kernel's definitive routing decision.
  - Filtered virtual and tunnel interfaces (`tun`, `tap`, `wg`, `ppp`, `lo`).
  - Added ambiguity detection for multiple conflicting default routes.

### NT-014 (P2): Symlink-Safe Tor Configuration Path Validation
- **Issue**: `is_valid_tor_config_path()` performed only lexical string checks, allowing symlinks under `/etc/tor/` to escape to external targets.
- **Remediation**:
  - Implemented canonical resolution via `Path.resolve()`.
  - Enforced that resolved canonical paths strictly reside within `/etc/tor/`.
  - Validated file ownership and permissions before write.

### NT-015 (P2): Atomic Durable Writes
- **Issue**: Configuration, state, and backup files were written directly, creating risk of zero-length or corrupted files on power loss or crash.
- **Remediation**:
  - Implemented `atomic_write()`: writes to temporary file in target directory, flushes, fsyncs file descriptor, sets permissions, atomically replaces destination via `os.replace()`, and fsyncs parent directory.
  - Applied to state files, user configs, Tor configuration modifications, and session backups.

### NT-016 (P2): Accurate Documentation & Requirements Alignment
- **Issue**: Documentation had drifted from code behavior (Python version, DNS policies, table flushes, uninstaller claims).
- **Remediation**:
  - Updated minimum Python version requirement to Python 3.8+.
  - Documented owned custom chains, conntrack marking, and atomic transactions.
  - Accurately documented DNS policy (UDP/53 redirected, TCP/53 rejected).
  - Clarified IPv6 fail-closed policy.
  - Added comprehensive recovery instructions for interrupted sessions.
