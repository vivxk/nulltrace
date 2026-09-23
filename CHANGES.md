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

---

## Post-Review Security & Correctness Hardening (Tickets P0.1 through P2.7)

This section details the critical security, lifecycle correctness, and host integration fixes implemented on 22 September 2026.

### P0.1: Bind Recovery and Stop to Persisted Active Session
- **Issue**: A fresh stop/recovery process generated a new session ID before accessing the recovery directory, causing backup lookups under a non-existent session directory.
- **Remediation**:
  - Bound stop and recovery operations directly to the persisted session ID.
  - Ensured all state transitions, directory lookups, and backup restores operate strictly on the target session directory.
  - Preserved session backups until live teardown verification is completely clean.

### P0.2: Never Trust Persisted ACTIVE Without Live Firewall Verification
- **Issue**: Disk state survived host reboots while runtime iptables rules did not, allowing stale ACTIVE state files to falsely report protection on an unprotected host.
- **Remediation**:
  - Implemented `_check_live_firewall_status()` and `reconcile_state()`.
  - Persisted ACTIVE state without verified NULLTRACE kernel rules is reconciled to `RECOVERY_REQUIRED`.
  - Status queries and state checks never fail open or report active without verified kernel enforcement.

### P0.3: Mandatory Recovery-State Persistence Failures Are Fatal
- **Issue**: Critical state persistence writes caught and ignored `OSError`, allowing activation or teardown to proceed without durable on-disk recovery records.
- **Remediation**:
  - Removed silent error-swallowing in `_persist_session_metadata()` and `_write_state()`.
  - Persistence failures raise fatal exceptions immediately to ensure unrecoverable intermediate states are never created.

### P0.4: Tri-State Teardown Verification
- **Issue**: Firewall teardown verification did not distinguish between inspection errors and verified absence of rules.
- **Remediation**:
  - Implemented tri-state verification returning `TeardownStatus.VERIFIED_CLEAN`, `TeardownStatus.VERIFIED_DIRTY`, or `TeardownStatus.VERIFICATION_FAILED`.
  - Only `VERIFIED_CLEAN` allows transitioning to `INACTIVE`. Any remaining rules or command failures preserve recovery metadata and set `RESTORE_FAILED`.

### P0.5: Crash/Reboot-Safe Lifecycle State Machine
- **Issue**: Lifecycle states lacked explicit modeling for interrupted preparation, crashed processes, and post-reboot mismatch.
- **Remediation**:
  - Added explicit lifecycle states `PREPARING`, `ACTIVE`, `RESTORING`, `RESTORE_FAILED`, `RECOVERY_REQUIRED`, and `INACTIVE`.
  - Integrated state reconciliation on all lifecycle boundaries.

### P1.1: Tor Configuration Permissions Preservation
- **Issue**: Replacing `/etc/tor/torrc` used hardcoded 0644 mode, potentially widening permissions on restrictive configurations (e.g. 0600 or 0640).
- **Remediation**:
  - Updated `atomic_write()` to inspect and preserve existing file mode (`stat().st_mode & 0o777`) and file ownership (UID/GID).
  - Used restrictive defaults (0600 for backups and state) for new files.

### P1.2: Reject IPv6 Listener `::1`
- **Issue**: Localhost validator accepted `::1` even though transparent interception is currently IPv4-based while application IPv6 is blocked.
- **Remediation**:
  - Enforced that Tor listener address must be strictly `127.0.0.1`.
  - Explicitly rejected `::1`, wildcard, and LAN addresses with descriptive error messages explaining transparent routing constraints.

### P1.3: Bit-Masked CONNMARK Namespace
- **Issue**: Unmasked whole-mark save/restore clobbered packet marks used by host VPNs, QoS, and policy routing.
- **Remediation**:
  - Reserved 16-bit mark namespace: `CONNMARK_MASK = "0xffff0000"`, `CONNMARK_VALUE = "0x4e540000"`, `CONNMARK_TOR = "0x4e540000/0xffff0000"`.
  - Updated iptables rules to use `--save-mark --mask 0xffff0000` and `--restore-mark --mask 0xffff0000`.

### P1.4: Eliminate Inbound Allow for Outbound Destination Exclusions
- **Issue**: Excluding an outbound destination subnet automatically created an inbound ACCEPT rule from that subnet in `INPUT`, punching holes in the host firewall.
- **Remediation**:
  - Removed the inbound ACCEPT loop for `excluded_networks` from `CHAIN_FILTER_INPUT`.
  - Outbound destination bypasses remain strictly in `OUTPUT` and `NAT` chains.

### P1.5: Verify Tor Process Listener Ownership
- **Issue**: DNSPort and TransPort health probes checked port connectivity but did not verify whether Tor or a rogue local process was listening.
- **Remediation**:
  - Added `_verify_listener_ownership()` inspecting process names via `ss` (`users:(("tor"...))`) and socket UIDs in `/proc/net/{tcp,udp}` matching the resolved Tor daemon UID.

### P1.6: Privileged Subprocess Environment Hardening
- **Issue**: Subprocesses inherited ambient environment variables, creating risks from `LD_PRELOAD`, `PYTHONPATH`, or proxy variables.
- **Remediation**:
  - Implemented `sanitize_environment()` in both `nulltrace.py` and `install.py`.
  - Sanitized execution environment to minimal explicit variables (`PATH`, `LANG`, `LC_ALL`), stripping `LD_*`, `PYTHON*`, `*PROXY*`, and `TMPDIR`.
  - Routed all privileged execution strictly through `run_trusted()`.

### P1.7: Custom Chain Authentication & Ownership
- **Issue**: Static chain names could allow collision with or accidental flushing of pre-existing administrator chains.
- **Remediation**:
  - Implemented `_authenticate_or_create_chain()` tagging owned chains with `CHAIN_MARKER_COMMENT` (`nulltrace-owned`).
  - Replaced blind chain creation with ownership verification, refusing to flush or mutate unauthenticated existing chains.

### P1.8: No Routine Global Conntrack Flush
- **Issue**: Calling `conntrack -F` during normal startup wiped out all unrelated host connection tracking entries.
- **Remediation**:
  - Removed global `conntrack -F` from `_activate_jump_rules()`.
  - Relied on strict packet filter default-drop policies and masked CONNMARK isolation.

### P2.1: Interrupted Restoration Signal Safety
- **Issue**: Abrupt termination via `SIGINT`/`SIGTERM` during `--stop` left persisted state at `RESTORING`.
- **Remediation**:
  - Registered signal handlers in `stop_privacy_mode()` to catch termination and persist `RESTORE_FAILED`.

### P2.2: Tor NEWNYM Signal Requirement
- **Issue**: `--new-ip` fell back to `pkill -HUP tor`, which reloads configuration but does not guarantee a new Tor circuit or identity.
- **Remediation**:
  - Removed `pkill -HUP` fallback entirely.
  - Required verified Tor ControlPort `SIGNAL NEWNYM` success or raised an explicit `RuntimeError`.

### P2.3: Tor ControlPort Effective Directive Discovery
- **Issue**: Tor config parser selected the first `ControlPort` line, ignoring overrides, comments, or address:port syntax.
- **Remediation**:
  - Implemented complete file scanning ignoring commented lines (`#`), parsing address:port notation, and selecting the last active valid directive.

### P2.4: Tor Service Restart Verification During Restoration
- **Issue**: Restoring Tor configuration on disk did not verify that the Tor daemon successfully restarted.
- **Remediation**:
  - Updated `restore_tor_config()` to inspect service restart exit codes and raise `RuntimeError` if the restart fails.

### P2.5: Uninstaller Live Firewall Detection
- **Issue**: `install.py --uninstall` only checked persisted state files, allowing recovery tooling to be removed while live iptables rules remained stranded.
- **Remediation**:
  - Added `has_live_nulltrace_rules()` inspecting live `iptables -S` / `ip6tables -S` rulesets.
  - Refused uninstallation if live NULLTRACE rules or jumps remain active.

### P2.6 & P2.7: Explicit Proxy Bypass & Strict Type Validation for IP Checks
- **Issue**: Ambient proxy environment variables (`HTTP_PROXY`, etc.) could hijack `--ip` queries, and truthy non-boolean values or IPv6 exit addresses were mishandled.
- **Remediation**:
  - Configured `urllib.request.ProxyHandler({})` in `show_current_ip()` to explicitly bypass ambient proxies.
  - Validated `IsTor` strictly as a Python `bool`.
  - Validated reported IP addresses using `ipaddress.ip_address()`, correctly supporting both IPv4 and IPv6 exit nodes.

---

## Final Security & Correctness Remediation (Tickets P0.1 through P2.10)

This section details the final security overhaul addressing every ticket in `nulltrace_remaining_issues_agent_handoff.md`.

### P0.1: User-Controlled Config Directory Symlink & Privileged Write Elimination
- **Remediation**:
  - Derived canonical target user home from `pwd.getpwnam(sudo_user).pw_dir`.
  - Inspected every path component leading to `~/.config/nulltrace/` using `os.lstat()` and rejected symlinks before writing or changing permissions.
  - Required target configuration paths to be regular files (`stat.S_ISREG`), rejecting symlinks, FIFOs, sockets, and devices.
  - Restricted operations to the canonical directory with `Path.relative_to()`.
  - Used `os.lchown()` where supported to prevent following symlinks during ownership updates.

### P0.2: Firewall Live-State Verification with Rule Manifests & Fingerprints
- **Remediation**:
  - Generated session enforcement manifests (`manifest.json`) recording expected chains, top-level jumps, and SHA256 fingerprints of canonicalized chain rules.
  - Enhanced `_check_live_firewall_status()` to inspect actual chain rule contents, requiring expected catch-all DROPs, REDIRECTs, and REJECTs.
  - Rejected early unconditioned `RETURN`/`ACCEPT` rules (policy bypasses).
  - Compared live chain rule fingerprints against persisted session manifest hashes.

### P0.3: Unconditional IPv6 Application Traffic Lockdown
- **Remediation**:
  - Always installs IPv6 enforcement chains whenever `ip6tables` is available, never conditioning enforcement on initial host interface or sysfs state.
  - Reconciled IPv6 state as part of the live firewall health check.
  - Aborts startup fail-closed if `ip6tables` is missing, preventing dual-stack cleartext leaks.

### P1.1: Tor Listener Ownership Hardening Against Process Spoofing
- **Remediation**:
  - Rejected process comm name matching alone.
  - Verified listener identity via socket listening state, exact bind address (`127.0.0.1`), owning PID, UID (`/proc/<pid>/status`), and resolved executable path (`/proc/<pid>/exe`) matching trusted Tor binaries.

### P1.2: Stale Inactive Historical Session Recovery Prevention
- **Remediation**:
  - Updated `_discover_session_id()` to query only sessions in `RECOVERABLE_STATES` (`ACTIVE`, `PREPARING`, `ACTIVATING`, `RESTORING`, `RESTORE_FAILED`, `RECOVERY_REQUIRED`).
  - Historical `INACTIVE` sessions are never selected as recovery candidates.
  - `--force-stop` reports clean when only inactive historical sessions exist.

### P1.3: Tor Configuration Restoration Preserves Administrator Additions
- **Remediation**:
  - Implemented `strip_tor_config_blocks()`, removing only the delimited Nulltrace-managed block upon teardown.
  - Preserves any independent settings or lines added to `/etc/tor/torrc` by the administrator while Nulltrace was active.

### P1.4: Non-Destructive Teardown Preserves Host Firewall State
- **Remediation**:
  - Normal teardown removes only Nulltrace-owned jumps and custom chains, preserving host firewall rules (UFW, firewalld, Docker, admin rules).
  - Whole-table backup snapshot restoration is isolated to the explicit `--destructive-restore` flag.

### P1.5: Uninstaller Tri-State Firewall Inspection & Unknown State Abort
- **Remediation**:
  - Implemented `inspect_live_nulltrace_rules()` returning `CLEAN`, `ACTIVE`, or `UNKNOWN`.
  - Uninstaller immediately aborts with code 1 upon `UNKNOWN` to avoid removing recovery tooling while rules are unverified.

### P1.6: Transactional Firewall Activation & Fail-Closed Rollback
- **Remediation**:
  - Constructed and verified complete custom chains before activating position-1 jumps.
  - State machine commits durable metadata prior to jump activation.
  - Interruption or command failure triggers transactional fail-closed rollback.

### P1.7: Strict Chain Ownership Authentication
- **Remediation**:
  - Required exact `nulltrace-owned` comment marker on existing chains before reuse or flushing.
  - Generic port numbers or marks are not accepted as ownership proof.

### P1.8: Single Baseline Tor Configuration Snapshot Per Session
- **Remediation**:
  - Baseline snapshot is taken exactly once per session and never overwritten during re-application.

### P2.1: Consistent Fatal Durability on Metadata & State Writes
- **Remediation**:
  - Persistence write failures during activation or state transitions raise immediately, preventing inconsistent or unrecorded states.

### P2.2: Restrictive 0600 Mode for Persistent State
- **Remediation**:
  - Ensured persistent and runtime state files (`state.json`, `metadata.json`, `manifest.json`) are created with `0600` permissions.

### P2.3: DNS Leak Verification Verifies Tor Process Ownership
- **Remediation**:
  - DNS leak test requires verified Tor process ownership of the DNSPort listener in addition to protocol packet probe success.

### P2.4: Hardened `/proc` Listener Fallback
- **Remediation**:
  - `/proc` fallback validates address, port, PID, UID, and executable binary path before accepting listener.

### P2.5: Strict Root-Only Ownership for Tor Configuration Files & Directories
- **Remediation**:
  - Enforced that `/etc/tor/` and `torrc` must be owned by UID 0 (root-owned) when running as root, rejecting daemon-owned or unprivileged ownership.

### P2.6: Regular File Verification for All Configuration Paths
- **Remediation**:
  - Required `stat.S_ISREG` for all file-backed configuration, explicitly rejecting FIFOs, sockets, and character/block devices.

### P2.7: Distinct Enforcement & Routing Status Reporting
- **Remediation**:
  - Exposes `ENFORCING_TOR_HEALTHY`, `ENFORCING_TOR_UNHEALTHY`, `INACTIVE`, `RECOVERY_REQUIRED`, `RESTORE_FAILED`, and `UNKNOWN`.
  - Invariant guaranteed: `ENFORCING_TOR_UNHEALTHY` keeps traffic safely blocked (fail-closed), never falling back to direct Internet.

### P2.8: Documented Position-1 Jump Priority in Firewall Coexistence
- **Remediation**:
  - Documented position-1 jump priorities and interaction with UFW, firewalld, Docker, and native nftables.

### P2.9: Canonical IP/CIDR Validation via `ipaddress`
- **Remediation**:
  - Replaced handwritten regex IP/CIDR validation with `ipaddress.ip_address()` and `ipaddress.ip_network()`, normalizing addresses and subnets.

### P2.10: ASCII-Only Exit Country Code Validation
- **Remediation**:
  - Enforced regex `^[A-Za-z]{2}$` and normalized to uppercase, rejecting non-ASCII unicode lookalikes.

---

## Comprehensive Security & Correctness Hardening (P0, P1, P2 Specifications)

### P0-1: Race-Resistant Privileged Configuration Writes (`atomic_write`)
- **Remediation**: Reimplemented `atomic_write()` with fd-relative operations (`os.open` with `O_DIRECTORY | O_NOFOLLOW` on POSIX), pre-stat symlink race checks, directory validation, fatal error reporting on chmod/chown/fsync, and directory fsync.

### P0-2: Exact Unconditional First-Rule Jump Verification
- **Remediation**: In `_check_live_firewall_status()`, required exact rule 0 unconditional jump (`-A <BASE_CHAIN> -j <NULLTRACE_CHAIN>`). Rejected non-first jumps, preceding `ACCEPT` bypasses, duplicate jumps, and conditional jumps.

### P1-1 & P1-2: Order-Preserving Complete-or-Fail Firewall Manifests
- **Remediation**: Preserved exact kernel rule ordering in canonical representation (no sorting) for SHA-256 fingerprints. Made manifest generation complete-or-fail across all 11 required chains (6 IPv4, 5 IPv6), raising `RuntimeError` on any inspection failure.

### P1-3: Mandatory Manifest Validation for ACTIVE Status
- **Remediation**: `_check_live_firewall_status()` strictly requires a valid persisted manifest, complete set of 11 chain fingerprints, and matching hashes for `ACTIVE` status. Missing or corrupt manifests return `PARTIAL`.

### P1-4 & P2-6: Strong Tor Process Identity & UID Validation
- **Remediation**: Eliminated process-name trust from `pgrep` candidate discovery in `_control_tor_service()`. Enforced multi-point validation in `_verify_process_is_tor()`: verified alive PID, `/proc/<pid>/exe` pointing to trusted Tor binary, effective UID matching expected Tor UID, and real UID matching expected UID or root (privilege drop service).

### P1-5: Hardened Trusted Binary Integrity
- **Remediation**: `resolve_trusted_binary()` in `nulltrace.py` and `install.py` requires regular files (`stat.S_ISREG`), root ownership on POSIX, no group/world writable bits (`mode & 0o022 == 0`), and symlinks strictly resolving inside trusted system directories.

### P1-6 & P2-8: Verified Emergency Teardown & All-Tables Flush
- **Remediation**: In `install.py`, expanded `--emergency-flush-all-rules` to flush (`-F`) and delete chains (`-X`) across all 5 netfilter tables (`filter`, `nat`, `mangle`, `raw`, `security`) for both `iptables` and `ip6tables`. Added post-flush live firewall inspection requiring `CLEAN` state before removing `/usr/share/nulltrace` and `/usr/bin/nulltrace`.

### P1-7: Tri-State Installer Firewall Inspection
- **Remediation**: `inspect_live_nulltrace_rules()` requires successful inspection of both `iptables` and `ip6tables` across all netfilter tables. Inability to inspect IPv6 returns `UNKNOWN`, never false `CLEAN`.

### P1-8: Unterminated Managed Tor Configuration Protection
- **Remediation**: In `strip_tor_config_blocks()`, unterminated managed blocks (`BEGIN` without `END`) raise `ValueError`, preventing truncation of administrator settings.

### P1-9: Original Tor Configuration Existence Tracking
- **Remediation**: Persisted `tor_config_existed` boolean metadata. On teardown, if torrc originally did not exist and only the managed block was added, the file is unlinked; if an administrator added settings, those are preserved.

### P1-10 & P1-11: Original Service & Interface State Restoration
- **Remediation**: Captured `tor_service_initially_active` and `tor_service_initially_enabled` before changes; restored to initial active/enabled states during teardown. Captured `interface_initially_up`; restored both hardware MAC and administrative UP/DOWN state.

### P2-1: Destructive Restore Safeguards
- **Remediation**: Added prominent warnings to CLI help and runtime logs explaining that `--destructive-restore` is a last-resort recovery mechanism that can overwrite host firewall rules modified after activation.

### P2-2: Runtime & Persistent Directory Security Validation
- **Remediation**: Implemented `_validate_secure_directory()` checking directory existence, regular directory type, not a symlink, root ownership, and restrictive non-writable permissions.

### P2-3: Strict Session ID Format Validation
- **Remediation**: Implemented `is_valid_session_id()` strictly enforcing lowercase hex 8-16 characters (`^[0-9a-f]{8,16}$`), rejecting directory traversal, special characters, and path separators.

### P2-5: Multi-PID Shared Socket Ownership
- **Remediation**: In `_find_pids_by_socket_inode()` and `_verify_listener_ownership()`, enumerated all processes sharing a socket (e.g. `SO_REUSEPORT`) and verified that every candidate PID is an authentic Tor daemon.

### P2-7: Durable Multi-Phase Activation Model
- **Remediation**: Modeled activation as a durable multi-phase process with intermediate checkpoints, pre-change state persistence, and fail-closed automatic rollback upon interruption.

### Final Verification & Edge-Case Hardening
- **`_check_tor_service_enabled()`**: Corrected return logic so that disabled systemd services (`systemctl is-enabled` returning non-zero/disabled) evaluate strictly to `False` rather than mistakenly defaulting to `True`, ensuring Tor is properly disabled on teardown when initially disabled.
- **`_is_interface_up()`**: Added direct kernel administrative state detection reading `/sys/class/net/<intf>/flags` bit 0 (`IFF_UP`), providing unambiguous administrative state detection independent of operational carrier status.
- **`atomic_write()`**: Added open file descriptor permissions setting (`fchmod`/`fchown` on `tf.fileno()`), parent directory symlink rejection in fallback mode, and pre-replacement symlink validation in fallback mode.
- **`resolve_trusted_binary()`**: Validated root ownership on both the symlink itself and resolved target on POSIX systems.
- **Regression Suite (Section 11)**: Expanded `TestSection11_ComprehensiveRegressions` with 11 additional unit tests, achieving 130 passing tests (100% pass rate) covering every bullet point in the specification document.
