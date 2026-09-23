# NullTrace — Master Remediation Handoff
## Final Consolidated Security, Correctness, Recovery & Integration Review

**Objective:** This is the **single master remediation document** for the coding agent. It consolidates the remaining issues found in the latest NullTrace archive after the Linux-Windows development mismatch was corrected.

The goal is to eliminate the repeated review/fix/review cycle. The agent must use this document as the authoritative remediation checklist, implement the fixes, add appropriate tests, and perform real Linux integration validation before declaring completion.

---

# 0. Current status and important context

The latest agent report claimed:

```text
196 tests
196 passed
0 failed
0 errors
```

That is useful and represents real progress.

However, the code review of the latest archive still identifies several issues that the current test suite does not fully prove.

The current implementation is **generally usable for ordinary NullTrace operation**, but it is not yet ready to be described as fully hardened under hostile filesystem conditions, abnormal service states, recovery corruption, administrator races, and firewall-management conflicts.

## Critical instruction

**Do not make the tests pass by weakening the production security model.**

Several tests still rely on mocks and can pass even when the underlying Linux invariant is not fully enforced.

For filesystem/security behavior, prefer real Linux fixtures wherever practical.

---

# 1. What is already considered fixed — DO NOT REGRESS THESE

The following areas from earlier reviews are materially improved and should remain intact:

## Filesystem writes

- FD-relative directory traversal.
- `O_DIRECTORY`.
- `O_NOFOLLOW`.
- `fstat()` validation.
- FD-relative temporary-file creation.
- `fchmod()`.
- `fchown()`.
- file `fsync()`.
- FD-relative `os.rename()`.
- parent-directory `fsync()`.
- no unsafe Linux pathname-based replacement fallback.

## Firewall verification

- exact first-rule jump verification.
- unconditional jump requirement.
- duplicate/ambiguous jump rejection.
- ordered chain fingerprints.
- complete-or-fail manifest generation.
- mandatory manifest before ACTIVE.
- IPv4 and IPv6 verification.
- live-state mismatch detection.

## Process identity

- process-name-only trust removed.
- `/proc/<pid>/status` UID validation.
- `/proc/<pid>/exe` validation.
- expected Tor UID enforcement.
- process liveness checks.
- shared socket owner enumeration.

## Firewall design

- no global `conntrack -F`.
- reserved masked connmark model.
- owned-chain creation/authentication.
- normal teardown does not blindly restore the entire host firewall.
- destructive firewall restore remains explicitly gated.

## Tor configuration

- managed block detection.
- unterminated managed block rejection.
- original torrc existence tracking.
- preservation of configuration outside the managed block.

---

# 2. P1 — Tor ACTIVE state still collapses UNKNOWN into INACTIVE

## Location

`nulltrace.py`

Relevant functions:

```text
_control_tor_service()
check_tor_service()
_has_verified_tor_process()
```

## Current behavior

`_control_tor_service("is-active")` ultimately returns:

```python
(False, ...)
```

when it cannot verify Tor.

`check_tor_service()` then converts that into:

```python
False
```

So these states are currently conflated:

```text
Tor definitely inactive
Tor state could not be determined
Tor process information temporarily inaccessible
systemd unavailable
/proc inspection failed
```

## Why this is dangerous

Startup captures:

```text
_tor_initially_active = self.check_tor_service()
```

Therefore:

```text
UNKNOWN
    ↓
False
```

can produce incorrect restoration behavior.

Example:

```text
Tor was originally running
        ↓
state inspection temporarily fails
        ↓
baseline records inactive
        ↓
NullTrace stops/reconfigures
        ↓
teardown stops Tor instead of restoring active state
```

## Required implementation

Create a true state model:

```text
ACTIVE
INACTIVE
UNKNOWN
```

or:

```python
True
False
None
```

Recommended contract:

```text
True  = verified active
False = verified inactive
None  = state cannot be established
```

`check_tor_service()` must stop returning a false negative for UNKNOWN.

Then define restoration behavior explicitly:

- baseline ACTIVE → restore ACTIVE;
- baseline INACTIVE → restore INACTIVE;
- baseline UNKNOWN → do not invent a state.

For UNKNOWN, use:

```text
RESTORE_FAILED
```

or:

```text
RECOVERY_REQUIRED
```

rather than silently choosing stop/start.

## Required tests

Add tests for:

- verified Tor process exists → ACTIVE;
- verified Tor process absent with reliable service state → INACTIVE;
- `/proc` inaccessible → UNKNOWN;
- service manager inaccessible → UNKNOWN;
- fake service reports active → UNKNOWN/INACTIVE unless process verified;
- teardown never treats UNKNOWN as INACTIVE.

---

# 3. P1 — Recovery must never fabricate missing baseline values

## Location

`nulltrace.py`

Relevant functions:

```text
_load_session_metadata()
restore_tor_config()
reconcile_state()
```

## Current issue

The metadata writer correctly stores values such as:

```text
None
```

until they are observed.

But restoration still contains defaults equivalent to:

```python
meta.get(
    "tor_config_existed",
    getattr(self, "_tor_config_existed", True)
)

meta.get(
    "tor_service_initially_active",
    getattr(self, "_tor_initially_active", True)
)
```

This means a missing field can become:

```text
tor_config_existed = True
tor_service_initially_active = True
```

even though those values were never observed.

## Why this matters

A corrupted/incomplete recovery record can cause the tool to make destructive assumptions.

Example:

```text
metadata.json corrupt
        ↓
baseline field absent
        ↓
default = True
        ↓
recovery assumes original Tor was active
```

## Required implementation

For every security-critical baseline field, require:

```text
baseline_captured == true
AND
required field exists
AND
field value is valid
```

Otherwise:

```text
RECOVERY_REQUIRED / RESTORE_FAILED
```

Do not use `True`/`False` defaults for:

- original Tor active state;
- original Tor enabled state;
- original torrc existence;
- original interface state.

If metadata is corrupt, do not silently treat it as missing.

If `metadata.json` exists but is invalid:

```text
metadata corruption
→ explicit recovery failure
```

not:

```text
try another weak fallback
```

unless the fallback is proven complete and authoritative.

---

# 4. P1 — Session discovery can select stale historical failed sessions

## Location

`nulltrace.py`

Function:

```text
_discover_session_id()
```

## Current behavior

The code:

1. checks state files;
2. then scans all:

```text
/var/lib/nulltrace/session_*
```

and selects the highest-priority recoverable historical session.

Old sessions with:

```text
RESTORE_FAILED
RECOVERY_REQUIRED
PREPARING
RESTORING
```

can therefore remain candidates indefinitely.

## Failure scenario

```text
Session A
    RESTORE_FAILED
    ↓
Later Session B
    ACTIVE → cleanly stopped → INACTIVE
    ↓
state.json = INACTIVE
    ↓
user runs `nulltrace --stop`
    ↓
session scan finds old Session A
    ↓
Session A gets selected
```

The system can then attempt recovery of an obsolete session even though the current system is clean.

This can also make future `--start` operations fail because `setup_network_rules()` sees a stale recoverable session.

## Required implementation

Define exactly one authoritative current/recoverable session.

Preferred design:

```text
state.json/current-session pointer
        ↓
only that session is eligible for automatic recovery
```

Historical failed sessions should not automatically become the current session.

Alternative:

- mark a failed session as resolved/consumed after explicit manual recovery;
- require an explicit session selection for historical recovery.

## Required tests

- old RESTORE_FAILED session exists + current system INACTIVE → normal `--stop` must not select old session;
- old failed session exists + new clean session → new session remains authoritative;
- state pointer references nonexistent session → RECOVERY_REQUIRED, not fabricated recovery;
- multiple stale sessions → deterministic safe behavior.

---

# 5. P1 — Session metadata/state identity must be validated as one object

## Location

`nulltrace.py`

Relevant:

```text
_discover_session_id()
_load_session_metadata()
_session_dir()
manifest handling
```

## Current issue

The code can obtain the session ID from one source and metadata from another without fully proving they all describe the same session.

Examples:

```text
state.json:
    session_id = AAA

metadata.json:
    session_id = BBB
```

or:

```text
session_<AAA>/metadata.json
    claims session_id = BBB
```

or:

```text
manifest.json
    session_id = CCC
```

## Required invariant

All of the following must agree:

```text
state.json.session_id
metadata.json.session_id
manifest.json.session_id
session directory basename
```

Where a session is expected to be recoverable, require:

```text
session_<sid>
+
metadata.session_id == sid
+
manifest.session_id == sid
```

If inconsistent:

```text
RECOVERY_REQUIRED
```

Do not guess which record is correct.

---

# 6. P1 — Firewall teardown still removes top-level jumps without ownership authentication

## Location

`nulltrace.py`

Function:

```text
_deactivate_jump_rules()
```

Current logic performs commands such as:

```text
iptables -D OUTPUT -j NULLTRACE_OUTPUT
iptables -D INPUT -j NULLTRACE_INPUT
...
```

before `_destroy_authenticated_chain()` validates custom-chain ownership.

## Why this is incomplete

The custom chain itself may be protected:

```text
NULLTRACE_OUTPUT
missing nulltrace-owned marker
→ don't flush/delete chain
```

but the top-level jump can still be removed.

An administrator could have:

```text
NULLTRACE_OUTPUT
```

as an unrelated chain.

With:

```text
-A OUTPUT -j NULLTRACE_OUTPUT
```

the current teardown can delete that jump even if the chain is not NullTrace-owned.

## Required implementation

Before removing each jump:

1. inspect the target chain;
2. authenticate ownership;
3. only remove the jump if ownership is confirmed;
4. otherwise leave it untouched.

If the chain is missing, deletion may be a safe no-op.

If inspection fails:

```text
do not modify the base chain
```

## Required test

Create:

```text
NULLTRACE_OUTPUT
```

without the ownership marker plus:

```text
-A OUTPUT -j NULLTRACE_OUTPUT
```

Then invoke forced teardown.

Expected:

```text
jump remains
chain remains
RESTORE_FAILED / RECOVERY_REQUIRED
```

---

# 7. P1 — Chain inspection still has an ambiguous “rc=1 + empty stderr = absent” rule

## Location

`nulltrace.py`

Function:

```text
_authenticate_or_create_chain()
_destroy_authenticated_chain()
```

Current logic includes an absence condition equivalent to:

```python
rc == 1 and not stderr
```

## Problem

Exit code 1 plus empty stderr is not sufficient evidence that the chain is absent.

It could indicate another inspection failure.

## Required implementation

Only treat the chain as absent when output positively establishes absence.

For example, recognize explicit messages such as:

```text
No chain/target/match by that name
does not exist
No such file or directory
```

Anything else:

```text
INSPECTION_ERROR
```

Do not create or destroy a chain based on ambiguous exit status.

## Required tests

- explicit absent message → create/no-op as appropriate;
- rc=1 + empty stderr → inspection failure;
- permission error → failure;
- xtables lock → failure;
- backend error → failure;
- malformed output → failure.

---

# 8. P1 — Service control commands require post-condition verification

## Location

`nulltrace.py`

Function:

```text
_control_tor_service()
```

## Current behavior

For actions other than `is-active`, successful command exit can be treated as sufficient:

```text
systemctl restart tor
returncode 0
→ success
```

Similarly:

```text
systemctl stop tor
returncode 0
→ success
```

and:

```text
systemctl disable tor
returncode 0
→ success
```

## Problem

Command success is not proof that the requested state was actually achieved.

## Required behavior

### START / RESTART

Verify:

```text
verified Tor process exists
+
expected UID
+
trusted executable
+
listener health
```

### STOP

After a bounded wait, verify:

```text
no verified Tor process remains
```

### ENABLE

Verify:

```text
is-enabled → enabled
```

### DISABLE

Verify:

```text
is-enabled → disabled
```

### Unknown

Return explicit UNKNOWN.

## Required tests

Simulate command exit 0 with incorrect resulting state.

The function must report failure/unknown rather than success.

---

# 9. P1 — `tor.real` process identity bypasses trusted-binary integrity checking

## Location

`nulltrace.py`

Function:

```text
_verify_process_is_tor()
```

## Current behavior

The process executable is accepted if its path resembles:

```text
/usr/bin/tor
/usr/bin/tor.real
```

But when the process is:

```text
/usr/bin/tor.real
```

the code does not necessarily call the full trusted-binary validation on `tor.real`.

## Risk

If a non-root-writable `tor.real` existed in a trusted-looking location, the process could pass the path-string check without the same file-integrity validation applied to the primary `tor` executable.

## Required implementation

Resolve and validate the actual executable target.

Accept only when:

```text
actual /proc/<pid>/exe target
    ==
validated trusted Tor executable target
```

If `tor` is a symlink to `tor.real`, resolve the actual target and validate:

- regular file;
- root-owned;
- not group-writable;
- not world-writable;
- trusted-directory containment.

Do not use a string-only special case for `tor.real`.

## Required tests

- valid root-owned `/usr/bin/tor.real` → accepted;
- group-writable `tor.real` → rejected;
- world-writable `tor.real` → rejected;
- non-root-owned `tor.real` → rejected;
- `/tmp/tor.real` → rejected.

---

# 10. P1 — Tor configuration restoration still has silent-failure paths

## Location

`nulltrace.py`

Function:

```text
restore_tor_config()
```

## Problems

### Case A — originally existed, backup missing

If the baseline says:

```text
tor_config_existed = True
```

but:

```text
torrc.bak
```

is missing, restoration can still proceed.

That must be a restoration failure.

### Case B — originally absent, removal fails

Current code can do:

```python
try:
    path.unlink()
except OSError:
    pass
```

then mark:

```text
_tor_file_restored = True
```

This is incorrect.

### Required implementation

If baseline says original config existed:

```text
missing required backup
→ RESTORE_FAILED
```

If baseline says original config did not exist:

```text
NullTrace-created file cannot be removed
→ RESTORE_FAILED
```

Every restoration success flag must represent verified success.

---

# 11. P1/P2 — Production code contains a test-framework-specific `MagicMock` reference

## Location

`nulltrace.py`

Inside:

```text
validate_tor_config_target()
```

there is production logic similar to:

```python
isinstance(p_st, MagicMock)
```

without a proper production import/justification.

The exception is broadly swallowed.

## Why this is a problem

Production code should not have branches that exist solely to make unit-test mocks work.

It can also produce:

```text
NameError
```

that is then hidden by:

```text
except Exception:
    pass
```

## Required implementation

Remove all `MagicMock` references from production source.

Modify tests to mock the proper boundary or use real fixtures.

---

# 12. P1/P2 — MAC randomization must use the baseline interface, not re-discover it

## Location

`nulltrace.py`

Functions:

```text
setup_network_rules()
_randomize_mac()
```

## Current problem

Startup first captures:

```text
self._spoofed_intf
self._original_mac
self._interface_initially_up
```

but `_randomize_mac()` then calls:

```text
_get_primary_interface()
```

again.

## Failure scenario

```text
baseline interface = eth0
        ↓
routing state changes
        ↓
_get_primary_interface() now returns eth1
        ↓
MAC randomization acts on eth1
        ↓
restore attempts to reconcile with eth0 baseline
```

## Required implementation

Once baseline interface is captured:

```text
self._spoofed_intf
```

must be authoritative.

`_randomize_mac()` should use that interface.

If the baseline interface is unavailable:

```text
fail safely
```

Do not silently choose another interface.

## Required tests

- route changes between baseline and randomization;
- baseline interface disappears;
- multiple default routes;
- VPN/tunnel is primary route.

---

# 13. P2 — MAC restoration must verify administrative state, not only MAC

## Location

`nulltrace.py`

Function:

```text
_restore_mac()
```

Current logic verifies MAC only when a current MAC value is successfully read.

If:

```text
_read_current_mac() → None
```

the restoration can still proceed without proof.

Similarly, administrative UP/DOWN state is not always post-verified.

## Required implementation

After restoration require:

```text
MAC == expected original MAC
AND
UP/DOWN == expected original state
```

If either value cannot be verified:

```text
RESTORE_FAILED
```

Do not mark `_mac_restored = True`.

---

# 14. P2 — Interface state detection fallback should use administrative flags consistently

## Location

`nulltrace.py`

Function:

```text
_is_interface_up()
```

The current primary mechanism checks `/sys/class/net/<iface>/flags`, which is appropriate.

The `operstate` fallback is not equivalent to administrative UP/DOWN in all cases.

## Required implementation

Prefer:

```text
IFF_UP
```

from `/sys/.../flags` or a reliable `ip link` flag parse.

Use `operstate` only as a clearly documented fallback and never confuse operational carrier state with administrative state.

---

# 15. P2 — DHCP renewal must have bounded execution and explicit result handling

## Location

`nulltrace.py`

Functions:

```text
_renew_dhcp()
_randomize_mac()
_restore_mac()
```

## Current issue

DHCP commands are run with:

```text
check=False
```

and without a timeout.

A DHCP client can block or fail silently.

## Effects

This can:

```text
hang MAC randomization
break connectivity
produce apparent success despite failed renewal
```

## Required implementation

Use bounded execution:

```text
timeout = defined value
```

Capture result.

At minimum:

```text
renewal failed
→ explicit warning
→ connectivity check
```

For a security-critical state transition, consider making MAC randomization fail if network recovery cannot be established.

Do not allow an indefinitely blocking DHCP command.

---

# 16. P2 — DNS “leak test” does not actually test for an external DNS leak

## Location

`nulltrace.py`

Function:

```text
run_dns_leak_test()
```

## Current behavior

The command mainly checks:

```text
resolv.conf
+
Tor DNSPort ownership
+
DNS response packet exists
```

That does not prove that actual system DNS traffic is unable to leave directly.

## Required implementation

Rename the function/documentation if it is only a configuration/health check.

OR implement a genuine leak test:

```text
generate actual DNS request
verify expected interception path
verify no direct resolver route
```

For production privacy claims, the documentation should clearly distinguish:

```text
DNS configuration/health check
```

from:

```text
actual DNS leak test
```

---

# 17. P2 — DNS probe should validate DNS response semantics, not only “response bit”

## Location

`nulltrace.py`

Function:

```text
_probe_dns_port()
```

## Current logic

Checks primarily:

```text
transaction ID
QR=response
```

A malformed/error response can still satisfy that.

## Required implementation

Parse at least:

```text
transaction ID
QR bit
RCODE
```

For a normal health query, require appropriate success:

```text
RCODE = NOERROR
```

Optionally validate that an answer exists for the chosen test name.

Avoid making health depend on one arbitrary external domain unless intended.

---

# 18. P2 — Tor control cookie should be validated before use

## Location

`nulltrace.py`

Function:

```text
_tor_control_newnym()
```

Current behavior selects the first existing cookie path and reads it.

## Required validation

Before reading:

- regular file;
- not symlink;
- expected owner;
- not group-writable;
- not world-writable;
- sensible restrictive mode.

Then authenticate against the control port.

Also parse the Tor protocol response as a real status code rather than:

```python
b"250" in response
```

## Required tests

- symlink cookie → reject;
- wrong owner → reject;
- group writable → reject;
- malformed auth response → reject;
- exact 250 response → accept.

---

# 19. P2 — Session/runtime directory creation and lock-file handling need consistent hardened creation

## Locations

`nulltrace.py`

Relevant:

```text
_ensure_runtime_dirs()
_validate_secure_directory()
_session_dir()
_acquire_lock()
```

## Problems

Some paths still use:

```text
mkdir(parents=True, exist_ok=True)
open(lock_path, "w")
```

before/without fully FD-bound security guarantees.

## Required implementation

For:

```text
/var/lib/nulltrace
/run/nulltrace
session_<id>
nulltrace.lock
```

ensure:

- root ownership;
- expected restrictive mode;
- regular directory/file type;
- no symlink;
- safe parent;
- atomic/hardened creation where privileged.

Create the lock with no-follow semantics if practical.

---

# 20. P2 — Secure helper should reject traversal and avoid pre-validation side effects

## Locations

```text
nulltrace.py
install.py
```

Functions:

```text
secure_open_dir_hierarchy()
atomic_write()
secure_deploy_file()
```

The helper now rejects:

```text
.
..
```

which is good.

But `atomic_write()` can still do:

```python
parent_path.mkdir(parents=True, exist_ok=True)
```

before securely opening the hierarchy.

## Problem

An unsafe symlinked ancestor can cause a privileged mkdir to create directories at an unintended location before the later secure traversal rejects the final write.

The final file write remains protected, but an unwanted privileged side effect can occur.

## Preferred implementation

For security-sensitive destinations:

```text
securely open/create each directory component
```

or:

```text
require destination hierarchy to already exist
```

Avoid `mkdir(parents=True)` through an unvalidated pathname.

---

# 21. P2 — Trusted binary validation should validate the trusted directory hierarchy

## Location

```text
resolve_trusted_binary()
```

in:

```text
nulltrace.py
install.py
```

The binary itself is now checked well.

For a hardened root tool, also validate the relevant directory hierarchy:

```text
/usr
/usr/bin
/usr/sbin
/bin
/sbin
```

where practical:

- root-owned;
- not group/world writable;
- not symlinked unexpectedly.

This is defense in depth. A writable trusted directory defeats executable trust.

---

# 22. P2 — Privileged installer source should have explicit trust assumptions

## Location

`install.py`

The installer does:

```text
source = Path(__file__).resolve().parent / "nulltrace.py"
```

then installs that source as root.

## Required design

Document that:

> Running `sudo install.py` means the administrator is explicitly trusting the source tree.

For higher-assurance installation:

- verify source is regular;
- reject source symlink if desired;
- verify source is owned by expected user/root;
- provide an optional checksum/signature mechanism.

Do not claim the installer authenticates the application source unless it actually does.

---

# 23. P2 — Remove unsafe Python fallback in privileged installer logic

## Location

`install.py`

Examples:

```python
resolve_trusted_binary("python3") or "/usr/bin/python3"
```

and:

```python
resolve_trusted_binary("python3") or "python3"
```

The second path is passed back through `run_trusted()`, so the current risk is limited, but the logic is inconsistent with the trusted-executable model.

## Required implementation

Use:

```text
require_trusted_binary("python3")
```

for privileged recovery/install execution.

No unvalidated fallback path.

---

# 24. P2 — Installer purge path trusts `SUDO_USER` as a filesystem path

## Location

`install.py`

Current behavior:

```python
cfg_dirs.append(Path(f"/home/{sudo_user}") / ".config" / "nulltrace")
```

## Problem

This treats `SUDO_USER` as a path fragment without validating that it is a valid local username.

A hostile/malformed environment could contain traversal characters.

Under normal sudo operation `SUDO_USER` is populated by sudo and is not normally attacker-controlled, so this is not equivalent to the earlier root-write P0. Treat it as privileged-input hardening.

## Required implementation

Use the system account database:

```text
pwd.getpwnam(SUDO_USER)
```

and only use the returned canonical home directory.

If username lookup fails:

```text
do not construct /home/<value>
```

---

# 25. P2 — Historical session scanning in the installer can make uninstall think NullTrace is active forever

## Location

`install.py`

Function:

```text
routing_may_be_active()
```

## Current behavior

It scans:

```text
/var/lib/nulltrace/session_*/metadata.json
```

and treats any recoverable historical session as evidence that routing may be active.

## Failure scenario

```text
old RESTORE_FAILED session
+
current system clean
=
uninstall attempts recovery anyway
```

This can make uninstall unnecessarily refuse to proceed.

## Required implementation

Tie uninstall to the authoritative current session/state.

Historical failed sessions should not automatically make a clean current system appear active.

---

# 26. P2 — `inspect_live_nulltrace_rules()` is overly broad

## Location

`install.py`

Function:

```text
inspect_live_nulltrace_rules()
```

It searches for:

```text
"NULLTRACE" in line
```

This can match unrelated administrator rules/chains whose names merely contain the string.

## Required implementation

Parse exact NullTrace-owned identifiers and/or exact ownership markers.

Distinguish:

```text
actual NullTrace chain/jump
```

from:

```text
unrelated chain containing "NULLTRACE"
```

This reduces false recovery/uninstall decisions.

---

# 27. P2 — Ownership marker parsing should be exact

## Locations

```text
_authenticate_or_create_chain()
_destroy_authenticated_chain()
_check_live_firewall_status()
```

Current authentication uses substring logic around:

```text
nulltrace-owned
```

## Required implementation

Parse the actual comment rule exactly.

For example require something equivalent to:

```text
-A <CHAIN> -m comment --comment nulltrace-owned
```

or a stronger session-bound marker.

Do not accept arbitrary lines containing the substring:

```text
nulltrace-owned
```

### Stronger option

Use a session-bound marker:

```text
nulltrace-owned:<session-id>
```

if compatible with the firewall-rule representation.

This is not cryptographic ownership against root/CAP_NET_ADMIN, but it significantly improves accidental collision handling.

---

# 28. P2 — Exact Tor systemd state should be preserved, not reduced to only enabled/disabled

## Location

`_check_tor_service_enabled()`

The current tristate improvement is good, but the original systemd state can distinguish:

```text
enabled
disabled
masked
masked-runtime
static
indirect
generated
enabled-runtime
```

Flattening all non-enabled cases to FALSE loses information.

## Required implementation

Use a richer state where restoration requires exact recovery, for example:

```text
ENABLED
DISABLED
MASKED
MASKED_RUNTIME
STATIC
INDIRECT
UNKNOWN
```

At minimum:

- don't call `disable` to restore a state that was actually `masked`;
- don't claim exact restoration when only a broad state category was captured.

---

# 29. P2 — When original Tor service was ENABLED, verify it remains ENABLED after restoration

## Location

`restore_tor_config()`

Current code explicitly disables only when:

```text
initially_enabled == False
```

It does not explicitly verify/restore:

```text
initially_enabled == True
```

## Required implementation

After restoration:

```text
initially enabled
→ verify still enabled
```

If it became disabled during the session:

```text
restore enabled
```

subject to the documented administrator-change policy.

This closes the symmetry gap.

---

# 30. P2 — Tor configuration file metadata beyond mode/UID/GID is not preserved

## Location

`atomic_write()`
`restore_tor_config()`

Replacing a file can discard:

- POSIX ACLs;
- extended attributes;
- SELinux/AppArmor-related metadata where applicable;
- other filesystem metadata.

Mode/UID/GID preservation is not equivalent to full metadata preservation.

## Required action

At minimum:

- document the limitation;
- test on distributions using additional security metadata.

For environments where this matters, preserve/restore supported ACL/xattr state or invoke a safe relabeling mechanism appropriate to the platform.

Do not silently claim full metadata preservation when only mode/ownership are preserved.

---

# 31. P2 — Tor config readability should be validated

## Location

`validate_tor_config_target()`

A root-owned file can still be too restrictive for the Tor daemon.

Example:

```text
0600 root:root
```

may prevent a non-root Tor daemon from reading the file depending on the service model.

## Required implementation

Determine the expected Tor service user.

Ensure the resulting torrc is readable by the required daemon identity while still satisfying the security model.

Alternatively reject configurations whose permissions make Tor startup impossible.

Add an integration test with the actual Tor service user.

---

# 32. P2 — Restore should verify Tor config actually matches the intended baseline

## Location

`restore_tor_config()`

Current logic can mark:

```text
_tor_file_restored = True
```

without verifying final file content.

## Required implementation

After restoration:

- calculate the resulting content hash;
- verify expected baseline semantics;
- verify absence of NullTrace managed block;
- verify original existence state;
- verify required metadata.

For originally absent file:

```text
file absent after restore
```

must be verified.

For originally present:

```text
managed block gone
+
baseline/admin-preservation policy satisfied
```

must be verified.

---

# 33. P2 — State/metadata persistence is not a single transaction

## Location

```text
_persist_session_metadata()
_set_state()
_write_state()
```

Current sequence writes:

```text
manifest.json
metadata.json
state.json
runtime state.json
```

as several separate operations.

A crash between them can produce:

```text
metadata says PREPARING
state says old state
manifest exists
```

or the reverse.

## Required implementation

Use an explicit persistence protocol:

```text
write complete new record
fsync
commit marker / generation
fsync
publish authoritative pointer
```

or clearly define one authoritative source and make readers reject inconsistent generations.

At minimum include:

```text
state generation / revision number
session ID
baseline revision
```

and validate cross-file consistency during recovery.

---

# 34. P2 — Recovery should not use a new random session ID when the existing recovery identity cannot be established

## Location

`stop_privacy_mode()`
`_load_session_metadata()`
`_session_dir()`

If recovery cannot load the original session, the object may still contain its newly generated constructor session ID.

Continuing with that session identity can make the tool look for backups that never existed.

## Required implementation

For recovery operations:

```text
no authoritative session
→ no automatic restoration from guessed/new session
→ RECOVERY_REQUIRED
```

Do not construct:

```text
session_<new-random-id>
```

and then treat it as if it were the active session.

---

# 35. P2 — Firewall drift after activation is detected only when checked

## Design limitation

An external component can insert a rule before NullTrace after activation:

```text
administrator/firewalld/UFW/Docker/etc.
        ↓
new ACCEPT rule before NullTrace jump
        ↓
NullTrace enforcement bypassed
```

The tool's verifier can detect this later, but it does not continuously enforce priority 1.

## Required action

Choose one:

### Option A

Add a watchdog/periodic integrity monitor.

### Option B

Integrate with the firewall backend in a way that preserves rule ordering.

### Option C

Document the external-firewall limitation clearly and expose a reliable health check.

At minimum:

```text
ACTIVE
```

must not be treated as permanently true after the initial verification.

The user-facing status should be able to report:

```text
ENFORCEMENT_DRIFT
```

or:

```text
RECOVERY_REQUIRED
```

when the live rules no longer match the manifest.

---

# 36. P2 — Startup privacy boundary should be explicit

Current startup is staged:

```text
capture baseline
↓
backup
↓
modify Tor
↓
build firewall chains
↓
insert jumps
↓
verify
↓
ACTIVE
```

There is necessarily a short period before the final priority-1 firewall jumps are active.

## Required action

Document the guarantee as:

> Traffic is protected once NullTrace reaches verified ACTIVE state.

Do not imply:

> No packet can leave directly from the instant startup begins.

For stronger protection, consider a temporary fail-closed barrier before modifying Tor/network state.

---

# 37. P2 — Firewall health verification should validate all security-critical rule semantics

The manifest is now good, but keep the semantic checks strong.

For the NAT chain:

Verify exact expected semantics for:

- Tor UID bypass;
- UDP/53 redirect;
- TCP/53 handling;
- configured exclusions;
- TCP redirect to TransPort.

For filter OUTPUT:

Verify:

- Tor UID handling;
- explicit exclusions;
- DNS TCP rejection;
- UDP drop;
- ICMP drop;
- final catch-all DROP.

For filter INPUT:

Verify:

- loopback;
- marked Tor return traffic;
- DHCP;
- exclusions;
- final DROP.

For IPv6:

Verify:

- loopback;
- required ICMPv6 neighbor traffic;
- Tor process handling;
- final REJECT/DROP.

The manifest should catch drift, while semantic checks should explain why the state is invalid.

---

# 38. P2 — Validate configured exclusions against privacy policy

## Location

`validate_network_config()`

A user can configure a very broad exclusion such as:

```text
0.0.0.0/0
```

which effectively bypasses IPv4 Tor enforcement.

This may be intentionally supported, but it defeats the default privacy guarantee.

## Required action

Choose a policy:

### Preferred

Reject full-route exclusions.

### Alternative

Allow but require an explicit confirmation/warning:

```text
WARNING: this exclusion bypasses NullTrace protection for all IPv4 destinations.
```

Also test:

- `/0`;
- large supernets;
- overlapping exclusions.

---

# 39. P2 — Validate port relationships before modifying Tor configuration

## Location

`validate_network_config()`

Current validation checks ranges but should also reject unsafe combinations such as:

```text
tor_port == dns_port
tor_port == control_port
dns_port == control_port
```

The control port is currently fixed to:

```text
9051
```

## Required action

Validate that all NullTrace-owned Tor ports are distinct.

Also consider rejecting privileged ports where the configured Tor daemon user cannot bind them.

Do this before any system mutation.

---

# 40. P2 — `_renew_dhcp()` should not be required for every environment

The current code assumes a DHCP-oriented recovery path.

Some systems use:

```text
NetworkManager
systemd-networkd
static addressing
VPNs
containers
bridges
```

## Required behavior

Detect supported network manager.

If no DHCP-capable mechanism exists:

```text
MAC change succeeds
→ do not falsely claim DHCP renewal
→ perform connectivity verification
```

Don't block an otherwise valid MAC operation solely because `dhclient` is absent.

---

# 41. P2 — WSL versus full Linux integration must remain explicit

Kali WSL is the correct primary development environment for:

- `/proc`;
- Linux permissions;
- filesystem operations;
- Python Linux APIs;
- iptables-nft command behavior where supported.

But WSL is not necessarily equivalent to a production Linux host for:

- systemd lifecycle;
- firewall/network namespace behavior;
- interface manipulation;
- Tor daemon integration.

## Required validation

### Kali WSL

Must pass:

```text
full automated suite
filesystem tests
process tests
iptables command tests
```

### Real Linux VM

Recommended for final acceptance:

```text
systemd + Tor
iptables/ip6tables
real interface
real routing
real DNS
start/stop/recovery
```

Do not describe WSL unit tests as full end-to-end production validation.

---

# 42. Required adversarial integration tests

The agent must attempt the following on Linux where feasible.

## Filesystem

### Attack 1 — destination symlink

```text
target → attacker file
```

Expected:

```text
write rejected
attacker file unchanged
```

### Attack 2 — intermediate symlink

```text
secure/a → attacker-controlled directory
```

Expected:

```text
write rejected
no privileged side effect outside intended tree
```

### Attack 3 — directory replacement

Replace an intermediate directory while write is underway.

Expected:

```text
no escape from validated directory FD
```

### Attack 4 — destination replacement with non-regular file

FIFO/socket/device.

Expected:

```text
rejected
```

---

# 43. Required firewall adversarial tests

## Unowned same-name chain

```text
NULLTRACE_OUTPUT
```

without marker.

Expected:

```text
no flush
no delete
no jump deletion
```

## Ambiguous chain inspection

```text
iptables -S
rc=1
stderr=""
```

Expected:

```text
inspection error
```

## External rule inserted above NullTrace

Expected:

```text
live verification detects drift
```

## Duplicate NullTrace jump

Expected:

```text
PARTIAL
```

## Conditional NullTrace jump

Expected:

```text
PARTIAL
```

---

# 44. Required Tor-service adversarial tests

## Fake Tor process

```text
Name = tor
UID = expected
exe = /tmp/fake
```

Expected:

```text
rejected
```

## Fake `tor.real`

Expected:

```text
rejected unless actual executable target passes full trusted-binary validation
```

## Service command exits 0 but Tor not running

Expected:

```text
NOT ACTIVE / FAILURE
```

## Service stop exits 0 but process remains

Expected:

```text
STOP FAILURE
```

## Restart exits 0 but ports unavailable

Expected:

```text
RESTART FAILURE
```

---

# 45. Required recovery corruption tests

Test:

```text
metadata missing
metadata corrupt
manifest missing
manifest corrupt
state.json missing
state.json corrupt
session directory missing
backup missing
session IDs disagree
metadata session ID disagrees with directory
manifest session ID disagrees with metadata
```

Expected:

```text
RECOVERY_REQUIRED / RESTORE_FAILED
```

Never:

```text
ACTIVE
INACTIVE
successful restoration
```

based on invented defaults.

---

# 46. Required administrator-change tests

Test:

```text
admin edits torrc during active session
admin deletes torrc during active session
admin enables Tor during active session
admin disables Tor during active session
admin changes firewall during active session
admin creates same-name chain
admin inserts firewall rule above NullTrace
```

The project must have one explicit documented policy:

### Policy A — baseline restoration

Always restore the captured baseline.

OR:

### Policy B — change-aware restoration

Preserve detected administrator changes.

Whichever policy is chosen must be:

- documented;
- tested;
- consistent across all restoration paths.

---

# 47. Required config tests

Test:

```text
tor_port == dns_port
tor_port == 9051
dns_port == 9051
dns_port == 53
tor_port == 53
excluded 0.0.0.0/0
overlapping exclusions
invalid CIDR
IPv6 exclusion
invalid exit country
path traversal
config symlink
group-writable torrc
world-writable torrc
non-root-owned torrc
unreadable torrc
```

---

# 48. Required installer tests

Test:

```text
/usr/share/nulltrace is symlink
/usr/share/nulltrace is file
/usr/share/nulltrace group writable
/usr/share/nulltrace world writable
nulltrace.py destination is symlink
/usr/bin/nulltrace destination is symlink
source file is symlink
source file is not regular
python3 trusted validation fails
SUDO_USER malformed
purge path traversal attempt
```

No test should require weakening the production validation.

---

# 49. Required quality cleanup

The agent should also clean up:

- duplicated/obsolete comments;
- contradictory issue labels from old iterations;
- stale “atomic/transactional” terminology;
- test-specific production branches;
- broad `except Exception: pass` where security state is affected;
- inconsistent `return False` vs UNKNOWN semantics;
- unused legacy helpers;
- dead compatibility paths where Linux is the actual supported platform.

The production code should make the security state machine understandable.

---

# 50. Recommended code architecture changes

This project has accumulated many patches. To prevent another iteration from fixing one branch while leaving another inconsistent, consolidate repeated security logic.

Create shared primitives for:

```text
TrustedExecutable
SecureDirectory
SecureFileWrite
SessionRecord
BaselineRecord
ServiceState
FirewallOwnership
FirewallVerification
```

Especially consolidate:

```text
Tor active state detection
Tor service control
session metadata validation
firewall chain ownership
safe path traversal
trusted executable validation
```

Avoid multiple slightly different implementations.

---

# 51. Definition of Done — hard release gate

Do not declare the project complete until every item below is true.

## Critical security

- [ ] No privileged Linux write uses unsafe pathname replacement.
- [ ] No privileged file operation relies on TOCTOU-prone validation followed by an unbound pathname.
- [ ] Trusted Tor executable identity validates the actual `/proc/<pid>/exe` target.
- [ ] Unowned firewall chains are never modified.
- [ ] Unowned same-name firewall jumps are never removed.
- [ ] Ambiguous firewall command failures never become “chain absent.”
- [ ] Missing/corrupt recovery records never produce fabricated baseline state.
- [ ] Unknown Tor/service/interface state is never converted into a definitive false/true state.

## Lifecycle correctness

- [ ] Tor active state supports ACTIVE/INACTIVE/UNKNOWN.
- [ ] Tor enabled state supports UNKNOWN and exact restoration semantics.
- [ ] Service control commands have post-condition verification.
- [ ] Restoration failures are recorded accurately.
- [ ] Original torrc existence is verified after restoration.
- [ ] Original Tor service state is verified after restoration.
- [ ] Original interface state is verified after restoration.
- [ ] MAC restoration verifies MAC and interface state.
- [ ] Baseline interface is authoritative for MAC randomization.
- [ ] Recovery never binds itself to a fabricated/random session when the real session cannot be established.

## Session/recovery integrity

- [ ] Only the authoritative current session is automatically recovered.
- [ ] Stale historical failed sessions cannot hijack normal start/stop.
- [ ] Session directory, metadata, manifest and state IDs agree.
- [ ] Corrupt/incomplete metadata causes recovery failure.
- [ ] Persistence consistency is explicitly handled.

## Installer

- [ ] Installation destinations are symlink-safe.
- [ ] Installation directories are root-owned and non-writable.
- [ ] Privileged temporary launcher creation is secure.
- [ ] Recovery execution uses only validated trusted binaries.
- [ ] Uninstaller purge paths do not trust raw `SUDO_USER`.
- [ ] Historical stale sessions cannot falsely block uninstall.

## Privacy behavior

- [ ] Actual firewall/Tor traffic path validated on Linux.
- [ ] IPv4 routing validated.
- [ ] IPv6 fail-closed behavior validated.
- [ ] DNS interception validated.
- [ ] DNS documentation accurately describes what is tested.
- [ ] Broad exclusions are handled explicitly.
- [ ] Startup privacy boundary is documented.

## Testing

- [ ] All automated tests pass on Kali WSL.
- [ ] Tests exercise real Linux filesystem semantics where possible.
- [ ] Adversarial symlink/race tests exist.
- [ ] Firewall adversarial tests exist.
- [ ] Service-state adversarial tests exist.
- [ ] Recovery-corruption tests exist.
- [ ] Administrator-change tests exist.
- [ ] A real privileged Linux integration workflow has been executed.
- [ ] A Linux VM integration run is performed if WSL cannot exercise the required networking/systemd behavior.

---

# 52. Final required test/report format from the agent

The final response must contain:

```text
Environment
-----------
OS:
Kernel:
Python:
iptables:
ip6tables:
systemd:
Tor:

Automated tests
---------------
Unit:
Security regression:
Integration:
Total:
Passed:
Failed:
Errors:

Linux integration
-----------------
Start:
Tor process:
Tor listener:
Firewall:
IPv4 routing:
IPv6:
DNS:
MAC:
Stop:
Restoration:

Remediation
-----------
Issue ID:
File:
Function:
Implemented change:
Security invariant:
Regression test:

Repeat for every issue fixed.

Known limitations
-----------------
<only genuine remaining limitations>

Final assessment
----------------
<evidence-based result>
```

Do not claim:

```text
all issues fixed
```

unless every applicable checkbox above has been verified.

Do not claim:

```text
196 integration tests
```

when the tests are actually mocked unit/regression tests.

Use:

```text
Linux-targeted automated regression tests
```

for mocked tests, and reserve:

```text
integration test
```

for actual system interaction.

---

# 53. Final engineering instruction

This is a security-sensitive privileged Linux application.

The objective is not simply:

```text
pytest = green
```

The objective is:

```text
secure design
+
correct state machine
+
safe recovery
+
verified firewall ownership
+
verified Tor identity
+
safe privileged filesystem operations
+
real Linux integration
```

The next implementation pass should prioritize the P1 items in this document first.

After fixing them, run the complete automated suite and the adversarial Linux integration tests.

Only after those pass should the P2 hardening items be finalized.

**Do not start another broad refactor without keeping the release invariants above intact.**
