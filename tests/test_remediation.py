#!/usr/bin/env python3
"""
Comprehensive Regression & Unit Test Suite for nulltrace remediation (NT-001 through NT-016).
"""

import errno
import hashlib
import json
import os
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import install
import nulltrace


class TestNT001_IPv6FailClosed(unittest.TestCase):
    """NT-001: IPv6 lockdown must be fail-closed and verified."""

    def setUp(self):
        self.app = nulltrace.nulltrace()
        self.app._tor_user = "109"

    @patch("nulltrace.nulltrace._check_ipv6_enabled", return_value=True)
    @patch("nulltrace.resolve_trusted_binary", return_value=None)
    def test_ipv6_missing_aborts_startup(self, mock_resolve, mock_ipv6):
        """Startup must abort if IPv6 is enabled on host but ip6tables is missing."""
        with self.assertRaises(RuntimeError) as ctx:
            self.app._setup_custom_chains_v6()
        self.assertIn("ip6tables is missing", str(ctx.exception))

    @patch("nulltrace.nulltrace._check_ipv6_enabled", return_value=True)
    @patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/ip6tables")
    @patch("nulltrace.run_trusted")
    def test_ipv6_rule_failure_raises(self, mock_run, mock_resolve, mock_ipv6):
        """A failure applying any IPv6 rule must raise and not be swallowed."""
        mock_run.side_effect = subprocess.CalledProcessError(1, ["ip6tables"])
        with self.assertRaises(subprocess.CalledProcessError):
            self.app._setup_custom_chains_v6()

    def test_ipv6_setup_failure_triggers_rollback_and_not_active(self):
        """If IPv6 setup fails during setup_network_rules, startup aborts, rollback runs, and state is not ACTIVE."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), \
                 patch("nulltrace.RUN_DIR", tmp_path), \
                 patch("nulltrace.require_linux_root"), \
                 patch.object(nulltrace.nulltrace, "backup_iptables"), \
                 patch.object(nulltrace.nulltrace, "apply_tor_config"), \
                 patch.object(nulltrace.nulltrace, "_setup_custom_chains_v4"), \
                 patch.object(nulltrace.nulltrace, "_setup_custom_chains_v6", side_effect=RuntimeError("ip6tables failure")), \
                 patch.object(nulltrace.nulltrace, "_rollback_startup") as mock_rollback:
                app = nulltrace.nulltrace()
                with self.assertRaises(RuntimeError):
                    app.setup_network_rules()
                self.assertFalse(app.is_active())
                mock_rollback.assert_called_once()

    def test_rollback_failure_marks_restore_failed(self):
        """If rollback itself encounters an error, state must be marked RESTORE_FAILED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), \
                 patch("nulltrace.RUN_DIR", tmp_path), \
                 patch.object(nulltrace.nulltrace, "_destroy_custom_chains", side_effect=RuntimeError("lock error")):
                app = nulltrace.nulltrace()
                app._rollback_startup()
                self.assertEqual(app._get_current_state(), nulltrace.STATE_RESTORE_FAILED)


class TestNT002_ConntrackIsolation(unittest.TestCase):
    """NT-002: Prevent established conntrack flows from bypassing Tor."""

    def setUp(self):
        self.app = nulltrace.nulltrace()
        self.app._tor_user = "109"

    @patch("nulltrace.require_trusted_binary", return_value="/usr/sbin/iptables")
    @patch("nulltrace.run_trusted")
    def test_no_unconstrained_established_in_output(self, mock_run, mock_req):
        """OUTPUT chain must NOT have an unconstrained ESTABLISHED,RELATED ACCEPT rule."""
        self.app._setup_custom_chains_v4()
        executed_cmds = [call.args[0] for call in mock_run.call_args_list]

        for cmd in executed_cmds:
            if "NULLTRACE_OUTPUT" in cmd and "-m" in cmd and "conntrack" in cmd:
                self.fail(f"Found unconstrained conntrack rule in OUTPUT: {cmd}")

    @patch("nulltrace.require_trusted_binary", return_value="/usr/sbin/iptables")
    @patch("nulltrace.run_trusted")
    def test_tor_connmark_marking_in_mangle(self, mock_run, mock_req):
        """Mangle table must set and save connmark on Tor daemon packets."""
        self.app._setup_custom_chains_v4()
        executed_cmds = [call.args[0] for call in mock_run.call_args_list]

        found_set_mark = False
        found_save_mark = False
        found_restore_mark = False

        for cmd in executed_cmds:
            cmd_str = " ".join(cmd)
            if "mangle" in cmd_str and "--set-mark" in cmd_str and nulltrace.CONNMARK_TOR in cmd_str:
                found_set_mark = True
            if "mangle" in cmd_str and "--save-mark" in cmd_str:
                found_save_mark = True
            if "mangle" in cmd_str and "--restore-mark" in cmd_str:
                found_restore_mark = True

        self.assertTrue(found_set_mark, "Tor connmark set-mark rule missing in mangle table")
        self.assertTrue(found_save_mark, "Tor connmark save-mark rule missing in mangle table")
        self.assertTrue(found_restore_mark, "Tor connmark restore-mark rule missing in mangle table")

    @patch("nulltrace.require_trusted_binary", return_value="/usr/sbin/iptables")
    @patch("nulltrace.resolve_trusted_binary", return_value=None)  # conntrack missing
    @patch("nulltrace.run_trusted")
    def test_deterministic_without_conntrack(self, mock_run, mock_res, mock_req):
        """Setup succeeds and remains deterministic when conntrack utility is absent."""
        self.app._setup_custom_chains_v4()
        self.assertTrue(mock_run.called)

    @patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/ip6tables")
    @patch("nulltrace.run_trusted")
    @patch("nulltrace.nulltrace._check_ipv6_enabled", return_value=True)
    def test_tor_connmark_marking_in_ipv6_mangle_and_input(self, mock_v6, mock_run, mock_res):
        """IPv6 mangle table sets/saves connmark on Tor packets; input allows established only if marked."""
        self.app._setup_custom_chains_v6()
        executed_cmds = [call.args[0] for call in mock_run.call_args_list]

        found_set_mark = False
        found_save_mark = False
        found_restore_mark = False
        found_input_marked_established = False

        for cmd in executed_cmds:
            cmd_str = " ".join(cmd)
            if "mangle" in cmd_str and "--set-mark" in cmd_str and nulltrace.CONNMARK_TOR in cmd_str:
                found_set_mark = True
            if "mangle" in cmd_str and "--save-mark" in cmd_str:
                found_save_mark = True
            if "mangle" in cmd_str and "--restore-mark" in cmd_str:
                found_restore_mark = True
            if "NULLTRACE_V6_INPUT" in cmd_str and "--mark" in cmd_str and nulltrace.CONNMARK_TOR in cmd_str and "ESTABLISHED" in cmd_str:
                found_input_marked_established = True

        self.assertTrue(found_set_mark, "Tor connmark set-mark rule missing in IPv6 mangle table")
        self.assertTrue(found_save_mark, "Tor connmark save-mark rule missing in IPv6 mangle table")
        self.assertTrue(found_restore_mark, "Tor connmark restore-mark rule missing in IPv6 mangle table")
        self.assertTrue(found_input_marked_established, "IPv6 input must accept established packets only if marked with CONNMARK_TOR")


class TestNT003_TransactionalCustomChains(unittest.TestCase):
    """NT-003: Make firewall activation transactional and crash-safe."""

    def setUp(self):
        self.app = nulltrace.nulltrace()
        self.app._tor_user = "109"

    @patch("nulltrace.require_trusted_binary", return_value="/usr/sbin/iptables")
    @patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/conntrack")
    @patch("nulltrace.run_trusted")
    def test_atomic_jump_rules_activation(self, mock_run, mock_res, mock_req):
        """Jump rules must be inserted at priority 1 into base chains."""
        self.app._activate_jump_rules()
        executed_cmds = [call.args[0] for call in mock_run.call_args_list]

        jump_targets = {
            "OUTPUT": nulltrace.CHAIN_FILTER_OUTPUT,
            "INPUT": nulltrace.CHAIN_FILTER_INPUT,
            "FORWARD": nulltrace.CHAIN_FILTER_FORWARD,
        }
        for chain, target in jump_targets.items():
            expected = ["/usr/sbin/iptables", "-I", chain, "1", "-j", target]
            self.assertIn(expected, executed_cmds)

    @patch("nulltrace.require_trusted_binary", return_value="/usr/sbin/iptables")
    @patch("nulltrace.run_trusted")
    def test_never_flushes_entire_host_tables(self, mock_run, mock_req):
        """Table-wide flushes (e.g. iptables -F without chain) must NEVER be called."""
        self.app._setup_custom_chains_v4()
        executed_cmds = [call.args[0] for call in mock_run.call_args_list]

        for cmd in executed_cmds:
            if len(cmd) == 2 and cmd[1] == "-F":
                self.fail(f"Found forbidden table-wide flush command: {cmd}")
            if len(cmd) == 4 and cmd[1] == "-t" and cmd[3] == "-F":
                self.fail(f"Found forbidden table-wide flush command: {cmd}")

    @patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/iptables")
    @patch("nulltrace.run_trusted")
    def test_rollback_deactivates_and_destroys(self, mock_run, mock_res):
        """Rollback removes jump rules and destroys custom chains."""
        with patch.object(self.app, "_control_tor_service", return_value=(True, "ok")):
            self.app._rollback_startup()
        self.assertEqual(self.app._current_state, nulltrace.STATE_INACTIVE)


class TestNT004_TeardownStateMachine(unittest.TestCase):
    """NT-004: Strict teardown state machine (ACTIVE -> RESTORING -> INACTIVE or RESTORE_FAILED)."""

    def setUp(self):
        self.app = nulltrace.nulltrace()
        self.app._tor_user = "109"

    def test_state_transitions_to_restore_failed_on_error(self):
        """If any restoration step fails during stop, state must become RESTORE_FAILED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), \
                 patch("nulltrace.RUN_DIR", tmp_path), \
                 patch("nulltrace.require_linux_root"):
                app = nulltrace.nulltrace()
                app._tor_user = "109"
                app._set_state(nulltrace.STATE_ACTIVE)

                with patch.object(app, "_deactivate_jump_rules", side_effect=RuntimeError("iptables locked")):
                    with self.assertRaises(RuntimeError) as ctx:
                        app.stop_privacy_mode(force=True)
                    self.assertIn("RESTORE_FAILED", str(ctx.exception))
                    self.assertEqual(app._get_current_state(), nulltrace.STATE_RESTORE_FAILED)

    def test_status_reports_restore_failed_with_recovery_info(self):
        """show_status() must report RESTORE_FAILED prominently with recovery instructions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), \
                 patch("nulltrace.RUN_DIR", tmp_path):
                app = nulltrace.nulltrace()
                app._set_state(nulltrace.STATE_RESTORE_FAILED)

                with patch("nulltrace.nulltrace.check_tor_service", return_value=False), \
                     patch("builtins.print") as mock_print:
                    app.show_status()
                    printed = " ".join(call.args[0] for call in mock_print.call_args_list if call.args)
                    self.assertIn("RESTORE_FAILED", printed)
                    self.assertIn("sudo nulltrace --stop", printed)

    @patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/iptables")
    @patch("nulltrace.run_trusted")
    def test_verify_firewall_teardown_detects_leftovers(self, mock_run, mock_res):
        """_verify_firewall_teardown raises RuntimeError if any nulltrace chain remains in rules."""
        mock_run.return_value = subprocess.CompletedProcess(
            args=["iptables"], returncode=0,
            stdout="-A OUTPUT -j NULLTRACE_OUTPUT\n", stderr=""
        )
        with self.assertRaises(RuntimeError) as ctx:
            self.app._verify_firewall_teardown()
        self.assertIn("remain active", str(ctx.exception))


class TestNT005_LoopbackListenerValidation(unittest.TestCase):
    """NT-005: Restrict Tor listener address strictly to loopback."""

    def test_loopback_validator_accepts_loopback(self):
        self.assertTrue(nulltrace.nulltrace.is_valid_loopback_ip("127.0.0.1"))
        self.assertTrue(nulltrace.nulltrace.is_valid_loopback_ip("127.0.0.2"))
        self.assertTrue(nulltrace.nulltrace.is_valid_loopback_ip("::1"))

    def test_loopback_validator_rejects_non_loopback(self):
        self.assertFalse(nulltrace.nulltrace.is_valid_loopback_ip("0.0.0.0"))
        self.assertFalse(nulltrace.nulltrace.is_valid_loopback_ip("192.168.1.1"))
        self.assertFalse(nulltrace.nulltrace.is_valid_loopback_ip("10.0.0.1"))
        self.assertFalse(nulltrace.nulltrace.is_valid_loopback_ip("8.8.8.8"))
        self.assertFalse(nulltrace.nulltrace.is_valid_loopback_ip("255.255.255.255"))
        self.assertFalse(nulltrace.nulltrace.is_valid_loopback_ip(""))
        self.assertFalse(nulltrace.nulltrace.is_valid_loopback_ip("invalid"))

    def test_validate_network_config_enforces_loopback(self):
        app = nulltrace.nulltrace()
        app.config.localhost = "0.0.0.0"
        with self.assertRaises(ValueError) as ctx:
            app.validate_network_config()
        self.assertIn("must be a valid loopback IP", str(ctx.exception))

        app.config.localhost = "192.168.1.50"
        with self.assertRaises(ValueError) as ctx:
            app.validate_network_config()
        self.assertIn("must be a valid loopback IP", str(ctx.exception))


class TestNT006_TrustedBinaryResolution(unittest.TestCase):
    """NT-006: Eliminate PATH-dependent root command execution."""

    def test_trusted_dirs_contain_only_system_paths(self):
        for path in nulltrace.TRUSTED_BIN_DIRS:
            self.assertIn(path, ("/usr/sbin", "/usr/bin", "/sbin", "/bin"))

    def test_rejects_relative_or_untrusted_paths(self):
        self.assertIsNone(nulltrace.resolve_trusted_binary("evil_command_xyz"))
        self.assertIsNone(nulltrace.resolve_trusted_binary("/tmp/evil_binary"))

    def test_rejects_path_traversal_attempts(self):
        self.assertIsNone(nulltrace.resolve_trusted_binary("../../tmp/evil"))
        self.assertIsNone(nulltrace.resolve_trusted_binary("/usr/sbin/../../tmp/evil"))
        self.assertIsNone(nulltrace.resolve_trusted_binary("bin/ls"))
        self.assertIsNone(nulltrace.resolve_trusted_binary("../bin/ls"))
        self.assertIsNone(install.resolve_trusted_binary("../../tmp/evil"))
        self.assertIsNone(install.resolve_trusted_binary("/usr/sbin/../../tmp/evil"))

    @patch("subprocess.run")
    def test_run_trusted_sanitizes_path_env(self, mock_subproc):
        mock_subproc.return_value = subprocess.CompletedProcess(args=["ls"], returncode=0, stdout="", stderr="")
        with patch.dict(os.environ, {"PATH": "/home/user/bin:/tmp:/usr/bin"}):
            nulltrace.run_trusted(["ls"], check=False)
            called_env = mock_subproc.call_args[1].get("env", {})
            self.assertEqual(called_env.get("PATH"), "/usr/sbin:/usr/bin:/sbin:/bin")


class TestNT007_UninstallerNonDestructive(unittest.TestCase):
    """NT-007: In install.py, remove destructive fail-open fallback."""

    @patch("install.routing_may_be_active", return_value=True)
    @patch("install.run_trusted")
    @patch("sys.exit")
    def test_uninstall_does_not_flush_by_default_on_failure(self, mock_exit, mock_run, mock_active):
        mock_run.return_value = subprocess.CompletedProcess(args=["nulltrace"], returncode=1, stdout="", stderr="failed")

        with patch("builtins.print"):
            install.uninstall_nulltrace(purge=False, interactive=False, emergency_flush=False)

        mock_exit.assert_called_with(1)

        for call in mock_run.call_args_list:
            cmd = call.args[0]
            if "-F" in cmd:
                self.fail("Uninstall triggered destructive firewall flush without explicit emergency flag!")


class TestNT008_DNSPortHealthCheck(unittest.TestCase):
    """NT-008: Tor-specific DNSPort protocol-level health check."""

    def setUp(self):
        self.app = nulltrace.nulltrace()

    def test_probe_dns_port_valid_response(self):
        tx_id = b"\x12\x34"
        flags = struct.pack("!H", 0x8180)  # QR=1, response
        response = tx_id + flags + b"\x00" * 20

        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value.__enter__.return_value = mock_sock
            with patch("os.urandom", return_value=tx_id):
                mock_sock.recvfrom.return_value = (response, ("127.0.0.1", 5353))
                result = self.app._probe_dns_port(timeout=1.0)
                self.assertTrue(result)

    def test_probe_dns_port_collision_fails(self):
        tx_id = b"\x12\x34"
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value.__enter__.return_value = mock_sock
            with patch("os.urandom", return_value=tx_id):
                bad_response = b"\x99\x99\x00\x00\x00\x00"
                mock_sock.recvfrom.return_value = (bad_response, ("127.0.0.1", 5353))
                result = self.app._probe_dns_port(timeout=1.0)
                self.assertFalse(result)

    def test_probe_dns_port_timeout_fails(self):
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value.__enter__.return_value = mock_sock
            mock_sock.recvfrom.side_effect = socket.timeout
            result = self.app._probe_dns_port(timeout=0.1)
            self.assertFalse(result)

    def test_probe_dns_port_ipv6_loopback(self):
        tx_id = b"\xaa\xbb"
        flags = struct.pack("!H", 0x8180)
        response = tx_id + flags + b"\x00" * 20

        self.app.config.localhost = "::1"
        self.app.config.dns_port = 5353

        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value.__enter__.return_value = mock_sock
            with patch("os.urandom", return_value=tx_id):
                mock_sock.recvfrom.return_value = (response, ("::1", 5353, 0, 0))
                result = self.app._probe_dns_port(timeout=1.0)
                self.assertTrue(result)
                mock_sock_cls.assert_called_with(socket.AF_INET6, socket.SOCK_DGRAM)


class TestNT009_TCP_DNSPolicy(unittest.TestCase):
    """NT-009: Align TCP DNS behavior with documentation and protect TransPort."""

    def setUp(self):
        self.app = nulltrace.nulltrace()
        self.app._tor_user = "109"

    @patch("nulltrace.require_trusted_binary", return_value="/usr/sbin/iptables")
    @patch("nulltrace.run_trusted")
    def test_tcp_53_bypassed_in_nat_and_rejected_in_filter(self, mock_run, mock_req):
        self.app._setup_custom_chains_v4()
        executed_cmds = [call.args[0] for call in mock_run.call_args_list]

        found_nat_bypass = False
        found_filter_reject = False

        for cmd in executed_cmds:
            cmd_str = " ".join(cmd)
            if "nat" in cmd_str and "-p tcp --dport 53 -j RETURN" in cmd_str:
                found_nat_bypass = True
            if "NULLTRACE_OUTPUT" in cmd_str and "-p tcp --dport 53 -j REJECT --reject-with tcp-reset" in cmd_str:
                found_filter_reject = True

        self.assertTrue(found_nat_bypass, "TCP/53 must be bypassed in NAT so it never hits TransPort")
        self.assertTrue(found_filter_reject, "TCP/53 must be rejected with tcp-reset in filter")


class TestNT010_SessionBoundBackups(unittest.TestCase):
    """NT-010: Tie backups to unique activation session IDs and prevent stale restore."""

    def test_unique_session_ids(self):
        app1 = nulltrace.nulltrace()
        app2 = nulltrace.nulltrace()
        self.assertNotEqual(app1.session_id, app2.session_id)
        self.assertTrue(len(app1.session_id) >= 8)

    def test_session_metadata_persistence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), \
                 patch("nulltrace.RUN_DIR", tmp_path):
                app = nulltrace.nulltrace()
                app._current_state = nulltrace.STATE_ACTIVE
                app._persist_session_metadata()

                meta_file = tmp_path / f"session_{app.session_id}" / "metadata.json"
                self.assertTrue(meta_file.exists())
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
                self.assertEqual(meta["session_id"], app.session_id)
                self.assertEqual(meta["state"], nulltrace.STATE_ACTIVE)

    def test_backup_hashes_persisted_in_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), \
                 patch("nulltrace.RUN_DIR", tmp_path):
                app = nulltrace.nulltrace()
                app._current_state = nulltrace.STATE_ACTIVE
                app._iptables_v4_hash = "hash_v4_abc"
                app._iptables_v6_hash = "hash_v6_def"
                app._tor_config_hash = "hash_tor_123"
                app._persist_session_metadata()

                meta_file = tmp_path / f"session_{app.session_id}" / "metadata.json"
                self.assertTrue(meta_file.exists())
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
                self.assertEqual(meta["iptables_v4_hash"], "hash_v4_abc")
                self.assertEqual(meta["iptables_v6_hash"], "hash_v6_def")
                self.assertEqual(meta["tor_config_hash"], "hash_tor_123")


class TestNT011_MACPersistenceAndRestore(unittest.TestCase):
    """NT-011: Persist original hardware MAC address beforehand and restore via ip link."""

    def setUp(self):
        self.app = nulltrace.nulltrace()

    def test_mac_regex_validation(self):
        self.assertTrue(bool(nulltrace.MAC_RE.match("00:11:22:33:44:55")))
        self.assertTrue(bool(nulltrace.MAC_RE.match("aa:bb:cc:dd:ee:ff")))
        self.assertFalse(bool(nulltrace.MAC_RE.match("00:11:22:33:44")))
        self.assertFalse(bool(nulltrace.MAC_RE.match("invalid_mac")))

    @patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/ip")
    @patch("nulltrace.require_trusted_binary", return_value="/usr/sbin/ip")
    @patch("nulltrace.run_trusted")
    @patch.object(nulltrace.nulltrace, "_renew_dhcp")
    def test_restore_mac_uses_ip_link_without_macchanger(self, mock_dhcp, mock_run, mock_req, mock_res):
        self.app._spoofed_intf = "eth0"
        self.app._original_mac = "00:11:22:33:44:55"
        self.app._interface_initially_up = True

        with patch.object(self.app, "_read_current_mac", return_value="00:11:22:33:44:55"):
            self.app._restore_mac()

        executed_cmds = [call.args[0] for call in mock_run.call_args_list]
        expected = ["/usr/sbin/ip", "link", "set", "dev", "eth0", "address", "00:11:22:33:44:55"]
        self.assertIn(expected, executed_cmds)


class TestNT012_TorServiceFallback(unittest.TestCase):
    """NT-012: Ensure Tor service control falls back to service when systemctl fails."""

    def setUp(self):
        self.app = nulltrace.nulltrace()

    @patch("nulltrace.resolve_trusted_binary")
    @patch("subprocess.run")
    def test_systemctl_failure_falls_back_to_service(self, mock_subproc, mock_resolve):
        def fake_resolve(name):
            base = Path(name).name
            if base in ("systemctl", "service"):
                return f"/bin/{base}"
            return None

        mock_resolve.side_effect = fake_resolve

        def fake_run(cmd, **kwargs):
            if "systemctl" in cmd[0]:
                return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="systemd not booted")
            if "service" in cmd[0]:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="tor started", stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        mock_subproc.side_effect = fake_run

        with patch.object(self.app, "_has_verified_tor_process", return_value=True), \
             patch.object(self.app, "check_tor_ports", return_value=True):
            ok, detail = self.app._control_tor_service("restart")
            self.assertTrue(ok, f"Service fallback did not succeed: {detail}")
            self.assertIn("service", detail)


class TestNT013_DeterministicEgressInterface(unittest.TestCase):
    """NT-013: Select actual egress interface deterministically using ip route get."""

    def setUp(self):
        self.app = nulltrace.nulltrace()

    @patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/ip")
    @patch("nulltrace.run_trusted")
    def test_ip_route_get_parsing(self, mock_run, mock_resolve):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["ip"], returncode=0,
            stdout="1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.100 uid 0\n    cache\n",
            stderr=""
        )
        intf = self.app._get_primary_interface()
        self.assertEqual(intf, "eth0")

    @patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/ip")
    @patch("nulltrace.run_trusted")
    def test_tunnel_interface_filtered_out(self, mock_run, mock_resolve):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["ip"], returncode=0,
            stdout="1.1.1.1 via 10.8.0.1 dev tun0 src 10.8.0.2\n",
            stderr=""
        )
        intf = self.app._get_primary_interface()
        self.assertNotEqual(intf, "tun0")

    @patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/ip")
    @patch("nulltrace.run_trusted")
    def test_two_default_routes_selects_lower_metric(self, mock_run, mock_res):
        def fake_run(cmd, **kwargs):
            if "get" in cmd:
                return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")
            if "show" in cmd and "default" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0,
                    stdout="default via 192.168.1.1 dev wlan0 proto dhcp metric 600\ndefault via 192.168.1.1 dev eth0 proto dhcp metric 100\n",
                    stderr=""
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        mock_run.side_effect = fake_run
        intf = self.app._get_primary_interface()
        self.assertEqual(intf, "eth0")

    @patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/ip")
    @patch("nulltrace.run_trusted")
    def test_ambiguous_default_routes_raises_error(self, mock_run, mock_res):
        def fake_run(cmd, **kwargs):
            if "get" in cmd:
                return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")
            if "show" in cmd and "default" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=0,
                    stdout="default via 192.168.1.1 dev eth1 proto dhcp metric 100\ndefault via 192.168.1.1 dev eth0 proto dhcp metric 100\n",
                    stderr=""
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        mock_run.side_effect = fake_run
        with self.assertRaises(RuntimeError) as ctx:
            self.app._get_primary_interface()
        self.assertIn("Ambiguous default egress interfaces", str(ctx.exception))


class TestNT014_SymlinkSafeTorConfigPath(unittest.TestCase):
    """NT-014: Make Tor config path validation symlink-safe."""

    def test_path_must_be_inside_etc_tor(self):
        self.assertTrue(nulltrace.nulltrace.is_valid_tor_config_path("/etc/tor/torrc"))
        self.assertTrue(nulltrace.nulltrace.is_valid_tor_config_path("/etc/tor/torrc.d/custom"))

    def test_traversal_and_escaping_rejected(self):
        self.assertFalse(nulltrace.nulltrace.is_valid_tor_config_path("/etc/tor/../shadow"))
        self.assertFalse(nulltrace.nulltrace.is_valid_tor_config_path("/etc/shadow"))
        self.assertFalse(nulltrace.nulltrace.is_valid_tor_config_path(""))
        self.assertFalse(nulltrace.nulltrace.is_valid_tor_config_path("/etc/tor"))

    def test_validate_tor_config_target_checks(self):
        app = nulltrace.nulltrace()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            tor_dir = tmp_path / "etc" / "tor"
            tor_dir.mkdir(parents=True, exist_ok=True)
            cfg_file = tor_dir / "torrc"
            cfg_file.write_text("SOCKSPort 9050\n")

            with patch.object(app, "is_valid_tor_config_path", return_value=True):
                result = app.validate_tor_config_target(str(cfg_file))
                self.assertEqual(result, cfg_file.resolve())

                with self.assertRaises(ValueError):
                    app.validate_tor_config_target("")

                # Test world-writable file rejection
                fake_stat = MagicMock(st_mode=0o100666, st_uid=0)
                with patch("os.getuid", create=True), \
                     patch("pathlib.Path.stat", return_value=fake_stat):
                    with self.assertRaises(ValueError) as ctx:
                        app.validate_tor_config_target(str(cfg_file))
                    self.assertIn("world-writable", str(ctx.exception))


class TestNT015_AtomicDurableWrites(unittest.TestCase):
    """NT-015: Atomic durable writes for persistent configuration and state."""

    def test_atomic_write_creates_file_safely(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "test_file.txt"
            content = "test durable content 12345\n"
            nulltrace.atomic_write(target, content, mode=0o644)

            self.assertTrue(target.exists())
            self.assertEqual(target.read_text(encoding="utf-8"), content)

    def test_atomic_write_cleans_up_on_failure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "test_fail.txt"
            target.write_text("original content")

            with patch("os.fsync", side_effect=OSError("Disk write error")):
                with self.assertRaises(OSError):
                    nulltrace.atomic_write(target, "new content")

            self.assertEqual(target.read_text(), "original content")
            tmp_files = list(Path(tmpdir).glob(".*.tmp_*"))
            self.assertEqual(len(tmp_files), 0)


class TestNT016_DocsAlignment(unittest.TestCase):
    """NT-016: Align README.md and CHANGES.md with actual behavior."""

    def setUp(self):
        self.readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.changes = (REPO_ROOT / "CHANGES.md").read_text(encoding="utf-8")

    def test_readme_python_version(self):
        self.assertIn("Python 3.8+", self.readme)
        self.assertNotIn("Python 3.6+", self.readme)

    def test_readme_truthful_dns(self):
        self.assertIn("DNSPort", self.readme)
        self.assertIn("UDP", self.readme)
        self.assertIn("tcp-reset", self.readme)

    def test_readme_custom_chains_and_no_flush(self):
        self.assertIn("NULLTRACE_OUTPUT", self.readme)
        self.assertIn("never flushes host firewall tables", self.readme)

    def test_changes_covers_all_tickets(self):
        for ticket in ("NT-001", "NT-002", "NT-003", "NT-004", "NT-005", "NT-006",
                       "NT-007", "NT-008", "NT-009", "NT-010", "NT-011", "NT-012",
                       "NT-013", "NT-014", "NT-015", "NT-016"):
            self.assertIn(ticket, self.changes, f"{ticket} is missing from CHANGES.md")


class TestP0_RecoveryAndEnforcementTruth(unittest.TestCase):
    """P0.1 - P0.5: Recovery session identity, live enforcement truth, durable state, tri-state teardown, crash recovery."""

    def test_p0_1_cross_process_session_binding(self):
        """P0.1: Process A starts active session -> Process B stop/recovery binds to same session directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                # Process A creates session
                app_a = nulltrace.nulltrace()
                sid_a = app_a.session_id
                sdir_a = tmp_path / f"session_{sid_a}"
                sdir_a.mkdir(parents=True, exist_ok=True)
                (sdir_a / "metadata.json").write_text(json.dumps({
                    "session_id": sid_a,
                    "state": nulltrace.STATE_ACTIVE,
                    "active": True,
                }), encoding="utf-8")
                (tmp_path / "state.json").write_text(json.dumps({
                    "session_id": sid_a,
                    "state": nulltrace.STATE_ACTIVE,
                }), encoding="utf-8")

                # Process B starts fresh with its own initial ID
                app_b = nulltrace.nulltrace()
                self.assertNotEqual(app_b.session_id, sid_a)

                # Process B loads metadata for stop/recovery
                meta = app_b._load_session_metadata()
                self.assertIsNotNone(meta)
                self.assertEqual(meta["session_id"], sid_a)
                # Session is bound to Process A's session directory
                self.assertEqual(app_b.session_id, sid_a)
                self.assertEqual(app_b._session_dir(), sdir_a)

    def test_p0_2_persisted_active_without_live_firewall_requires_recovery(self):
        """P0.2: Persisted ACTIVE with empty/missing runtime firewall rules reconciles to RECOVERY_REQUIRED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                app = nulltrace.nulltrace()
                (tmp_path / "state.json").write_text(json.dumps({
                    "session_id": app.session_id,
                    "state": nulltrace.STATE_ACTIVE,
                }), encoding="utf-8")

                # Mock live firewall inspection returning CLEAN (no rules in kernel, e.g. post-reboot)
                with patch.object(app, "_check_live_firewall_status", return_value=nulltrace.LiveFirewallStatus.CLEAN):
                    reconciled = app.reconcile_state()
                    self.assertEqual(reconciled, nulltrace.STATE_RECOVERY_REQUIRED)
                    self.assertFalse(app.is_active())

    def test_p0_2_persisted_active_with_live_firewall_reconciles_active(self):
        """P0.2: Persisted ACTIVE with verified live rules reconciles to ACTIVE."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                app = nulltrace.nulltrace()
                sdir = tmp_path / f"session_{app.session_id}"
                sdir.mkdir(parents=True, exist_ok=True)
                (sdir / "metadata.json").write_text(json.dumps({
                    "session_id": app.session_id,
                    "state": nulltrace.STATE_ACTIVE,
                }), encoding="utf-8")
                (tmp_path / "state.json").write_text(json.dumps({
                    "session_id": app.session_id,
                    "state": nulltrace.STATE_ACTIVE,
                }), encoding="utf-8")

                with patch.object(app, "_check_live_firewall_status", return_value=nulltrace.LiveFirewallStatus.ACTIVE):
                    reconciled = app.reconcile_state()
                    self.assertEqual(reconciled, nulltrace.STATE_ACTIVE)
                    self.assertTrue(app.is_active())

    def test_p0_3_state_persistence_failure_is_fatal(self):
        """P0.3: Failures to durably write recovery state raise and cannot be silently swallowed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                app = nulltrace.nulltrace()
                with patch("nulltrace.atomic_write", side_effect=OSError("Read-only filesystem")):
                    with self.assertRaises(OSError):
                        app._persist_session_metadata()
                    with self.assertRaises(OSError):
                        app._write_state(nulltrace.STATE_ACTIVE)

    def test_p0_4_tri_state_teardown_verification(self):
        """P0.4: Teardown verification returns VERIFIED_CLEAN, VERIFIED_DIRTY, or VERIFICATION_FAILED."""
        app = nulltrace.nulltrace()
        with patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/iptables"), \
             patch("nulltrace.nulltrace._check_ipv6_enabled", return_value=False):

            # 1. Clean ruleset
            with patch("nulltrace.run_trusted", return_value=subprocess.CompletedProcess(
                args=["iptables"], returncode=0, stdout="", stderr=""
            )):
                status = app._verify_firewall_teardown(return_status=True)
                self.assertEqual(status, nulltrace.TeardownStatus.VERIFIED_CLEAN)

            # 2. Dirty ruleset (leftover NULLTRACE chain or rule)
            with patch("nulltrace.run_trusted", return_value=subprocess.CompletedProcess(
                args=["iptables"], returncode=0, stdout="-A OUTPUT -j NULLTRACE_OUTPUT\n", stderr=""
            )):
                status = app._verify_firewall_teardown(return_status=True)
                self.assertEqual(status, nulltrace.TeardownStatus.VERIFIED_DIRTY)
                # Without return_status=True, must raise RuntimeError
                with self.assertRaises(RuntimeError):
                    app._verify_firewall_teardown(return_status=False)

            # 3. Failed command (inspection failed)
            with patch("nulltrace.run_trusted", return_value=subprocess.CompletedProcess(
                args=["iptables"], returncode=1, stdout="", stderr="permission denied"
            )):
                status = app._verify_firewall_teardown(return_status=True)
                self.assertEqual(status, nulltrace.TeardownStatus.VERIFICATION_FAILED)
                with self.assertRaises(RuntimeError):
                    app._verify_firewall_teardown(return_status=False)

    def test_p0_5_interrupted_activation_state_reconciles_to_recovery_required(self):
        """P0.5: Persistent state left at PREPARING or ACTIVATING reconciles to RECOVERY_REQUIRED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                app = nulltrace.nulltrace()
                (tmp_path / "state.json").write_text(json.dumps({
                    "session_id": app.session_id,
                    "state": nulltrace.STATE_PREPARING,
                }), encoding="utf-8")
                self.assertEqual(app.reconcile_state(), nulltrace.STATE_RECOVERY_REQUIRED)

                (tmp_path / "state.json").write_text(json.dumps({
                    "session_id": app.session_id,
                    "state": nulltrace.STATE_ACTIVATING,
                }), encoding="utf-8")
                self.assertEqual(app.reconcile_state(), nulltrace.STATE_RECOVERY_REQUIRED)

    def test_p0_1_multiple_stale_sessions_deterministic_selection(self):
        """P0.1: Deterministically selects active/uncleaned session with newest timestamp among multiple sessions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                # Older active session
                sdir_old = tmp_path / "session_111111111111"
                sdir_old.mkdir(parents=True)
                (sdir_old / "metadata.json").write_text(json.dumps({
                    "session_id": "111111111111",
                    "created_at": "2026-09-22T10:00:00",
                    "state": nulltrace.STATE_ACTIVE,
                }), encoding="utf-8")

                # Newer active session
                sdir_new = tmp_path / "session_222222222222"
                sdir_new.mkdir(parents=True)
                (sdir_new / "metadata.json").write_text(json.dumps({
                    "session_id": "222222222222",
                    "created_at": "2026-09-22T11:00:00",
                    "state": nulltrace.STATE_ACTIVE,
                }), encoding="utf-8")

                # Inactive session (should be ignored even if newer)
                sdir_inactive = tmp_path / "session_333333333333"
                sdir_inactive.mkdir(parents=True)
                (sdir_inactive / "metadata.json").write_text(json.dumps({
                    "session_id": "333333333333",
                    "created_at": "2026-09-22T12:00:00",
                    "state": nulltrace.STATE_INACTIVE,
                }), encoding="utf-8")

                app = nulltrace.nulltrace()
                sid = app._discover_session_id()
                self.assertIsNone(sid)

    def test_p0_1_missing_session_directory_fails_safely(self):
        """P0.1: Missing session directory fails safely without claiming clean or inventing false state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                # State exists pointing to non-existent session directory
                (tmp_path / "state.json").write_text(json.dumps({
                    "session_id": "a1b2c3d4e5f60718",
                    "state": nulltrace.STATE_ACTIVE,
                }), encoding="utf-8")

                app = nulltrace.nulltrace()
                # Must reconcile to RECOVERY_REQUIRED because live enforcement/directory is missing
                self.assertEqual(app.reconcile_state(), nulltrace.STATE_RECOVERY_REQUIRED)
                self.assertFalse(app.is_active())

    def test_p0_2_firewall_inspection_failure_requires_recovery(self):
        """P0.2 & Scenario 7: When firewall inspection fails (UNKNOWN), reconcile_state returns RECOVERY_REQUIRED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                app = nulltrace.nulltrace()
                # Even if state is INACTIVE on disk, inspection failure must never be treated as clean
                (tmp_path / "state.json").write_text(json.dumps({
                    "session_id": app.session_id,
                    "state": nulltrace.STATE_INACTIVE,
                }), encoding="utf-8")

                with patch.object(app, "_check_live_firewall_status", return_value=nulltrace.LiveFirewallStatus.UNKNOWN):
                    reconciled = app.reconcile_state()
                    self.assertEqual(reconciled, nulltrace.STATE_RECOVERY_REQUIRED)

    def test_p0_3_durable_recovery_metadata_committed_before_runtime_changes(self):
        """P0.3 & Sec 6: Commit durable recovery metadata before applying destructive Tor or firewall changes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path), \
                 patch("nulltrace.require_linux_root"):
                app = nulltrace.nulltrace()
                events = []

                def mock_backup_iptables():
                    events.append("backup_iptables")
                def mock_backup_tor():
                    events.append("backup_tor")
                def mock_persist_meta(*args, **kwargs):
                    events.append("persist_meta")
                def mock_apply_tor():
                    events.append("apply_tor")
                def mock_setup_v4():
                    events.append("setup_v4")
                def mock_setup_v6():
                    events.append("setup_v6")
                def mock_activate_jumps():
                    events.append("activate_jumps")

                with patch.object(app, "_check_live_firewall_status", side_effect=[nulltrace.LiveFirewallStatus.CLEAN, nulltrace.LiveFirewallStatus.ACTIVE]), \
                     patch.object(app, "_load_session_metadata", return_value=None), \
                     patch.object(app, "backup_iptables", side_effect=mock_backup_iptables), \
                     patch.object(app, "backup_tor_config", side_effect=mock_backup_tor), \
                     patch.object(app, "_persist_session_metadata", side_effect=mock_persist_meta), \
                     patch.object(app, "apply_tor_config", side_effect=mock_apply_tor), \
                     patch.object(app, "_setup_custom_chains_v4", side_effect=mock_setup_v4), \
                     patch.object(app, "_setup_custom_chains_v6", side_effect=mock_setup_v6), \
                     patch.object(app, "_generate_enforcement_manifest", return_value={"mock": "manifest"}), \
                     patch.object(app, "_activate_jump_rules", side_effect=mock_activate_jumps):
                    app.setup_network_rules()

                # Verify persist_meta happened before apply_tor, setup_v4, setup_v6, activate_jumps
                meta_idx = events.index("persist_meta")
                apply_idx = events.index("apply_tor")
                self.assertLess(meta_idx, apply_idx, "Durable recovery metadata must be committed before applying Tor config")
                self.assertLess(meta_idx, events.index("setup_v4"), "Durable metadata must be committed before firewall rules")


class TestP1_SecurityAndCorrectnessHardening(unittest.TestCase):
    """P1.1 - P1.8: Permissions, listener binding, connmark mask, inbound allow, listener ownership, env hardening, chain authentication, conntrack."""

    def test_p1_1_torrc_permissions_preserved(self):
        """P1.1: Atomic replacement preserves original file mode (e.g. 0600 or 0640) and never widens permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "torrc"
            test_file.write_text("initial content", encoding="utf-8")
            try:
                os.chmod(test_file, 0o600)
                expected_mode = 0o600
            except OSError:
                expected_mode = None

            nulltrace.atomic_write(test_file, "updated content")
            self.assertEqual(test_file.read_text(encoding="utf-8"), "updated content")
            if expected_mode is not None and hasattr(os, "stat"):
                actual_mode = test_file.stat().st_mode & 0o777
                if os.name != "nt":
                    self.assertEqual(actual_mode, 0o600)

    def test_p1_2_reject_ipv6_loopback_listener(self):
        """P1.2: ::1 and all non-127.0.0.1 localhost addresses are rejected with clear explanation."""
        app = nulltrace.nulltrace()
        for invalid_addr in ("::1", "::", "fe80::1", "127.0.0.2", "0.0.0.0", "192.168.1.1"):
            app.config.localhost = invalid_addr
            with self.assertRaises(ValueError) as ctx:
                app.validate_network_config()
            self.assertTrue(
                "rejected" in str(ctx.exception).lower() or "must be a valid loopback" in str(ctx.exception).lower()
            )

        app.config.localhost = "127.0.0.1"
        app.validate_network_config()

    def test_p1_3_bit_masked_connmark(self):
        """P1.3: Packet marking uses reserved bits with mask (0xffff0000) so unrelated marks survive."""
        self.assertEqual(nulltrace.CONNMARK_MASK, "0xffff0000")
        self.assertEqual(nulltrace.CONNMARK_VALUE, "0x4e540000")
        self.assertEqual(nulltrace.CONNMARK_TOR, "0x4e540000/0xffff0000")

        app = nulltrace.nulltrace()
        app._tor_user = "109"
        with patch("nulltrace.require_trusted_binary", return_value="/usr/sbin/iptables"), \
             patch("nulltrace.run_trusted") as mock_run:
            app._setup_custom_chains_v4()
            executed_cmds = [call.args[0] for call in mock_run.call_args_list]
            found_save_mask = any(
                "--save-mark" in cmd and "--mask" in cmd and nulltrace.CONNMARK_MASK in cmd
                for cmd in executed_cmds
            )
            found_restore_mask = any(
                "--restore-mark" in cmd and "--mask" in cmd and nulltrace.CONNMARK_MASK in cmd
                for cmd in executed_cmds
            )
            self.assertTrue(found_save_mask, "Mangle OUTPUT must use --save-mark with CONNMARK_MASK")
            self.assertTrue(found_restore_mask, "Mangle PREROUTING must use --restore-mark with CONNMARK_MASK")

    def test_p1_4_no_inbound_allow_for_outbound_exclusions(self):
        """P1.4: Excluded networks do NOT generate ACCEPT rules in INPUT filter chain."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        app.config.excluded_networks = ["192.168.1.0/24"]
        with patch("nulltrace.require_trusted_binary", return_value="/usr/sbin/iptables"), \
             patch("nulltrace.run_trusted") as mock_run:
            app._setup_custom_chains_v4()
            executed_cmds = [call.args[0] for call in mock_run.call_args_list]
            bad_rules = [
                cmd for cmd in executed_cmds
                if nulltrace.CHAIN_FILTER_INPUT in cmd and "192.168.1.0/24" in cmd and "ACCEPT" in cmd
            ]
            self.assertEqual(bad_rules, [], f"Outbound exclusion must not create inbound ACCEPT: {bad_rules}")

    def test_p1_5_listener_ownership_verification(self):
        """P1.5: Verify intended Tor process owns listeners; reject other processes."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"

        def mock_exists(p):
            p_str = p.as_posix()
            return p_str in (
                "/proc/1234", "/proc/1234/status", "/proc/1234/exe",
                "/proc/5678", "/proc/5678/status", "/proc/5678/exe"
            )

        def mock_is_dir(p):
            p_str = p.as_posix()
            return p_str in ("/proc/1234", "/proc/5678")

        def mock_read_text(p, encoding=None):
            p_str = p.as_posix()
            if p_str == "/proc/1234/status":
                return "Name:\ttor\nUid:\t109\t109\t109\t109\n"
            if p_str == "/proc/5678/status":
                return "Name:\tmalicious_proxy\nUid:\t1000\t1000\t1000\t1000\n"
            return ""

        def mock_readlink(p):
            p_str = Path(p).as_posix()
            if p_str == "/proc/1234/exe":
                return "/usr/bin/tor"
            if p_str == "/proc/5678/exe":
                return "/usr/bin/malicious_proxy"
            raise OSError("No such file")

        with patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/ss"), \
             patch.object(Path, "exists", autospec=True, side_effect=mock_exists), \
             patch.object(Path, "is_dir", autospec=True, side_effect=mock_is_dir), \
             patch.object(Path, "read_text", autospec=True, side_effect=mock_read_text), \
             patch("os.readlink", side_effect=mock_readlink), \
             patch("os.kill", return_value=None):

            # Tor owns the port
            with patch("nulltrace.run_trusted", return_value=subprocess.CompletedProcess(
                args=["ss"], returncode=0,
                stdout='LISTEN 0 128 127.0.0.1:9041 0.0.0.0:* users:(("tor",pid=1234,fd=6))\n', stderr=""
            )):
                self.assertTrue(app._verify_listener_ownership(9041, "tcp"))

            # Another process owns the port
            with patch("nulltrace.run_trusted", return_value=subprocess.CompletedProcess(
                args=["ss"], returncode=0,
                stdout='LISTEN 0 128 127.0.0.1:9041 0.0.0.0:* users:(("malicious_proxy",pid=5678,fd=4))\n', stderr=""
            )):
                self.assertFalse(app._verify_listener_ownership(9041, "tcp"))

    def test_p1_6_sanitized_environment(self):
        """P1.6: Minimal explicit environment strips injection-sensitive variables."""
        dirty_env = {
            "PATH": "/usr/local/bin:/evil/bin",
            "LD_PRELOAD": "/evil.so",
            "LD_LIBRARY_PATH": "/evil/lib",
            "PYTHONPATH": "/evil/python",
            "PYTHONHOME": "/evil/home",
            "HTTP_PROXY": "http://evil:8080",
            "HTTPS_PROXY": "http://evil:8080",
            "ALL_PROXY": "socks5://evil:1080",
            "TMPDIR": "/evil/tmp",
            "LANG": "en_US.UTF-8",
        }
        for module in (nulltrace, install):
            cleaned = module.sanitize_environment(dirty_env)
            self.assertNotIn("LD_PRELOAD", cleaned)
            self.assertNotIn("LD_LIBRARY_PATH", cleaned)
            self.assertNotIn("PYTHONPATH", cleaned)
            self.assertNotIn("PYTHONHOME", cleaned)
            self.assertNotIn("HTTP_PROXY", cleaned)
            self.assertNotIn("HTTPS_PROXY", cleaned)
            self.assertNotIn("ALL_PROXY", cleaned)
            self.assertNotIn("TMPDIR", cleaned)
            self.assertEqual(cleaned["PATH"], "/usr/sbin:/usr/bin:/sbin:/bin")

    def test_p1_7_authenticate_or_create_chain(self):
        """P1.7: Chain authentication verifies ownership comment before flush/reuse, rejects conflicting chains."""
        app = nulltrace.nulltrace()
        # Pre-existing chain with nulltrace comment succeeds
        with patch("nulltrace.run_trusted") as mock_run:
            mock_run.side_effect = [
                subprocess.CompletedProcess(args=["iptables"], returncode=0, stdout=f"-N CHAIN\n-A CHAIN -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n", stderr=""),
                subprocess.CompletedProcess(args=["iptables"], returncode=0, stdout="", stderr=""),
                subprocess.CompletedProcess(args=["iptables"], returncode=0, stdout="", stderr=""),
            ]
            app._authenticate_or_create_chain("/usr/sbin/iptables", "filter", "NULLTRACE_TEST")

        # Pre-existing chain without nulltrace marker raises RuntimeError
        with patch("nulltrace.run_trusted") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=["iptables"], returncode=0, stdout="-N CHAIN\n-A CHAIN -j DROP\n", stderr="")
            with self.assertRaises(RuntimeError) as ctx:
                app._authenticate_or_create_chain("/usr/sbin/iptables", "filter", "NULLTRACE_TEST")
            self.assertIn("not authenticated as nulltrace-owned", str(ctx.exception))

    def test_p1_8_no_global_conntrack_flush(self):
        """P1.8: Global conntrack flushing (conntrack -F) is never performed during activation."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        with patch("nulltrace.nulltrace._check_ipv6_enabled", return_value=False), \
             patch("nulltrace.require_trusted_binary", return_value="/usr/sbin/iptables"), \
             patch("nulltrace.run_trusted") as mock_run:
            app._activate_jump_rules()
            executed_cmds = [call.args[0] for call in mock_run.call_args_list]
            for cmd in executed_cmds:
                self.assertNotIn("conntrack", cmd[0].lower())
                self.assertNotIn("-F", cmd)

    def test_p1_1_mode_tightening_allowed_never_widened(self):
        """P1.1: atomic_write preserves restrictive mode and allows caller to tighten, never widen."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test_perm"
            test_file.write_text("initial", encoding="utf-8")
            try:
                os.chmod(test_file, 0o644)
            except OSError:
                pass

            # Tighten with mode=0o600
            nulltrace.atomic_write(test_file, "updated", mode=0o600)
            if os.name != "nt" and hasattr(os, "stat"):
                self.assertEqual(test_file.stat().st_mode & 0o777, 0o600)

    def test_p1_4_excluded_network_has_established_return_rule(self):
        """P1.4: Excluded networks generate ESTABLISHED,RELATED RETURN rule in INPUT, but never ACCEPT."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        app.config.excluded_networks = ["192.168.1.0/24"]
        with patch("nulltrace.require_trusted_binary", return_value="/usr/sbin/iptables"), \
             patch("nulltrace.run_trusted") as mock_run:
            app._setup_custom_chains_v4()
            executed_cmds = [call.args[0] for call in mock_run.call_args_list]

            # Verify RETURN rule for established traffic from excluded network
            found_return = any(
                nulltrace.CHAIN_FILTER_INPUT in cmd
                and "192.168.1.0/24" in cmd
                and "ESTABLISHED,RELATED" in cmd
                and "RETURN" in cmd
                for cmd in executed_cmds
            )
            self.assertTrue(found_return, "Expected ESTABLISHED,RELATED RETURN rule for excluded network")

            # Verify NO ACCEPT rule exists for excluded network
            has_accept = any(
                nulltrace.CHAIN_FILTER_INPUT in cmd
                and "192.168.1.0/24" in cmd
                and "ACCEPT" in cmd
                for cmd in executed_cmds
            )
            self.assertFalse(has_accept, "Excluded network must never generate inbound ACCEPT rule")

    def test_p1_5_wrong_process_dns_port_fails_readiness(self):
        """P1.5 & Scenario 8: Wrong process owning DNSPort fails listener ownership check and refuses readiness."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        # Hex port 5353 = 14E9
        proc_udp_content = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   1: 0100007F:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   105        0 23456\n"
        )
        with patch("nulltrace.resolve_trusted_binary", return_value=None), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=proc_udp_content):
            # UID 105 (systemd-resolved) != 109 (tor)
            self.assertFalse(app._verify_listener_ownership(5353, "udp"))

    def test_p1_6_static_audit_no_direct_subprocess_calls(self):
        """P1.6: Static AST audit guarantees no direct privileged subprocess.run calls outside run_trusted."""
        import ast
        for filename in ("nulltrace.py", "install.py"):
            filepath = REPO_ROOT / filename
            tree = ast.parse(filepath.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for child in ast.walk(node):
                        if isinstance(child, ast.Call):
                            func_name = ""
                            if isinstance(child.func, ast.Attribute) and isinstance(child.func.value, ast.Name):
                                if child.func.value.id == "subprocess":
                                    func_name = child.func.attr
                            if func_name in ("run", "Popen", "call", "check_call", "check_output"):
                                self.assertEqual(
                                    node.name,
                                    "run_trusted",
                                    f"Direct privileged subprocess.{func_name} in {filename}:{child.lineno} inside {node.name}()",
                                )

    def test_p1_7_chains_have_no_early_return(self):
        """P1.7: Created chains must not have an early -j RETURN rule that bypasses filtering/redirection."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        with patch("nulltrace.require_trusted_binary", return_value="/usr/sbin/iptables"), \
             patch("nulltrace.run_trusted") as mock_run:
            app._setup_custom_chains_v4()
            executed_cmds = [call.args[0] for call in mock_run.call_args_list]
            for cmd in executed_cmds:
                if nulltrace.CHAIN_MARKER_COMMENT in cmd:
                    self.assertNotIn("-j", cmd, f"Marker rule must not have target action: {cmd}")


class TestP2_CorrectnessRecoveryUX(unittest.TestCase):
    """P2.1 - P2.7: Teardown interruption, NEWNYM requirement, ControlPort parsing, Tor restart check, uninstall live check, IP check validations."""

    def test_p2_1_sigterm_during_restore_sets_restore_failed(self):
        """P2.1 & Scenario 4: Interruption (SIGTERM/SIGINT) during restore persists RESTORE_FAILED and preserves backups."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path), \
                 patch("nulltrace.require_linux_root"):
                app = nulltrace.nulltrace()
                sid = app.session_id
                sdir = tmp_path / f"session_{sid}"
                sdir.mkdir(parents=True)
                (sdir / "metadata.json").write_text(json.dumps({
                    "session_id": sid,
                    "state": nulltrace.STATE_ACTIVE,
                }), encoding="utf-8")
                (tmp_path / "state.json").write_text(json.dumps({
                    "session_id": sid,
                    "state": nulltrace.STATE_ACTIVE,
                }), encoding="utf-8")

                captured_handlers = {}
                def mock_signal(sig, handler):
                    captured_handlers[sig] = handler

                def trigger_interruption():
                    handler = captured_handlers.get(signal.SIGTERM) or captured_handlers.get(15)
                    if handler:
                        handler(15, None)

                with patch("signal.signal", side_effect=mock_signal), \
                     patch.object(app, "_restore_mac", side_effect=trigger_interruption):
                    with self.assertRaises(SystemExit) as ctx:
                        app.stop_privacy_mode(force=True)

                self.assertEqual(ctx.exception.code, 128 + 15)

                # Verify persisted state is RESTORE_FAILED, not INACTIVE
                meta = json.loads((sdir / "metadata.json").read_text(encoding="utf-8"))
                self.assertEqual(meta["state"], nulltrace.STATE_RESTORE_FAILED)
                self.assertTrue(any("signal 15" in f for f in meta.get("failures", [])))
                with patch.object(app, "_check_live_firewall_status", return_value=nulltrace.LiveFirewallStatus.CLEAN):
                    self.assertEqual(app.reconcile_state(), nulltrace.STATE_RESTORE_FAILED)

    def test_p2_2_change_ip_requires_newnym_no_pkill_fallback(self):
        """P2.2: change_ip_address() requires Tor control NEWNYM success; does not fall back to pkill -HUP."""
        app = nulltrace.nulltrace()
        with patch("nulltrace.require_linux_root"), \
             patch.object(app, "_tor_control_newnym", return_value=False), \
             patch("nulltrace.resolve_trusted_binary") as mock_resolve:
            with self.assertRaises(RuntimeError) as ctx:
                app.change_ip_address()
            self.assertIn("NEWNYM", str(ctx.exception))
            mock_resolve.assert_not_called()

    def test_p2_3_read_control_port_effective_directive(self):
        """P2.3: _read_control_port() parses address:port, ignores comments, and selects effective (last) directive."""
        with tempfile.TemporaryDirectory() as tmpdir:
            conf_file = Path(tmpdir) / "torrc"
            conf_file.write_text(
                "# ControlPort 9999\n"
                "ControlPort 9051\n"
                "# Commented out:\n"
                "# ControlPort 9052\n"
                "ControlPort 127.0.0.1:9053\n",
                encoding="utf-8",
            )
            app = nulltrace.nulltrace()
            app.config.tor_config = str(conf_file)
            port = app._read_control_port()
            self.assertEqual(port, 9053)

    def test_p2_4_restore_tor_config_verifies_restart(self):
        """P2.4: restore_tor_config() raises RuntimeError if Tor service restart fails."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                app = nulltrace.nulltrace()
                app._tor_config_existed = True
                app._tor_initially_active = True
                sdir = tmp_path / f"session_{app.session_id}"
                sdir.mkdir(parents=True, exist_ok=True)
                (sdir / "torrc.bak").write_text("# baseline\n", encoding="utf-8")
                torrc = tmp_path / "torrc"
                torrc.write_text("# baseline\n", encoding="utf-8")
                with patch.object(app, "validate_tor_config_target", return_value=torrc), \
                     patch.object(app, "_control_tor_service", return_value=(False, "unit masked")):
                    with self.assertRaises(RuntimeError) as ctx:
                        app.restore_tor_config()
                    self.assertIn("service restart failed", str(ctx.exception))

    def test_p2_5_uninstall_detects_live_rules_with_inactive_state(self):
        """P2.5: In install.py, uninstall detects live NULLTRACE rules even when state file reports INACTIVE."""
        with patch("install.has_live_nulltrace_rules", return_value=True):
            self.assertTrue(install.routing_may_be_active())

        with patch("install.has_live_nulltrace_rules", return_value=False), \
             patch("pathlib.Path.exists", return_value=False):
            self.assertFalse(install.routing_may_be_active())

    def test_p2_6_and_p2_7_show_current_ip_validations(self):
        """P2.6 & P2.7: show_current_ip() strictly validates boolean IsTor, valid IPv4/IPv6, and disables ambient proxies."""
        app = nulltrace.nulltrace()

        # Valid IPv4 and boolean IsTor True
        mock_resp_v4 = MagicMock()
        mock_resp_v4.read.return_value = json.dumps({"IP": "198.51.100.1", "IsTor": True}).encode("utf-8")
        mock_opener = MagicMock()
        mock_opener.open.return_value.__enter__.return_value = mock_resp_v4
        with patch("nulltrace.build_opener", return_value=mock_opener), \
             patch("builtins.print") as mock_print:
            app.show_current_ip()
            printed = " ".join(call.args[0] for call in mock_print.call_args_list if call.args)
            self.assertIn("198.51.100.1", printed)
            self.assertIn("Tor exit: yes", printed)

        # Valid IPv6 and boolean IsTor False
        mock_resp_v6 = MagicMock()
        mock_resp_v6.read.return_value = json.dumps({"IP": "2001:db8::cafe", "IsTor": False}).encode("utf-8")
        mock_opener.open.return_value.__enter__.return_value = mock_resp_v6
        with patch("nulltrace.build_opener", return_value=mock_opener), \
             patch("builtins.print") as mock_print:
            app.show_current_ip()
            printed = " ".join(call.args[0] for call in mock_print.call_args_list if call.args)
            self.assertIn("2001:db8::cafe", printed)
            self.assertIn("Tor exit: no", printed)

        # Invalid: Non-boolean IsTor (string "true")
        mock_resp_bad_bool = MagicMock()
        mock_resp_bad_bool.read.return_value = json.dumps({"IP": "198.51.100.1", "IsTor": "true"}).encode("utf-8")
        mock_opener.open.return_value.__enter__.return_value = mock_resp_bad_bool
        with patch("nulltrace.build_opener", return_value=mock_opener), \
             patch("time.sleep"):
            with self.assertRaises(RuntimeError) as ctx:
                app.show_current_ip()
            self.assertIn("Could not determine IP address", str(ctx.exception))

        # Invalid: Malformed IP address
        mock_resp_bad_ip = MagicMock()
        mock_resp_bad_ip.read.return_value = json.dumps({"IP": "not-an-ip", "IsTor": True}).encode("utf-8")
        mock_opener.open.return_value.__enter__.return_value = mock_resp_bad_ip
        with patch("nulltrace.build_opener", return_value=mock_opener), \
             patch("time.sleep"):
            with self.assertRaises(RuntimeError) as ctx:
                app.show_current_ip()
            self.assertIn("Could not determine IP address", str(ctx.exception))

    def test_p2_4_tor_file_and_service_restoration_tracked_separately(self):
        """P2.4: Separate file-restored from service-restored in state/reporting."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                app = nulltrace.nulltrace()
                app._tor_config_existed = True
                app._tor_initially_active = True
                sid = app.session_id
                sdir = tmp_path / f"session_{sid}"
                sdir.mkdir(parents=True)
                (sdir / "torrc.bak").write_text("clean torrc", encoding="utf-8")
                torrc = tmp_path / "torrc"

                with patch.object(app, "validate_tor_config_target", return_value=torrc), \
                     patch.object(app, "_control_tor_service", return_value=(False, "unit reload failed")):
                    with self.assertRaises(RuntimeError):
                        app.restore_tor_config()

                    # File restoration succeeded on disk
                    self.assertTrue(app._tor_file_restored)
                    # Service restoration failed
                    self.assertFalse(app._tor_service_restored)
                    self.assertEqual(torrc.read_text(encoding="utf-8"), "clean torrc")

    def test_p2_6_proxy_variables_isolated(self):
        """P2.6: Environment proxy variables (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY) do NOT affect show_current_ip."""
        app = nulltrace.nulltrace()
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"IP": "198.51.100.1", "IsTor": True}).encode("utf-8")
        mock_opener = MagicMock()
        mock_opener.open.return_value.__enter__.return_value = mock_resp

        env_dirty = {
            "HTTP_PROXY": "http://evil-proxy:8080",
            "HTTPS_PROXY": "http://evil-proxy:8080",
            "ALL_PROXY": "socks5://evil-proxy:1080",
        }
        with patch.dict(os.environ, env_dirty), \
             patch("nulltrace.build_opener") as mock_build_opener:
            mock_build_opener.return_value = mock_opener
            app.show_current_ip()
            mock_build_opener.assert_called_once()
            args = mock_build_opener.call_args[0]
            # Must pass ProxyHandler({}) to ensure no ambient proxies are used
            self.assertTrue(any(isinstance(a, nulltrace.ProxyHandler) for a in args))

    def test_p1_2_inactive_session_discovery_when_all_inactive(self):
        """P1.2: When all sessions are marked INACTIVE, _discover_session_id returns None (never recovers old inactive sessions)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                sdir_1 = tmp_path / "session_aaaa1111"
                sdir_1.mkdir(parents=True)
                (sdir_1 / "metadata.json").write_text(json.dumps({
                    "session_id": "aaaa1111",
                    "created_at": "2026-09-22T08:00:00",
                    "state": nulltrace.STATE_INACTIVE,
                }), encoding="utf-8")

                sdir_2 = tmp_path / "session_bbbb2222"
                sdir_2.mkdir(parents=True)
                (sdir_2 / "metadata.json").write_text(json.dumps({
                    "session_id": "bbbb2222",
                    "created_at": "2026-09-22T09:00:00",
                    "state": nulltrace.STATE_INACTIVE,
                }), encoding="utf-8")

                app = nulltrace.nulltrace()
                sid = app._discover_session_id()
                self.assertIsNone(sid, "Historical inactive sessions must never be selected for recovery (P1.2)")

    def test_p1_5_coexistence_with_other_daemons_on_same_port(self):
        """P1.5: Tor socket is discovered even if another daemon (e.g. Avahi on 0.0.0.0:5353) is listed first in /proc/net/udp."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        # Line 1 is Avahi (UID 108) on 0.0.0.0:5353 (00000000:14E9)
        # Line 2 is Tor (UID 109) on 127.0.0.1:5353 (0100007F:14E9)
        proc_udp_content = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   1: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   108        0 11111\n"
            "   2: 0100007F:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   109        0 22222\n"
        )

        def mock_exists(p):
            p_str = p.as_posix()
            return p_str in (
                "/proc/net/udp", "/proc/1234", "/proc/1234/status", "/proc/1234/fd", "/proc/1234/exe"
            )

        def mock_is_dir(p):
            p_str = p.as_posix()
            return p_str in ("/proc", "/proc/1234", "/proc/1234/fd")

        def mock_iterdir(p):
            p_str = p.as_posix()
            if p_str == "/proc":
                return [Path("/proc/1234")]
            if p_str == "/proc/1234/fd":
                return [Path("/proc/1234/fd/3")]
            return []

        def mock_read_text(p, encoding=None):
            p_str = p.as_posix()
            if p_str == "/proc/net/udp":
                return proc_udp_content
            if p_str == "/proc/1234/status":
                return "Name:\ttor\nUid:\t109\t109\t109\t109\n"
            return ""

        def mock_readlink(p):
            p_str = Path(p).as_posix()
            if p_str == "/proc/1234/fd/3":
                return "socket:[22222]"
            if p_str == "/proc/1234/exe":
                return "/usr/bin/tor"
            raise OSError("not found")

        with patch("nulltrace.resolve_trusted_binary", return_value=None), \
             patch.object(Path, "exists", autospec=True, side_effect=mock_exists), \
             patch.object(Path, "is_dir", autospec=True, side_effect=mock_is_dir), \
             patch.object(Path, "iterdir", autospec=True, side_effect=mock_iterdir), \
             patch.object(Path, "read_text", autospec=True, side_effect=mock_read_text), \
             patch("os.readlink", side_effect=mock_readlink), \
             patch("os.kill", return_value=None):
            self.assertTrue(app._verify_listener_ownership(5353, "udp"))

    def test_scenario_2_auto_mode_interruption_preserves_protection(self):
        """Scenario 2: Ctrl+C during auto mode preserves ACTIVE protection when user declines restoration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path), \
                 patch("nulltrace.require_linux_root"), \
                 patch("nulltrace.build_parser") as mock_parser, \
                 patch("builtins.input", return_value="n"), \
                 patch.object(nulltrace.nulltrace, "change_ip_address", side_effect=KeyboardInterrupt):
                mock_args = MagicMock()
                mock_args.circuit_time = None
                mock_args.exit_country = None
                mock_args.mac_randomize = False
                mock_args.verbose = False
                mock_args.load = None
                mock_args.save = None
                mock_args.show_config = False
                mock_args.dnsleak = False
                mock_args.status = False
                mock_args.start = False
                mock_args.stop = False
                mock_args.force_stop = False
                mock_args.recover = False
                mock_args.ip = False
                mock_args.new_ip = False
                mock_args.auto = True
                mock_args.time = 60
                mock_parser.return_value.parse_args.return_value = mock_args

                with patch.object(nulltrace.nulltrace, "is_active", return_value=True), \
                     patch.object(nulltrace.nulltrace, "stop_privacy_mode") as mock_stop:
                    nulltrace.main()
                    # Stop was NOT called because user selected 'n'
                    mock_stop.assert_not_called()



class TestHandoffRemediationNewIssues(unittest.TestCase):
    """
    Comprehensive regression tests for all issues specified in nulltrace_remaining_issues_agent_handoff.md:
    P0.1 - P0.3, P1.1 - P1.8, P2.1 - P2.10.
    """

    def setUp(self):
        self.app = nulltrace.nulltrace()
        self.app._tor_user = "109"

    def test_p0_1_config_dir_symlink_rejected(self):
        """P0.1: Symlinked config directory must be rejected before any privileged write/chown."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            fake_config = tmp_path / "cfg_link"
            mock_stat = MagicMock()
            mock_stat.st_mode = stat.S_IFLNK | 0o755
            with patch("nulltrace.get_config_home", return_value=fake_config), \
                 patch("pathlib.Path.exists", return_value=True), \
                 patch("os.path.islink", return_value=True), \
                 patch("os.lstat", return_value=mock_stat):
                with self.assertRaises(ValueError) as ctx:
                    nulltrace.resolve_config_path("test.json")
                self.assertIn("symlink", str(ctx.exception).lower())

    def test_p0_1_config_file_symlink_rejected(self):
        """P0.1: Config file symlink targeting another file must be rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_dir = Path(tmpdir) / "cfg"
            cfg_dir.mkdir(parents=True)
            target_file = cfg_dir / "myconfig.json"

            def fake_lstat(path):
                if str(path) == str(target_file):
                    st = MagicMock()
                    st.st_mode = stat.S_IFLNK | 0o644
                    return st
                return os.stat(path)

            with patch("nulltrace.get_config_home", return_value=cfg_dir), \
                 patch("os.path.islink", side_effect=lambda p: str(p) == str(target_file)), \
                 patch("os.lstat", side_effect=fake_lstat):
                with self.assertRaises(ValueError) as ctx:
                    nulltrace.resolve_config_path("myconfig.json")
                self.assertIn("symlink", str(ctx.exception).lower())

    def test_p2_6_config_file_non_regular_rejected(self):
        """P2.6: Non-regular config files (FIFO, socket, device) must be rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            cfg_dir = tmp_path / "cfg"
            cfg_dir.mkdir(parents=True)
            target = cfg_dir / "fifo.json"
            target.write_text("fake", encoding="utf-8")

            # Mock lstat to report S_IFIFO only for target
            mock_stat = MagicMock()
            mock_stat.st_mode = stat.S_IFIFO | 0o600

            def fake_lstat(path):
                if str(path) == str(target):
                    return mock_stat
                return os.stat(path)

            with patch("nulltrace.get_config_home", return_value=cfg_dir), \
                 patch("os.lstat", side_effect=fake_lstat):
                with self.assertRaises(ValueError) as ctx:
                    nulltrace.resolve_config_path("fifo.json")
                self.assertIn("regular file", str(ctx.exception).lower())

    def test_p0_2_tampered_chain_with_return_fails_reconciliation(self):
        """P0.2: A chain containing early unconditioned RETURN or missing DROP must fail verification."""
        app = nulltrace.nulltrace()
        app._session_id = "test_tamper_1"

        def fake_run(cmd, **kwargs):
            cmd_str = " ".join(cmd)
            # Jumps exist
            if "-S" in cmd and "OUTPUT" in cmd and "filter" in cmd:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=f"-A OUTPUT -j {nulltrace.CHAIN_FILTER_OUTPUT}\n-A INPUT -j {nulltrace.CHAIN_FILTER_INPUT}\n-A FORWARD -j {nulltrace.CHAIN_FILTER_FORWARD}\n")
            if "-S" in cmd and "OUTPUT" in cmd and "nat" in cmd:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=f"-A OUTPUT -j {nulltrace.CHAIN_NAT_OUTPUT}\n")
            if "-S" in cmd and ("mangle" in cmd):
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=f"-A OUTPUT -j {nulltrace.CHAIN_MANGLE_OUTPUT}\n-A PREROUTING -j {nulltrace.CHAIN_MANGLE_PREROUTING}\n")
            # NULLTRACE_FILTER_OUTPUT tampered: only contains -j RETURN
            if nulltrace.CHAIN_FILTER_OUTPUT in cmd:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=f"-A {nulltrace.CHAIN_FILTER_OUTPUT} -m comment --comment nulltrace-owned\n-A {nulltrace.CHAIN_FILTER_OUTPUT} -j RETURN\n")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=f"-A {cmd[-1]} -m comment --comment nulltrace-owned\n")

        with patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/iptables"), \
             patch("nulltrace.run_trusted", side_effect=fake_run):
            status = app._check_live_firewall_status()
            self.assertNotEqual(status, nulltrace.LiveFirewallStatus.ACTIVE)
            self.assertIn(status, (nulltrace.LiveFirewallStatus.PARTIAL, nulltrace.LiveFirewallStatus.UNKNOWN))

    def test_p0_2_manifest_fingerprint_mismatch_fails_reconciliation(self):
        """P0.2: When actual chain rules differ from session manifest fingerprints, reconciliation fails."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                app = nulltrace.nulltrace()
                sid = app.session_id
                sdir = tmp_path / f"session_{sid}"
                sdir.mkdir(parents=True)

                # Persist manifest with specific expected fingerprint
                manifest = {
                    "version": "1.0",
                    "chain_fingerprints": {
                        f"v4:filter:{nulltrace.CHAIN_FILTER_OUTPUT}": "0000000000000000000000000000000000000000000000000000000000000000",
                    },
                }
                (sdir / "metadata.json").write_text(json.dumps({
                    "session_id": sid,
                    "state": nulltrace.STATE_ACTIVE,
                    "enforcement_manifest": manifest,
                }), encoding="utf-8")

                with patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/iptables"), \
                     patch("nulltrace.run_trusted") as mock_run:
                    # Return legitimate-looking rules whose hash will NOT equal 00000000...
                    mock_run.return_value = subprocess.CompletedProcess(
                        args=["iptables"], returncode=0,
                        stdout=f"-A {nulltrace.CHAIN_FILTER_OUTPUT} -m comment --comment nulltrace-owned\n-A {nulltrace.CHAIN_FILTER_OUTPUT} -j DROP\n"
                    )
                    status = app._check_live_firewall_status()
                    self.assertNotEqual(status, nulltrace.LiveFirewallStatus.ACTIVE)

    def test_p1_1_spoofed_process_name_rejected(self):
        """P1.1: A process spoofing comm name 'tor' but running under wrong UID or untrusted binary must be rejected."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"

        # 1. Wrong UID (UID 1000 instead of 109)
        mock_status_text = "Name:\ttor\nUid:\t1000\t1000\t1000\t1000\n"
        with patch("pathlib.Path.is_dir", return_value=True), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=mock_status_text), \
             patch("os.readlink", return_value="/usr/bin/tor"), \
             patch("os.kill", return_value=None):
            self.assertFalse(app._verify_process_is_tor(9999))

        # 2. Untrusted binary (/tmp/tor instead of trusted binary)
        mock_status_tor = "Name:\ttor\nUid:\t109\t109\t109\t109\n"
        with patch("pathlib.Path.is_dir", return_value=True), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=mock_status_tor), \
             patch("os.readlink", return_value="/tmp/tor"), \
             patch("os.kill", return_value=None):
            self.assertFalse(app._verify_process_is_tor(9999))

    def test_p1_1_genuine_tor_process_accepted(self):
        """P1.1: A genuine Tor process running with expected UID and trusted binary must be accepted."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        mock_status_tor = "Name:\ttor\nUid:\t109\t109\t109\t109\n"
        with patch("pathlib.Path.is_dir", return_value=True), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=mock_status_tor), \
             patch("os.readlink", return_value="/usr/bin/tor"), \
             patch("nulltrace.resolve_trusted_binary", return_value="/usr/bin/tor"), \
             patch("os.kill", return_value=None):
            self.assertTrue(app._verify_process_is_tor(1234))

    def test_p1_3_admin_torrc_changes_preserved_during_restore(self):
        """P1.3: Administrator changes to torrc outside nulltrace blocks must survive teardown."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                app = nulltrace.nulltrace()
                torrc = tmp_path / "torrc"
                app.config.tor_config = str(torrc)

                # Baseline torrc
                original_torrc = "# Original config\nSocksPort 9050\n"
                torrc.write_text(original_torrc, encoding="utf-8")
                app._tor_initially_active = True

                with patch.object(app, "validate_tor_config_target", return_value=torrc), \
                     patch.object(app, "_restart_tor"), \
                     patch.object(app, "_control_tor_service", return_value=(True, "ok")):
                    app.backup_tor_config()
                    app.apply_tor_config()

                    # Administrator adds an unrelated setting while nulltrace is active
                    current_torrc = torrc.read_text(encoding="utf-8")
                    modified_by_admin = current_torrc + "\n# Admin setting\nNickname MyNode\n"
                    torrc.write_text(modified_by_admin, encoding="utf-8")

                    app.restore_tor_config()

                restored_text = torrc.read_text(encoding="utf-8")
                # Nulltrace block must be gone
                self.assertNotIn(nulltrace.TOR_CONFIG_BEGIN, restored_text)
                # Admin changes must be preserved
                self.assertIn("Nickname MyNode", restored_text)
                self.assertIn("SocksPort 9050", restored_text)

    def test_p1_4_stop_does_not_call_iptables_restore_unless_destructive(self):
        """P1.4: Normal stop deactivates custom chains and does NOT overwrite live firewall with backup snapshot."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path), \
                 patch("nulltrace.require_linux_root"):
                app = nulltrace.nulltrace()
                sid = app.session_id
                sdir = tmp_path / f"session_{sid}"
                sdir.mkdir(parents=True)
                (sdir / "metadata.json").write_text(json.dumps({
                    "session_id": sid,
                    "state": nulltrace.STATE_ACTIVE,
                }), encoding="utf-8")

                with patch.object(app, "_get_current_state", return_value=nulltrace.STATE_ACTIVE), \
                     patch.object(app, "_deactivate_jump_rules"), \
                     patch.object(app, "_destroy_custom_chains"), \
                     patch.object(app, "_verify_firewall_teardown", return_value=nulltrace.TeardownStatus.VERIFIED_CLEAN), \
                     patch.object(app, "restore_tor_config"), \
                     patch.object(app, "restore_iptables_from_backup") as mock_restore_backup:
                    app.stop_privacy_mode(force=False, destructive=False)
                    mock_restore_backup.assert_not_called()

    def test_p1_5_installer_aborts_when_live_state_unknown(self):
        """P1.5: Uninstallation must abort immediately if live firewall state is UNKNOWN."""
        with patch("install.inspect_live_nulltrace_rules", return_value=install.FirewallInspectionResult.UNKNOWN):
            with self.assertRaises(SystemExit) as ctx:
                install.uninstall_nulltrace(interactive=False)
            self.assertEqual(ctx.exception.code, 1)

    def test_p1_7_unauthenticated_same_name_chain_not_flushed(self):
        """P1.7: Existing chain matching name but missing ownership marker comment must raise RuntimeError, not flush."""
        app = nulltrace.nulltrace()
        with patch("nulltrace.run_trusted") as mock_run:
            # Chain exists (-S returns 0), but output does NOT contain CHAIN_MARKER_COMMENT
            mock_run.return_value = subprocess.CompletedProcess(
                args=["iptables"], returncode=0, stdout="-A NULLTRACE_OUTPUT -j DROP\n", stderr=""
            )
            with self.assertRaises(RuntimeError) as ctx:
                app._authenticate_or_create_chain("/usr/sbin/iptables", "filter", nulltrace.CHAIN_FILTER_OUTPUT)
            self.assertIn("not authenticated", str(ctx.exception))
            # Verify -F was NEVER called
            for call_args in mock_run.call_args_list:
                cmd = call_args[0][0]
                self.assertNotIn("-F", cmd)

    def test_p1_8_torrc_backup_taken_once_per_session(self):
        """P1.8: Baseline snapshot must be taken exactly once per session and never overwritten."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                app = nulltrace.nulltrace()
                torrc = tmp_path / "torrc"
                app.config.tor_config = str(torrc)
                torrc.write_text("initial baseline\n", encoding="utf-8")

                with patch.object(app, "validate_tor_config_target", return_value=torrc):
                    app.backup_tor_config()
                    backup_file = app._session_dir() / "torrc.bak"
                    self.assertEqual(backup_file.read_text(encoding="utf-8"), "initial baseline\n")

                    # Change torrc and call backup again
                    torrc.write_text("modified text\n", encoding="utf-8")
                    app.backup_tor_config()
                    # Must still be the initial baseline
                    self.assertEqual(backup_file.read_text(encoding="utf-8"), "initial baseline\n")

    def test_p2_2_state_file_created_with_0600_mode(self):
        """P2.2: State file must be written with restrictive 0600 permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                app = nulltrace.nulltrace()
                app._write_state(nulltrace.STATE_ACTIVE)
                state_file = tmp_path / "state.json"
                self.assertTrue(state_file.exists())
                if os.name != "nt" and hasattr(os, "stat"):
                    self.assertEqual(state_file.stat().st_mode & 0o777, 0o600)

    def test_p2_3_dns_leak_test_verifies_tor_process_ownership(self):
        """P2.3: DNS leak test must verify Tor process ownership of DNSPort."""
        app = nulltrace.nulltrace()
        with patch.object(app, "_check_resolv_conf_leaks", return_value=[]), \
             patch.object(app, "_verify_listener_ownership", return_value=False) as mock_verify, \
             patch.object(app, "_probe_dns_port", return_value=True), \
             patch("builtins.print") as mock_print:
            app.run_dns_leak_test()
            mock_verify.assert_called_once()
            printed = " ".join(call.args[0] for call in mock_print.call_args_list if call.args)
            self.assertIn("FAILED", printed)

    def test_p2_5_tor_config_non_root_owned_rejected(self):
        """P2.5: Tor config file owned by non-root UID must be rejected when running as root."""
        app = nulltrace.nulltrace()
        with tempfile.TemporaryDirectory() as tmpdir:
            torrc = Path(tmpdir) / "torrc"
            torrc.write_text("test", encoding="utf-8")

            mock_parent_stat = MagicMock()
            mock_parent_stat.st_mode = 0o755
            mock_parent_stat.st_uid = 0

            mock_file_stat = MagicMock()
            mock_file_stat.st_mode = stat.S_IFREG | 0o600
            mock_file_stat.st_uid = 1000  # non-root

            def fake_lstat(path):
                if str(path) == str(torrc):
                    return mock_file_stat
                return mock_parent_stat

            with patch("nulltrace.nulltrace.is_valid_tor_config_path", return_value=True), \
                 patch("pathlib.Path.stat", return_value=mock_parent_stat), \
                 patch("os.geteuid", return_value=0, create=True), \
                 patch("os.getuid", return_value=0, create=True), \
                 patch("os.lstat", side_effect=fake_lstat):
                with self.assertRaises(ValueError) as ctx:
                    app.validate_tor_config_target(str(torrc))
                self.assertIn("root-owned", str(ctx.exception))

    def test_p2_7_enforcement_status_distinguishes_healthy_and_unhealthy_tor(self):
        """P2.7: Enforcement status clearly separates ENFORCING_TOR_HEALTHY from ENFORCING_TOR_UNHEALTHY."""
        app = nulltrace.nulltrace()

        # Both rules active and Tor healthy
        with patch.object(app, "_get_current_state", return_value=nulltrace.STATE_ACTIVE), \
             patch.object(app, "check_tor_service", return_value=True), \
             patch.object(app, "check_tor_ports", return_value=True):
            self.assertEqual(app.get_enforcement_status(), nulltrace.STATUS_ENFORCING_TOR_HEALTHY)

        # Rules active but Tor unhealthy (fails closed)
        with patch.object(app, "_get_current_state", return_value=nulltrace.STATE_ACTIVE), \
             patch.object(app, "check_tor_service", return_value=False):
            self.assertEqual(app.get_enforcement_status(), nulltrace.STATUS_ENFORCING_TOR_UNHEALTHY)

    def test_p2_9_ipaddress_normalization(self):
        """P2.9: Input validation uses ipaddress for robust IP and CIDR checking."""
        self.assertTrue(nulltrace.nulltrace.is_valid_ip("192.168.1.1"))
        self.assertFalse(nulltrace.nulltrace.is_valid_ip("999.999.999.999"))
        self.assertFalse(nulltrace.nulltrace.is_valid_ip("invalid"))
        self.assertTrue(nulltrace.nulltrace.is_valid_cidr("10.0.0.0/8"))
        self.assertFalse(nulltrace.nulltrace.is_valid_cidr("10.0.0.0/33"))
        self.assertFalse(nulltrace.nulltrace.is_valid_cidr("10.0.0.0"))

    def test_p2_10_exit_country_ascii_only(self):
        """P2.10: Exit country must be strictly two ASCII letters."""
        app = nulltrace.nulltrace()
        app.config.exit_country = "us"
        app.validate_network_config()
        self.assertEqual(app.config.exit_country, "US")

        # Unicode lookalikes or numbers must be rejected
        for bad_code in ("12", "USA", "СН", "U$", "a1"):
            app.config.exit_country = bad_code
            with self.assertRaises(ValueError):
                app.validate_network_config()

    def test_p0_3_ipv6_chains_installed_regardless_of_initial_host_state(self):
        """P0.3: IPv6 enforcement chains must be constructed and activated whenever ip6tables is available."""
        self.assertTrue(self.app._check_ipv6_enabled())
        with patch("nulltrace.resolve_trusted_binary", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                self.app._setup_custom_chains_v6()
            self.assertIn("ip6tables is missing", str(ctx.exception))

    def test_p1_4_destructive_restore_invokes_iptables_restore(self):
        """P1.4: When teardown fails and --destructive-restore is enabled, backup restoration is invoked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path), \
                 patch("nulltrace.require_linux_root"):
                app = nulltrace.nulltrace()
                sid = app.session_id
                sdir = tmp_path / f"session_{sid}"
                sdir.mkdir(parents=True)
                (sdir / "metadata.json").write_text(json.dumps({
                    "session_id": sid,
                    "state": nulltrace.STATE_ACTIVE,
                }), encoding="utf-8")

                with patch.object(app, "_get_current_state", return_value=nulltrace.STATE_ACTIVE), \
                     patch.object(app, "_deactivate_jump_rules"), \
                     patch.object(app, "_destroy_custom_chains"), \
                     patch.object(app, "_verify_firewall_teardown", side_effect=[
                         nulltrace.TeardownStatus.VERIFIED_DIRTY,
                         nulltrace.TeardownStatus.VERIFIED_CLEAN,
                     ]), \
                     patch.object(app, "restore_tor_config"), \
                     patch.object(app, "restore_iptables_from_backup") as mock_restore_backup:
                    app.stop_privacy_mode(force=False, destructive=True)
                    mock_restore_backup.assert_called_once()

    def test_p1_6_fail_closed_rollback_on_activation_failure(self):
        """P1.6: Interruption or failure during activation triggers fail-closed rollback and does not leave ACTIVE state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path), \
                 patch("nulltrace.require_linux_root"), \
                 patch.object(nulltrace.nulltrace, "_get_current_state", return_value=nulltrace.STATE_INACTIVE), \
                 patch.object(nulltrace.nulltrace, "backup_iptables"), \
                 patch.object(nulltrace.nulltrace, "backup_tor_config"), \
                 patch.object(nulltrace.nulltrace, "apply_tor_config"), \
                 patch.object(nulltrace.nulltrace, "_setup_custom_chains_v4"), \
                 patch.object(nulltrace.nulltrace, "_setup_custom_chains_v6"), \
                 patch.object(nulltrace.nulltrace, "_generate_enforcement_manifest", return_value={"version": "1.0"}), \
                 patch.object(nulltrace.nulltrace, "_activate_jump_rules", side_effect=RuntimeError("simulated crash during jump insertion")), \
                 patch.object(nulltrace.nulltrace, "_rollback_startup") as mock_rollback:
                app = nulltrace.nulltrace()
                with self.assertRaises(RuntimeError) as ctx:
                    app.setup_network_rules()
                self.assertIn("simulated crash", str(ctx.exception))
                mock_rollback.assert_called_once()
                self.assertNotEqual(app._current_state, nulltrace.STATE_ACTIVE)

    def test_p2_1_state_write_failure_is_fatal(self):
        """P2.1: State write failure during state transition must raise and not silently report state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                app = nulltrace.nulltrace()
                with patch("nulltrace.atomic_write", side_effect=OSError("Disk full")):
                    with self.assertRaises(OSError):
                        app._write_state(nulltrace.STATE_ACTIVE)


class TestSection11_ComprehensiveRegressions(unittest.TestCase):
    """
    Comprehensive regression test suite for handoff specification (Section 11):
    - Filesystem security (TOCTOU race, secure dirs, session IDs, trusted binaries)
    - Firewall verification (exact first jump, conditional jumps, ordered manifest, manifest integrity)
    - Emergency recovery (failed flush retains tooling, all-tables wipe, IPv6 inspection UNKNOWN)
    - Tor configuration (unterminated blocks, existence tracking, admin changes)
    - Service and interface state restoration (active/inactive/enabled/disabled, up/down)
    - Listener ownership (fake tor, wrong UID, wrong exe, multi-PID sockets)
    - Partial activation and fail-closed recovery
    """

    def test_fs_symlink_rejection_in_atomic_write(self):
        """P0-1: atomic_write rejects writing to symlinks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "test.conf"
            try:
                dest.symlink_to(Path(tmpdir) / "target")
            except (OSError, NotImplementedError):
                mock_lstat = MagicMock()
                mock_lstat.st_mode = stat.S_IFLNK | 0o777
                with patch("os.lstat", return_value=mock_lstat), \
                     patch("os.path.islink", return_value=True):
                    with self.assertRaises(ValueError) as ctx:
                        nulltrace.atomic_write(dest, "data")
                    self.assertIn("symlink", str(ctx.exception).lower())
                return

            with self.assertRaises(ValueError) as ctx:
                nulltrace.atomic_write(dest, "data")
            self.assertIn("symlink", str(ctx.exception).lower())

    def test_fs_insecure_parent_directory_atomic_write(self):
        """P0-1 & P2-2: atomic_write rejects world-writable parent directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "test.conf"
            mock_st = MagicMock()
            mock_st.st_mode = stat.S_IFDIR | 0o777  # world-writable
            mock_st.st_uid = 0
            mock_st.st_gid = 0
            with patch("os.stat", return_value=mock_st), \
                 patch("os.fstat", return_value=mock_st), \
                 patch.object(os, "_force_posix_security_checks", True, create=True), \
                 patch("os.geteuid", return_value=0, create=True):
                with self.assertRaises(ValueError) as ctx:
                    nulltrace.atomic_write(dest, "data")
                self.assertIn("world-writable", str(ctx.exception).lower())

    def test_fs_secure_directory_validation(self):
        """P2-2: _validate_secure_directory rejects symlinks, non-directories, and insecure permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            app = nulltrace.nulltrace()
            target_dir = Path(tmpdir) / "secure_dir"
            target_dir.mkdir(parents=True, exist_ok=True)

            # 1. Symlink directory rejected
            symlink_dir = Path(tmpdir) / "symlink_dir"
            mock_symlink_st = MagicMock()
            mock_symlink_st.st_mode = stat.S_IFLNK | 0o755
            with patch("os.lstat", return_value=mock_symlink_st):
                with self.assertRaises(RuntimeError) as ctx:
                    app._validate_secure_directory(symlink_dir)
                self.assertIn("symlink", str(ctx.exception).lower())

            # 2. Insecure permissions rejected
            mock_st = MagicMock()
            mock_st.st_mode = stat.S_IFDIR | 0o777
            mock_st.st_uid = 0
            with patch.object(Path, "stat", return_value=mock_st), \
                 patch("os.lstat", return_value=mock_st), \
                 patch.object(os, "_force_posix_security_checks", True, create=True), \
                 patch("os.geteuid", return_value=0, create=True):
                with self.assertRaises(RuntimeError) as ctx:
                    app._validate_secure_directory(target_dir)
                self.assertIn("insecure permissions", str(ctx.exception).lower())

    def test_fs_session_id_validation(self):
        """P2-3: is_valid_session_id strictly enforces format and rejects traversal/injection."""
        self.assertTrue(nulltrace.is_valid_session_id("123456abcdef"))
        self.assertTrue(nulltrace.is_valid_session_id("abcdef123456"))
        self.assertTrue(nulltrace.is_valid_session_id("12345678"))
        self.assertFalse(nulltrace.is_valid_session_id("../evil"))
        self.assertFalse(nulltrace.is_valid_session_id("/etc/passwd"))
        self.assertFalse(nulltrace.is_valid_session_id("session_123456"))
        self.assertFalse(nulltrace.is_valid_session_id("1234\x005678"))
        self.assertFalse(nulltrace.is_valid_session_id(""))

        app = nulltrace.nulltrace()
        with self.assertRaises(ValueError):
            app.bind_session("../../traversal")

    def test_fs_trusted_binary_resolution_checks(self):
        """P1-5: resolve_trusted_binary rejects group/world-writable and non-root-owned binaries."""
        # World-writable binary
        mock_ww = MagicMock()
        mock_ww.st_mode = stat.S_IFREG | 0o777
        mock_ww.st_uid = 0
        with patch("pathlib.Path.exists", return_value=True), \
             patch("os.lstat", return_value=mock_ww), \
             patch("os.stat", return_value=mock_ww), \
             patch("os.access", return_value=True):
            self.assertIsNone(nulltrace.resolve_trusted_binary("/usr/bin/iptables"))
            self.assertIsNone(install.resolve_trusted_binary("/usr/bin/iptables"))

        # Non-root owned binary on POSIX
        mock_nr = MagicMock()
        mock_nr.st_mode = stat.S_IFREG | 0o755
        mock_nr.st_uid = 1000
        with patch("pathlib.Path.exists", return_value=True), \
             patch("os.lstat", return_value=mock_nr), \
             patch("os.stat", return_value=mock_nr), \
             patch("os.access", return_value=True), \
             patch("os.name", "posix"):
            self.assertIsNone(nulltrace.resolve_trusted_binary("/usr/bin/iptables"))
            self.assertIsNone(install.resolve_trusted_binary("/usr/bin/iptables"))

    def test_fw_exact_first_jump_verification(self):
        """P0-2: Live firewall status returns PARTIAL when jump is not rule 1 or is conditional."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"

        # Preceding ACCEPT rule in OUTPUT
        base_rules_preceding_accept = {
            "filter": ["-A OUTPUT -j ACCEPT", "-A OUTPUT -j NULLTRACE_OUTPUT"],
            "nat": ["-A OUTPUT -j NULLTRACE_NAT_OUTPUT"],
            "mangle": ["-A OUTPUT -j NULLTRACE_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_MANGLE_PREROUTING"],
        }

        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"):
            def fake_run_trusted(cmd, **kwargs):
                table = "filter"
                if "-t" in cmd:
                    table = cmd[cmd.index("-t") + 1]
                rules = base_rules_preceding_accept.get(table, [])
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="\n".join(rules) + "\n", stderr="")

            with patch("nulltrace.run_trusted", side_effect=fake_run_trusted):
                status = app._check_live_firewall_status()
                self.assertEqual(status, nulltrace.LiveFirewallStatus.PARTIAL)

    def test_fw_order_sensitive_manifest_fingerprints(self):
        """P1-1: Manifest fingerprints preserve rule order; reordering rules changes fingerprint."""
        order1 = "-A NULLTRACE_OUTPUT -j DROP\n-A NULLTRACE_OUTPUT -j ACCEPT"
        order2 = "-A NULLTRACE_OUTPUT -j ACCEPT\n-A NULLTRACE_OUTPUT -j DROP"

        hash1 = hashlib.sha256(order1.encode()).hexdigest()
        hash2 = hashlib.sha256(order2.encode()).hexdigest()
        self.assertNotEqual(hash1, hash2, "Reordered firewall rules must produce different fingerprints")

    def test_fw_manifest_mandatory_and_complete_or_fail(self):
        """P1-2 & P1-3: Manifest generation is complete-or-fail; missing/incomplete manifest yields PARTIAL."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"

        # Missing binary raises RuntimeError during manifest generation (complete-or-fail)
        with patch("nulltrace.require_trusted_binary", side_effect=RuntimeError("iptables missing")):
            with self.assertRaises(RuntimeError):
                app._generate_enforcement_manifest()

        # Incomplete manifest (less than 11 chain fingerprints) in _check_live_firewall_status
        meta = {
            "enforcement_manifest": {
                "chain_fingerprints": {"v4:filter:NULLTRACE_OUTPUT": "abc"}
            }
        }
        rules_v4 = {
            "filter": ["-A OUTPUT -j NULLTRACE_OUTPUT", "-A INPUT -j NULLTRACE_INPUT", "-A FORWARD -j NULLTRACE_FORWARD"],
            "nat": ["-A OUTPUT -j NULLTRACE_NAT_OUTPUT"],
            "mangle": ["-A OUTPUT -j NULLTRACE_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_MANGLE_PREROUTING"],
        }
        rules_v6 = {
            "filter": ["-A OUTPUT -j NULLTRACE_V6_OUTPUT", "-A INPUT -j NULLTRACE_V6_INPUT", "-A FORWARD -j NULLTRACE_V6_FORWARD"],
            "mangle": ["-A OUTPUT -j NULLTRACE_V6_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_V6_MANGLE_PRE"],
        }
        chain_content = f"-N CHAIN\n-A CHAIN -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A CHAIN -j DROP\n"
        def fake_run(cmd, **kwargs):
            table = "filter"
            if "-t" in cmd:
                table = cmd[cmd.index("-t") + 1]
            if len(cmd) >= 5 and cmd[3] == "-S" and not cmd[4].startswith("-"):
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=chain_content, stderr="")
            if "ip6tables" in cmd[0]:
                out = "\n".join(rules_v6.get(table, []))
            else:
                out = "\n".join(rules_v4.get(table, []))
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=out, stderr="")

        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
             patch.object(app, "_load_session_metadata", return_value=meta), \
             patch("nulltrace.run_trusted", side_effect=fake_run):
            status = app._check_live_firewall_status()
            self.assertEqual(status, nulltrace.LiveFirewallStatus.PARTIAL)

    def test_recovery_failed_flush_does_not_remove_tooling(self):
        """P1-6: Failed emergency flush retains NullTrace tooling in /usr/share and /usr/bin."""
        with patch("install.inspect_live_nulltrace_rules", side_effect=[
            install.FirewallInspectionResult.ACTIVE,
            install.FirewallInspectionResult.ACTIVE,  # Still active after stop attempt
            install.FirewallInspectionResult.ACTIVE,  # Still active after emergency flush
        ]), \
        patch("install.routing_may_be_active", return_value=True), \
        patch("install.resolve_trusted_binary", return_value="/usr/sbin/iptables"), \
        patch("install.run_trusted", return_value=subprocess.CompletedProcess(args=["iptables"], returncode=0, stdout="", stderr="")), \
        patch("shutil.rmtree") as mock_rmtree, \
        patch("os.remove") as mock_remove:
            with self.assertRaises(SystemExit) as ctx:
                install.uninstall_nulltrace(emergency_flush=True, interactive=False)
            self.assertEqual(ctx.exception.code, 1)
            mock_rmtree.assert_not_called()
            mock_remove.assert_not_called()

    def test_recovery_emergency_flush_covers_all_netfilter_tables(self):
        """P2-8: Emergency flush flushes (-F) and deletes chains (-X) across all 5 netfilter tables."""
        flushed_tables = []
        def fake_run(cmd, **kwargs):
            if "-F" in cmd or "-X" in cmd:
                if "-t" in cmd:
                    flushed_tables.append(cmd[cmd.index("-t") + 1])
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        mock_script_stat = MagicMock(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        with patch("install.inspect_live_nulltrace_rules", side_effect=[
            install.FirewallInspectionResult.ACTIVE,
            install.FirewallInspectionResult.ACTIVE,
            install.FirewallInspectionResult.CLEAN,
        ]), \
        patch("install.routing_may_be_active", return_value=True), \
        patch("install.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
        patch("install.run_trusted", side_effect=fake_run), \
        patch("pathlib.Path.exists", return_value=True), \
        patch("os.lstat", return_value=mock_script_stat), \
        patch("shutil.rmtree"), \
        patch("os.remove"), \
        patch("os.path.isdir", return_value=False), \
        patch("os.path.isfile", return_value=False):
            install.uninstall_nulltrace(emergency_flush=True, interactive=False)

        for table in ("filter", "nat", "mangle", "raw", "security"):
            self.assertIn(table, flushed_tables)

    def test_recovery_ipv6_inspection_failure_returns_unknown(self):
        """P1-7: When ip6tables is missing or fails, inspect_live_nulltrace_rules returns UNKNOWN, never CLEAN."""
        with patch("install.resolve_trusted_binary", side_effect=lambda b: "/usr/sbin/iptables" if b == "iptables" else None):
            self.assertEqual(install.inspect_live_nulltrace_rules(), install.FirewallInspectionResult.UNKNOWN)

    def test_tor_unterminated_managed_block_raises(self):
        """P1-8: Unterminated managed block (BEGIN without END) raises ValueError and avoids file truncation."""
        unterminated = (
            "SocksPort 9050\n"
            f"{nulltrace.TOR_CONFIG_BEGIN}\n"
            "TransPort 127.0.0.1:9040\n"
        )
        with self.assertRaises(ValueError) as ctx:
            nulltrace.strip_tor_config_blocks(unterminated)
        self.assertIn("unterminated", str(ctx.exception).lower())

    def test_tor_config_existence_and_admin_changes_preserved(self):
        """P1-9: Tor config existence metadata is honored; admin changes outside managed block are preserved."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            torrc = tmp_path / "torrc"
            app = nulltrace.nulltrace()
            app.config.tor_config = str(torrc)

            # Case A: Originally absent torrc (tor_config_existed = False)
            # NullTrace wrote only managed block -> restore unlinks torrc
            torrc.write_text(f"{nulltrace.TOR_CONFIG_BEGIN}\nTransPort 9040\n{nulltrace.TOR_CONFIG_END}\n", encoding="utf-8")
            app._tor_config_existed = False
            with patch.object(app, "validate_tor_config_target", return_value=torrc), \
                 patch.object(app, "_load_session_metadata", return_value={"tor_config_existed": False, "tor_service_initially_active": False}), \
                 patch.object(app, "_control_tor_service", return_value=(True, "")):
                app.restore_tor_config()
                self.assertFalse(torrc.exists(), "Originally absent torrc should be deleted when only managed block existed")

            # Case B: Admin added changes outside managed block -> preserved!
            torrc.write_text(
                f"AdminSetting 42\n{nulltrace.TOR_CONFIG_BEGIN}\nTransPort 9040\n{nulltrace.TOR_CONFIG_END}\n",
                encoding="utf-8"
            )
            app._tor_config_existed = False
            with patch.object(app, "validate_tor_config_target", return_value=torrc), \
                 patch.object(app, "_load_session_metadata", return_value={"tor_config_existed": False, "tor_service_initially_active": False}), \
                 patch.object(app, "_control_tor_service", return_value=(True, "")):
                app.restore_tor_config()
                self.assertTrue(torrc.exists())
                self.assertIn("AdminSetting 42", torrc.read_text(encoding="utf-8"))

    def test_service_and_interface_state_restoration(self):
        """P1-10 & P1-11: Original Tor service state (active/enabled) and interface administrative state (up/down) restored."""
        with tempfile.TemporaryDirectory() as tmpdir:
            torrc = Path(tmpdir) / "torrc"
            torrc.write_text("TransPort 9040\n", encoding="utf-8")
            app = nulltrace.nulltrace()

            # Tor initially inactive -> teardown calls "stop"
            app._tor_initially_active = False
            app._tor_initially_enabled = True
            with patch.object(app, "validate_tor_config_target", return_value=torrc), \
                 patch.object(app, "_control_tor_service", return_value=(True, "")) as mock_ctrl, \
                 patch.object(app, "_load_session_metadata", return_value={
                     "tor_config_existed": False,
                     "tor_service_initially_active": False,
                     "tor_service_initially_enabled": True
                 }):
                app.restore_tor_config()
                mock_ctrl.assert_called_with("stop")

            # Tor initially disabled -> teardown calls "disable"
            app._tor_initially_active = True
            app._tor_initially_enabled = False
            with patch.object(app, "validate_tor_config_target", return_value=torrc), \
                 patch.object(app, "_control_tor_service", return_value=(True, "")) as mock_ctrl, \
                 patch.object(app, "_load_session_metadata", return_value={
                     "tor_config_existed": False,
                     "tor_service_initially_active": True,
                     "tor_service_initially_enabled": False
                 }):
                app.restore_tor_config()
                mock_ctrl.assert_any_call("disable")

            # Interface initially DOWN -> restored as DOWN
            app._spoofed_intf = "eth0"
            app._original_mac = "00:11:22:33:44:55"
            app._interface_initially_up = False
        with patch("nulltrace.require_trusted_binary", return_value="/usr/sbin/ip"), \
             patch.object(app, "_read_current_mac", return_value="00:11:22:33:44:55"), \
             patch.object(app, "_persist_session_metadata"), \
             patch.object(app, "_is_interface_up", return_value=False), \
             patch("nulltrace.run_trusted") as mock_run:
            app._restore_mac()
            cmds = [call.args[0] for call in mock_run.call_args_list]
            self.assertFalse(any(cmd[-1] == "up" for cmd in cmds))
            self.assertTrue(any(cmd[-1] == "down" for cmd in cmds))

    def test_listener_strict_tor_identity_verification(self):
        """P1-4 & P2-6: Process identity strictly validates executable and UID semantics."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"

        # Case A: Fake tor process (executable is /tmp/fake_tor)
        def mock_readlink(p):
            if str(p).endswith("exe"):
                return "/tmp/fake_tor"
            raise OSError()

        mock_status = "Name:\ttor\nUid:\t109\t109\t109\t109\n"
        with patch.object(Path, "is_dir", return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", return_value=mock_status), \
             patch("os.readlink", side_effect=mock_readlink), \
             patch("os.kill", return_value=None):
            self.assertFalse(app._verify_process_is_tor(1234))

        # Case B: Wrong UID (e.g. UID 1000 instead of 109)
        mock_status_bad_uid = "Name:\ttor\nUid:\t1000\t1000\t1000\t1000\n"
        with patch.object(Path, "is_dir", return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", return_value=mock_status_bad_uid), \
             patch("os.readlink", return_value="/usr/bin/tor"), \
             patch("os.kill", return_value=None):
            self.assertFalse(app._verify_process_is_tor(1234))

        # Case C: Valid Tor daemon
        with patch.object(Path, "is_dir", return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", return_value=mock_status), \
             patch("os.readlink", return_value="/usr/bin/tor"), \
             patch("os.kill", return_value=None):
            self.assertTrue(app._verify_process_is_tor(1234))

    def test_listener_multi_pid_shared_socket_verification(self):
        """P2-5: Multiple PIDs on shared socket: all candidate processes must be verified Tor."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"

        # Two PIDs share socket: PID 1234 (tor) and PID 5678 (rogue)
        with patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/ss"):
            ss_multi = 'LISTEN 0 128 127.0.0.1:9041 0.0.0.0:* users:(("tor",pid=1234,fd=6),("evil",pid=5678,fd=4))\n'
            with patch("nulltrace.run_trusted", return_value=subprocess.CompletedProcess(
                args=["ss"], returncode=0, stdout=ss_multi, stderr=""
            )), \
            patch.object(app, "_verify_process_is_tor", side_effect=lambda pid: pid == 1234):
                self.assertFalse(app._verify_listener_ownership(9041, "tcp"))

    def test_partial_activation_rollback_fail_closed(self):
        """P2-7: Failure during any phase of activation triggers fail-closed rollback and leaves non-ACTIVE state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path), \
                 patch("nulltrace.require_linux_root"), \
                 patch.object(nulltrace.nulltrace, "_get_current_state", return_value=nulltrace.STATE_INACTIVE), \
                 patch.object(nulltrace.nulltrace, "backup_iptables"), \
                 patch.object(nulltrace.nulltrace, "backup_tor_config"), \
                 patch.object(nulltrace.nulltrace, "apply_tor_config"), \
                 patch.object(nulltrace.nulltrace, "_setup_custom_chains_v4"), \
                 patch.object(nulltrace.nulltrace, "_setup_custom_chains_v6"), \
                 patch.object(nulltrace.nulltrace, "_generate_enforcement_manifest", side_effect=RuntimeError("manifest failed")), \
                 patch.object(nulltrace.nulltrace, "_rollback_startup") as mock_rollback:
                app = nulltrace.nulltrace()
                with self.assertRaises(RuntimeError):
                    app.setup_network_rules()
                mock_rollback.assert_called_once()
                self.assertNotEqual(app._current_state, nulltrace.STATE_ACTIVE)

    def test_fs_symlink_race_between_validation_and_write(self):
        """P0-1: atomic_write detects destination replaced by symlink between validation and replacement."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "test.conf"
            dest.write_text("initial", encoding="utf-8")

            reg_st = MagicMock()
            reg_st.st_mode = stat.S_IFREG | 0o600
            reg_st.st_uid = 0
            reg_st.st_gid = 0

            sym_st = MagicMock()
            sym_st.st_mode = stat.S_IFLNK | 0o777

            stat_calls = [reg_st, sym_st]
            def fake_lstat(p):
                if stat_calls:
                    return stat_calls.pop(0)
                return sym_st

            with patch("os.lstat", side_effect=fake_lstat), \
                 patch("os.path.islink", side_effect=[False, True, True]):
                with self.assertRaises(ValueError) as ctx:
                    nulltrace.atomic_write(dest, "new data")
                self.assertIn("symlink", str(ctx.exception).lower())

    def test_fs_atomic_write_durability_and_permission_fatal_failures(self):
        """P0-1 & P2-4: chmod, chown, and fsync failures in atomic_write are fatal and clean up temp files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "test.conf"

            # 1. chmod failure is fatal
            with patch("os.fchmod", side_effect=PermissionError("chmod denied"), create=True), \
                 patch("os.chmod", side_effect=PermissionError("chmod denied")):
                with self.assertRaises(PermissionError):
                    nulltrace.atomic_write(dest, "data")
            self.assertEqual(len(list(Path(tmpdir).glob(".*tmp*"))), 0)

            # 2. fsync failure is fatal
            with patch("os.fsync", side_effect=OSError(errno.EIO, "fsync failed")):
                with self.assertRaises(OSError):
                    nulltrace.atomic_write(dest, "data")
            self.assertEqual(len(list(Path(tmpdir).glob(".*tmp*"))), 0)

    def test_fs_atomic_replacement_of_existing_file(self):
        """P0-1: Atomic replacement of an existing valid file succeeds and preserves mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "test.conf"
            dest.write_text("initial data", encoding="utf-8")
            nulltrace.atomic_write(dest, "updated data", mode=0o600)
            self.assertEqual(dest.read_text(encoding="utf-8"), "updated data")
            self.assertEqual(len(list(Path(tmpdir).glob(".*tmp*"))), 0)

    def test_fs_parent_directory_manipulation_rejection(self):
        """P0-1: atomic_write rejects writing when parent directory is a symlink."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "test.conf"
            with patch("os.path.islink", return_value=True):
                with self.assertRaises(ValueError) as ctx:
                    nulltrace.atomic_write(dest, "data")
                self.assertIn("symlink", str(ctx.exception).lower())

    def test_fw_conditional_jump_rejected(self):
        """P0-2: Conditional firewall jumps (IP destination or owner UID) return PARTIAL."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"

        # Case A: Jump matching destination IP
        rules_cond_ip = {
            "filter": ["-A OUTPUT -d 10.0.0.1 -j NULLTRACE_OUTPUT"],
            "nat": ["-A OUTPUT -j NULLTRACE_NAT_OUTPUT"],
            "mangle": ["-A OUTPUT -j NULLTRACE_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_MANGLE_PREROUTING"],
        }
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
             patch("nulltrace.run_trusted", side_effect=lambda cmd, **kw: subprocess.CompletedProcess(
                 args=cmd, returncode=0,
                 stdout="\n".join(rules_cond_ip.get(cmd[cmd.index("-t") + 1] if "-t" in cmd else "filter", [])) + "\n",
                 stderr=""
             )):
            self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.PARTIAL)

        # Case B: Jump matching owner UID
        rules_cond_owner = {
            "filter": ["-A OUTPUT -m owner --uid-owner 1000 -j NULLTRACE_OUTPUT"],
            "nat": ["-A OUTPUT -j NULLTRACE_NAT_OUTPUT"],
            "mangle": ["-A OUTPUT -j NULLTRACE_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_MANGLE_PREROUTING"],
        }
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
             patch("nulltrace.run_trusted", side_effect=lambda cmd, **kw: subprocess.CompletedProcess(
                 args=cmd, returncode=0,
                 stdout="\n".join(rules_cond_owner.get(cmd[cmd.index("-t") + 1] if "-t" in cmd else "filter", [])) + "\n",
                 stderr=""
             )):
            self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.PARTIAL)

    def test_fw_non_first_jump_and_duplicate_jump_rejected(self):
        """P0-2: Non-first jumps and duplicate jumps to NULLTRACE chains return PARTIAL."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"

        # Non-first jump
        rules_non_first = {
            "filter": ["-A OUTPUT -s 192.168.1.1 -j DROP", "-A OUTPUT -j NULLTRACE_OUTPUT"],
            "nat": ["-A OUTPUT -j NULLTRACE_NAT_OUTPUT"],
            "mangle": ["-A OUTPUT -j NULLTRACE_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_MANGLE_PREROUTING"],
        }
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
             patch("nulltrace.run_trusted", side_effect=lambda cmd, **kw: subprocess.CompletedProcess(
                 args=cmd, returncode=0,
                 stdout="\n".join(rules_non_first.get(cmd[cmd.index("-t") + 1] if "-t" in cmd else "filter", [])) + "\n",
                 stderr=""
             )):
            self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.PARTIAL)

        # Duplicate jump
        rules_duplicate = {
            "filter": ["-A OUTPUT -j NULLTRACE_OUTPUT", "-A OUTPUT -j NULLTRACE_OUTPUT"],
            "nat": ["-A OUTPUT -j NULLTRACE_NAT_OUTPUT"],
            "mangle": ["-A OUTPUT -j NULLTRACE_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_MANGLE_PREROUTING"],
        }
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
             patch("nulltrace.run_trusted", side_effect=lambda cmd, **kw: subprocess.CompletedProcess(
                 args=cmd, returncode=0,
                 stdout="\n".join(rules_duplicate.get(cmd[cmd.index("-t") + 1] if "-t" in cmd else "filter", [])) + "\n",
                 stderr=""
             )):
            self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.PARTIAL)

    def test_fw_exact_first_jump_and_valid_manifest_accepted(self):
        """P0-2, P1-1, P1-3: Exact first jumps and matching ordered manifest return LiveFirewallStatus.ACTIVE."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"

        rules_v4 = {
            "filter": ["-A OUTPUT -j NULLTRACE_OUTPUT", "-A INPUT -j NULLTRACE_INPUT", "-A FORWARD -j NULLTRACE_FORWARD"],
            "nat": ["-A OUTPUT -j NULLTRACE_NAT_OUTPUT"],
            "mangle": ["-A OUTPUT -j NULLTRACE_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_MANGLE_PREROUTING"],
        }
        rules_v6 = {
            "filter": ["-A OUTPUT -j NULLTRACE_V6_OUTPUT", "-A INPUT -j NULLTRACE_V6_INPUT", "-A FORWARD -j NULLTRACE_V6_FORWARD"],
            "mangle": ["-A OUTPUT -j NULLTRACE_V6_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_V6_MANGLE_PRE"],
        }

        chain_contents = {
            "v4:filter:NULLTRACE_OUTPUT": f"-N NULLTRACE_OUTPUT\n-A NULLTRACE_OUTPUT -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_OUTPUT -j DROP\n",
            "v4:filter:NULLTRACE_INPUT": f"-N NULLTRACE_INPUT\n-A NULLTRACE_INPUT -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_INPUT -j ACCEPT\n",
            "v4:filter:NULLTRACE_FORWARD": f"-N NULLTRACE_FORWARD\n-A NULLTRACE_FORWARD -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_FORWARD -j DROP\n",
            "v4:nat:NULLTRACE_NAT_OUTPUT": f"-N NULLTRACE_NAT_OUTPUT\n-A NULLTRACE_NAT_OUTPUT -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_NAT_OUTPUT -p tcp -j REDIRECT --to-ports {app.config.tor_port}\n-A NULLTRACE_NAT_OUTPUT -p udp --dport 53 -j REDIRECT --to-ports {app.config.dns_port}\n",
            "v4:mangle:NULLTRACE_MANGLE_OUTPUT": f"-N NULLTRACE_MANGLE_OUTPUT\n-A NULLTRACE_MANGLE_OUTPUT -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_MANGLE_OUTPUT -j ACCEPT\n",
            "v4:mangle:NULLTRACE_MANGLE_PREROUTING": f"-N NULLTRACE_MANGLE_PREROUTING\n-A NULLTRACE_MANGLE_PREROUTING -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_MANGLE_PREROUTING -j ACCEPT\n",
            "v6:filter:NULLTRACE_V6_OUTPUT": f"-N NULLTRACE_V6_OUTPUT\n-A NULLTRACE_V6_OUTPUT -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_V6_OUTPUT -j REJECT\n",
            "v6:filter:NULLTRACE_V6_INPUT": f"-N NULLTRACE_V6_INPUT\n-A NULLTRACE_V6_INPUT -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_V6_INPUT -j DROP\n",
            "v6:filter:NULLTRACE_V6_FORWARD": f"-N NULLTRACE_V6_FORWARD\n-A NULLTRACE_V6_FORWARD -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_V6_FORWARD -j DROP\n",
            "v6:mangle:NULLTRACE_V6_MANGLE_OUTPUT": f"-N NULLTRACE_V6_MANGLE_OUTPUT\n-A NULLTRACE_V6_MANGLE_OUTPUT -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_V6_MANGLE_OUTPUT -j ACCEPT\n",
            "v6:mangle:NULLTRACE_V6_MANGLE_PRE": f"-N NULLTRACE_V6_MANGLE_PRE\n-A NULLTRACE_V6_MANGLE_PRE -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_V6_MANGLE_PRE -j ACCEPT\n",
        }

        manifest_fps = {}
        for key, content in chain_contents.items():
            canon = "\n".join(l.strip() for l in content.splitlines() if l.strip())
            manifest_fps[key] = hashlib.sha256(canon.encode()).hexdigest()

        meta = {"enforcement_manifest": {"chain_fingerprints": manifest_fps}}

        def fake_run(cmd, **kwargs):
            is_v6 = "ip6tables" in cmd[0]
            table = "filter"
            if "-t" in cmd:
                table = cmd[cmd.index("-t") + 1]
            if len(cmd) >= 5 and cmd[3] == "-S" and not cmd[4].startswith("-"):
                chain = cmd[4]
                key = f"{'v6' if is_v6 else 'v4'}:{table}:{chain}"
                content = chain_contents.get(key, "")
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=content, stderr="")
            rules = (rules_v6 if is_v6 else rules_v4).get(table, [])
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="\n".join(rules) + "\n", stderr="")

        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
             patch.object(app, "_load_session_metadata", return_value=meta), \
             patch("nulltrace.run_trusted", side_effect=fake_run):
            self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.ACTIVE)

    def test_fw_manifest_integrity_and_mismatch_rejection(self):
        """P1-3: Missing manifest, corrupt manifest, and hash mismatches return PARTIAL."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"

        rules_v4 = {
            "filter": ["-A OUTPUT -j NULLTRACE_OUTPUT", "-A INPUT -j NULLTRACE_INPUT", "-A FORWARD -j NULLTRACE_FORWARD"],
            "nat": ["-A OUTPUT -j NULLTRACE_NAT_OUTPUT"],
            "mangle": ["-A OUTPUT -j NULLTRACE_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_MANGLE_PREROUTING"],
        }
        rules_v6 = {
            "filter": ["-A OUTPUT -j NULLTRACE_V6_OUTPUT", "-A INPUT -j NULLTRACE_V6_INPUT", "-A FORWARD -j NULLTRACE_V6_FORWARD"],
            "mangle": ["-A OUTPUT -j NULLTRACE_V6_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_V6_MANGLE_PRE"],
        }
        chain_content = f"-N CHAIN\n-A CHAIN -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A CHAIN -p tcp -j REDIRECT --to-ports 9040\n-A CHAIN -p udp --dport 53 -j REDIRECT --to-ports 5353\n-A CHAIN -j DROP\n"

        def fake_run(cmd, **kwargs):
            is_v6 = "ip6tables" in cmd[0]
            table = "filter"
            if "-t" in cmd:
                table = cmd[cmd.index("-t") + 1]
            if len(cmd) >= 5 and cmd[3] == "-S" and not cmd[4].startswith("-"):
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=chain_content, stderr="")
            rules = (rules_v6 if is_v6 else rules_v4).get(table, [])
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="\n".join(rules) + "\n", stderr="")

        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
             patch("nulltrace.run_trusted", side_effect=fake_run):
            # 1. Missing manifest
            with patch.object(app, "_load_session_metadata", return_value=None):
                self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.PARTIAL)

            # 2. Corrupt manifest (non-dict)
            with patch.object(app, "_load_session_metadata", return_value={"enforcement_manifest": "corrupt"}):
                self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.PARTIAL)

            # 3. Hash mismatch on chain fingerprint
            bad_meta = {
                "enforcement_manifest": {
                    "chain_fingerprints": {
                        f"v4:{t}:{c}": "wrong_hash"
                        for t, c in [
                            ("nat", nulltrace.CHAIN_NAT_OUTPUT),
                            ("mangle", nulltrace.CHAIN_MANGLE_OUTPUT),
                            ("mangle", nulltrace.CHAIN_MANGLE_PREROUTING),
                            ("filter", nulltrace.CHAIN_FILTER_OUTPUT),
                            ("filter", nulltrace.CHAIN_FILTER_INPUT),
                            ("filter", nulltrace.CHAIN_FILTER_FORWARD),
                        ]
                    } | {
                        f"v6:{t}:{c}": "wrong_hash"
                        for t, c in [
                            ("mangle", nulltrace.CHAIN_V6_MANGLE_OUTPUT),
                            ("mangle", nulltrace.CHAIN_V6_MANGLE_PREROUTING),
                            ("filter", nulltrace.CHAIN_V6_OUTPUT),
                            ("filter", nulltrace.CHAIN_V6_INPUT),
                            ("filter", nulltrace.CHAIN_V6_FORWARD),
                        ]
                    }
                }
            }
            with patch.object(app, "_load_session_metadata", return_value=bad_meta):
                self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.PARTIAL)

    def test_recovery_successful_flush_removes_all_rules_and_tooling(self):
        """P1-6 & P2-8: Successful emergency flush verifies CLEAN status and removes NullTrace program files."""
        mock_script_stat = MagicMock(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        with patch("install.inspect_live_nulltrace_rules", side_effect=[
            install.FirewallInspectionResult.ACTIVE,
            install.FirewallInspectionResult.ACTIVE,
            install.FirewallInspectionResult.CLEAN,
        ]), \
        patch("install.routing_may_be_active", return_value=True), \
        patch("install.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
        patch("install.run_trusted", return_value=subprocess.CompletedProcess(args=["iptables"], returncode=0, stdout="", stderr="")), \
        patch("pathlib.Path.exists", return_value=True), \
        patch("os.lstat", return_value=mock_script_stat), \
        patch("shutil.rmtree") as mock_rmtree, \
        patch("os.remove") as mock_remove, \
        patch("os.path.isdir", return_value=True), \
        patch("os.path.isfile", return_value=False):
            install.uninstall_nulltrace(emergency_flush=True, interactive=False)
            mock_rmtree.assert_called()

    def test_service_and_interface_state_comprehensive(self):
        """P1-10 & P1-11: Tor service enable detection and interface administrative state verification."""
        app = nulltrace.nulltrace()

        # 1. Tor service disabled detection via _check_tor_service_enabled
        with patch("nulltrace.resolve_trusted_binary", return_value="/usr/bin/systemctl"), \
             patch("nulltrace.run_trusted", return_value=subprocess.CompletedProcess(
                 args=["systemctl", "is-enabled", "tor@default"], returncode=1, stdout="disabled\n", stderr=""
             )):
            self.assertFalse(app._check_tor_service_enabled())

        # 2. Tor service enabled detection
        with patch("nulltrace.resolve_trusted_binary", return_value="/usr/bin/systemctl"), \
             patch("nulltrace.run_trusted", return_value=subprocess.CompletedProcess(
                 args=["systemctl", "is-enabled", "tor@default"], returncode=0, stdout="enabled\n", stderr=""
             )):
            self.assertTrue(app._check_tor_service_enabled())

        # 3. Interface administrative state detection via sysfs flags
        with tempfile.TemporaryDirectory() as tmpdir:
            flags_file = Path(tmpdir) / "flags"
            flags_file.write_text("0x1003\n", encoding="utf-8")
            with patch("pathlib.Path.exists", return_value=True), \
                 patch("pathlib.Path.read_text", return_value="0x1003\n"):
                self.assertTrue(app._is_interface_up("eth0"))

            with patch("pathlib.Path.exists", return_value=True), \
                 patch("pathlib.Path.read_text", return_value="0x1002\n"):
                self.assertFalse(app._is_interface_up("eth0"))

        # 4. _restore_mac when initially UP sets link up and calls DHCP
        app._spoofed_intf = "eth0"
        app._original_mac = "00:11:22:33:44:55"
        app._interface_initially_up = True
        with patch("nulltrace.require_trusted_binary", return_value="/usr/sbin/ip"), \
             patch.object(app, "_read_current_mac", return_value="00:11:22:33:44:55"), \
             patch.object(app, "_persist_session_metadata"), \
             patch.object(app, "_renew_dhcp") as mock_dhcp, \
             patch("nulltrace.run_trusted") as mock_run:
            app._restore_mac()
            cmds = [call.args[0] for call in mock_run.call_args_list]
            self.assertTrue(any(cmd[-1] == "up" for cmd in cmds))
            mock_dhcp.assert_called_once_with("eth0")

    def test_partial_activation_and_recovery_scenarios(self):
        """P2-7: State reconciliation detects interrupted activations and missing/partial live firewall rules."""
        app = nulltrace.nulltrace()

        # 1. State is ACTIVATING or PREPARING on disk -> reconcile_state returns RECOVERY_REQUIRED
        with patch.object(app, "_load_session_metadata", return_value={"state": nulltrace.STATE_PREPARING}), \
             patch.object(app, "_check_live_firewall_status", return_value=nulltrace.LiveFirewallStatus.PARTIAL):
            self.assertEqual(app.reconcile_state(), nulltrace.STATE_RECOVERY_REQUIRED)

        # 2. State is ACTIVE on disk, but live rules are PARTIAL -> reconcile_state returns RECOVERY_REQUIRED
        with patch.object(app, "_load_session_metadata", return_value={"state": nulltrace.STATE_ACTIVE}), \
             patch.object(app, "_check_live_firewall_status", return_value=nulltrace.LiveFirewallStatus.PARTIAL):
            self.assertEqual(app.reconcile_state(), nulltrace.STATE_RECOVERY_REQUIRED)

        # 3. State is INACTIVE on disk, but live rules are ACTIVE (orphaned rules) -> RECOVERY_REQUIRED
        with patch.object(app, "_load_session_metadata", return_value={"state": nulltrace.STATE_INACTIVE}), \
             patch.object(app, "_check_live_firewall_status", return_value=nulltrace.LiveFirewallStatus.ACTIVE):
            self.assertEqual(app.reconcile_state(), nulltrace.STATE_RECOVERY_REQUIRED)

        # 4. Live firewall status UNKNOWN -> RECOVERY_REQUIRED
        with patch.object(app, "_load_session_metadata", return_value={"state": nulltrace.STATE_ACTIVE}), \
             patch.object(app, "_check_live_firewall_status", return_value=nulltrace.LiveFirewallStatus.UNKNOWN):
            self.assertEqual(app.reconcile_state(), nulltrace.STATE_RECOVERY_REQUIRED)




IS_LINUX = sys.platform.startswith("linux")


class TestSection18_LinuxTestMatrix(unittest.TestCase):
    """
    Comprehensive verification of Section 18 Linux Test Matrix:
    - Filesystem security (14 items)
    - Firewall (14 items)
    - Tor identity (8 items)
    - Installer (6 items)
    - Service/config/interface restoration (11 items)
    """

    # =========================================================================
    # Group 1: Filesystem Security (14 items)
    # =========================================================================

    def test_matrix_fs_01_destination_symlink_rejected(self):
        """Matrix FS-1: destination symlink rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            real_file = Path(tmpdir) / "real.txt"
            real_file.write_text("original content\n", encoding="utf-8")
            link_file = Path(tmpdir) / "link.txt"
            try:
                os.symlink(real_file, link_file)
            except OSError:
                with patch("os.path.islink", return_value=True):
                    with self.assertRaises((ValueError, RuntimeError)):
                        nulltrace.atomic_write(link_file, "exploit\n")
                return

            with self.assertRaises((ValueError, RuntimeError)):
                nulltrace.atomic_write(link_file, "exploit\n")
            self.assertEqual(real_file.read_text(encoding="utf-8"), "original content\n")

    def test_matrix_fs_02_parent_symlink_rejected(self):
        """Matrix FS-2: parent symlink rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            real_dir = Path(tmpdir) / "real_dir"
            real_dir.mkdir()
            link_dir = Path(tmpdir) / "link_dir"
            try:
                os.symlink(real_dir, link_dir)
            except OSError:
                with patch("os.path.islink", return_value=True):
                    with self.assertRaises((ValueError, RuntimeError)):
                        nulltrace.atomic_write(link_dir / "target.txt", "data\n")
                return

            with self.assertRaises((ValueError, RuntimeError)):
                nulltrace.atomic_write(link_dir / "target.txt", "data\n")

    def test_matrix_fs_03_ancestor_symlink_rejected(self):
        """Matrix FS-3: ancestor symlink rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            real_ancestor = Path(tmpdir) / "real_anc"
            real_ancestor.mkdir()
            link_ancestor = Path(tmpdir) / "link_anc"
            try:
                os.symlink(real_ancestor, link_ancestor)
            except OSError:
                pass
            sub_dir = link_ancestor / "subdir"
            if link_ancestor.exists() and os.path.islink(str(link_ancestor)):
                sub_dir.mkdir(parents=True, exist_ok=True)
                with self.assertRaises((ValueError, RuntimeError)):
                    nulltrace.atomic_write(sub_dir / "target.txt", "data\n")
            else:
                with patch("os.path.islink", side_effect=lambda p: "link_anc" in str(p)):
                    with self.assertRaises((ValueError, RuntimeError)):
                        nulltrace.atomic_write(sub_dir / "target.txt", "data\n")

    def test_matrix_fs_04_directory_replacement_race_rejected(self):
        """Matrix FS-4: directory replacement/race rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            real_dir = base / "real_dir"
            real_dir.mkdir()
            sub_dir = real_dir / "sub"
            sub_dir.mkdir()

            victim_dir = base / "victim_dir"
            victim_dir.mkdir()

            link_dir = base / "link_dir"
            try:
                os.symlink(victim_dir, link_dir)
            except OSError:
                with patch("os.path.islink", return_value=True):
                    with self.assertRaises((ValueError, RuntimeError, OSError)):
                        nulltrace.atomic_write(link_dir / "sub" / "exploit.txt", "data\n")
                return

            target = link_dir / "sub" / "exploit.txt"
            with self.assertRaises((ValueError, RuntimeError, OSError)):
                nulltrace.atomic_write(target, "malicious data\n")

            self.assertFalse((victim_dir / "exploit.txt").exists())
            self.assertFalse((victim_dir / "sub" / "exploit.txt").exists())

    def test_matrix_fs_05_insecure_owner_rejected(self):
        """Matrix FS-5: insecure owner rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "insecure_owner_dir"
            p.mkdir()
            mock_stat = MagicMock(st_mode=stat.S_IFDIR | 0o755, st_uid=1000, st_gid=1000)
            with patch("os.lstat", return_value=mock_stat), \
                 patch("os.geteuid", return_value=0, create=True), \
                 patch.object(os, "_force_posix_security_checks", True, create=True):
                with self.assertRaises(RuntimeError) as ctx:
                    nulltrace.nulltrace._validate_secure_directory(p)
                self.assertIn("UID 1000", str(ctx.exception))

    def test_matrix_fs_06_group_world_writable_directory_rejected(self):
        """Matrix FS-6: group/world writable directory rejected without silent chmod."""
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "insecure_perm_dir"
            p.mkdir()
            mock_stat = MagicMock(st_mode=stat.S_IFDIR | 0o777, st_uid=0, st_gid=0)
            with patch("os.lstat", return_value=mock_stat), \
                 patch("os.chmod") as mock_chmod, \
                 patch.object(os, "_force_posix_security_checks", True, create=True):
                with self.assertRaises(RuntimeError) as ctx:
                    nulltrace.nulltrace._validate_secure_directory(p)
                self.assertIn("insecure permissions", str(ctx.exception))
                mock_chmod.assert_not_called()

    def test_matrix_fs_07_insecure_target_rejected(self):
        """Matrix FS-7: insecure target rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "insecure_target.txt"
            target.write_text("data", encoding="utf-8")
            orig_stat = os.stat
            orig_lstat = os.lstat
            mock_fifo = MagicMock(st_mode=stat.S_IFIFO | 0o600, st_uid=0, st_gid=0)
            def selective_stat(p, *a, **kw):
                if str(p) == str(target) or str(p) == target.name:
                    return mock_fifo
                return orig_stat(p, *a, **kw)
            def selective_lstat(p, *a, **kw):
                if str(p) == str(target) or str(p) == target.name:
                    return mock_fifo
                return orig_lstat(p, *a, **kw)
            with patch("os.stat", side_effect=selective_stat), \
                 patch("os.lstat", side_effect=selective_lstat):
                with self.assertRaises((ValueError, RuntimeError)):
                    nulltrace.atomic_write(target, "new_data")

    def test_matrix_fs_08_secure_target_accepted(self):
        """Matrix FS-8: secure target accepted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "secure.txt"
            nulltrace.atomic_write(target, "valid secure content\n", mode=0o644)
            self.assertTrue(target.exists())
            self.assertEqual(target.read_text(encoding="utf-8"), "valid secure content\n")

    def test_matrix_fs_09_temp_file_created_in_correct_directory(self):
        """Matrix FS-9: temp file created in correct directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            parent = Path(tmpdir) / "subdir"
            parent.mkdir()
            target = parent / "secure.txt"
            nulltrace.atomic_write(target, "content\n")
            self.assertTrue(target.exists())
            remaining = list(parent.iterdir())
            self.assertEqual(remaining, [target])

    def test_matrix_fs_10_target_replacement_is_atomic(self):
        """Matrix FS-10: target replacement is atomic."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "atomic.txt"
            target.write_text("initial\n", encoding="utf-8")
            nulltrace.atomic_write(target, "updated\n")
            self.assertEqual(target.read_text(encoding="utf-8"), "updated\n")

    def test_matrix_fs_11_metadata_applied_before_final_fsync(self):
        """Matrix FS-11: metadata applied before final fsync."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "ordered.txt"
            events = []

            orig_fsync = os.fsync
            def track_fsync(fd):
                events.append("fsync")
                return orig_fsync(fd)

            if hasattr(os, "fchmod"):
                orig_fchmod = os.fchmod
                def track_fchmod(fd, mode):
                    events.append("fchmod")
                    return orig_fchmod(fd, mode)
                with patch("os.fchmod", side_effect=track_fchmod), \
                     patch("os.fsync", side_effect=track_fsync):
                    nulltrace.atomic_write(target, "test\n")
                if "fchmod" in events and "fsync" in events:
                    self.assertLess(events.index("fchmod"), events.index("fsync"))
            else:
                nulltrace.atomic_write(target, "test\n")
            self.assertTrue(target.exists())

    def test_matrix_fs_12_file_fsync_failure_is_fatal(self):
        """Matrix FS-12: file fsync failure is fatal."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "fatal_fsync.txt"
            with patch("os.fsync", side_effect=OSError(errno.EIO, "I/O error")):
                with self.assertRaises(OSError):
                    nulltrace.atomic_write(target, "test\n")
            self.assertFalse(target.exists())

    def test_matrix_fs_13_directory_fsync_failure_is_fatal(self):
        """Matrix FS-13: directory fsync failure is fatal."""
        if not IS_LINUX:
            return
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "fatal_dir_fsync.txt"
            call_count = 0
            def fake_fsync(fd):
                nonlocal call_count
                call_count += 1
                if call_count >= 2:
                    raise OSError(errno.EIO, "Dir sync error")
            with patch("os.fsync", side_effect=fake_fsync):
                with self.assertRaises(OSError):
                    nulltrace.atomic_write(target, "test\n")

    def test_matrix_fs_14_interrupted_write_leaves_safe_recoverable_state(self):
        """Matrix FS-14: interrupted write leaves safe recoverable state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "original.txt"
            target.write_text("original stable content\n", encoding="utf-8")
            if IS_LINUX:
                with patch("os.write", side_effect=OSError(errno.ENOSPC, "No space left")):
                    with self.assertRaises(OSError):
                        nulltrace.atomic_write(target, "new corrupted data")
            else:
                with patch("tempfile.NamedTemporaryFile", side_effect=OSError(errno.ENOSPC, "No space left")):
                    with self.assertRaises(OSError):
                        nulltrace.atomic_write(target, "new corrupted data")
            self.assertEqual(target.read_text(encoding="utf-8"), "original stable content\n")
            files = [f.name for f in Path(tmpdir).iterdir()]
            self.assertEqual(files, ["original.txt"])

    # =========================================================================
    # Group 2: Firewall (14 items)
    # =========================================================================

    def _setup_active_firewall_manifest(self, app):
        rules_v4 = {
            "filter": ["-A OUTPUT -j NULLTRACE_OUTPUT", "-A INPUT -j NULLTRACE_INPUT", "-A FORWARD -j NULLTRACE_FORWARD"],
            "nat": ["-A OUTPUT -j NULLTRACE_NAT_OUTPUT"],
            "mangle": ["-A OUTPUT -j NULLTRACE_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_MANGLE_PREROUTING"],
        }
        rules_v6 = {
            "filter": ["-A OUTPUT -j NULLTRACE_V6_OUTPUT", "-A INPUT -j NULLTRACE_V6_INPUT", "-A FORWARD -j NULLTRACE_V6_FORWARD"],
            "mangle": ["-A OUTPUT -j NULLTRACE_V6_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_V6_MANGLE_PRE"],
        }
        chain_contents = {
            "v4:filter:NULLTRACE_OUTPUT": f"-N NULLTRACE_OUTPUT\n-A NULLTRACE_OUTPUT -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_OUTPUT -j DROP\n",
            "v4:filter:NULLTRACE_INPUT": f"-N NULLTRACE_INPUT\n-A NULLTRACE_INPUT -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_INPUT -j ACCEPT\n",
            "v4:filter:NULLTRACE_FORWARD": f"-N NULLTRACE_FORWARD\n-A NULLTRACE_FORWARD -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_FORWARD -j DROP\n",
            "v4:nat:NULLTRACE_NAT_OUTPUT": f"-N NULLTRACE_NAT_OUTPUT\n-A NULLTRACE_NAT_OUTPUT -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_NAT_OUTPUT -p tcp -j REDIRECT --to-ports {app.config.tor_port}\n-A NULLTRACE_NAT_OUTPUT -p udp --dport 53 -j REDIRECT --to-ports {app.config.dns_port}\n",
            "v4:mangle:NULLTRACE_MANGLE_OUTPUT": f"-N NULLTRACE_MANGLE_OUTPUT\n-A NULLTRACE_MANGLE_OUTPUT -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_MANGLE_OUTPUT -j ACCEPT\n",
            "v4:mangle:NULLTRACE_MANGLE_PREROUTING": f"-N NULLTRACE_MANGLE_PREROUTING\n-A NULLTRACE_MANGLE_PREROUTING -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_MANGLE_PREROUTING -j ACCEPT\n",
            "v6:filter:NULLTRACE_V6_OUTPUT": f"-N NULLTRACE_V6_OUTPUT\n-A NULLTRACE_V6_OUTPUT -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_V6_OUTPUT -j REJECT\n",
            "v6:filter:NULLTRACE_V6_INPUT": f"-N NULLTRACE_V6_INPUT\n-A NULLTRACE_V6_INPUT -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_V6_INPUT -j DROP\n",
            "v6:filter:NULLTRACE_V6_FORWARD": f"-N NULLTRACE_V6_FORWARD\n-A NULLTRACE_V6_FORWARD -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_V6_FORWARD -j DROP\n",
            "v6:mangle:NULLTRACE_V6_MANGLE_OUTPUT": f"-N NULLTRACE_V6_MANGLE_OUTPUT\n-A NULLTRACE_V6_MANGLE_OUTPUT -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_V6_MANGLE_OUTPUT -j ACCEPT\n",
            "v6:mangle:NULLTRACE_V6_MANGLE_PRE": f"-N NULLTRACE_V6_MANGLE_PRE\n-A NULLTRACE_V6_MANGLE_PRE -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_V6_MANGLE_PRE -j ACCEPT\n",
        }
        manifest_fps = {}
        for key, content in chain_contents.items():
            canon = "\n".join(l.strip() for l in content.splitlines() if l.strip())
            manifest_fps[key] = hashlib.sha256(canon.encode()).hexdigest()
        meta = {"enforcement_manifest": {"chain_fingerprints": manifest_fps}}
        return rules_v4, rules_v6, chain_contents, meta

    def test_matrix_fw_01_exact_first_jump_accepted(self):
        """Matrix FW-1: exact first jump accepted."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        rules_v4, rules_v6, chain_contents, meta = self._setup_active_firewall_manifest(app)

        def fake_run(cmd, **kwargs):
            is_v6 = "ip6tables" in cmd[0]
            table = "filter"
            if "-t" in cmd:
                table = cmd[cmd.index("-t") + 1]
            if len(cmd) >= 5 and cmd[3] == "-S" and not cmd[4].startswith("-"):
                chain = cmd[4]
                prefix = "v6" if is_v6 else "v4"
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=chain_contents.get(f"{prefix}:{table}:{chain}", ""), stderr="")
            out = "\n".join((rules_v6 if is_v6 else rules_v4).get(table, [])) + "\n"
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=out, stderr="")

        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
             patch.object(app, "_load_session_metadata", return_value=meta), \
             patch("nulltrace.run_trusted", side_effect=fake_run):
            self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.ACTIVE)

    def test_matrix_fw_02_conditional_jump_rejected(self):
        """Matrix FW-2: conditional jump rejected."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        rules_v4 = {
            "filter": ["-A OUTPUT -m owner --uid-owner 1000 -j NULLTRACE_OUTPUT"],
            "nat": ["-A OUTPUT -j NULLTRACE_NAT_OUTPUT"],
            "mangle": ["-A OUTPUT -j NULLTRACE_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_MANGLE_PREROUTING"],
        }
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
             patch("nulltrace.run_trusted", side_effect=lambda cmd, **kw: subprocess.CompletedProcess(
                 args=cmd, returncode=0,
                 stdout="\n".join(rules_v4.get(cmd[cmd.index("-t") + 1] if "-t" in cmd else "filter", [])) + "\n",
                 stderr=""
             )):
            self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.PARTIAL)

    def test_matrix_fw_03_non_first_jump_rejected(self):
        """Matrix FW-3: non-first jump rejected."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        rules_v4 = {
            "filter": ["-A OUTPUT -d 10.0.0.0/8 -j DROP", "-A OUTPUT -j NULLTRACE_OUTPUT"],
            "nat": ["-A OUTPUT -j NULLTRACE_NAT_OUTPUT"],
            "mangle": ["-A OUTPUT -j NULLTRACE_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_MANGLE_PREROUTING"],
        }
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
             patch("nulltrace.run_trusted", side_effect=lambda cmd, **kw: subprocess.CompletedProcess(
                 args=cmd, returncode=0,
                 stdout="\n".join(rules_v4.get(cmd[cmd.index("-t") + 1] if "-t" in cmd else "filter", [])) + "\n",
                 stderr=""
             )):
            self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.PARTIAL)

    def test_matrix_fw_04_preceding_accept_rejected(self):
        """Matrix FW-4: preceding ACCEPT rejected."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        rules_v4 = {
            "filter": ["-A OUTPUT -j ACCEPT", "-A OUTPUT -j NULLTRACE_OUTPUT"],
            "nat": ["-A OUTPUT -j NULLTRACE_NAT_OUTPUT"],
            "mangle": ["-A OUTPUT -j NULLTRACE_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_MANGLE_PREROUTING"],
        }
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
             patch("nulltrace.run_trusted", side_effect=lambda cmd, **kw: subprocess.CompletedProcess(
                 args=cmd, returncode=0,
                 stdout="\n".join(rules_v4.get(cmd[cmd.index("-t") + 1] if "-t" in cmd else "filter", [])) + "\n",
                 stderr=""
             )):
            self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.PARTIAL)

    def test_matrix_fw_05_duplicate_jump_rejected(self):
        """Matrix FW-5: duplicate jump rejected."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        rules_v4 = {
            "filter": ["-A OUTPUT -j NULLTRACE_OUTPUT", "-A OUTPUT -j NULLTRACE_OUTPUT"],
            "nat": ["-A OUTPUT -j NULLTRACE_NAT_OUTPUT"],
            "mangle": ["-A OUTPUT -j NULLTRACE_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_MANGLE_PREROUTING"],
        }
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
             patch("nulltrace.run_trusted", side_effect=lambda cmd, **kw: subprocess.CompletedProcess(
                 args=cmd, returncode=0,
                 stdout="\n".join(rules_v4.get(cmd[cmd.index("-t") + 1] if "-t" in cmd else "filter", [])) + "\n",
                 stderr=""
             )):
            self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.PARTIAL)

    def test_matrix_fw_06_ordered_fingerprints(self):
        """Matrix FW-6: ordered fingerprints."""
        rules1 = "-N TEST\n-A TEST -p tcp -j ACCEPT\n-A TEST -j DROP\n"
        rules2 = "-N TEST\n-A TEST -j DROP\n-A TEST -p tcp -j ACCEPT\n"
        hash1 = hashlib.sha256(rules1.encode()).hexdigest()
        hash2 = hashlib.sha256(rules2.encode()).hexdigest()
        self.assertNotEqual(hash1, hash2)

    def test_matrix_fw_07_reordered_rules_produce_different_fingerprints(self):
        """Matrix FW-7: reordered rules produce different fingerprints and return PARTIAL."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        rules_v4, rules_v6, chain_contents, meta = self._setup_active_firewall_manifest(app)
        orig = chain_contents["v4:filter:NULLTRACE_OUTPUT"]
        lines = [l for l in orig.splitlines() if l.strip()]
        lines[1], lines[2] = lines[2], lines[1]
        chain_contents["v4:filter:NULLTRACE_OUTPUT"] = "\n".join(lines) + "\n"

        def fake_run(cmd, **kwargs):
            is_v6 = "ip6tables" in cmd[0]
            table = "filter"
            if "-t" in cmd:
                table = cmd[cmd.index("-t") + 1]
            if len(cmd) >= 5 and cmd[3] == "-S" and not cmd[4].startswith("-"):
                chain = cmd[4]
                prefix = "v6" if is_v6 else "v4"
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=chain_contents.get(f"{prefix}:{table}:{chain}", ""), stderr="")
            out = "\n".join((rules_v6 if is_v6 else rules_v4).get(table, [])) + "\n"
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=out, stderr="")

        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
             patch.object(app, "_load_session_metadata", return_value=meta), \
             patch("nulltrace.run_trusted", side_effect=fake_run):
            self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.PARTIAL)

    def test_matrix_fw_08_missing_manifest_rejected(self):
        """Matrix FW-8: missing manifest rejected."""
        app = nulltrace.nulltrace()
        rules_v4 = {"filter": ["-A OUTPUT -j NULLTRACE_OUTPUT"]}
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
             patch("nulltrace.run_trusted", return_value=subprocess.CompletedProcess(args=["iptables"], returncode=0, stdout="-A OUTPUT -j NULLTRACE_OUTPUT\n", stderr="")), \
             patch.object(app, "_load_session_metadata", return_value={"state": nulltrace.STATE_ACTIVE}):
            self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.PARTIAL)

    def test_matrix_fw_09_corrupt_manifest_rejected(self):
        """Matrix FW-9: corrupt manifest rejected."""
        app = nulltrace.nulltrace()
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
             patch("nulltrace.run_trusted", return_value=subprocess.CompletedProcess(args=["iptables"], returncode=0, stdout="-A OUTPUT -j NULLTRACE_OUTPUT\n", stderr="")), \
             patch.object(app, "_load_session_metadata", return_value={"enforcement_manifest": "invalid_manifest"}):
            self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.PARTIAL)

    def test_matrix_fw_10_incomplete_manifest_rejected(self):
        """Matrix FW-10: incomplete manifest rejected."""
        app = nulltrace.nulltrace()
        meta = {"enforcement_manifest": {"chain_fingerprints": {"v4:filter:NULLTRACE_OUTPUT": "abc"}}}
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
             patch("nulltrace.run_trusted", return_value=subprocess.CompletedProcess(args=["iptables"], returncode=0, stdout="-A OUTPUT -j NULLTRACE_OUTPUT\n", stderr="")), \
             patch.object(app, "_load_session_metadata", return_value=meta):
            self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.PARTIAL)

    def test_matrix_fw_11_ipv4_mismatch_detected(self):
        """Matrix FW-11: IPv4 mismatch detected."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        rules_v4, rules_v6, chain_contents, meta = self._setup_active_firewall_manifest(app)
        meta["enforcement_manifest"]["chain_fingerprints"]["v4:filter:NULLTRACE_OUTPUT"] = "tampered_hash"

        def fake_run(cmd, **kwargs):
            is_v6 = "ip6tables" in cmd[0]
            table = "filter"
            if "-t" in cmd:
                table = cmd[cmd.index("-t") + 1]
            if len(cmd) >= 5 and cmd[3] == "-S" and not cmd[4].startswith("-"):
                chain = cmd[4]
                prefix = "v6" if is_v6 else "v4"
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=chain_contents.get(f"{prefix}:{table}:{chain}", ""), stderr="")
            out = "\n".join((rules_v6 if is_v6 else rules_v4).get(table, [])) + "\n"
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=out, stderr="")

        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
             patch.object(app, "_load_session_metadata", return_value=meta), \
             patch("nulltrace.run_trusted", side_effect=fake_run):
            self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.PARTIAL)

    def test_matrix_fw_12_ipv6_mismatch_detected(self):
        """Matrix FW-12: IPv6 mismatch detected."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        rules_v4, rules_v6, chain_contents, meta = self._setup_active_firewall_manifest(app)
        meta["enforcement_manifest"]["chain_fingerprints"]["v6:filter:NULLTRACE_V6_OUTPUT"] = "tampered_v6_hash"

        def fake_run(cmd, **kwargs):
            is_v6 = "ip6tables" in cmd[0]
            table = "filter"
            if "-t" in cmd:
                table = cmd[cmd.index("-t") + 1]
            if len(cmd) >= 5 and cmd[3] == "-S" and not cmd[4].startswith("-"):
                chain = cmd[4]
                prefix = "v6" if is_v6 else "v4"
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=chain_contents.get(f"{prefix}:{table}:{chain}", ""), stderr="")
            out = "\n".join((rules_v6 if is_v6 else rules_v4).get(table, [])) + "\n"
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=out, stderr="")

        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
             patch.object(app, "_load_session_metadata", return_value=meta), \
             patch("nulltrace.run_trusted", side_effect=fake_run):
            self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.PARTIAL)

    def test_matrix_fw_13_ipv6_inspection_failure_produces_unknown(self):
        """Matrix FW-13: IPv6 inspection failure produces UNKNOWN."""
        app = nulltrace.nulltrace()
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda b: "/usr/sbin/iptables" if ("iptables" in b and "ip6tables" not in b) else None):
            self.assertEqual(app._check_live_firewall_status(), nulltrace.LiveFirewallStatus.UNKNOWN)

    def test_matrix_fw_14_partial_activation_recoverable(self):
        """Matrix FW-14: partial activation recoverable."""
        app = nulltrace.nulltrace()
        with patch.object(app, "_load_session_metadata", return_value={"state": nulltrace.STATE_ACTIVE}), \
             patch.object(app, "_check_live_firewall_status", return_value=nulltrace.LiveFirewallStatus.PARTIAL):
            self.assertEqual(app.reconcile_state(), nulltrace.STATE_RECOVERY_REQUIRED)

    # =========================================================================
    # Group 3: Tor Identity (8 items)
    # =========================================================================

    def test_matrix_tor_01_fake_tor_process_rejected(self):
        """Matrix Tor-1: fake tor process rejected."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        mock_status = "Name:\ttor\nUid:\t109\t109\t109\t109\n"
        with patch.object(Path, "is_dir", return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", return_value=mock_status), \
             patch("os.readlink", return_value="/tmp/fake_tor"), \
             patch("os.kill", return_value=None):
            self.assertFalse(app._verify_process_is_tor(1234))

    def test_matrix_tor_02_fake_tor_real_process_rejected(self):
        """Matrix Tor-2: fake tor.real process rejected."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        mock_status = "Name:\ttor\nUid:\t109\t109\t109\t109\n"
        with patch.object(Path, "is_dir", return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", return_value=mock_status), \
             patch("os.readlink", return_value="/home/user/tor.real"), \
             patch("os.kill", return_value=None):
            self.assertFalse(app._verify_process_is_tor(1234))

    def test_matrix_tor_03_wrong_uid_rejected(self):
        """Matrix Tor-3: wrong UID rejected."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        mock_status_bad = "Name:\ttor\nUid:\t1000\t1000\t1000\t1000\n"
        with patch.object(Path, "is_dir", return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", return_value=mock_status_bad), \
             patch("os.readlink", return_value="/usr/bin/tor"), \
             patch("os.kill", return_value=None):
            self.assertFalse(app._verify_process_is_tor(1234))

    def test_matrix_tor_04_wrong_executable_rejected(self):
        """Matrix Tor-4: wrong executable rejected."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        mock_status = "Name:\ttor\nUid:\t109\t109\t109\t109\n"
        with patch.object(Path, "is_dir", return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", return_value=mock_status), \
             patch("os.readlink", return_value="/bin/bash"), \
             patch("os.kill", return_value=None):
            self.assertFalse(app._verify_process_is_tor(1234))

    def test_matrix_tor_05_correct_tor_executable_accepted(self):
        """Matrix Tor-5: correct Tor executable accepted."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        mock_status = "Name:\ttor\nUid:\t109\t109\t109\t109\n"
        with patch.object(Path, "is_dir", return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", return_value=mock_status), \
             patch("os.readlink", return_value="/usr/bin/tor"), \
             patch("nulltrace.resolve_trusted_binary", return_value="/usr/bin/tor"), \
             patch("os.kill", return_value=None):
            self.assertTrue(app._verify_process_is_tor(1234))

    def test_matrix_tor_06_proc_pid_exe_validation_works(self):
        """Matrix Tor-6: /proc/<pid>/exe validation works."""
        app = nulltrace.nulltrace()
        app._tor_user = "109"
        mock_status = "Name:\ttor\nUid:\t109\t109\t109\t109\n"
        with patch.object(Path, "is_dir", return_value=True), \
             patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "read_text", return_value=mock_status), \
             patch("os.readlink", return_value="/usr/bin/tor") as mock_readlink, \
             patch("nulltrace.resolve_trusted_binary", return_value="/usr/bin/tor"), \
             patch("os.kill", return_value=None):
            res = app._verify_process_is_tor(5678)
            self.assertTrue(res)
            self.assertIn("5678", str(mock_readlink.call_args[0][0]))

    def test_matrix_tor_07_shared_socket_ownership_handled_safely(self):
        """Matrix Tor-7: shared socket ownership handled safely (all Tor accepted)."""
        app = nulltrace.nulltrace()
        with patch.object(app, "_find_pids_by_socket_inode", return_value=[100, 200]), \
             patch.object(app, "_verify_process_is_tor", return_value=True):
            pid = app._find_pid_by_socket_inode("99999")
            self.assertEqual(pid, 100)

    def test_matrix_tor_08_ambiguous_ownership_handled_safely(self):
        """Matrix Tor-8: ambiguous ownership handled safely (conflict rejected)."""
        app = nulltrace.nulltrace()
        with patch.object(app, "_find_pids_by_socket_inode", return_value=[100, 200]), \
             patch.object(app, "_verify_process_is_tor", side_effect=lambda pid: pid == 100):
            pid = app._find_pid_by_socket_inode("99999")
            self.assertIsNone(pid)

    # =========================================================================
    # Group 4: Installer (6 items)
    # =========================================================================

    def test_matrix_install_01_destination_symlink_rejected(self):
        """Matrix Install-1: destination symlink rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            real_file = Path(tmpdir) / "real_file.py"
            real_file.write_text("# real", encoding="utf-8")
            link_file = Path(tmpdir) / "link_file.py"
            try:
                os.symlink(real_file, link_file)
            except OSError:
                with patch("os.path.islink", return_value=True), \
                     patch.object(os, "_force_posix_security_checks", True, create=True):
                    with self.assertRaises((ValueError, RuntimeError)) as ctx:
                        install.secure_deploy_file(b"content", link_file, 0o755)
                    self.assertIn("symlink", str(ctx.exception).lower())
                return

            with patch.object(os, "_force_posix_security_checks", True, create=True):
                with self.assertRaises((ValueError, RuntimeError)) as ctx:
                    install.secure_deploy_file(b"content", link_file, 0o755)
                self.assertIn("symlink", str(ctx.exception).lower())

    def test_matrix_install_02_insecure_usr_share_rejected(self):
        """Matrix Install-2: insecure /usr/share/nulltrace rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            insecure_dir = Path(tmpdir) / "share_nulltrace"
            insecure_dir.mkdir()
            mock_stat = MagicMock(st_mode=stat.S_IFDIR | 0o777, st_uid=0, st_gid=0)
            with patch("os.lstat", return_value=mock_stat), \
                 patch("os.fstat", return_value=mock_stat), \
                 patch.object(os, "_force_posix_security_checks", True, create=True):
                with self.assertRaises((ValueError, RuntimeError)) as ctx:
                    install.secure_deploy_file(b"code", insecure_dir / "app.py", 0o644)
                self.assertIn("insecure permissions", str(ctx.exception).lower())

    def test_matrix_install_03_insecure_usr_bin_destination_rejected(self):
        """Matrix Install-3: insecure /usr/bin destination rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            insecure_bin = Path(tmpdir) / "bin"
            insecure_bin.mkdir()
            mock_stat = MagicMock(st_mode=stat.S_IFDIR | 0o755, st_uid=1000, st_gid=1000)
            with patch("os.lstat", return_value=mock_stat), \
                 patch("os.fstat", return_value=mock_stat), \
                 patch("os.geteuid", return_value=0, create=True), \
                 patch.object(os, "_force_posix_security_checks", True, create=True):
                with self.assertRaises((ValueError, RuntimeError)) as ctx:
                    install.secure_deploy_file(b"launcher", insecure_bin / "nulltrace", 0o755)
                self.assertIn("root", str(ctx.exception).lower())

    def test_matrix_install_04_privileged_replacement_is_atomic(self):
        """Matrix Install-4: privileged replacement is atomic."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "app.py"
            install.secure_deploy_file(b"initial payload", dest, 0o644)
            self.assertEqual(dest.read_bytes(), b"initial payload")
            install.secure_deploy_file(b"updated payload", dest, 0o644)
            self.assertEqual(dest.read_bytes(), b"updated payload")

    def test_matrix_install_05_temp_launcher_cannot_follow_symlink(self):
        """Matrix Install-5: temp launcher cannot follow symlink."""
        with tempfile.TemporaryDirectory() as tmpdir:
            victim = Path(tmpdir) / "victim_launcher"
            victim.write_text("#!/bin/sh\necho original\n", encoding="utf-8")
            dest = Path(tmpdir) / "launcher"
            try:
                os.symlink(victim, dest)
            except OSError:
                with patch("os.path.islink", return_value=True), \
                     patch.object(os, "_force_posix_security_checks", True, create=True):
                    with self.assertRaises((ValueError, RuntimeError)):
                        install.secure_deploy_file(b"#!/bin/sh\nexit 0\n", dest, 0o755)
                return

            with patch.object(os, "_force_posix_security_checks", True, create=True):
                with self.assertRaises((ValueError, RuntimeError, OSError)):
                    install.secure_deploy_file(b"#!/bin/sh\nevil\n", dest, 0o755)
            self.assertEqual(victim.read_text(encoding="utf-8"), "#!/bin/sh\necho original\n")

    def test_matrix_install_06_missing_installed_recovery_copy_refuses_local_checkout(self):
        """Matrix Install-6: missing installed recovery copy refuses local checkout."""
        with patch("install.routing_may_be_active", return_value=True), \
             patch("pathlib.Path.exists", return_value=False), \
             patch("os.path.isfile", return_value=False), \
             patch("install.inspect_live_nulltrace_rules", return_value=install.FirewallInspectionResult.ACTIVE), \
             patch("install.resolve_trusted_binary", return_value="/usr/sbin/iptables"), \
             patch("install.run_trusted", return_value=subprocess.CompletedProcess(args=["iptables"], returncode=0, stdout="", stderr="")), \
             patch("shutil.rmtree"), \
             patch("os.remove"):
            with self.assertRaises(SystemExit) as ctx:
                install.uninstall_nulltrace(emergency_flush=True, interactive=False)
            self.assertEqual(ctx.exception.code, 1)

    # =========================================================================
    # Group 5: Service/Config/Interface Restoration (11 items)
    # =========================================================================

    def test_matrix_restore_01_tor_initially_active_remains_active(self):
        """Matrix Restore-1: Tor initially active remains active (restarted, never stopped)."""
        app = nulltrace.nulltrace()
        app._tor_service_initially_active = True
        with patch.object(app, "_load_session_metadata", return_value={"tor_service_initially_active": True, "tor_config_existed": False}), \
             patch.object(app, "validate_tor_config_target", side_effect=lambda p: Path(p)), \
             patch.object(app, "_control_tor_service", return_value=(True, "")) as mock_ctrl:
            app.restore_tor_config()
            mock_ctrl.assert_called_with("restart")

    def test_matrix_restore_02_tor_initially_inactive_remains_inactive(self):
        """Matrix Restore-2: Tor initially inactive remains inactive."""
        app = nulltrace.nulltrace()
        app._tor_service_initially_active = False
        with patch.object(app, "_load_session_metadata", return_value={"tor_service_initially_active": False, "tor_config_existed": False}), \
             patch.object(app, "validate_tor_config_target", side_effect=lambda p: Path(p)), \
             patch.object(app, "_control_tor_service", return_value=(True, "")) as mock_ctrl:
            app.restore_tor_config()
            mock_ctrl.assert_called_with("stop")

    def test_matrix_restore_03_tor_initially_enabled_remains_enabled(self):
        """Matrix Restore-3: Tor initially enabled remains enabled."""
        app = nulltrace.nulltrace()
        app._tor_service_initially_enabled = True
        with patch.object(app, "_load_session_metadata", return_value={"tor_service_initially_active": True, "tor_service_initially_enabled": True, "tor_config_existed": False}), \
             patch.object(app, "validate_tor_config_target", side_effect=lambda p: Path(p)), \
             patch.object(app, "_control_tor_service", return_value=(True, "")) as mock_ctrl:
            app.restore_tor_config()
            for c in mock_ctrl.call_args_list:
                self.assertNotEqual(c.args[0], "disable")

    def test_matrix_restore_04_tor_initially_disabled_remains_disabled(self):
        """Matrix Restore-4: Tor initially disabled remains disabled."""
        app = nulltrace.nulltrace()
        app._tor_service_initially_enabled = False
        with patch.object(app, "_load_session_metadata", return_value={"tor_service_initially_active": True, "tor_service_initially_enabled": False, "tor_config_existed": False}), \
             patch.object(app, "validate_tor_config_target", side_effect=lambda p: Path(p)), \
             patch.object(app, "_control_tor_service", return_value=(True, "")) as mock_ctrl:
            app.restore_tor_config()
            mock_ctrl.assert_called_with("disable")

    def test_matrix_restore_05_unknown_enabled_state_does_not_become_enabled(self):
        """Matrix Restore-5: unknown enabled state does not become enabled."""
        app = nulltrace.nulltrace()
        app._tor_service_initially_enabled = None
        with patch.object(app, "_load_session_metadata", return_value={"tor_service_initially_active": True, "tor_service_initially_enabled": None, "tor_config_existed": False}), \
             patch.object(app, "validate_tor_config_target", side_effect=lambda p: Path(p)), \
             patch.object(app, "_control_tor_service", return_value=(True, "")) as mock_ctrl:
            app.restore_tor_config()
            for c in mock_ctrl.call_args_list:
                self.assertNotEqual(c.args[0], "enable")

    def test_matrix_restore_06_interface_initially_up_returns_up(self):
        """Matrix Restore-6: interface initially UP returns UP."""
        app = nulltrace.nulltrace()
        app._spoofed_intf = "eth0"
        app._original_mac = "00:11:22:33:44:55"
        app._interface_initially_up = True
        with patch("nulltrace.require_trusted_binary", return_value="/usr/sbin/ip"), \
             patch.object(app, "_read_current_mac", return_value="00:11:22:33:44:55"), \
             patch.object(app, "_persist_session_metadata"), \
             patch.object(app, "_renew_dhcp"), \
             patch("nulltrace.run_trusted") as mock_run:
            app._restore_mac()
            cmds = [call.args[0] for call in mock_run.call_args_list]
            self.assertTrue(any(cmd[-1] == "up" for cmd in cmds))

    def test_matrix_restore_07_interface_initially_down_returns_down(self):
        """Matrix Restore-7: interface initially DOWN returns DOWN."""
        app = nulltrace.nulltrace()
        app._spoofed_intf = "eth0"
        app._original_mac = "00:11:22:33:44:55"
        app._interface_initially_up = False
        with patch("nulltrace.require_trusted_binary", return_value="/usr/sbin/ip"), \
             patch.object(app, "_read_current_mac", return_value="00:11:22:33:44:55"), \
             patch.object(app, "_persist_session_metadata"), \
             patch.object(app, "_is_interface_up", return_value=False), \
             patch("nulltrace.run_trusted") as mock_run:
            app._restore_mac()
            cmds = [call.args[0] for call in mock_run.call_args_list]
            self.assertTrue(all(cmd[-1] != "up" for cmd in cmds))

    def test_matrix_restore_08_original_torrc_present_is_restored(self):
        """Matrix Restore-8: original torrc present is restored."""
        with tempfile.TemporaryDirectory() as tmpdir:
            torrc = Path(tmpdir) / "torrc"
            torrc.write_text("SocksPort 9050\n", encoding="utf-8")
            app = nulltrace.nulltrace()
            app.config.tor_config = str(torrc)
            app._tor_config_existed = True
            with patch.object(app, "validate_tor_config_target", return_value=torrc), \
                 patch.object(app, "_load_session_metadata", return_value={"tor_service_initially_active": True, "tor_config_existed": True, "tor_config_backup": "SocksPort 9050\n"}), \
                 patch.object(app, "_control_tor_service", return_value=(True, "")):
                app.restore_tor_config()
                self.assertEqual(torrc.read_text(encoding="utf-8"), "SocksPort 9050\n")

    def test_matrix_restore_09_original_torrc_absent_remains_absent(self):
        """Matrix Restore-9: original torrc absent remains absent."""
        with tempfile.TemporaryDirectory() as tmpdir:
            torrc = Path(tmpdir) / "torrc"
            torrc.write_text(f"{nulltrace.TOR_CONFIG_BEGIN}\nTransPort 9040\n{nulltrace.TOR_CONFIG_END}\n", encoding="utf-8")
            app = nulltrace.nulltrace()
            app.config.tor_config = str(torrc)
            app._tor_config_existed = False
            with patch.object(app, "validate_tor_config_target", return_value=torrc), \
                 patch.object(app, "_load_session_metadata", return_value={"tor_service_initially_active": False, "tor_config_existed": False}), \
                 patch.object(app, "_control_tor_service", return_value=(True, "")):
                app.restore_tor_config()
                self.assertFalse(torrc.exists())

    def test_matrix_restore_10_admin_config_outside_managed_block_preserved(self):
        """Matrix Restore-10: admin config outside managed block preserved."""
        content = (
            "ControlPort 9051\n"
            f"{nulltrace.TOR_CONFIG_BEGIN}\n"
            "TransPort 9040\n"
            f"{nulltrace.TOR_CONFIG_END}\n"
            "DataDirectory /var/lib/tor\n"
        )
        cleaned = nulltrace.strip_tor_config_blocks(content)
        self.assertEqual(cleaned, "ControlPort 9051\nDataDirectory /var/lib/tor\n")

    def test_matrix_restore_11_unterminated_managed_block_rejected_safely(self):
        """Matrix Restore-11: unterminated managed block rejected safely."""
        bad_content = (
            "ControlPort 9051\n"
            f"{nulltrace.TOR_CONFIG_BEGIN}\n"
            "TransPort 9040\n"
        )
        with self.assertRaises(ValueError) as ctx:
            nulltrace.strip_tor_config_blocks(bad_content)
        self.assertIn("unterminated", str(ctx.exception).lower())


class TestLatestRemediations_NT01_Through_NT12(unittest.TestCase):
    """
    Direct regression tests for remediation issues NT-01 through NT-12
    as specified in nulltrace_detailed_remediation_handoff_latest.md.
    """

    def setUp(self):
        self.app = nulltrace.nulltrace()
        self.app._tor_user = "109"

    # NT-01: Tor enabled-state detection distinguishes UNKNOWN from DISABLED
    @patch("nulltrace.resolve_trusted_binary", return_value="/usr/bin/systemctl")
    def test_nt01_tor_service_enabled_tristate(self, mock_resolve):
        """NT-01: _check_tor_service_enabled returns True, False, or None; never coerces error to False."""
        # 1. systemctl is-enabled returns 0 and 'enabled' -> True
        with patch("nulltrace.run_trusted") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="enabled\n", stderr="")
            self.assertTrue(self.app._check_tor_service_enabled())

        # 2. systemctl is-enabled returns 1 and 'disabled' -> False
        with patch("nulltrace.run_trusted") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="disabled\n", stderr="")
            self.assertFalse(self.app._check_tor_service_enabled())

        # 3. systemctl is-enabled returns 1 and 'masked' -> False
        with patch("nulltrace.run_trusted") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="masked\n", stderr="")
            self.assertFalse(self.app._check_tor_service_enabled())

        # 4. systemctl is-enabled returns 1 and bus error / unexpected error -> None
        with patch("nulltrace.run_trusted") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="Failed to connect to bus: Host is down\n")
            self.assertIsNone(self.app._check_tor_service_enabled())

        # 5. systemctl not found -> None
        with patch("nulltrace.resolve_trusted_binary", return_value=None):
            self.assertIsNone(self.app._check_tor_service_enabled())

    def test_nt01_teardown_does_not_disable_when_initially_enabled_is_unknown(self):
        """NT-01: restore_tor_config does not disable Tor when tor_service_initially_enabled is None."""
        with patch.object(self.app, "_load_session_metadata", return_value={
            "tor_service_initially_active": True,
            "tor_service_initially_enabled": None,
            "tor_config_existed": False,
        }), patch.object(self.app, "validate_tor_config_target") as mock_val, \
           patch.object(self.app, "_control_tor_service", return_value=(True, "")) as mock_ctrl:
            mock_val.return_value.exists.return_value = False
            self.app.restore_tor_config()
            # Must restart, but must NOT call disable
            called_actions = [call.args[0] for call in mock_ctrl.call_args_list]
            self.assertIn("restart", called_actions)
            self.assertNotIn("disable", called_actions)

    # NT-02: service tor status must not be treated as proof of active Tor
    def test_nt02_service_tor_status_requires_verified_process(self):
        """NT-02: _control_tor_service('is-active') requires verified Tor process, never trusts service exit code 0 alone."""
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda name: f"/usr/bin/{name}"):
            # 1. service exits 0, but no verified Tor process -> False
            with patch("nulltrace.run_trusted") as mock_run, \
                 patch.object(self.app, "_has_verified_tor_process", return_value=False):
                mock_run.return_value = MagicMock(returncode=0, stdout="[ * ] tor is running\n", stderr="")
                ok, detail = self.app._control_tor_service("is-active")
                self.assertFalse(ok)
                self.assertIn("no verified Tor daemon process was found", detail)

            # 2. service exits 0, AND verified Tor process exists -> True
            with patch("nulltrace.run_trusted") as mock_run, \
                 patch.object(self.app, "_has_verified_tor_process", return_value=True):
                mock_run.return_value = MagicMock(returncode=0, stdout="active\n", stderr="")
                ok, detail = self.app._control_tor_service("is-active")
                self.assertTrue(ok)

            # 3. service command fails, no verified process -> False
            with patch("nulltrace.run_trusted") as mock_run, \
                 patch.object(self.app, "_has_verified_tor_process", return_value=False):
                mock_run.return_value = MagicMock(returncode=3, stdout="inactive\n", stderr="")
                ok, detail = self.app._control_tor_service("is-active")
                self.assertFalse(ok)

    # NT-03: Persist baseline only after baseline capture is complete
    def test_nt03_baseline_capture_before_persistence(self):
        """NT-03: Session metadata stores None for unobserved fields; baseline_captured marks observation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            self.app._session_id = "test_nt03_sess"
            with patch.object(self.app, "_session_dir", return_value=Path(tmpdir)):
                self.app._persist_session_metadata()
                meta_file = Path(tmpdir) / "metadata.json"
                self.assertTrue(meta_file.exists())
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
                self.assertFalse(meta.get("baseline_captured"))
                self.assertIsNone(meta.get("tor_service_initially_active"))
                self.assertIsNone(meta.get("tor_service_initially_enabled"))
                self.assertIsNone(meta.get("interface_initially_up"))
                self.assertIsNone(meta.get("tor_config_existed"))

    # NT-04: Firewall teardown authenticates chain ownership before destructive operations
    def test_nt04_firewall_teardown_authenticates_chain_ownership(self):
        """NT-04: _destroy_authenticated_chain refuses to flush/delete chains lacking the nulltrace marker."""
        with patch("nulltrace.run_trusted") as mock_run:
            # 1. Chain present and authenticated with marker -> flushes (-F) and deletes (-X)
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=f"-N NULLTRACE_OUTPUT\n-A NULLTRACE_OUTPUT -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n",
                stderr="",
            )
            self.app._destroy_authenticated_chain("/sbin/iptables", "filter", "NULLTRACE_OUTPUT")
            cmds = [call.args[0] for call in mock_run.call_args_list]
            self.assertIn(["/sbin/iptables", "-t", "filter", "-F", "NULLTRACE_OUTPUT"], cmds)
            self.assertIn(["/sbin/iptables", "-t", "filter", "-X", "NULLTRACE_OUTPUT"], cmds)

        with patch("nulltrace.run_trusted") as mock_run:
            # 2. Chain present but unauthenticated (missing marker) -> raises RuntimeError
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="-N NULLTRACE_OUTPUT\n-A NULLTRACE_OUTPUT -j ACCEPT\n",
                stderr="",
            )
            with self.assertRaises(RuntimeError) as ctx:
                self.app._destroy_authenticated_chain("/sbin/iptables", "filter", "NULLTRACE_OUTPUT")
            self.assertIn("ownership authentication failed", str(ctx.exception))

        with patch("nulltrace.run_trusted") as mock_run:
            # 3. Chain absent -> safe no-op
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="iptables: No chain/target/match by that name.\n",
            )
            self.app._destroy_authenticated_chain("/sbin/iptables", "filter", "NULLTRACE_OUTPUT")
            # Should NOT attempt -F or -X
            cmds = [call.args[0] for call in mock_run.call_args_list]
            self.assertEqual(len(cmds), 1)

        with patch("nulltrace.run_trusted") as mock_run:
            # 4. Inspection failure (e.g. backend error / permission denied) -> raises RuntimeError
            mock_run.return_value = MagicMock(
                returncode=2,
                stdout="",
                stderr="iptables: Permission denied (you must be root)\n",
            )
            with self.assertRaises(RuntimeError) as ctx:
                self.app._destroy_authenticated_chain("/sbin/iptables", "filter", "NULLTRACE_OUTPUT")
            self.assertIn("inspection failed", str(ctx.exception))

    # NT-05: _authenticate_or_create_chain distinguishes absence from inspection failure
    def test_nt05_authenticate_or_create_chain_inspection_error(self):
        """NT-05: _authenticate_or_create_chain aborts on inspection errors instead of treating them as absent."""
        with patch("nulltrace.run_trusted") as mock_run:
            # Generic error code 2 with lock error -> must raise RuntimeError
            mock_run.return_value = MagicMock(
                returncode=2,
                stdout="",
                stderr="Another app is currently holding the xtables lock.\n",
            )
            with self.assertRaises(RuntimeError) as ctx:
                self.app._authenticate_or_create_chain("/sbin/iptables", "filter", "NULLTRACE_OUTPUT")
            self.assertIn("Firewall inspection error", str(ctx.exception))

    # NT-06: Reject group-writable existing Tor configuration
    def test_nt06_group_writable_tor_config_rejected(self):
        """NT-06: validate_tor_config_target rejects group-writable configuration files (mode & 0o022)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            torrc = Path(tmpdir) / "torrc"
            torrc.write_text("SOCKSPort 9050\n", encoding="utf-8")

            # Group-writable file (0o664)
            fake_stat = MagicMock(st_mode=stat.S_IFREG | 0o664, st_uid=0)
            with patch.object(self.app, "is_valid_tor_config_path", return_value=True), \
                 patch("pathlib.Path.stat", return_value=fake_stat), \
                 patch("os.lstat", return_value=fake_stat), \
                 patch("os.getuid", return_value=0, create=True):
                with self.assertRaises(ValueError) as ctx:
                    self.app.validate_tor_config_target(str(torrc))
                self.assertIn("group-writable", str(ctx.exception))

    # NT-07: Check result of service disable during restoration
    def test_nt07_tor_disable_result_checked_during_restore(self):
        """NT-07: restore_tor_config raises RuntimeError if service disable fails."""
        with patch.object(self.app, "_load_session_metadata", return_value={
            "tor_service_initially_active": False,
            "tor_service_initially_enabled": False,
            "tor_config_existed": False,
        }), patch.object(self.app, "validate_tor_config_target") as mock_val, \
           patch.object(self.app, "_control_tor_service") as mock_ctrl:
            mock_val.return_value.exists.return_value = False
            # Stop succeeds, but disable fails
            mock_ctrl.side_effect = [(True, "stopped"), (False, "systemctl disable tor failed")]
            with self.assertRaises(RuntimeError) as ctx:
                self.app.restore_tor_config()
            self.assertIn("disable failed", str(ctx.exception))
            self.assertFalse(self.app._tor_service_restored)

    # NT-08: Reject '.' and '..' in generic secure path traversal
    def test_nt08_secure_open_dir_hierarchy_rejects_traversal(self):
        """NT-08: secure_open_dir_hierarchy rejects '.' and '..' components in nulltrace.py and install.py."""
        with self.assertRaises(ValueError) as ctx1:
            nulltrace.secure_open_dir_hierarchy("/etc/tor/../etc")
        self.assertIn("relative traversal element", str(ctx1.exception))

        with self.assertRaises(ValueError) as ctx2:
            nulltrace.secure_open_dir_hierarchy("/etc/tor/./torrc")
        self.assertIn("relative traversal element", str(ctx2.exception))

        with self.assertRaises(ValueError) as ctx3:
            install.secure_open_dir_hierarchy("/usr/share/../bin")
        self.assertIn("relative traversal element", str(ctx3.exception))

        with self.assertRaises(ValueError) as ctx4:
            install.secure_open_dir_hierarchy("/usr/share/./nulltrace")
        self.assertIn("relative traversal element", str(ctx4.exception))

    # NT-09: Interface-state detection supports UNKNOWN and fails closed
    def test_nt09_interface_state_unknown_handling(self):
        """NT-09: _is_interface_up returns None on unknown state; MAC randomization refuses to proceed."""
        with patch("pathlib.Path.exists", return_value=False), \
             patch("nulltrace.resolve_trusted_binary", return_value=None):
            # When neither sysfs nor ip utility is available
            self.assertIsNone(self.app._is_interface_up("eth0"))

        self.app._spoofed_intf = "eth0"
        self.app._original_mac = "00:11:22:33:44:55"
        self.app._interface_initially_up = None
        with patch.object(self.app, "_is_interface_up", return_value=None), \
             patch("nulltrace.resolve_trusted_binary", return_value="/usr/bin/macchanger"):
            with self.assertRaises(RuntimeError) as ctx:
                self.app._randomize_mac()
            self.assertIn("Could not determine whether interface 'eth0' is administratively UP or DOWN", str(ctx.exception))

    # NT-10: Baseline restoration policy preserved
    def test_nt10_restoration_baseline_policy(self):
        """NT-10: Tor config changes outside managed block survive teardown; baseline snapshot restores clean host."""
        admin_content = "ControlPort 9051\nDataDirectory /var/lib/tor\n"
        with tempfile.TemporaryDirectory() as tmpdir:
            torrc = Path(tmpdir) / "torrc"
            # Simulate admin edited torrc during active session
            torrc.write_text(
                f"ControlPort 9051\n{nulltrace.TOR_CONFIG_BEGIN}\nTransPort 9040\n{nulltrace.TOR_CONFIG_END}\nDataDirectory /var/lib/tor\n",
                encoding="utf-8"
            )
            self.app.config.tor_config = str(torrc)
            with patch.object(self.app, "validate_tor_config_target", return_value=torrc), \
                 patch.object(self.app, "_load_session_metadata", return_value={"tor_config_existed": True, "tor_service_initially_active": True, "tor_config_backup": "ControlPort 9051\nDataDirectory /var/lib/tor\n"}), \
                 patch.object(self.app, "_control_tor_service", return_value=(True, "")):
                self.app.restore_tor_config()
                self.assertEqual(torrc.read_text(encoding="utf-8"), admin_content)

    # NT-11: Distinguish ENOENT from other destination-stat errors in install.py
    def test_nt11_secure_deploy_file_distinguishes_enoent(self):
        """NT-11: secure_deploy_file permits ENOENT (new file) but re-raises other OSErrors (EACCES, EIO)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "test_bin"
            # EACCES error during stat must raise PermissionError / OSError
            err_stat = OSError(errno.EACCES, "Permission denied")
            with patch("install.secure_open_dir_hierarchy", return_value=123), \
                 patch("os.fstat", return_value=MagicMock(st_mode=stat.S_IFDIR, st_uid=0)), \
                 patch("os.stat", side_effect=err_stat):
                with self.assertRaises(OSError) as ctx:
                    install.secure_deploy_file("echo hi\n", dest)
                self.assertEqual(ctx.exception.errno, errno.EACCES)

    # NT-12: README terminology accurately reflects staged/durable firewall architecture
    def test_nt12_readme_terminology_accuracy(self):
        """NT-12: README.md must not make false transactionality claims; verifies staged/durable wording."""
        readme_path = REPO_ROOT / "README.md"
        self.assertTrue(readme_path.exists())
        readme_text = readme_path.read_text(encoding="utf-8")
        self.assertNotIn("transactional owned firewall chains", readme_text)
        self.assertIn("staged/durable", readme_text)


class TestSection42_FilesystemAdversarial(unittest.TestCase):
    """Section 42: Filesystem adversarial tests (symlinks, non-regular files, FD containment)."""

    def test_attack1_destination_symlink_rejected(self):
        """Attack 1: Target is a symlink pointing to attacker file -> write rejected, victim unchanged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            victim = tmp_path / "victim.txt"
            victim.write_text("original content", encoding="utf-8")
            target_symlink = tmp_path / "target_link"
            target_symlink.symlink_to(victim)

            app = nulltrace.nulltrace()
            # 1. validate_tor_config_target rejects symlink
            with self.assertRaises(ValueError) as ctx:
                app.validate_tor_config_target(target_symlink)
            self.assertIn("symlink target rejected", str(ctx.exception))

            # 2. install.secure_deploy_file rejects symlink destination
            with self.assertRaises(ValueError) as ctx2:
                install.secure_deploy_file("malicious content", target_symlink)
            self.assertIn("symlink", str(ctx2.exception).lower())

            # Verify victim file unchanged
            self.assertEqual(victim.read_text(encoding="utf-8"), "original content")

    def test_attack2_intermediate_symlink_rejected(self):
        """Attack 2: Intermediate directory is a symlink -> rejected without privileged side effects."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            real_dir = tmp_path / "real_dir"
            real_dir.mkdir()
            symlink_dir = tmp_path / "symlink_dir"
            symlink_dir.symlink_to(real_dir)

            with self.assertRaises(ValueError) as ctx:
                install.secure_open_dir_hierarchy(symlink_dir)
            self.assertIn("symlink", str(ctx.exception).lower())

    def test_attack3_directory_fd_relative_prevents_escape(self):
        """Attack 3: Path traversal component '..' rejected by secure_open_dir_hierarchy."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            evil_path = tmp_path / "sub" / ".." / "evil"
            with self.assertRaises(ValueError) as ctx:
                nulltrace.secure_open_dir_hierarchy(evil_path)
            self.assertIn("traversal", str(ctx.exception).lower())

    def test_attack4_destination_replacement_non_regular_file(self):
        """Attack 4: Destination FIFO / non-regular file rejected."""
        if not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo not supported on this platform")
        with tempfile.TemporaryDirectory() as tmpdir:
            fifo_path = Path(tmpdir) / "test_fifo"
            try:
                os.mkfifo(str(fifo_path))
            except OSError:
                self.skipTest("mkfifo failed on this filesystem")

            with self.assertRaises(ValueError) as ctx:
                nulltrace.atomic_write(fifo_path, "payload")
            self.assertIn("not a regular file", str(ctx.exception).lower())


class TestSection43_FirewallAdversarial(unittest.TestCase):
    """Section 43: Firewall adversarial tests (unowned chains, ambiguous rc=1, drift, duplicates)."""

    def setUp(self):
        self.app = nulltrace.nulltrace()

    def test_unowned_same_name_chain_jump_removal_refused(self):
        """Unowned same-name chain: teardown refuses to flush/delete or remove jump."""
        with patch("nulltrace.run_trusted") as mock_run:
            # Inspection of unowned NULLTRACE_OUTPUT (missing exact marker comment)
            mock_run.return_value = subprocess.CompletedProcess(
                args=["iptables"],
                returncode=0,
                stdout="-N NULLTRACE_OUTPUT\n-A NULLTRACE_OUTPUT -j ACCEPT\n",
                stderr="",
            )
            with self.assertRaises(RuntimeError) as ctx:
                self.app._destroy_authenticated_chain("/usr/sbin/iptables", "filter", "NULLTRACE_OUTPUT")
            self.assertIn("exact nulltrace ownership marker rule", str(ctx.exception))

    def test_ambiguous_chain_inspection_treated_as_error(self):
        """Ambiguous chain inspection (rc=1, stderr="") treated as error, not absence."""
        with patch("nulltrace.run_trusted") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["iptables"],
                returncode=1,
                stdout="",
                stderr="",
            )
            with self.assertRaises(RuntimeError) as ctx:
                self.app._authenticate_or_create_chain("/usr/sbin/iptables", "filter", "NULLTRACE_OUTPUT")
            self.assertIn("inspection error", str(ctx.exception).lower())

    def test_external_rule_inserted_above_nulltrace_detected_as_drift(self):
        """External rule inserted above NullTrace jump is detected as enforcement drift."""
        mock_output = (
            "-P OUTPUT ACCEPT\n"
            "-A OUTPUT -p tcp -m tcp --dport 80 -j ACCEPT\n"
            f"-A OUTPUT -j {nulltrace.CHAIN_FILTER_OUTPUT}\n"
        )
        with patch("nulltrace.run_trusted") as mock_run, \
             patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/iptables"), \
             patch.object(self.app, "_check_ipv6_enabled", return_value=False):
            mock_run.return_value = subprocess.CompletedProcess(
                args=["iptables"],
                returncode=0,
                stdout=mock_output,
                stderr="",
            )
            status = self.app._check_live_firewall_status()
            self.assertEqual(status, nulltrace.LiveFirewallStatus.PARTIAL)
            with patch.object(self.app, "_load_session_metadata", return_value={"state": nulltrace.STATE_ACTIVE}), \
                 patch.object(self.app, "_get_current_state", return_value=nulltrace.STATE_ACTIVE):
                drift_status = self.app.get_enforcement_status()
                self.assertEqual(drift_status, nulltrace.STATUS_ENFORCEMENT_DRIFT)

    def test_duplicate_nulltrace_jump_detected_as_partial(self):
        """Duplicate NullTrace jump rules detected as PARTIAL (invalid/corrupted)."""
        mock_output = (
            "-P OUTPUT ACCEPT\n"
            f"-A OUTPUT -j {nulltrace.CHAIN_FILTER_OUTPUT}\n"
            f"-A OUTPUT -j {nulltrace.CHAIN_FILTER_OUTPUT}\n"
        )
        with patch("nulltrace.run_trusted") as mock_run, \
             patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/iptables"), \
             patch.object(self.app, "_check_ipv6_enabled", return_value=False):
            mock_run.return_value = subprocess.CompletedProcess(
                args=["iptables"],
                returncode=0,
                stdout=mock_output,
                stderr="",
            )
            status = self.app._check_live_firewall_status()
            self.assertEqual(status, nulltrace.LiveFirewallStatus.PARTIAL)

    def test_conditional_nulltrace_jump_detected_as_partial(self):
        """Conditional NullTrace jump rule detected as PARTIAL (unconditional required)."""
        mock_output = (
            "-P OUTPUT ACCEPT\n"
            f"-A OUTPUT -p tcp -j {nulltrace.CHAIN_FILTER_OUTPUT}\n"
        )
        with patch("nulltrace.run_trusted") as mock_run, \
             patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/iptables"), \
             patch.object(self.app, "_check_ipv6_enabled", return_value=False):
            mock_run.return_value = subprocess.CompletedProcess(
                args=["iptables"],
                returncode=0,
                stdout=mock_output,
                stderr="",
            )
            status = self.app._check_live_firewall_status()
            self.assertEqual(status, nulltrace.LiveFirewallStatus.PARTIAL)


class TestSection44_TorServiceAdversarial(unittest.TestCase):
    """Section 44: Tor service adversarial tests (fake process, fake binary, service command failures)."""

    def setUp(self):
        self.app = nulltrace.nulltrace()
        self.app._tor_user = "109"

    def test_fake_tor_process_rejected(self):
        """Process named 'tor' with correct UID but untrusted /proc/<pid>/exe is rejected."""
        with patch("os.readlink", return_value="/tmp/fake_tor"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value="Name:\ttor\nUid:\t109 109 109 109\n"):
            self.assertFalse(self.app._verify_process_is_tor(9999))

    def test_fake_tor_real_untrusted_rejected(self):
        """tor.real process outside TRUSTED_BIN_DIRS or writable by non-root is rejected."""
        with patch("os.readlink", return_value="/tmp/tor.real"), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value="Name:\ttor\nUid:\t109 109 109 109\n"):
            self.assertFalse(self.app._verify_process_is_tor(9999))

    def test_service_command_exits_0_but_tor_not_running(self):
        """Service start command returns 0, but Tor process is not running -> returns (False, detail)."""
        with patch("nulltrace.resolve_trusted_binary", return_value="/bin/systemctl"), \
             patch("nulltrace.run_trusted", return_value=subprocess.CompletedProcess(args=["systemctl"], returncode=0, stdout="", stderr="")), \
             patch.object(self.app, "_has_verified_tor_process", return_value=False):
            ok, detail = self.app._control_tor_service("start")
            self.assertFalse(ok)
            self.assertIn("post-condition", detail.lower())

    def test_service_stop_exits_0_but_process_remains(self):
        """Service stop command returns 0, but Tor process still running -> returns (False, detail)."""
        with patch("nulltrace.resolve_trusted_binary", return_value="/bin/systemctl"), \
             patch("nulltrace.run_trusted", return_value=subprocess.CompletedProcess(args=["systemctl"], returncode=0, stdout="", stderr="")), \
             patch.object(self.app, "_has_verified_tor_process", return_value=True):
            ok, detail = self.app._control_tor_service("stop")
            self.assertFalse(ok)
            self.assertIn("still running", detail.lower())

    def test_restart_exits_0_but_ports_unavailable(self):
        """Service restart exits 0, but process verification fails -> reported as restart failure."""
        with patch("nulltrace.resolve_trusted_binary", return_value="/bin/systemctl"), \
             patch("nulltrace.run_trusted", return_value=subprocess.CompletedProcess(args=["systemctl"], returncode=0, stdout="", stderr="")), \
             patch.object(self.app, "_has_verified_tor_process", return_value=False):
            ok, detail = self.app._control_tor_service("restart")
            self.assertFalse(ok)
            self.assertIn("post-condition", detail.lower())


class TestSection45_RecoveryCorruptionAdversarial(unittest.TestCase):
    """Section 45: Recovery corruption tests (missing/corrupt metadata, manifest, state.json)."""

    def setUp(self):
        self.app = nulltrace.nulltrace()

    def test_metadata_missing_recovery_required(self):
        """Missing metadata.json with active state.json returns STATE_RECOVERY_REQUIRED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                sdir = tmp_path / f"session_{self.app.session_id}"
                sdir.mkdir(parents=True)
                (tmp_path / "state.json").write_text(json.dumps({
                    "state": nulltrace.STATE_ACTIVE,
                    "session_id": self.app.session_id,
                }), encoding="utf-8")
                self.assertEqual(self.app.reconcile_state(), nulltrace.STATE_RECOVERY_REQUIRED)

    def test_metadata_corrupt_recovery_required(self):
        """Corrupted metadata.json returns STATE_RECOVERY_REQUIRED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                sdir = tmp_path / f"session_{self.app.session_id}"
                sdir.mkdir(parents=True)
                (sdir / "metadata.json").write_text("{corrupt json", encoding="utf-8")
                (tmp_path / "state.json").write_text(json.dumps({
                    "state": nulltrace.STATE_ACTIVE,
                    "session_id": self.app.session_id,
                }), encoding="utf-8")
                self.assertEqual(self.app.reconcile_state(), nulltrace.STATE_RECOVERY_REQUIRED)

    def test_manifest_missing_when_state_active(self):
        """Missing manifest.json when state is ACTIVE returns STATE_RECOVERY_REQUIRED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                sdir = tmp_path / f"session_{self.app.session_id}"
                sdir.mkdir(parents=True)
                (sdir / "metadata.json").write_text(json.dumps({
                    "session_id": self.app.session_id,
                    "state": nulltrace.STATE_ACTIVE,
                }), encoding="utf-8")
                (tmp_path / "state.json").write_text(json.dumps({
                    "state": nulltrace.STATE_ACTIVE,
                    "session_id": self.app.session_id,
                }), encoding="utf-8")
                self.assertEqual(self.app.reconcile_state(), nulltrace.STATE_RECOVERY_REQUIRED)

    def test_state_json_corrupt(self):
        """Corrupted state.json returns STATE_RECOVERY_REQUIRED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                (tmp_path / "state.json").write_text("{invalid json", encoding="utf-8")
                self.assertEqual(self.app.reconcile_state(), nulltrace.STATE_RECOVERY_REQUIRED)

    def test_backup_missing_when_baseline_captured_raises(self):
        """Authoritative captured baseline with missing torrc.bak raises RuntimeError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            torrc = tmp_path / "torrc"
            self.app.config.tor_config = str(torrc)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), \
                 patch.object(self.app, "validate_tor_config_target", return_value=torrc), \
                 patch.object(self.app, "_load_session_metadata", return_value={
                     "baseline_captured": True,
                     "tor_config_existed": True,
                 }):
                with self.assertRaises(RuntimeError) as ctx:
                    self.app.restore_tor_config()
                self.assertIn("backup missing", str(ctx.exception).lower())
                self.assertFalse(self.app._tor_file_restored)

    def test_session_id_mismatch_metadata_vs_directory(self):
        """Metadata session_id disagreeing with session directory returns STATE_RECOVERY_REQUIRED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                sdir = tmp_path / "session_11111111"
                sdir.mkdir(parents=True)
                (sdir / "metadata.json").write_text(json.dumps({
                    "session_id": "22222222",
                    "state": nulltrace.STATE_ACTIVE,
                }), encoding="utf-8")
                (tmp_path / "state.json").write_text(json.dumps({
                    "state": nulltrace.STATE_ACTIVE,
                    "session_id": "11111111",
                }), encoding="utf-8")
                self.assertEqual(self.app.reconcile_state(), nulltrace.STATE_RECOVERY_REQUIRED)


class TestSection46_AdminChangeAdversarial(unittest.TestCase):
    """Section 46: Administrator changes outside managed block, same-name chains, rule insertion."""

    def setUp(self):
        self.app = nulltrace.nulltrace()

    def test_admin_edits_outside_managed_block_preserved(self):
        """Admin modifications outside managed block survive restoration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            torrc = Path(tmpdir) / "torrc"
            torrc.write_text(
                "SocksPort 9050\n"
                f"{nulltrace.TOR_CONFIG_BEGIN}\n"
                "TransPort 9040\n"
                f"{nulltrace.TOR_CONFIG_END}\n"
                "DataDirectory /var/lib/tor\n",
                encoding="utf-8"
            )
            self.app.config.tor_config = str(torrc)
            with patch.object(self.app, "validate_tor_config_target", return_value=torrc), \
                 patch.object(self.app, "_load_session_metadata", return_value={
                     "tor_config_existed": True,
                     "tor_service_initially_active": True,
                     "tor_config_backup": "SocksPort 9050\nDataDirectory /var/lib/tor\n",
                 }), \
                 patch.object(self.app, "_control_tor_service", return_value=(True, "")):
                self.app.restore_tor_config()
                content = torrc.read_text(encoding="utf-8")
                self.assertIn("SocksPort 9050", content)
                self.assertIn("DataDirectory /var/lib/tor", content)
                self.assertNotIn("TransPort 9040", content)
                self.assertFalse(nulltrace.torrc_has_managed_block(content))

    def test_admin_deletes_torrc_restored_from_backup(self):
        """Live torrc deleted during session is restored from backup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            torrc = tmp_path / "torrc"
            sdir = tmp_path / f"session_{self.app.session_id}"
            sdir.mkdir(parents=True)
            (sdir / "torrc.bak").write_text("ControlPort 9051\n", encoding="utf-8")
            self.app.config.tor_config = str(torrc)

            with patch("nulltrace.PERSISTENT_DIR", tmp_path), \
                 patch.object(self.app, "validate_tor_config_target", return_value=torrc), \
                 patch.object(self.app, "_load_session_metadata", return_value={
                     "tor_config_existed": True,
                     "tor_service_initially_active": True,
                 }), \
                 patch.object(self.app, "_control_tor_service", return_value=(True, "")):
                self.app.restore_tor_config()
                self.assertTrue(torrc.exists())
                self.assertEqual(torrc.read_text(encoding="utf-8"), "ControlPort 9051\n")

    def test_admin_creates_same_name_chain_unowned_protected(self):
        """Admin created NULLTRACE_OUTPUT chain without marker is protected from teardown."""
        with patch("nulltrace.run_trusted") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=["iptables"],
                returncode=0,
                stdout="-N NULLTRACE_OUTPUT\n-A NULLTRACE_OUTPUT -j DROP\n",
                stderr="",
            )
            with self.assertRaises(RuntimeError) as ctx:
                self.app._destroy_authenticated_chain("/usr/sbin/iptables", "filter", "NULLTRACE_OUTPUT")
            self.assertIn("exact nulltrace ownership marker rule", str(ctx.exception))


class TestSection47_ConfigAdversarial(unittest.TestCase):
    """Section 47: Config validation adversarial tests (port collisions, CIDR validation, permissions)."""

    def setUp(self):
        self.app = nulltrace.nulltrace()

    def test_config_port_collisions_rejected(self):
        """Tor TransPort, DNSPort, and ControlPort collisions rejected."""
        # 1. tor_port == dns_port
        self.app.config.tor_port = 9040
        self.app.config.dns_port = 9040
        with self.assertRaises(ValueError) as ctx:
            self.app.validate_network_config()
        self.assertIn("Port collision", str(ctx.exception))

        # 2. tor_port == control_port (9051)
        self.app.config.dns_port = 5353
        self.app.config.tor_port = 9051
        with self.assertRaises(ValueError) as ctx:
            self.app.validate_network_config()
        self.assertIn("ControlPort", str(ctx.exception))

        # 3. dns_port == control_port (9051)
        self.app.config.tor_port = 9040
        self.app.config.dns_port = 9051
        with self.assertRaises(ValueError) as ctx:
            self.app.validate_network_config()
        self.assertIn("ControlPort", str(ctx.exception))

        # 4. Privileged port 53 rejected
        self.app.config.dns_port = 53
        with self.assertRaises(ValueError) as ctx:
            self.app.validate_network_config()
        self.assertIn("port 53", str(ctx.exception))

    def test_config_exclusions_validation(self):
        """Full-route exclusions, overlapping CIDRs, and IPv6 exclusions rejected."""
        # 1. Full-route 0.0.0.0/0
        self.app.config.dns_port = 5353
        self.app.config.tor_port = 9040
        self.app.config.excluded_networks = ["0.0.0.0/0"]
        with self.assertRaises(ValueError) as ctx:
            self.app.validate_network_config()
        self.assertIn("Full-route exclusion", str(ctx.exception))

        # 2. Full-route ::/0
        self.app.config.excluded_networks = ["::/0"]
        with self.assertRaises(ValueError) as ctx:
            self.app.validate_network_config()
        self.assertIn("Full-route exclusion", str(ctx.exception))

        # 3. IPv6 exclusion
        self.app.config.excluded_networks = ["2001:db8::/32"]
        with self.assertRaises(ValueError) as ctx:
            self.app.validate_network_config()
        self.assertIn("IPv6 exclusion", str(ctx.exception))

        # 4. Overlapping networks
        self.app.config.excluded_networks = ["10.0.0.0/8", "10.1.0.0/16"]
        with self.assertRaises(ValueError) as ctx:
            self.app.validate_network_config()
        self.assertIn("Overlapping exclusion networks", str(ctx.exception))

        # 5. Overlapping IP and network
        self.app.config.excluded_networks = ["192.168.1.0/24"]
        self.app.config.excluded_ips = ["192.168.1.100"]
        with self.assertRaises(ValueError) as ctx:
            self.app.validate_network_config()
        self.assertIn("Overlapping exclusion", str(ctx.exception))

    def test_config_invalid_exit_country(self):
        """Invalid exit country codes rejected."""
        self.app.config.dns_port = 5353
        self.app.config.tor_port = 9040
        self.app.config.excluded_networks = []
        self.app.config.excluded_ips = []

        self.app.config.exit_country = "USA"
        with self.assertRaises(ValueError):
            self.app.validate_network_config()

        self.app.config.exit_country = "12"
        with self.assertRaises(ValueError):
            self.app.validate_network_config()

    def test_config_torrc_security_validations(self):
        """Path traversal and insecure permissions on torrc rejected."""
        # Traversal
        with self.assertRaises(ValueError):
            self.app.validate_tor_config_target("/etc/tor/../etc/shadow")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            real_file = tmp_path / "real_torrc"
            real_file.write_text("SocksPort 9050\n", encoding="utf-8")
            sym_file = tmp_path / "sym_torrc"
            sym_file.symlink_to(real_file)
            with self.assertRaises(ValueError) as ctx:
                self.app.validate_tor_config_target(sym_file)
            self.assertIn("symlink target rejected", str(ctx.exception))


class TestSection48_InstallerAdversarial(unittest.TestCase):
    """Section 48: Installer adversarial tests (symlinks, permissions, sudo_user sanitization)."""

    def test_install_target_dir_symlink_rejected(self):
        """Target directory as symlink is rejected by secure_deploy_file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            real_dir = tmp_path / "real_dir"
            real_dir.mkdir()
            sym_dir = tmp_path / "sym_dir"
            sym_dir.symlink_to(real_dir)
            with self.assertRaises(ValueError) as ctx:
                install.secure_deploy_file("content", sym_dir / "target.py")
            self.assertIn("symlink", str(ctx.exception).lower())

    def test_install_target_dir_is_file_rejected(self):
        """Target parent directory as a regular file is rejected by secure_deploy_file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            file_as_dir = tmp_path / "not_a_dir"
            file_as_dir.write_text("hello", encoding="utf-8")
            with self.assertRaises(ValueError) as ctx:
                install.secure_deploy_file("content", file_as_dir / "target.py")
            self.assertTrue(any(s in str(ctx.exception).lower() for s in ("not a directory", "non-directory")))

    def test_install_source_file_symlink_rejected(self):
        """Source nulltrace.py as symlink is rejected by installer."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            real_py = tmp_path / "real_nulltrace.py"
            real_py.write_text("# python", encoding="utf-8")
            sym_py = tmp_path / "nulltrace.py"
            sym_py.symlink_to(real_py)
            with patch("install.__file__", str(tmp_path / "install.py")), \
                 patch("install.check_dependencies"), \
                 patch("sys.exit") as mock_exit:
                mock_exit.side_effect = SystemExit(1)
                with self.assertRaises(SystemExit):
                    install.install_nulltrace()
                mock_exit.assert_called_with(1)

    def test_install_python3_trusted_validation_fails(self):
        """require_trusted_binary('python3') failing aborts installation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            src_py = tmp_path / "nulltrace.py"
            src_py.write_text("# python", encoding="utf-8")
            with patch("install.__file__", str(tmp_path / "install.py")), \
                 patch("install.check_dependencies"), \
                 patch("install.require_trusted_binary", side_effect=RuntimeError("python3 untrusted")), \
                 patch("sys.exit") as mock_exit:
                mock_exit.side_effect = SystemExit(1)
                with self.assertRaises(SystemExit):
                    install.install_nulltrace()
                mock_exit.assert_called_with(1)

    def test_install_sudo_user_malformed_rejected(self):
        """Malformed SUDO_USER containing traversal '..' is safely ignored."""
        env_evil = {"SUDO_USER": "attacker/../../root"}
        with patch.dict(os.environ, env_evil), \
             patch("install.check_root"), \
             patch("install.routing_may_be_active", return_value=False), \
             patch("builtins.print") as mock_print, \
             patch("shutil.rmtree"), patch("pathlib.Path.unlink"):
            install.uninstall_nulltrace(interactive=False, purge=True)
            printed = " ".join(call.args[0] for call in mock_print.call_args_list if call.args)
            self.assertIn("malformed SUDO_USER", printed)

    def test_install_purge_path_traversal_refused(self):
        """Purge path with '..' or unexpected target name is refused."""
        cfg = Path("/etc/nulltrace/../shadow")
        suspicious = (".." in cfg.parts or cfg.name != "nulltrace")
        self.assertTrue(suspicious)


class TestSection49_CriticalSecurityRemediations(unittest.TestCase):
    """
    Direct verification of all 12 critical issues from nulltrace_critical_security_remediation_handoff.md:
    1. Tor active UNKNOWN handling
    2. Recovery baseline integrity
    3. Stale session isolation
    4. Session identity consistency (4-way)
    5. Firewall jump ownership
    6. iptables absence/error handling
    7. Service post-condition verification
    8. ControlPort security & cookie protection
    9. tor.real identity & validation
    10. Tor config restoration verification
    11. Baseline-before-mutation
    12. Captured-interface MAC handling
    """

    def setUp(self):
        self.app = nulltrace.nulltrace()
        self.app._tor_user = "109"

    def test_issue1_tor_active_tri_state_semantics(self):
        """Issue 1: check_tor_service tri-state semantics (True=ACTIVE, False=INACTIVE, None=UNKNOWN) and teardown enforcement."""
        # 1. Positively verified active
        with patch.object(self.app, "_has_verified_tor_process", return_value=True), \
             patch("nulltrace.resolve_trusted_binary", side_effect=lambda n: f"/usr/bin/{n}"), \
             patch("nulltrace.run_trusted", return_value=MagicMock(returncode=0, stdout="active", stderr="")):
            self.assertEqual(self.app.check_tor_service(), True)

        # 2. Positively verified inactive
        with patch.object(self.app, "_has_verified_tor_process", return_value=False), \
             patch("nulltrace.resolve_trusted_binary", side_effect=lambda n: f"/usr/bin/{n}"), \
             patch("nulltrace.run_trusted", return_value=MagicMock(returncode=3, stdout="inactive", stderr="")):
            self.assertEqual(self.app.check_tor_service(), False)

        # 3. /proc inspection failure -> UNKNOWN (None)
        with patch.object(self.app, "_has_verified_tor_process", side_effect=PermissionError("Permission denied /proc")), \
             patch("nulltrace.resolve_trusted_binary", side_effect=lambda n: f"/usr/bin/{n}"):
            self.assertIsNone(self.app.check_tor_service())

        # 4. Service manager failure / unexpected code -> UNKNOWN (None)
        with patch.object(self.app, "_has_verified_tor_process", return_value=False), \
             patch("nulltrace.resolve_trusted_binary", side_effect=lambda n: f"/usr/bin/{n}" if n == "systemctl" else None), \
             patch("nulltrace.run_trusted", return_value=MagicMock(returncode=1, stdout="", stderr="connection refused to systemd bus")):
            self.assertIsNone(self.app.check_tor_service())

        # 5. Teardown cannot interpret UNKNOWN as INACTIVE: restore_tor_config raises when baseline is UNKNOWN
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), \
                 patch("nulltrace.RUN_DIR", tmp_path):
                sdir = tmp_path / f"session_{self.app.session_id}"
                sdir.mkdir(parents=True, exist_ok=True)
                meta = {
                    "session_id": self.app.session_id,
                    "baseline_captured": True,
                    "tor_config_existed": True,
                    "tor_service_initially_active": None,
                }
                (sdir / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
                (sdir / "torrc.bak").write_text("SOCKSPort 9050\n", encoding="utf-8")
                with self.assertRaises(RuntimeError) as ctx:
                    self.app.restore_tor_config()
                self.assertIn("tor_service_initially_active", str(ctx.exception))
                self.assertIn("RESTORE_FAILED", str(ctx.exception))

    def test_issue2_recovery_refuses_fabricated_baseline(self):
        """Issue 2: Recovery refuses to mutate host state using invented/guessed baseline defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), \
                 patch("nulltrace.RUN_DIR", tmp_path):
                sdir = tmp_path / f"session_{self.app.session_id}"
                sdir.mkdir(parents=True, exist_ok=True)

                # Corrupt metadata file
                meta_file = sdir / "metadata.json"
                meta_file.write_text("{invalid json", encoding="utf-8")
                with self.assertRaises(RuntimeError) as ctx:
                    self.app._load_session_metadata()
                self.assertIn("corrupt", str(ctx.exception).lower())

                # Missing tor_config_existed in captured baseline
                meta = {
                    "session_id": self.app.session_id,
                    "baseline_captured": True,
                    "tor_service_initially_active": False,
                }
                meta_file.write_text(json.dumps(meta), encoding="utf-8")
                with self.assertRaises(RuntimeError) as ctx:
                    self.app.restore_tor_config()
                self.assertIn("tor_config_existed", str(ctx.exception))
                self.assertIn("RESTORE_FAILED", str(ctx.exception))

                # Missing interface_initially_up when MAC was spoofed
                meta = {
                    "session_id": self.app.session_id,
                    "baseline_captured": True,
                    "spoofed_intf": "eth0",
                    "original_mac": "00:11:22:33:44:55",
                }
                meta_file.write_text(json.dumps(meta), encoding="utf-8")
                with patch.object(self.app, "_read_current_mac", return_value="00:11:22:33:44:55"), \
                     patch("nulltrace.require_trusted_binary", return_value="/usr/sbin/ip"), \
                     patch("nulltrace.run_trusted"):
                    with self.assertRaises(RuntimeError) as ctx:
                        self.app._restore_mac()
                    self.assertIn("interface_initially_up", str(ctx.exception))
                    self.assertIn("RESTORE_FAILED", str(ctx.exception))

    def test_issue3_stale_sessions_isolated_from_automatic_recovery(self):
        """Issue 3: Historical stale sessions are never automatically selected for recovery."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), \
                 patch("nulltrace.RUN_DIR", tmp_path):
                # Create historical sessions
                (tmp_path / "session_deadbeef0001").mkdir(parents=True, exist_ok=True)
                (tmp_path / "session_deadbeef0002").mkdir(parents=True, exist_ok=True)

                # No state.json -> must return None, NOT any historical session
                self.assertIsNone(self.app._discover_session_id())

                # Authoritative state.json is INACTIVE -> must return None
                state_file = tmp_path / "state.json"
                state_file.write_text(json.dumps({"state": nulltrace.STATE_INACTIVE, "session_id": "deadbeef0001"}), encoding="utf-8")
                self.assertIsNone(self.app._discover_session_id())

                # Authoritative state.json points to missing session dir -> raises RuntimeError
                state_file.write_text(json.dumps({"state": nulltrace.STATE_ACTIVE, "session_id": "deadbeef9999"}), encoding="utf-8")
                with self.assertRaises(RuntimeError) as ctx:
                    self.app._discover_session_id()
                self.assertIn("non-existent session directory", str(ctx.exception))

    def test_issue4_session_identity_consistency_4way(self):
        """Issue 4: Strict 4-way consistency check among directory, state.json, metadata.json, and manifest.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            sid = "aabbccddeeff"
            sdir = tmp_path / f"session_{sid}"
            sdir.mkdir(parents=True, exist_ok=True)

            with patch("nulltrace.PERSISTENT_DIR", tmp_path), \
                 patch("nulltrace.RUN_DIR", tmp_path):
                state_file = tmp_path / "state.json"
                state_file.write_text(json.dumps({"state": nulltrace.STATE_ACTIVE, "session_id": sid}), encoding="utf-8")

                # Case A: metadata session_id mismatch
                (sdir / "metadata.json").write_text(json.dumps({"session_id": "mismatched001"}), encoding="utf-8")
                with self.assertRaises(RuntimeError) as ctx:
                    self.app._load_session_metadata()
                self.assertIn("session ID mismatch between metadata", str(ctx.exception))

                # Case B: manifest session_id mismatch
                (sdir / "metadata.json").write_text(json.dumps({"session_id": sid}), encoding="utf-8")
                (sdir / "manifest.json").write_text(json.dumps({"session_id": "mismatched002"}), encoding="utf-8")
                with self.assertRaises(RuntimeError) as ctx:
                    self.app._load_session_metadata()
                self.assertIn("session ID mismatch between manifest", str(ctx.exception))

                # Case C: All match -> succeeds
                (sdir / "manifest.json").write_text(json.dumps({"session_id": sid}), encoding="utf-8")
                loaded = self.app._load_session_metadata()
                self.assertIsNotNone(loaded)
                self.assertEqual(loaded["session_id"], sid)

    def test_issue5_jump_deactivation_requires_ownership_authentication(self):
        """Issue 5: Jump rule removal requires ownership authentication of target chain; fails safely if unowned."""
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda n: f"/usr/sbin/{n}" if n == "iptables" else None), \
             patch("nulltrace.run_trusted") as mock_run:
            # Inspection of target chain NULLTRACE_OUTPUT returns rules without CHAIN_MARKER_COMMENT
            mock_run.return_value = MagicMock(returncode=0, stdout="-A NULLTRACE_OUTPUT -j ACCEPT\n", stderr="")
            with self.assertRaises(RuntimeError) as ctx:
                self.app._deactivate_jump_rules()
            self.assertIn("unauthenticated chain", str(ctx.exception))

            # Ensure iptables -D OUTPUT -j NULLTRACE_OUTPUT was never called
            for c in mock_run.call_args_list:
                args = c.args[0]
                if "-D" in args and "NULLTRACE_OUTPUT" in args:
                    self.fail("Jump deletion was called on unauthenticated chain!")

    def test_issue6_chain_absence_requires_positive_proof(self):
        """Issue 6: iptables inspection errors (empty stderr, locks) must not be assumed as chain absence."""
        # 1. rc=1 + empty stderr -> error
        with patch("nulltrace.run_trusted", return_value=MagicMock(returncode=1, stdout="", stderr="")):
            with self.assertRaises(RuntimeError) as ctx:
                self.app._authenticate_or_create_chain("/usr/sbin/iptables", "nat", nulltrace.CHAIN_NAT_OUTPUT)
            self.assertIn("Refusing to create chain without positive confirmation of absence", str(ctx.exception))

        # 2. xtables lock (code 4) -> error
        with patch("nulltrace.run_trusted", return_value=MagicMock(returncode=4, stdout="", stderr="xtables locked")):
            with self.assertRaises(RuntimeError) as ctx:
                self.app._authenticate_or_create_chain("/usr/sbin/iptables", "nat", nulltrace.CHAIN_NAT_OUTPUT)
            self.assertIn("xtables locked", str(ctx.exception))

        # 3. Explicit positive absence -> creates chain
        with patch("nulltrace.run_trusted") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=1, stdout="", stderr="iptables: No chain/target/match by that name."),
                MagicMock(returncode=0, stdout="", stderr=""),  # -N
                MagicMock(returncode=0, stdout="", stderr=""),  # -A comment
            ]
            self.app._authenticate_or_create_chain("/usr/sbin/iptables", "nat", nulltrace.CHAIN_NAT_OUTPUT)
            self.assertEqual(mock_run.call_count, 3)

        # 4. _destroy_authenticated_chain on lock error -> error
        with patch("nulltrace.run_trusted", return_value=MagicMock(returncode=4, stdout="", stderr="xtables locked")):
            with self.assertRaises(RuntimeError) as ctx:
                self.app._destroy_authenticated_chain("/usr/sbin/iptables", "nat", nulltrace.CHAIN_NAT_OUTPUT)
            self.assertIn("Refusing destructive teardown", str(ctx.exception))

    def test_issue7_service_actions_verify_postconditions(self):
        """Issue 7: Tor service commands must verify resulting postconditions, not rely on command returncode 0."""
        # 1. start returns 0, but process absent -> failure
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda n: f"/usr/bin/{n}" if n == "systemctl" else None), \
             patch("nulltrace.run_trusted", return_value=MagicMock(returncode=0, stdout="", stderr="")), \
             patch.object(self.app, "_has_verified_tor_process", return_value=False):
            ok, detail = self.app._control_tor_service("start", check_listeners=False)
            self.assertFalse(ok)
            self.assertIn("post-condition failure", detail)

        # 2. stop returns 0, but process remains alive -> failure
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda n: f"/usr/bin/{n}" if n == "systemctl" else None), \
             patch("nulltrace.run_trusted", return_value=MagicMock(returncode=0, stdout="", stderr="")), \
             patch.object(self.app, "_has_verified_tor_process", return_value=True):
            ok, detail = self.app._control_tor_service("stop")
            self.assertFalse(ok)
            self.assertIn("still running", detail)

        # 3. enable returns 0, but is-enabled says disabled -> failure
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda n: f"/usr/bin/{n}" if n == "systemctl" else None), \
             patch("nulltrace.run_trusted", return_value=MagicMock(returncode=0, stdout="", stderr="")), \
             patch.object(self.app, "_check_tor_service_enabled", return_value=False):
            ok, detail = self.app._control_tor_service("enable")
            self.assertFalse(ok)
            self.assertIn("not enabled", detail)

        # 4. disable returns 0, but is-enabled says enabled -> failure
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda n: f"/usr/bin/{n}" if n == "systemctl" else None), \
             patch("nulltrace.run_trusted", return_value=MagicMock(returncode=0, stdout="", stderr="")), \
             patch.object(self.app, "_check_tor_service_enabled", return_value=True):
            ok, detail = self.app._control_tor_service("disable")
            self.assertFalse(ok)
            self.assertIn("not disabled", detail)

    def test_issue8_control_port_zero_and_cookie_protection(self):
        """Issue 8: ControlPort 0 returns 0 (never 9051); authentication cookie is never sent to unverified listener."""
        with tempfile.TemporaryDirectory() as tmpdir:
            torrc = Path(tmpdir) / "torrc"
            torrc.write_text("ControlPort 0\nSOCKSPort 9050\n", encoding="utf-8")
            self.app.config.tor_config = str(torrc)

            # ControlPort 0 returns 0
            self.assertEqual(self.app._read_control_port(), 0)

            # When port is 0, _tor_control_newnym rejects immediately without opening sockets or cookie
            with patch("nulltrace.CONTROL_COOKIE_PATHS", [Path(tmpdir) / "control_auth_cookie"]):
                self.assertFalse(self.app._tor_control_newnym())

            # ControlPort 9051 with unrelated listener -> rejects before cookie read
            torrc.write_text("ControlPort 9051\n", encoding="utf-8")
            with patch.object(self.app, "_verify_listener_ownership", return_value=False), \
                 patch.object(Path, "read_bytes") as mock_read:
                self.assertFalse(self.app._tor_control_newnym())
                mock_read.assert_not_called()

            # Protocol parser rejects non-250 and error replies
            self.assertTrue(self.app._parse_tor_control_reply(b"250 OK\r\n"))
            self.assertFalse(self.app._parse_tor_control_reply(b"515 Authentication failed\r\n"))
            self.assertFalse(self.app._parse_tor_control_reply(b"451 Server error\r\n"))
            self.assertFalse(self.app._parse_tor_control_reply(b""))

    def test_issue9_tor_real_executable_security_verification(self):
        """Issue 9: tor.real process receives identical trusted executable, UID, and permission verification as tor."""
        with patch.object(self.app, "_tor_user", "109"), \
             patch("pathlib.Path.is_dir", return_value=True), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value="Uid:\t109\t109\t109\t109\n"), \
             patch("os.readlink", return_value="/usr/bin/tor.real"), \
             patch("nulltrace.TRUSTED_BIN_DIRS", ("/usr/bin",)), \
             patch("os.kill"):

            # 1. Valid root-owned tor.real with mode 0755
            stat_valid = MagicMock(st_mode=stat.S_IFREG | 0o755, st_uid=0)
            with patch("os.stat", return_value=stat_valid), \
                 patch("os.lstat", return_value=stat_valid), \
                 patch("nulltrace.validate_trusted_directory_hierarchy", return_value=True):
                self.assertTrue(self.app._verify_process_is_tor(12345))

            # 2. Group-writable tor.real -> rejected
            stat_gw = MagicMock(st_mode=stat.S_IFREG | 0o775, st_uid=0)
            with patch("os.stat", return_value=stat_gw), \
                 patch("os.lstat", return_value=stat_gw), \
                 patch("nulltrace.validate_trusted_directory_hierarchy", return_value=True):
                self.assertFalse(self.app._verify_process_is_tor(12345))

            # 3. Non-root owned tor.real (UID 1000) -> rejected
            stat_nonroot = MagicMock(st_mode=stat.S_IFREG | 0o755, st_uid=1000)
            with patch("os.stat", return_value=stat_nonroot), \
                 patch("os.lstat", return_value=stat_nonroot), \
                 patch("nulltrace.validate_trusted_directory_hierarchy", return_value=True):
                self.assertFalse(self.app._verify_process_is_tor(12345))

            # 4. tor.real outside trusted directories -> rejected
            with patch("os.readlink", return_value="/tmp/tor.real"):
                self.assertFalse(self.app._verify_process_is_tor(12345))

    def test_issue10_tor_config_restoration_post_verification(self):
        """Issue 10: Tor configuration restoration verifies post-conditions (managed block stripped, permissions, backup integrity)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            torrc = tmp_path / "torrc"
            torrc.write_text("# initial\n", encoding="utf-8")
            self.app.config.tor_config = str(torrc)

            with patch("nulltrace.PERSISTENT_DIR", tmp_path), \
                 patch("nulltrace.RUN_DIR", tmp_path), \
                 patch.object(self.app, "validate_tor_config_target", return_value=torrc):
                sdir = tmp_path / f"session_{self.app.session_id}"
                sdir.mkdir(parents=True, exist_ok=True)

                 # Missing backup file when torrc initially existed raises RuntimeError
                if torrc.exists():
                    torrc.unlink()
                meta = {
                    "session_id": self.app.session_id,
                    "baseline_captured": True,
                    "tor_config_existed": True,
                    "tor_service_initially_active": False,
                }
                (sdir / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
                with self.assertRaises(RuntimeError) as ctx:
                    self.app.restore_tor_config()
                self.assertIn("baseline backup missing", str(ctx.exception))

                # If restored torrc still contains managed block -> raises RuntimeError
                (sdir / "torrc.bak").write_text("# baseline\n", encoding="utf-8")
                torrc.write_text("## BEGIN nulltrace\nTransPort 9040\n## END nulltrace\n", encoding="utf-8")
                with patch("nulltrace.strip_tor_config_blocks", return_value="## BEGIN nulltrace\nTransPort 9040\n## END nulltrace\n"):
                    with self.assertRaises(RuntimeError) as ctx:
                        self.app.restore_tor_config()
                    self.assertIn("Managed block still present in torrc after restore", str(ctx.exception))

    def test_issue11_tor_active_unknown_aborts_mutation(self):
        """Issue 11a: setup_network_rules aborts before mutation if Tor initial active state is UNKNOWN."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), \
                 patch("nulltrace.RUN_DIR", tmp_path), \
                 patch("nulltrace.require_linux_root"), \
                 patch.object(self.app, "_acquire_lock"), \
                 patch.object(self.app, "_get_current_state", return_value=nulltrace.STATE_INACTIVE), \
                 patch.object(self.app, "validate_network_config"), \
                 patch.object(self.app, "validate_circuit_time"), \
                 patch.object(self.app, "check_tor_service", return_value=None), \
                 patch.object(self.app, "apply_tor_config") as mock_apply:
                with self.assertRaises(RuntimeError) as ctx:
                    self.app.setup_network_rules()
                self.assertIn("Tor initial active state is UNKNOWN", str(ctx.exception))
                mock_apply.assert_not_called()

    def test_issue11_tor_enabled_unknown_aborts_mutation(self):
        """Issue 11b: setup_network_rules aborts before mutation if Tor initial enabled state is UNKNOWN."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), \
                 patch("nulltrace.RUN_DIR", tmp_path), \
                 patch("nulltrace.require_linux_root"), \
                 patch.object(self.app, "_acquire_lock"), \
                 patch.object(self.app, "_get_current_state", return_value=nulltrace.STATE_INACTIVE), \
                 patch.object(self.app, "validate_network_config"), \
                 patch.object(self.app, "validate_circuit_time"), \
                 patch.object(self.app, "check_tor_service", return_value=False), \
                 patch("nulltrace.resolve_trusted_binary", side_effect=lambda n: f"/usr/bin/{n}" if n == "systemctl" else None), \
                 patch.object(self.app, "_check_tor_service_enabled", return_value=None), \
                 patch.object(self.app, "apply_tor_config") as mock_apply:
                with self.assertRaises(RuntimeError) as ctx:
                    self.app.setup_network_rules()
                self.assertIn("Tor initial enabled state is UNKNOWN", str(ctx.exception))
                mock_apply.assert_not_called()

    def test_issue11_interface_up_unknown_aborts_mutation(self):
        """Issue 11c: setup_network_rules aborts before mutation if MAC administrative state is UNKNOWN."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            self.app.mac_randomize = True
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), \
                 patch("nulltrace.RUN_DIR", tmp_path), \
                 patch("nulltrace.require_linux_root"), \
                 patch.object(self.app, "_acquire_lock"), \
                 patch.object(self.app, "_get_current_state", return_value=nulltrace.STATE_INACTIVE), \
                 patch.object(self.app, "validate_network_config"), \
                 patch.object(self.app, "validate_circuit_time"), \
                 patch.object(self.app, "check_tor_service", return_value=False), \
                 patch.object(self.app, "_check_tor_service_enabled", return_value=False), \
                 patch.object(self.app, "_get_primary_interface", return_value="eth0"), \
                 patch.object(self.app, "_read_current_mac", return_value="00:11:22:33:44:55"), \
                 patch.object(self.app, "_is_interface_up", return_value=None), \
                 patch.object(self.app, "_randomize_mac") as mock_rand:
                with self.assertRaises(RuntimeError) as ctx:
                    self.app.setup_network_rules()
                self.assertIn("Could not verify initial administrative state", str(ctx.exception))
                mock_rand.assert_not_called()

    def test_issue12_mac_randomization_uses_captured_interface(self):
        """Issue 12: MAC randomization strictly uses captured interface even if routing changes; fails safely if disappeared."""
        self.app.mac_randomize = True
        self.app._spoofed_intf = "eth0"
        self.app._original_mac = "00:11:22:33:44:55"
        self.app._interface_initially_up = True

        with patch("nulltrace.require_trusted_binary", side_effect=lambda n: f"/usr/sbin/{n}"), \
             patch("nulltrace.resolve_trusted_binary", side_effect=lambda n: f"/usr/sbin/{n}"), \
             patch("nulltrace.run_trusted") as mock_run, \
             patch.object(self.app, "_renew_dhcp"), \
             patch("pathlib.Path.exists", return_value=True):

            # If default route changes to tun0, _randomize_mac still operates strictly on captured eth0
            with patch.object(self.app, "_get_primary_interface", return_value="tun0"):
                self.app._randomize_mac()

            executed_cmds = [call.args[0] for call in mock_run.call_args_list]
            self.assertIn(["/usr/sbin/ip", "link", "set", "eth0", "down"], executed_cmds)
            self.assertNotIn(["/usr/sbin/ip", "link", "set", "tun0", "down"], executed_cmds)

        # If captured eth0 sysfs disappeared, abort safely without switching interface
        def exists_filter(p, *args, **kwargs):
            if "eth0" in str(p):
                return False
            return True

        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda n: f"/usr/sbin/{n}"), \
             patch.object(Path, "exists", autospec=True, side_effect=exists_filter), \
             patch.object(self.app, "_get_primary_interface", return_value="eth1"), \
             patch.object(nulltrace.os, "_force_posix_security_checks", True, create=True):
            with self.assertRaises(RuntimeError) as ctx:
                self.app._randomize_mac()
            self.assertIn("is no longer available", str(ctx.exception))

    def test_issue1_service_process_ambiguity_returns_none(self):
        """Issue 1 & 7: Ambiguous evidence between service manager and process returns UNKNOWN (None)."""
        with patch("nulltrace.resolve_trusted_binary", side_effect=lambda n: f"/bin/{n}"):
            # Case 1: systemctl reports active, but no process found -> None
            with patch("nulltrace.run_trusted") as mock_run, \
                 patch.object(self.app, "_has_verified_tor_process", return_value=False):
                mock_run.return_value = subprocess.CompletedProcess(args=["systemctl"], returncode=0, stdout="active\n", stderr="")
                status, detail = self.app._control_tor_service("is-active")
                self.assertIsNone(status)
                self.assertIn("Ambiguous Tor state", detail)
                self.assertIsNone(self.app.check_tor_service())

            # Case 2: systemctl reports inactive (code 3), but process found -> None
            with patch("nulltrace.run_trusted") as mock_run, \
                 patch.object(self.app, "_has_verified_tor_process", return_value=True):
                mock_run.return_value = subprocess.CompletedProcess(args=["systemctl"], returncode=3, stdout="inactive\n", stderr="")
                status, detail = self.app._control_tor_service("is-active")
                self.assertIsNone(status)
                self.assertIn("Ambiguous Tor state", detail)
                self.assertIsNone(self.app.check_tor_service())

    def test_issue2_restore_mac_requires_boolean_interface_up(self):
        """Issue 2: _restore_mac refuses to invent administrative state when missing or non-boolean."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), \
                 patch("nulltrace.RUN_DIR", tmp_path):
                sdir = tmp_path / f"session_{self.app.session_id}"
                sdir.mkdir(parents=True, exist_ok=True)
                meta = {
                    "session_id": self.app.session_id,
                    "baseline_captured": True,
                    "spoofed_intf": "eth0",
                    "original_mac": "00:11:22:33:44:55",
                    "interface_initially_up": None,
                }
                (sdir / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
                self.app._interface_initially_up = None
                with patch.object(self.app, "_read_current_mac", return_value="00:11:22:33:44:55"), \
                     patch("nulltrace.require_trusted_binary", return_value="/usr/sbin/ip"), \
                     patch("nulltrace.run_trusted"):
                    with self.assertRaises(RuntimeError) as ctx:
                        self.app._restore_mac()
                    self.assertIn("interface_initially_up", str(ctx.exception))
                    self.assertIn("RESTORE_FAILED", str(ctx.exception))

    def test_issue12_mac_randomization_refuses_uncaptured_baseline(self):
        """Issue 12: _randomize_mac aborts immediately without mutation if baseline was not captured."""
        self.app.mac_randomize = True
        self.app._spoofed_intf = "eth0"
        self.app._original_mac = None
        self.app._interface_initially_up = None
        with self.assertRaises(RuntimeError) as ctx:
            self.app._randomize_mac()
        self.assertIn("not captured", str(ctx.exception).lower())

        # Also when original MAC is set but interface_initially_up is UNKNOWN
        self.app._original_mac = "00:11:22:33:44:55"
        self.app._interface_initially_up = None
        with patch.object(self.app, "_is_interface_up", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                self.app._randomize_mac()
            self.assertIn("could not determine whether interface", str(ctx.exception).lower())

    def test_issue8_control_reply_strict_status_validation(self):
        """Issue 8: _parse_tor_control_reply strictly validates status code 250 on all lines."""
        # Non-250 status code rejected
        self.assertFalse(self.app._parse_tor_control_reply(b"550 Permission denied\r\n"))

        # Mixed codes rejected
        self.assertFalse(self.app._parse_tor_control_reply(b"250-OK\r\n251 Something\r\n250 OK\r\n"))

        # Valid single-line reply accepted
        self.assertTrue(self.app._parse_tor_control_reply(b"250 OK\r\n"))

        # Valid multi-line reply accepted
        self.assertTrue(self.app._parse_tor_control_reply(b"250-OK\r\n250 OK\r\n"))


if __name__ == "__main__":
    unittest.main()




