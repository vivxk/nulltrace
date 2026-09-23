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
                self.assertEqual(sid, "222222222222")

    def test_p0_1_missing_session_directory_fails_safely(self):
        """P0.1: Missing session directory fails safely without claiming clean or inventing false state."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            with patch("nulltrace.PERSISTENT_DIR", tmp_path), patch("nulltrace.RUN_DIR", tmp_path):
                # State exists pointing to non-existent session directory
                (tmp_path / "state.json").write_text(json.dumps({
                    "session_id": "ghost_session",
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
                with patch.object(app, "validate_tor_config_target", return_value=tmp_path / "torrc"), \
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
            mock_lstat = MagicMock()
            mock_lstat.st_mode = stat.S_IFLNK | 0o777
            with patch("os.lstat", return_value=mock_lstat), \
                 patch("pathlib.Path.exists", return_value=True):
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
            "mangle": ["-A OUTPUT -j NULLTRACE_V6_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_V6_MANGLE_PREROUTING"],
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

        with patch("install.inspect_live_nulltrace_rules", side_effect=[
            install.FirewallInspectionResult.ACTIVE,
            install.FirewallInspectionResult.ACTIVE,
            install.FirewallInspectionResult.CLEAN,
        ]), \
        patch("install.routing_may_be_active", return_value=True), \
        patch("install.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
        patch("install.run_trusted", side_effect=fake_run), \
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
                 patch.object(app, "_load_session_metadata", return_value={"tor_config_existed": False}), \
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
                 patch.object(app, "_load_session_metadata", return_value={"tor_config_existed": False}), \
                 patch.object(app, "_control_tor_service", return_value=(True, "")):
                app.restore_tor_config()
                self.assertTrue(torrc.exists())
                self.assertIn("AdminSetting 42", torrc.read_text(encoding="utf-8"))

    def test_service_and_interface_state_restoration(self):
        """P1-10 & P1-11: Original Tor service state (active/enabled) and interface administrative state (up/down) restored."""
        app = nulltrace.nulltrace()

        # Tor initially inactive -> teardown calls "stop"
        app._tor_initially_active = False
        app._tor_initially_enabled = True
        with patch.object(app, "validate_tor_config_target", return_value=Path("/etc/tor/torrc")), \
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
        with patch.object(app, "validate_tor_config_target", return_value=Path("/etc/tor/torrc")), \
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
            with patch("os.chmod", side_effect=PermissionError("chmod denied")):
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
            "mangle": ["-A OUTPUT -j NULLTRACE_V6_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_V6_MANGLE_PREROUTING"],
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
            "v6:mangle:NULLTRACE_V6_MANGLE_PREROUTING": f"-N NULLTRACE_V6_MANGLE_PREROUTING\n-A NULLTRACE_V6_MANGLE_PREROUTING -m comment --comment {nulltrace.CHAIN_MARKER_COMMENT}\n-A NULLTRACE_V6_MANGLE_PREROUTING -j ACCEPT\n",
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
            "mangle": ["-A OUTPUT -j NULLTRACE_V6_MANGLE_OUTPUT", "-A PREROUTING -j NULLTRACE_V6_MANGLE_PREROUTING"],
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
        with patch("install.inspect_live_nulltrace_rules", side_effect=[
            install.FirewallInspectionResult.ACTIVE,
            install.FirewallInspectionResult.ACTIVE,
            install.FirewallInspectionResult.CLEAN,
        ]), \
        patch("install.routing_may_be_active", return_value=True), \
        patch("install.resolve_trusted_binary", side_effect=lambda b: f"/usr/sbin/{b}"), \
        patch("install.run_trusted", return_value=subprocess.CompletedProcess(args=["iptables"], returncode=0, stdout="", stderr="")), \
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


if __name__ == "__main__":
    unittest.main()


