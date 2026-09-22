#!/usr/bin/env python3
"""
Comprehensive Regression & Unit Test Suite for nulltrace remediation (NT-001 through NT-016).
"""

import json
import os
import signal
import socket
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
            if name in ("systemctl", "service"):
                return f"/bin/{name}"
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
                def mock_persist_meta():
                    events.append("persist_meta")
                def mock_apply_tor():
                    events.append("apply_tor")
                def mock_setup_v4():
                    events.append("setup_v4")
                def mock_setup_v6():
                    events.append("setup_v6")
                def mock_activate_jumps():
                    events.append("activate_jumps")

                with patch.object(app, "_check_live_firewall_status", return_value=nulltrace.LiveFirewallStatus.CLEAN), \
                     patch.object(app, "_load_session_metadata", return_value=None), \
                     patch.object(app, "backup_iptables", side_effect=mock_backup_iptables), \
                     patch.object(app, "backup_tor_config", side_effect=mock_backup_tor), \
                     patch.object(app, "_persist_session_metadata", side_effect=mock_persist_meta), \
                     patch.object(app, "apply_tor_config", side_effect=mock_apply_tor), \
                     patch.object(app, "_setup_custom_chains_v4", side_effect=mock_setup_v4), \
                     patch.object(app, "_setup_custom_chains_v6", side_effect=mock_setup_v6), \
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

        with patch("nulltrace.resolve_trusted_binary", return_value="/usr/sbin/ss"):
            # Tor owns the port
            with patch("nulltrace.run_trusted", return_value=subprocess.CompletedProcess(
                args=["ss"], returncode=0,
                stdout='users:(("tor",pid=1234,fd=6))\n', stderr=""
            )):
                self.assertTrue(app._verify_listener_ownership(9041, "tcp"))

            # Another process owns the port
            with patch("nulltrace.run_trusted", return_value=subprocess.CompletedProcess(
                args=["ss"], returncode=0,
                stdout='users:(("malicious_proxy",pid=5678,fd=4))\n', stderr=""
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

    def test_p0_1_inactive_session_discovery_when_all_inactive(self):
        """P0.1: When all sessions are marked INACTIVE, _discover_session_id selects latest session for force-stop/recover."""
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
                self.assertEqual(sid, "bbbb2222")

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
        with patch("nulltrace.resolve_trusted_binary", return_value=None), \
             patch("pathlib.Path.exists", return_value=True), \
             patch("pathlib.Path.read_text", return_value=proc_udp_content):
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


if __name__ == "__main__":
    unittest.main()
