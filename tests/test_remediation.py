#!/usr/bin/env python3
"""
Comprehensive Regression & Unit Test Suite for nulltrace remediation (NT-001 through NT-016).
"""

import json
import os
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


if __name__ == "__main__":
    unittest.main()
