from __future__ import annotations

import contextlib
from dataclasses import replace
import io
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import naver_vpn as core
import vpn as manager
import vpn_daemon as daemon
from test_naver_vpn import SAFE_PROFILE


class DaemonTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        for patch in (
            mock.patch.object(core, "RUNTIME_DIR", self.root / "runtime"),
            mock.patch.object(manager, "CONFIG_DIR", self.root / "config"),
            mock.patch.object(manager, "STATE_FILE", self.root / "config/connection.json"),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        self.profile = core.parse_profile_text(SAFE_PROFILE, Path("vpn2361.ovpn"))
        self.credentials = core.Credentials("vpn2361", "synthetic-user", "synthetic-secret")

    @contextlib.contextmanager
    def launch(self, *, initialized=True, stop_fails=False):
        observed = {}
        control = mock.Mock()
        control.connected.return_value = True
        running = [True]
        def popen(command, **kwargs):
            observed["command"] = command
            observed["auth"] = Path(command[command.index("--auth-user-pass") + 1])
            observed["config"] = Path(command[command.index("--config") + 1])
            observed["log"] = Path(command[command.index("--log") + 1])
            for name in ("auth", "config", "log"):
                self.assertEqual(stat.S_IMODE(observed[name].stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(core.RUNTIME_DIR.stat().st_mode), 0o700)
            self.assertNotIn("synthetic-secret", " ".join(command))
            self.assertEqual(manager.load_state().pid, 0, "launch intent must exist before root child")
            if initialized:
                observed["log"].write_text("Initialization Sequence Completed\n")
            return mock.Mock(pid=12345, wait=mock.Mock(return_value=0))
        def record(_environment, _config, **_kwargs):
            owned = replace(manager.load_state(), pid=4321, started="Mon Oct 12 10:00:00 2026")
            manager.save_state(owned)
            return owned
        def stop(owned, _control):
            if stop_fails:
                raise core.RuntimeSafetyError("stop timeout")
            running[0] = False
            manager.cleanup_connection(owned)
        with mock.patch.object(core, "authenticate", return_value=core.AuthResult(False)), \
             mock.patch.object(core, "collect_metadata", return_value=object()), \
             mock.patch.object(subprocess, "Popen", side_effect=popen), \
             mock.patch.object(manager, "capture", return_value="launcher-start"), \
             mock.patch.object(manager, "record_connection", side_effect=record), \
             mock.patch.object(manager, "processes", side_effect=lambda state: [state] if running[0] else []), \
             mock.patch.object(manager, "management_control", return_value=control), \
             mock.patch.object(manager, "stop_connection", side_effect=stop) as stop_call, \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            yield observed, control, stop_call

    def test_success_requires_initialization_state_and_pid_retains_daemon_files(self):
        with self.launch() as (observed, control, stop):
            self.assertEqual(daemon.connect_daemon("dev", self.credentials, self.profile, "1.1.3", manager), 0)
        control.connected.assert_called_once()
        control.verify_pid.assert_called_once_with(4321)
        control.close.assert_called_once()
        stop.assert_not_called()
        self.assertFalse(observed["auth"].exists())
        self.assertTrue(observed["config"].exists())
        self.assertTrue(observed["log"].exists())
        self.assertEqual(manager.load_state().mode, "daemon")
        self.assertEqual(manager.load_state().pid, 4321)

    def test_launcher_zero_without_initialization_never_reports_connected_and_cleans(self):
        with self.launch(initialized=False) as (observed, control, stop), \
             mock.patch.object(daemon, "START_TIMEOUT", 0), \
             self.assertRaisesRegex(core.RuntimeSafetyError, "did not reach CONNECTED"):
            daemon.connect_daemon("dev", self.credentials, self.profile, "1.1.3", manager)
        stop.assert_called_once()
        self.assertFalse(observed["auth"].exists())
        self.assertFalse(observed["config"].exists())
        self.assertFalse(observed["log"].exists())
        self.assertIsNone(manager.load_state())

    def test_failed_stop_retains_verified_ownership_but_always_removes_otp(self):
        with self.launch(initialized=False, stop_fails=True) as (observed, control, stop), \
             mock.patch.object(daemon, "START_TIMEOUT", 0), self.assertRaises(core.RuntimeSafetyError):
            daemon.connect_daemon("dev", self.credentials, self.profile, "1.1.3", manager)
        self.assertFalse(observed["auth"].exists())
        self.assertTrue(observed["config"].exists())
        self.assertTrue(observed["log"].exists())
        self.assertEqual(manager.load_state().pid, 4321)
        self.assertEqual(manager.load_state().mode, "daemon")

    def test_otp_nonterminal_fails_before_creating_runtime_files(self):
        with mock.patch.object(core, "authenticate", return_value=core.AuthResult(True)), \
             mock.patch.object(core, "collect_metadata", return_value=object()), \
             mock.patch.object(sys.stdin, "isatty", return_value=False), \
             self.assertRaises(core.RuntimeSafetyError):
            daemon.connect_daemon("dev", self.credentials, self.profile, "1.1.3", manager)
        self.assertFalse(core.RUNTIME_DIR.exists())

    def test_delayed_live_launcher_retains_pending_ownership_and_nonsecret_files(self):
        child = mock.Mock(pid=12345)
        child.poll.return_value = None
        child.wait.side_effect = subprocess.TimeoutExpired("synthetic launcher", 90)
        with mock.patch.object(core, "authenticate", return_value=core.AuthResult(False)), \
             mock.patch.object(core, "collect_metadata", return_value=object()), \
             mock.patch.object(subprocess, "Popen", return_value=child), \
             mock.patch.object(manager, "capture", return_value="launcher-start"), \
             mock.patch.object(manager, "record_connection", side_effect=core.RuntimeSafetyError("new OpenVPN process could not be identified")), \
             mock.patch.object(manager, "processes", return_value=[]), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
             self.assertRaisesRegex(core.RuntimeSafetyError, "launcher timed out"):
            daemon.connect_daemon("dev", self.credentials, self.profile, "1.1.3", manager)
        intent = manager.load_state()
        self.assertEqual(intent.pid, 0)
        self.assertEqual(intent.started, "pending")
        self.assertTrue(Path(intent.config).exists())
        self.assertTrue(Path(intent.log).exists())
        self.assertFalse(Path(intent.auth).exists())
        self.assertEqual(child.wait.call_count, 2)
        child.terminate.assert_not_called()
        child.kill.assert_not_called()

    def test_pending_live_or_unknown_launcher_blocks_new_auth_and_false_disconnect(self):
        for launcher_pid, started in ((12345, "launcher-start"), (None, None)):
            intent = manager.Connection(0, "dev", "pending", "config", "auth", True, "daemon", "log",
                                        launcher_pid, started)
            manager.save_state(intent)
            def capture(arguments):
                return "" if arguments[1] == "-axo" else "launcher-start"
            for arguments in (["audit"], ["--disconnect"]):
                output, errors = io.StringIO(), io.StringIO()
                with self.subTest(pid=launcher_pid, arguments=arguments), \
                     mock.patch.object(manager, "capture", side_effect=capture), \
                     mock.patch.object(manager, "credentials_for") as credentials, \
                     mock.patch.object(manager, "authorize_sudo") as sudo, \
                     mock.patch.object(core, "authenticate") as authenticate, \
                     contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    self.assertEqual(manager.main(arguments), 1)
                    self.assertNotIn("DISCONNECTED", output.getvalue())
                    credentials.assert_not_called()
                    sudo.assert_not_called()
                    authenticate.assert_not_called()
                    self.assertEqual(manager.load_state(), intent)

    def test_interrupt_during_spawn_is_delivered_only_after_launcher_is_owned(self):
        child = mock.Mock(pid=12345)
        child.poll.return_value = None
        child.wait.side_effect = subprocess.TimeoutExpired("synthetic launcher", 3)
        def popen(*_args, **kwargs):
            self.assertTrue(callable(kwargs["preexec_fn"]))
            os.kill(os.getpid(), signal.SIGINT)
            return child
        with mock.patch.object(core, "authenticate", return_value=core.AuthResult(False)), \
             mock.patch.object(core, "collect_metadata", return_value=object()), \
             mock.patch.object(subprocess, "Popen", side_effect=popen), \
             mock.patch.object(manager, "capture", return_value="launcher-start"), \
             mock.patch.object(manager, "record_connection", side_effect=core.RuntimeSafetyError("new OpenVPN process could not be identified")), \
             mock.patch.object(manager, "processes", return_value=[]), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
             self.assertRaises(KeyboardInterrupt):
            daemon.connect_daemon("dev", self.credentials, self.profile, "1.1.3", manager)
        intent = manager.load_state()
        self.assertEqual(intent.launcher_pid, 12345)
        self.assertEqual(intent.launcher_started, "launcher-start")
        self.assertTrue(Path(intent.config).exists())
        self.assertTrue(Path(intent.log).exists())
        self.assertFalse(Path(intent.auth).exists())

    def test_same_environment_daemon_is_no_auth_no_tty_no_sudo(self):
        owned = manager.Connection(4321, "dev", "date", "config", "auth", True, "daemon", "log")
        control = mock.Mock()
        control.connected.return_value = True
        with mock.patch.object(manager, "processes", return_value=[owned]), \
             mock.patch.object(manager, "installation_preflight", return_value="valid"), \
             mock.patch.object(manager, "management_control", return_value=control), \
             mock.patch.object(manager, "credentials_for") as credentials, \
             mock.patch.object(manager, "require_terminal") as terminal, \
             mock.patch.object(manager, "authorize_sudo") as sudo, \
             mock.patch.object(core, "authenticate") as auth, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(manager.main(["dev"]), 0)
        credentials.assert_not_called()
        terminal.assert_not_called()
        sudo.assert_not_called()
        auth.assert_not_called()
        control.close.assert_called_once()

    def test_disconnect_needs_no_credentials_tty_or_sudo(self):
        owned = manager.Connection(4321, "dev", "date", "config", "auth", True, "daemon", "log")
        control = mock.Mock()
        with mock.patch.object(manager, "processes", return_value=[owned]), \
             mock.patch.object(manager, "installation_preflight", return_value="valid"), \
             mock.patch.object(manager, "management_control", return_value=control), \
             mock.patch.object(manager, "stop_connection") as stop, \
             mock.patch.object(manager, "credentials_for") as credentials, \
             mock.patch.object(manager, "require_terminal") as terminal, \
             mock.patch.object(manager, "authorize_sudo") as sudo, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(manager.main(["--disconnect"]), 0)
        stop.assert_called_once_with(owned, control)
        credentials.assert_not_called()
        terminal.assert_not_called()
        sudo.assert_not_called()
        control.close.assert_called_once()

    def expired_daemon(self):
        config = daemon.private_file("profile-", ".ovpn", b"synthetic")
        auth = daemon.private_file("auth-", ".txt", b"synthetic")
        log = daemon.private_file("daemon-", ".log", b"synthetic")
        state = manager.Connection(4321, "dev", "date", str(config), str(auth), True, "daemon", str(log))
        manager.save_state(state)
        return state, [config, auth, log]

    def test_expired_daemon_disconnect_cleans_owned_files_and_record(self):
        _state, paths = self.expired_daemon()
        with mock.patch.object(manager, "processes", return_value=[]), \
             mock.patch.object(manager, "installation_preflight", return_value="valid"), \
             mock.patch.object(manager, "credentials_for") as credentials, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(manager.main(["--disconnect"]), 0)
        credentials.assert_not_called()
        self.assertIsNone(manager.load_state())
        self.assertTrue(all(not path.exists() for path in paths))

    def test_new_start_cleans_expired_daemon_before_replacing_ownership(self):
        _state, paths = self.expired_daemon()
        def connect(*_args):
            self.assertIsNone(manager.load_state())
            self.assertTrue(all(not path.exists() for path in paths))
            return 0
        with mock.patch.object(manager, "processes", return_value=[]), \
             mock.patch.object(manager, "installation_preflight", return_value="valid"), \
             mock.patch.object(manager, "require_terminal"), \
             mock.patch.object(core, "resolve_profile", return_value=Path("profile")), \
             mock.patch.object(core, "load_profile", return_value=self.profile), \
             mock.patch.object(core, "check_tls", return_value=True), \
             mock.patch.object(manager, "credentials_for", return_value=self.credentials), \
             mock.patch.object(manager, "authorize_sudo"), \
             mock.patch.object(core, "management_port_open", return_value=False), \
             mock.patch.object(manager, "backup_app_auth_file"), \
             mock.patch.object(core, "verify_installation", return_value="1.1.3"), \
             mock.patch.object(daemon, "connect_daemon", side_effect=connect) as start:
            self.assertEqual(manager.main(["dev"]), 0)
        start.assert_called_once()

    def test_synthetic_native_daemon_survives_launcher_parent_exit(self):
        executable = self.root / "fake-openvpn.py"
        pid_file = self.root / "pid"
        executable.write_text(
            "import subprocess,sys; from pathlib import Path\n"
            "assert '--daemon' in sys.argv\n"
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'], "
            "start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            f"Path({str(pid_file)!r}).write_text(str(child.pid))\n")
        with mock.patch.object(core, "OPENVPN", executable):
            command = daemon.daemon_command(self.root / "profile.ovpn", self.root / "auth.txt", self.root / "daemon.log")
        # A regular user synthetic executable exercises native detach semantics;
        # it creates no tunnel, route, authentication request, or privileged process.
        result = subprocess.run([sys.executable] + command[3:], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        self.assertEqual(result.returncode, 0)
        pid = int(pid_file.read_text())
        try:
            os.kill(pid, 0)
            self.assertEqual(os.getsid(pid), pid)
        finally:
            os.kill(pid, signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
