from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import vpn as switch
import naver_vpn as vpn
import vpn_daemon


class SwitchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.patches = [
            mock.patch.object(switch, "CONFIG_DIR", self.root / "config"),
            mock.patch.object(switch, "STATE_FILE", self.root / "config/connection.json"),
        ]
        for patch in self.patches:
            patch.start()
        self.addCleanup(self.temporary.cleanup)
        self.addCleanup(lambda: [patch.stop() for patch in reversed(self.patches)])

    def inspect(self, config: str, auth: str | None = None, *, started="Mon Oct 12 10:00:00 2026", extra=""):
        auth = str(switch.APP_AUTH_FILE) if auth is None else auth
        def capture(arguments):
            if arguments[1] == "-axo":
                return f"47420 {vpn.OPENVPN}\n8 /usr/bin/unrelated"
            if arguments[-1] == "args=":
                return f"{vpn.OPENVPN} --config {config} --auth-user-pass {auth}{extra}"
            if arguments[-1] == "lstart=":
                return started
            raise AssertionError(arguments)
        return mock.patch.object(switch, "capture", side_effect=capture)

    @contextlib.contextmanager
    def management_server(self, *, pid=47420, eof_on_signal=False, silent=False):
        client, server = socket.socketpair()
        commands = []
        def serve():
            try:
                with server, server.makefile("rb") as reader:
                    if not silent:
                        server.sendall(b">INFO:OpenVPN Management Interface Version 1 -- type 'help' for more info\r\n")
                    while command := reader.readline():
                        commands.append(command)
                        if command == b"pid\r\n":
                            server.sendall(f"SUCCESS: pid={pid}\r\n".encode("ascii"))
                        elif command == b"state\r\n":
                            server.sendall(b"1,CONNECTED,SUCCESS,10.0.0.1,127.0.0.1,1234,,\r\nEND\r\n")
                        elif command == b"signal SIGTERM\r\n":
                            if not eof_on_signal:
                                server.sendall(b"SUCCESS: signal SIGTERM thrown\r\n")
                            return
            except (BrokenPipeError, ConnectionResetError):
                pass
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            with mock.patch.object(switch.socket, "create_connection", return_value=client):
                yield client, commands
        finally:
            client.close()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive(), "management test server did not close")

    def test_management_socket_validates_pid_and_stops_with_ack_or_eof(self):
        connection = switch.Connection(47420, "dev", "date", "config", "auth", False)
        for eof in (False, True):
            with self.subTest(eof=eof), self.management_server(eof_on_signal=eof) as (client, commands):
                control = switch.management_control(connection)
                try:
                    with mock.patch.object(switch, "load_state", return_value=None), \
                         mock.patch.object(switch, "processes", side_effect=[[connection], []]):
                        switch.stop_connection(connection, control)
                finally:
                    control.close()
                self.assertEqual(commands, [b"pid\r\n", b"pid\r\n", b"signal SIGTERM\r\n"])
                self.assertEqual(client.fileno(), -1)

    def test_management_socket_wrong_pid_never_sends_signal_and_closes(self):
        connection = switch.Connection(47420, "dev", "date", "config", "auth", False)
        with self.management_server(pid=9999) as (client, commands), \
             self.assertRaisesRegex(vpn.RuntimeSafetyError, "PID does not match"):
            switch.management_control(connection)
        self.assertEqual(commands, [b"pid\r\n"])
        self.assertEqual(client.fileno(), -1)

    def test_busy_management_fails_before_sudo_or_auth_and_closes_socket(self):
        connection = switch.Connection(47420, "dev", "date", "config", "auth", False)
        output = io.StringIO()
        with self.management_server(silent=True) as (client, commands), \
             mock.patch.object(switch, "processes", return_value=[connection]), \
             mock.patch.object(switch, "installation_preflight", return_value="valid"), \
             mock.patch.object(switch, "require_terminal"), \
             mock.patch.object(vpn, "resolve_profile", return_value=Path("profile")), \
             mock.patch.object(vpn, "load_profile", return_value=object()), \
             mock.patch.object(vpn, "check_tls", return_value=True), \
             mock.patch.object(switch, "credentials_for", return_value=object()), \
             mock.patch.object(switch, "authorize_sudo") as sudo, \
             mock.patch.object(vpn, "authenticate") as authenticate, \
             mock.patch.object(switch, "stop_connection") as stop, \
             contextlib.redirect_stderr(output):
            self.assertEqual(switch.main(["audit"]), 1)
            sudo.assert_not_called()
            authenticate.assert_not_called()
            stop.assert_not_called()
            self.assertEqual(client.fileno(), -1)
        self.assertIn("Disconnect", output.getvalue())
        self.assertEqual(commands, [])

    def test_management_identity_change_refuses_signal(self):
        connection = switch.Connection(47420, "dev", "date", "config", "auth", False)
        control = mock.Mock()
        with mock.patch.object(switch, "load_state", return_value=None), \
             mock.patch.object(switch, "processes", return_value=[]), \
             self.assertRaisesRegex(vpn.RuntimeSafetyError, "identity changed"):
            switch.stop_connection(connection, control)
        control.stream.sendall.assert_not_called()

    def test_daemon_flags_and_pending_intent_match_only_exact_private_paths(self):
        config = str(vpn.RUNTIME_DIR / "profile-test.ovpn")
        auth = str(vpn.RUNTIME_DIR / "auth-test.txt")
        log = str(vpn.RUNTIME_DIR / "daemon-test.log")
        owned = switch.Connection(47420, "dev", "Mon Oct 12 10:00:00 2026", config, auth, True, "daemon", log)
        with self.inspect(config, auth, extra=f" --daemon --log {log}"):
            self.assertEqual(switch.processes(owned), [owned])
            pending = switch.Connection(0, "dev", "pending", config, auth, True, "daemon", log)
            self.assertEqual(switch.processes(pending), [owned])
            with self.assertRaises(vpn.RuntimeSafetyError):
                switch.processes()
        for extra in (f" --daemon other-name --log {log}",
                      f" --daemon --log {log} --script-security 2",
                      " --daemon --log /tmp/unapproved.log"):
            with self.subTest(extra=extra), self.inspect(config, auth, extra=extra), \
                 self.assertRaises(vpn.RuntimeSafetyError):
                switch.processes(owned)

    def test_verified_daemon_disconnect_removes_private_files_and_state(self):
        runtime = self.root / "runtime"
        runtime.mkdir(mode=0o700)
        paths = [runtime / "profile-test.ovpn", runtime / "auth-test.txt", runtime / "daemon-test.log"]
        for path in paths:
            path.write_text("synthetic")
            path.chmod(0o600)
        owned = switch.Connection(47420, "dev", "date", str(paths[0]), str(paths[1]), True, "daemon", str(paths[2]))
        switch.save_state(owned)
        with mock.patch.object(vpn, "RUNTIME_DIR", runtime), self.management_server() as (_client, commands), \
             mock.patch.object(switch, "processes", side_effect=[[owned], []]):
            control = switch.management_control(owned)
            try:
                switch.stop_connection(owned, control)
            finally:
                control.close()
        self.assertTrue(all(not path.exists() for path in paths))
        self.assertIsNone(switch.load_state())
        self.assertEqual(commands[-1], b"signal SIGTERM\r\n")

    def test_detects_dev_and_audit_app_paths_with_spaces(self):
        for environment, stem in switch.PROFILES.items():
            with self.subTest(environment=environment), self.inspect(str(vpn.PROFILES_DIR / f"{stem}.ovpn")):
                result = switch.processes()
                self.assertEqual(result[0].environment, environment)
                self.assertFalse(result[0].managed)

    def test_production_unknown_and_unapproved_auth_are_refused(self):
        for config, auth in [
            (str(vpn.PROFILES_DIR / "vpn2440.ovpn"), None),
            ("/tmp/unknown.ovpn", None),
            (str(vpn.PROFILES_DIR / "vpn2361.ovpn"), "/tmp/unknown.txt"),
        ]:
            with self.subTest(config=config), self.inspect(config, auth), self.assertRaises(vpn.RuntimeSafetyError):
                switch.processes()

    def test_managed_process_requires_exact_pid_start_config_and_auth(self):
        config = str(vpn.RUNTIME_DIR / "profile-test.ovpn")
        auth = str(vpn.RUNTIME_DIR / "auth-test.txt")
        state = switch.Connection(47420, "dev", "Mon Oct 12 10:00:00 2026", config, auth, True)
        with self.inspect(config, auth):
            self.assertEqual(switch.processes(state), [state])
            with self.assertRaises(vpn.RuntimeSafetyError):
                switch.processes()
        with self.inspect(config, auth, started="Tue Oct 13 10:00:00 2026"), self.assertRaises(vpn.RuntimeSafetyError):
            switch.processes(state)

    def test_unknown_process_refused_before_setup_or_sudo(self):
        with mock.patch.object(switch, "processes", side_effect=vpn.RuntimeSafetyError("unknown")), \
             mock.patch.object(switch, "setup") as setup, \
             mock.patch.object(switch, "authorize_sudo") as sudo, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(switch.main(["dev", "--setup"]), 1)
            setup.assert_not_called()
            sudo.assert_not_called()

    def test_nonterminal_setup_never_prompts_or_writes(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=False), \
             mock.patch.object(switch.getpass, "getpass") as prompt, self.assertRaises(vpn.RuntimeSafetyError):
            switch.setup("dev")
        prompt.assert_not_called()
        self.assertFalse(switch.CONFIG_DIR.exists())

    def test_setup_saves_private_separate_files_without_authenticating(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
             mock.patch.object(switch.getpass, "getpass", side_effect=["user", "a\"# b='", "audit-user", "audit-secret"]), \
             mock.patch.object(vpn, "authenticate") as authenticate:
            switch.setup("dev")
            switch.setup("audit")
        authenticate.assert_not_called()
        for environment in switch.PROFILES:
            path = switch.CONFIG_DIR / f"{environment}.env"
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(vpn.load_credentials(path).profile, switch.PROFILES[environment])
        self.assertEqual(vpn.load_credentials(switch.CONFIG_DIR / "dev.env").password, "a\"# b='")
        self.assertEqual(stat.S_IMODE(switch.CONFIG_DIR.stat().st_mode), 0o700)
        self.assertEqual(sorted(p.name for p in switch.CONFIG_DIR.iterdir()), ["audit.env", "dev.env"])

    def test_credential_profile_and_permissions_fail_closed(self):
        switch.CONFIG_DIR.mkdir(mode=0o700)
        path = switch.CONFIG_DIR / "dev.env"
        path.write_text("NAVER_VPN_PROFILE=vpn2203\nNAVER_VPN_USERNAME=u\nNAVER_VPN_PASSWORD=p\n")
        path.chmod(0o600)
        with self.assertRaises(vpn.ConfigError):
            switch.credentials_for("dev")
        path.chmod(0o644)
        with self.assertRaises(vpn.ConfigError):
            switch.credentials_for("dev")

    def test_setup_command_does_not_authenticate_stop_or_authorize(self):
        with mock.patch.object(switch, "processes", return_value=[]), \
             mock.patch.object(switch, "installation_preflight", return_value="valid"), \
             mock.patch.object(switch, "setup") as setup, \
             mock.patch.object(vpn, "authenticate") as authenticate, \
             mock.patch.object(switch, "stop_connection") as stop, \
             mock.patch.object(switch, "authorize_sudo") as sudo, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(switch.main(["audit", "--setup"]), 0)
        setup.assert_called_once_with("audit")
        authenticate.assert_not_called()
        stop.assert_not_called()
        sudo.assert_not_called()

    def test_backup_moves_unread_app_auth_file_and_restricts_permissions(self):
        original = self.root / "app auth-file.txt"
        original.write_text("synthetic OTP")
        original.chmod(0o644)
        with mock.patch.object(switch, "APP_AUTH_FILE", original), \
             mock.patch.object(Path, "read_text", side_effect=AssertionError("must not read auth contents")):
            switch.backup_app_auth_file()
        self.assertFalse(original.exists())
        files = list(switch.CONFIG_DIR.glob("app-auth-backup-*/auth-file.txt"))
        self.assertEqual(len(files), 1)
        self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)

    def test_backup_rejects_symlinks_and_hardlinks(self):
        source = self.root / "source"
        source.write_text("synthetic")
        symlink = self.root / "link"
        symlink.symlink_to(source)
        hardlink = self.root / "hard"
        hardlink.hardlink_to(source)
        for path in [symlink, hardlink]:
            with self.subTest(path=path), mock.patch.object(switch, "APP_AUTH_FILE", path), \
                 self.assertRaises(vpn.RuntimeSafetyError):
                switch.backup_app_auth_file()

    def test_status_reads_no_secrets_and_reports_redacted_processes(self):
        item = switch.Connection(47420, "dev", "date", "config", "auth", False)
        output = io.StringIO()
        with mock.patch.object(switch, "processes", return_value=[item]), \
             mock.patch.object(switch, "installation_preflight", return_value="valid"), \
             mock.patch.object(vpn, "load_credentials", side_effect=AssertionError("no secrets")), \
             mock.patch.object(vpn, "authenticate", side_effect=AssertionError("no auth")), \
             mock.patch.object(switch, "management_control", side_effect=vpn.RuntimeSafetyError("busy")), \
             contextlib.redirect_stdout(output):
            self.assertEqual(switch.status(), 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["active"], [{"pid": 47420, "profile": "dev", "managed": False,
                                           "mode": "foreground", "state": "unknown"}])
        self.assertNotIn("config", report["active"][0])

    def test_stop_uses_only_pid_verified_management_sigterm(self):
        connection = switch.Connection(47420, "dev", "date", "config", "auth", False)
        control = mock.Mock()
        control.response.return_value = b"SUCCESS: signal SIGTERM thrown"
        with mock.patch.object(switch, "load_state", return_value=None), \
             mock.patch.object(switch, "processes", side_effect=[[connection], []]), \
             mock.patch.object(subprocess, "run") as run:
            switch.stop_connection(connection, control)
        control.verify_pid.assert_called_once_with(47420)
        control.stream.sendall.assert_called_once_with(b"signal SIGTERM\r\n")
        run.assert_not_called()

    def test_sudo_prompt_identifies_mac_login_password_before_prompting(self):
        output = io.StringIO()
        def authorize(*_args, **_kwargs):
            self.assertIn("Mac 로그인 비밀번호", output.getvalue())
            self.assertIn("VPN 비밀번호가 아닌", output.getvalue())
            return mock.Mock(returncode=0)
        with mock.patch.object(switch, "require_terminal"), \
             mock.patch.object(vpn, "sudo_ready", side_effect=[False, True]), \
             mock.patch.object(subprocess, "run", side_effect=authorize) as run, \
             contextlib.redirect_stdout(output):
            switch.authorize_sudo()
        self.assertEqual(run.call_args.args[0], ["/usr/bin/sudo", "-v"])

    def test_stop_times_out_without_force_kill(self):
        connection = switch.Connection(47420, "dev", "date", "config", "auth", False)
        control = mock.Mock()
        control.response.return_value = b"SUCCESS: signal SIGTERM thrown"
        with mock.patch.object(switch, "load_state", return_value=None), \
             mock.patch.object(switch, "processes", return_value=[connection]), \
             mock.patch.object(switch.time, "monotonic", side_effect=[0, 11]), \
             mock.patch.object(subprocess, "run") as run, \
             self.assertRaisesRegex(vpn.RuntimeSafetyError, "no force kill"):
            switch.stop_connection(connection, control)
        run.assert_not_called()
        control.stream.sendall.assert_called_once_with(b"signal SIGTERM\r\n")

    def test_strict_signature_failure_is_never_globally_bypassed(self):
        with mock.patch.object(vpn, "verify_installation", side_effect=vpn.RuntimeSafetyError("VPN app code signature verification failed")), \
             mock.patch.object(subprocess, "run", return_value=mock.Mock(returncode=1, stdout="", stderr="tampered binary")) as run, \
             self.assertRaisesRegex(vpn.RuntimeSafetyError, "unapproved mismatch"):
            switch.installation_preflight()
        self.assertIn("--deep", run.call_args.args[0])
        self.assertIn("--strict", run.call_args.args[0])

    def test_real_exec_child_does_not_inherit_blocked_termination_signals(self):
        record = self.root / "mask.json"
        auth = self.root / "auth.txt"
        auth.write_text("synthetic")
        code = ("import json,signal; from pathlib import Path; "
                f"Path({str(record)!r}).write_text(json.dumps(sorted(int(s) for s in "
                "signal.pthread_sigmask(signal.SIG_BLOCK,set()))))")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(vpn._monitor_openvpn([sys.executable, "-c", code], auth), 0)
        blocked = json.loads(record.read_text())
        self.assertTrue({int(signal.SIGINT), int(signal.SIGTERM), int(signal.SIGHUP)}.isdisjoint(blocked))
        self.assertFalse(auth.exists())

    def test_permission_error_uses_cached_sudo_without_force_kill(self):
        child = mock.Mock(pid=1234, stdout=[])
        child.poll.return_value = None
        child.wait.side_effect = [0, 0]
        child.send_signal.side_effect = PermissionError
        auth = self.root / "auth.txt"
        auth.write_text("synthetic")
        with mock.patch.object(subprocess, "Popen", return_value=child), \
             mock.patch.object(subprocess, "run", return_value=mock.Mock(returncode=0)) as run, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(vpn._monitor_openvpn(["synthetic"], auth), 0)
        child.send_signal.assert_called_once_with(signal.SIGTERM)
        self.assertEqual(run.call_args.args[0], ["/usr/bin/sudo", "-n", "/bin/kill", "-TERM", "1234"])
        child.terminate.assert_not_called()
        child.kill.assert_not_called()

    def test_sudo_preflight_permission_error_is_explicit(self):
        with mock.patch.object(subprocess, "run", side_effect=PermissionError), \
             self.assertRaisesRegex(vpn.RuntimeSafetyError, "could not be checked"):
            vpn.sudo_ready()

    def test_verbose_signature_diagnostic_accepts_only_exact_extra_auth_file(self):
        diagnostic = mock.Mock(returncode=1,
            stderr=f"--prepared:{vpn.APP_PATH}/Contents/Frameworks/Example.framework/Versions/Current/.\n"
                   f"--validated:{vpn.APP_PATH}/Contents/Frameworks/Example.framework/Versions/Current/.\n"
                   f"{vpn.APP_PATH}: a sealed resource is missing or invalid\n",
            stdout=f"file added: {switch.APP_AUTH_FILE}\n")
        details = mock.Mock(returncode=0, stderr=f"TeamIdentifier={vpn.APP_TEAM_ID}\n", stdout="")
        with mock.patch.object(vpn, "verify_installation", side_effect=vpn.RuntimeSafetyError("VPN app code signature verification failed")), \
             mock.patch.object(subprocess, "run", side_effect=[diagnostic, details]) as run, \
             mock.patch.object(Path, "open", mock.mock_open()), \
             mock.patch.object(switch.plistlib, "load", return_value={"CFBundleIdentifier": vpn.APP_BUNDLE_ID}), \
             mock.patch.object(switch, "validate_app_auth_file"):
            self.assertEqual(switch.installation_preflight(), "legacy_auth_file_present")
        self.assertIn("--verbose=2", run.call_args_list[0].args[0])
        diagnostic.stdout += "file added: /tmp/unapproved\n"
        with mock.patch.object(vpn, "verify_installation", side_effect=vpn.RuntimeSafetyError("VPN app code signature verification failed")), \
             mock.patch.object(subprocess, "run", return_value=diagnostic), \
             self.assertRaises(vpn.RuntimeSafetyError):
            switch.installation_preflight()

    def test_second_transition_refused_before_credentials_or_process_changes(self):
        descriptor = switch.transition_lock()
        try:
            with mock.patch.object(switch, "processes") as processes, \
                 mock.patch.object(switch, "credentials_for") as credentials, \
                 mock.patch.object(switch, "stop_connection") as stop, \
                 contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(switch.main(["audit"]), 1)
            processes.assert_not_called()
            credentials.assert_not_called()
            stop.assert_not_called()
        finally:
            os.close(descriptor)

    def test_failed_stop_preserves_live_managed_ownership_record(self):
        owned = switch.Connection(47420, "dev", "date", "config", "auth", True)
        def record(*_args):
            switch.save_state(owned)
            return owned
        def connect(*_args, **kwargs):
            record()
            raise vpn.RuntimeSafetyError("OpenVPN did not stop")
        with mock.patch.object(switch, "processes", side_effect=[[], []]), \
             mock.patch.object(switch, "installation_preflight", return_value="valid"), \
             mock.patch.object(switch, "require_terminal"), \
             mock.patch.object(vpn, "resolve_profile", return_value=Path("profile")), \
             mock.patch.object(vpn, "load_profile", return_value=object()), \
             mock.patch.object(vpn, "check_tls", return_value=True), \
             mock.patch.object(switch, "credentials_for", return_value=object()), \
             mock.patch.object(switch, "authorize_sudo"), \
             mock.patch.object(vpn, "management_port_open", return_value=False), \
             mock.patch.object(switch, "backup_app_auth_file"), \
             mock.patch.object(vpn, "verify_installation", return_value="1.1.3"), \
             mock.patch.object(switch, "record_connection", side_effect=record), \
             mock.patch.object(vpn_daemon, "connect_daemon", side_effect=connect), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(switch.main(["dev"]), 1)
        self.assertEqual(switch.load_state(), owned)

    def test_vanished_process_is_benign_but_other_inspection_errors_are_explicit(self):
        with mock.patch.object(subprocess, "run", return_value=mock.Mock(returncode=1, stdout="")), \
             mock.patch.object(os, "kill", side_effect=ProcessLookupError):
            self.assertEqual(switch.capture(["/bin/ps", "-p", "47420", "-o", "args="]), "")
        with mock.patch.object(subprocess, "run", return_value=mock.Mock(returncode=1, stdout="")), \
             mock.patch.object(os, "kill", side_effect=PermissionError), \
             self.assertRaises(vpn.RuntimeSafetyError):
            switch.capture(["/bin/ps", "-p", "47420", "-o", "args="])

    def test_process_start_time_does_not_depend_on_caller_locale(self):
        # 2026-10-15: a tunnel started from a Korean-locale Terminal recorded "2026년 10월 15일 ..." and a
        # later English-locale status call read "Thu Oct 15 ..." for the same process, so it was "unknown".
        pid = str(os.getpid())
        with mock.patch.dict(os.environ, {"LANG": "ko_KR.UTF-8", "LC_ALL": "ko_KR.UTF-8"}):
            korean_caller = switch.capture(["/bin/ps", "-p", pid, "-o", "lstart="])
        with mock.patch.dict(os.environ, {"LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8"}):
            english_caller = switch.capture(["/bin/ps", "-p", pid, "-o", "lstart="])
        self.assertEqual(korean_caller, english_caller)
        self.assertRegex(korean_caller, r"^[A-Z][a-z]{2} [A-Z][a-z]{2} ")


if __name__ == "__main__":
    unittest.main()
