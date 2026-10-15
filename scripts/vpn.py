#!/usr/bin/env python3
"""Terminal-only AIDT dev/audit VPN setup and switching."""

from __future__ import annotations

import argparse
import fcntl
import getpass
import json
import os
import plistlib
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path

import naver_vpn as vpn


PROFILES = {"dev": "vpn2361", "audit": "vpn2203"}
CONFIG_DIR = vpn.DEFAULT_ENV_FILE.parent
STATE_FILE = CONFIG_DIR / "connection.json"
APP_AUTH_FILE = vpn.APP_PATH / "Contents/vpn/auth-file.txt"


def transition_lock() -> int:
    vpn.ensure_private_runtime(CONFIG_DIR)
    descriptor = os.open(CONFIG_DIR / "transition.lock",
                         os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise vpn.RuntimeSafetyError("VPN transition lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise vpn.RuntimeSafetyError("another VPN transition is in progress") from error
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@dataclass(frozen=True)
class Connection:
    pid: int
    environment: str
    started: str
    config: str
    auth: str
    managed: bool
    mode: str = "foreground"
    log: str | None = None
    launcher_pid: int | None = None
    launcher_started: str | None = None


class ManagementControl:
    def __init__(self, stream: socket.socket):
        self.stream = stream
        self.pending = b""

    def close(self) -> None:
        self.stream.close()

    def line(self, deadline: float | None = None) -> bytes:
        deadline = time.monotonic() + 2 if deadline is None else deadline
        while b"\n" not in self.pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            self.stream.settimeout(remaining)
            chunk = self.stream.recv(1024)
            if not chunk:
                raise EOFError
            self.pending += chunk
            if len(self.pending) > 8192:
                raise vpn.RuntimeSafetyError("VPN management response exceeded its limit")
        line, self.pending = self.pending.split(b"\n", 1)
        return line.rstrip(b"\r")

    def response(self) -> bytes:
        deadline = time.monotonic() + 2
        total = 0
        for _ in range(16):
            line = self.line(deadline)
            total += len(line) + 1
            if total > 8192:
                raise vpn.RuntimeSafetyError("VPN management response exceeded its limit")
            if not line.startswith(b">"):
                return line
        raise vpn.RuntimeSafetyError("VPN management sent too many notifications")

    def verify_pid(self, pid: int) -> None:
        self.stream.sendall(b"pid\r\n")
        if self.response() != f"SUCCESS: pid={pid}".encode("ascii"):
            raise vpn.RuntimeSafetyError("VPN management PID does not match the approved process")

    def connected(self) -> bool:
        self.stream.sendall(b"state\r\n")
        deadline = time.monotonic() + 2
        total = 0
        connected = False
        for _ in range(16):
            line = self.line(deadline)
            total += len(line) + 1
            if total > 8192:
                break
            if line == b"END":
                return connected
            fields = line.split(b",")
            if len(fields) >= 3 and fields[1:3] == [b"CONNECTED", b"SUCCESS"]:
                connected = True
        raise vpn.RuntimeSafetyError("VPN management state response was invalid")


def management_control(connection: Connection) -> ManagementControl:
    control = None
    try:
        control = ManagementControl(socket.create_connection(vpn.MANAGEMENT, timeout=2))
        if not control.line().startswith(b">INFO:OpenVPN Management Interface Version "):
            raise vpn.RuntimeSafetyError("VPN management banner was not recognized")
        control.verify_pid(connection.pid)
        return control
    except BaseException as error:
        if control is not None:
            control.close()
        if isinstance(error, (OSError, EOFError)):
            raise vpn.RuntimeSafetyError(
                "NAVER VPN 앱에서 Disconnect를 한 번 누른 뒤 다시 실행하세요. "
                "관리 연결을 사용할 수 없어 VPN과 sudo 인증을 변경하지 않았습니다."
            ) from error
        raise


def capture(arguments: list[str]) -> str:
    try:
        # Fixed locale: `ps -o lstart=` is a process identity key and must read the same from any Terminal.
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, check=False,
                                env={**os.environ, "LC_ALL": "C", "LANG": "C"})
    except OSError as error:
        raise vpn.RuntimeSafetyError("process inspection is not permitted in this environment") from error
    if result.returncode:
        if arguments[:2] == ["/bin/ps", "-p"] and not result.stdout:
            try:
                os.kill(int(arguments[2]), 0)
            except ProcessLookupError:
                return ""
            except PermissionError:
                pass  # A root-owned process is still alive: preserve the error.
        raise vpn.RuntimeSafetyError("process inspection failed")
    return result.stdout.strip()


def load_state() -> Connection | None:
    if not STATE_FILE.exists() and not STATE_FILE.is_symlink():
        return None
    try:
        data = json.loads(vpn._open_owned_file(STATE_FILE, private=True, max_bytes=4096))
        connection = Connection(**data)
    except (vpn.ConfigError, ValueError, TypeError) as error:
        raise vpn.RuntimeSafetyError("managed connection record is invalid") from error
    pending = connection.pid == 0 and connection.started == "pending" and connection.mode == "daemon"
    if (type(connection.pid) is not int or (connection.pid <= 1 and not pending)
            or connection.environment not in PROFILES or connection.managed is not True
            or connection.mode not in {"foreground", "daemon"}
            or (connection.mode == "daemon" and not isinstance(connection.log, str))
            or not all(isinstance(value, str) and value for value in
                       (connection.started, connection.config, connection.auth))):
        raise vpn.RuntimeSafetyError("managed connection record is invalid")
    return connection


def argument(arguments: str, option: str) -> str:
    matches = re.findall(r"(?:^| )" + re.escape(option) + r" (.*?)(?= --[A-Za-z]|$)", arguments)
    if len(matches) != 1:
        raise vpn.RuntimeSafetyError("OpenVPN arguments are ambiguous")
    return matches[0]


def processes(state: Connection | None = None) -> list[Connection]:
    active = []
    for line in capture(["/bin/ps", "-axo", "pid=,comm="]).splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) != 2 or fields[1] != str(vpn.OPENVPN):
            continue
        pid = int(fields[0])
        arguments = capture(["/bin/ps", "-p", str(pid), "-o", "args="])
        if not arguments:
            continue
        if not arguments.startswith(str(vpn.OPENVPN) + " "):
            raise vpn.RuntimeSafetyError("OpenVPN executable identity is ambiguous")
        options = arguments[len(str(vpn.OPENVPN)) + 1:]
        flags = re.findall(r"(?:^| )(--[A-Za-z][A-Za-z-]*)", options)
        daemon = flags == ["--config", "--auth-user-pass", "--daemon", "--log"]
        if flags != ["--config", "--auth-user-pass"] and not daemon:
            raise vpn.RuntimeSafetyError("OpenVPN options are not approved")
        config = argument(options, "--config")
        auth = argument(options, "--auth-user-pass")
        started = capture(["/bin/ps", "-p", str(pid), "-o", "lstart="])
        if not started:
            continue
        environments = [name for name, stem in PROFILES.items()
                        if config == str(vpn.PROFILES_DIR / f"{stem}.ovpn")]
        if len(environments) == 1 and auth == str(APP_AUTH_FILE) and not daemon:
            active.append(Connection(pid, environments[0], started, config, auth, False))
        elif (state is not None and ((pid == state.pid and started == state.started)
              or (state.pid == 0 and state.started == "pending" and state.mode == "daemon"))
              and config == state.config and auth == state.auth
              and (state.mode == "daemon") == daemon
              and (not daemon or (argument(options, "--log") == state.log
                   and re.search(r"(?:^| )--daemon --log ", options)
                   and Path(state.log).parent == vpn.RUNTIME_DIR
                   and re.fullmatch(r"daemon-[A-Za-z0-9_-]+\.log", Path(state.log).name)))
              and Path(config).parent == vpn.RUNTIME_DIR
              and re.fullmatch(r"profile-[A-Za-z0-9_-]+\.ovpn", Path(config).name)
              and Path(auth).parent == vpn.RUNTIME_DIR
              and re.fullmatch(r"auth-[A-Za-z0-9_-]+\.txt", Path(auth).name)):
            active.append(replace(state, pid=pid, started=started))
        else:
            raise vpn.RuntimeSafetyError("production or unknown OpenVPN is active; no changes made")
    if len(active) > 1:
        raise vpn.RuntimeSafetyError("multiple OpenVPN processes are active; no changes made")
    if not active and state is not None and state.pid == 0:
        if type(state.launcher_pid) is not int or state.launcher_pid <= 1 or not isinstance(state.launcher_started, str):
            raise vpn.RuntimeSafetyError("unresolved VPN startup; inspect its launcher before retrying")
        started = capture(["/bin/ps", "-p", str(state.launcher_pid), "-o", "lstart="])
        if started and started == state.launcher_started:
            raise vpn.RuntimeSafetyError("VPN launcher is still running; pending ownership retained; retry after it exits")
    return active


def save_state(connection: Connection) -> None:
    vpn.ensure_private_runtime(CONFIG_DIR)
    descriptor, temporary = tempfile.mkstemp(prefix=".connection-", dir=CONFIG_DIR)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(asdict(connection), handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, STATE_FILE)
    finally:
        Path(temporary).unlink(missing_ok=True)


def record_connection(environment: str, config: Path, *, log: Path | None = None) -> Connection:
    # Inspect only the exact temporary config that this invocation created.
    matches = []
    for line in capture(["/bin/ps", "-axo", "pid=,comm="]).splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) != 2 or fields[1] != str(vpn.OPENVPN):
            continue
        pid = int(fields[0])
        arguments = capture(["/bin/ps", "-p", str(pid), "-o", "args="])
        if not arguments.startswith(str(vpn.OPENVPN) + " "):
            continue
        options = arguments[len(str(vpn.OPENVPN)) + 1:]
        if argument(options, "--config") == str(config):
            auth = argument(options, "--auth-user-pass")
            matches.append(Connection(pid, environment,
                                      capture(["/bin/ps", "-p", str(pid), "-o", "lstart="]),
                                      str(config), auth, True,
                                      "daemon" if log is not None else "foreground",
                                      str(log) if log is not None else None))
    if len(matches) != 1:
        raise vpn.RuntimeSafetyError("new OpenVPN process could not be identified")
    connection = matches[0]
    if processes(connection) != [connection]:
        raise vpn.RuntimeSafetyError("new OpenVPN process did not pass ownership checks")
    save_state(connection)
    return connection


def require_terminal() -> None:
    if not sys.stdin.isatty():
        raise vpn.RuntimeSafetyError("run this command in your Mac Terminal; secrets are never accepted here")


def setup(environment: str) -> vpn.Credentials:
    require_terminal()
    username = getpass.getpass(f"{environment} VPN ID: ")
    password = getpass.getpass(f"{environment} VPN password: ")
    if not username or not password or any(c in username + password for c in "\r\n\x00"):
        raise vpn.ConfigError("credentials were empty or contained unsupported characters")
    credentials = vpn.Credentials(PROFILES[environment], username, password)
    content = (f'NAVER_VPN_PROFILE="{credentials.profile}"\n'
               f'NAVER_VPN_USERNAME="{username}"\nNAVER_VPN_PASSWORD="{password}"\n')
    vpn.ensure_private_runtime(CONFIG_DIR)
    descriptor, temporary = tempfile.mkstemp(prefix=".credentials-", dir=CONFIG_DIR)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, CONFIG_DIR / f"{environment}.env")
    finally:
        Path(temporary).unlink(missing_ok=True)
    return credentials


def credentials_for(environment: str) -> vpn.Credentials:
    path = CONFIG_DIR / f"{environment}.env"
    credentials = vpn.load_credentials(path) if path.exists() or path.is_symlink() else setup(environment)
    if credentials.profile != PROFILES[environment]:
        raise vpn.ConfigError("credential profile does not match the selected environment")
    return credentials


def installation_preflight() -> str:
    try:
        vpn.verify_installation()
        return "valid"
    except vpn.RuntimeSafetyError as error:
        if str(error) != "VPN app code signature verification failed":
            raise
    # An app-generated OTP file is the only tolerated pre-disconnect mismatch.
    # No exception is allowed after moving it: full strict verification follows.
    diagnostic = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", str(vpn.APP_PATH)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=False,
    )
    expected = [f"{vpn.APP_PATH}: a sealed resource is missing or invalid",
                f"file added: {APP_AUTH_FILE}"]
    diagnostics = [line for line in (diagnostic.stderr + diagnostic.stdout).strip().splitlines()
                   if not any(line.startswith(prefix + str(vpn.APP_PATH / "Contents/Frameworks") + "/")
                              for prefix in ("--prepared:", "--validated:"))]
    if diagnostic.returncode == 0 or diagnostics != expected:
        raise vpn.RuntimeSafetyError("VPN app signature has an unapproved mismatch")
    with vpn.APP_INFO.open("rb") as handle:
        info = plistlib.load(handle)
    details = subprocess.run(["/usr/bin/codesign", "-dv", "--verbose=4", str(vpn.APP_PATH)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, check=False)
    teams = [line.partition("=")[2] for line in details.stderr.splitlines()
             if line.startswith("TeamIdentifier=")]
    if (info.get("CFBundleIdentifier") != vpn.APP_BUNDLE_ID or details.returncode
            or teams != [vpn.APP_TEAM_ID]):
        raise vpn.RuntimeSafetyError("VPN app identity did not match")
    validate_app_auth_file()
    return "legacy_auth_file_present"


def validate_app_auth_file() -> None:
    metadata = APP_AUTH_FILE.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1 or metadata.st_size > vpn.MAX_CONFIG_BYTES):
        raise vpn.RuntimeSafetyError("app authentication file is unsafe")


def backup_app_auth_file() -> None:
    if not APP_AUTH_FILE.exists() and not APP_AUTH_FILE.is_symlink():
        return
    validate_app_auth_file()
    descriptor = os.open(APP_AUTH_FILE, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        validate_app_auth_file()
        original = os.fstat(descriptor)
        current = APP_AUTH_FILE.lstat()
        if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
            raise vpn.RuntimeSafetyError("app authentication file changed before backup")
        vpn.ensure_private_runtime(CONFIG_DIR)
        backup_dir = Path(tempfile.mkdtemp(prefix="app-auth-backup-", dir=CONFIG_DIR))
        os.fchmod(descriptor, 0o600)
        APP_AUTH_FILE.rename(backup_dir / "auth-file.txt")
    finally:
        os.close(descriptor)


def authorize_sudo() -> None:
    require_terminal()
    if not vpn.sudo_ready():
        print("Mac 관리자 권한 확인: 다음 Password에는 VPN 비밀번호가 아닌 Mac 로그인 비밀번호를 입력하세요.", flush=True)
        result = subprocess.run(["/usr/bin/sudo", "-v"], check=False)
        if result.returncode or not vpn.sudo_ready():
            raise vpn.RuntimeSafetyError("sudo authorization failed")


def stop_connection(connection: Connection, control: ManagementControl) -> None:
    if processes(load_state()) != [connection]:
        raise vpn.RuntimeSafetyError("OpenVPN identity changed before stop")
    control.verify_pid(connection.pid)
    control.stream.sendall(b"signal SIGTERM\r\n")
    try:
        if control.response() != b"SUCCESS: signal SIGTERM thrown":
            raise vpn.RuntimeSafetyError("VPN management did not acknowledge the graceful stop")
    except EOFError:
        pass  # A daemon may close its management socket while exiting.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if not processes(load_state()):
            cleanup_connection(connection)
            return
        time.sleep(0.2)
    raise vpn.RuntimeSafetyError("OpenVPN did not stop within 10 seconds; no force kill was attempted")


def cleanup_connection(connection: Connection) -> None:
    if connection.managed and connection.mode == "daemon":
        for value, pattern in ((connection.config, r"profile-[A-Za-z0-9_-]+\.ovpn"),
                               (connection.auth, r"auth-[A-Za-z0-9_-]+\.txt"),
                               (connection.log, r"daemon-[A-Za-z0-9_-]+\.log")):
            path = Path(value)
            if path.parent != vpn.RUNTIME_DIR or not re.fullmatch(pattern, path.name):
                raise vpn.RuntimeSafetyError("daemon cleanup path was not approved")
            if path.exists() or path.is_symlink():
                metadata = path.lstat()
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                        or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) & 0o077):
                    raise vpn.RuntimeSafetyError("daemon cleanup file was unsafe")
                path.unlink()
    state = load_state()
    if connection.managed and (state == connection or (state is not None and state.pid == 0
            and state.started == "pending" and state.config == connection.config
            and state.auth == connection.auth and state.log == connection.log)):
        STATE_FILE.unlink(missing_ok=True)


def status() -> int:
    report: dict[str, object] = {"active": [], "credentials": {}}
    failed = False
    try:
        state = load_state()
        if state is not None and state.pid == 0:
            report["startup"] = "pending"
        active = processes(state)
        report["active"] = [{"pid": item.pid, "profile": item.environment, "managed": item.managed,
                             "mode": item.mode, "state": "unknown"}
                            for item in active]
        for item in active:
            control = None
            try:
                control = management_control(item)
                report["active"][0]["state"] = "CONNECTED" if control.connected() else "not_connected"
            except (vpn.VpnError, OSError, EOFError):
                pass
            finally:
                if control is not None:
                    control.close()
    except vpn.VpnError as error:
        report["process_error"] = str(error)
        failed = True
    try:
        report["signature"] = installation_preflight()
    except (vpn.VpnError, OSError, plistlib.InvalidFileException) as error:
        report["signature"] = "invalid"
        failed = True
    for environment in PROFILES:
        path = CONFIG_DIR / f"{environment}.env"
        present = path.exists() or path.is_symlink()
        private = False
        if present:
            metadata = path.lstat()
            private = (stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()
                       and not stat.S_IMODE(metadata.st_mode) & 0o077)
        report["credentials"][environment] = {"present": present, "private": private}
    print(json.dumps(report, ensure_ascii=False))
    return int(failed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("environment", choices=PROFILES, nargs="?")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--status", action="store_true", help="redacted read-only readiness")
    modes.add_argument("--setup", action="store_true", help="save ID/password locally; no authentication")
    modes.add_argument("--disconnect", action="store_true", help="gracefully stop the verified dev/audit tunnel")
    modes.add_argument("--reconnect", action="store_true", help="explicitly reconnect, migrating a foreground tunnel")
    args = parser.parse_args(argv)
    if args.status:
        return status()
    if not args.setup and not args.disconnect and args.environment is None:
        parser.error("choose dev or audit, or use --status / --setup")
    lock: int | None = None
    control: ManagementControl | None = None
    try:
        if not args.setup:
            lock = transition_lock()
        state = load_state()
        active = processes(state)
        installation_preflight()
        if (state is not None and not active and not args.setup
                and (state.pid == 0 or (state.managed and state.mode == "daemon"))):
            cleanup_connection(state)  # ps proved no owned tunnel/uncertain launcher remains.
        if args.setup:
            for environment in [args.environment] if args.environment else PROFILES:
                setup(environment)
                print(f"SETUP_OK {environment}")
            return 0
        if args.disconnect:
            if not active:
                print("DISCONNECTED")
                return 0
            if args.environment and active[0].environment != args.environment:
                raise vpn.RuntimeSafetyError("active VPN does not match the requested environment")
            control = management_control(active[0])
            stop_connection(active[0], control)
            print("DISCONNECTED")
            return 0
        if active and active[0].environment == args.environment and not args.reconnect:
            control = management_control(active[0])
            if not control.connected():
                raise vpn.RuntimeSafetyError("selected VPN is not CONNECTED; use --reconnect to retry")
            if active[0].mode == "foreground":
                print("CONNECTED foreground: keep its Terminal open; use --reconnect to migrate to daemon")
            else:
                print(f"CONNECTED {args.environment} daemon")
            return 0
        require_terminal()
        environment = args.environment
        profile = vpn.load_profile(vpn.resolve_profile(vpn.PROFILES_DIR, PROFILES[environment]))
        if not vpn.check_tls(profile):
            raise vpn.RuntimeSafetyError("selected VPN API TLS verification failed; current VPN retained")
        credentials = credentials_for(environment)
        if active:
            control = management_control(active[0])
        authorize_sudo()
        if active:
            stop_connection(active[0], control)
            control.close()
            control = None
        if processes(load_state()) or vpn.management_port_open():
            raise vpn.RuntimeSafetyError("VPN process or management port is still active")
        backup_app_auth_file()
        version = vpn.verify_installation()

        from vpn_daemon import connect_daemon
        return connect_daemon(environment, credentials, profile, version, sys.modules[__name__])
    except KeyboardInterrupt:
        return 130
    except (vpn.VpnError, OSError, plistlib.InvalidFileException):
        # OS errors can include private paths; never print arbitrary exceptions.
        error = sys.exc_info()[1]
        print(f"ERROR: {error if isinstance(error, vpn.VpnError) else 'local file or process operation failed'}",
              file=sys.stderr)
        return 1
    finally:
        if control is not None:
            control.close()
        if lock is not None:
            os.close(lock)


if __name__ == "__main__":
    raise SystemExit(main())
