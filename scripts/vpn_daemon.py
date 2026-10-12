"""Native OpenVPN daemon startup; no Python supervisor remains after success."""

from __future__ import annotations

import getpass
from dataclasses import replace
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import ModuleType

import naver_vpn as vpn


START_TIMEOUT = 90


def private_file(prefix: str, suffix: str, content: bytes = b"") -> Path:
    vpn.ensure_private_runtime(vpn.RUNTIME_DIR)
    descriptor, value = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=vpn.RUNTIME_DIR)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        Path(value).unlink(missing_ok=True)
        raise
    return Path(value)


def daemon_command(config: Path, authentication: Path, log: Path) -> list[str]:
    return vpn.build_openvpn_command(vpn.OPENVPN, config, authentication) + [
        "--daemon", "--log", str(log)
    ]


def connect_daemon(environment: str, credentials: vpn.Credentials,
                   profile: vpn.ProfileInfo, version: str, manager: ModuleType) -> int:
    result = vpn.authenticate(vpn.HttpsTransport(), profile, credentials, vpn.collect_metadata(version))
    secret = credentials.password
    if result.otp_required:
        manager.require_terminal()
        secret = getpass.getpass("OTP: ")
    if not secret or any(character in secret for character in "\r\n\x00"):
        raise vpn.ConfigError("authentication secret was empty or invalid")
    content = result.profile_bytes if result.profile_bytes is not None else profile.text.encode("utf-8")
    vpn.parse_profile_text(content.decode("utf-8"), profile.path)
    config = private_file("profile-", ".ovpn", content)
    log = None
    owned = None
    control = None
    success = False
    intent = None
    child = None
    launch_attempted = False
    try:
        log = private_file("daemon-", ".log")
        with vpn.termination_guard(), vpn.auth_file(vpn.RUNTIME_DIR, credentials.username, secret) as authentication:
            # Persist exact paths before a root child can outlive this invocation.
            # Read-only status can recover its real PID/start identity from ps.
            intent = manager.Connection(0, environment, "pending", str(config), str(authentication),
                                        True, "daemon", str(log))
            manager.save_state(intent)
            deadline = time.monotonic() + START_TIMEOUT
            print("CONNECTING", flush=True)
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK,
                                                   {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
            try:
                launch_attempted = True
                child = subprocess.Popen(daemon_command(config, authentication, log),
                                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL,
                                         preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask))
                intent = replace(intent, launcher_pid=child.pid,
                                 launcher_started=manager.capture(["/bin/ps", "-p", str(child.pid), "-o", "lstart="]))
                manager.save_state(intent)
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            try:
                code = child.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as error:
                raise vpn.RuntimeSafetyError("OpenVPN daemon launcher timed out") from error
            if code != 0:
                raise vpn.RuntimeSafetyError("OpenVPN daemon launcher failed")
            while time.monotonic() < deadline:
                if owned is None:
                    try:
                        owned = manager.record_connection(environment, config, log=log)
                    except vpn.RuntimeSafetyError as error:
                        if str(error) != "new OpenVPN process could not be identified":
                            raise
                        time.sleep(0.2)
                        continue
                if manager.processes(owned) != [owned]:
                    raise vpn.RuntimeSafetyError("OpenVPN daemon exited before connecting")
                if control is None:
                    try:
                        control = manager.management_control(owned)
                    except vpn.RuntimeSafetyError as error:
                        if not str(error).startswith("NAVER VPN 앱"):
                            raise
                        time.sleep(0.2)
                        continue
                text = vpn._open_owned_file(log, private=True, max_bytes=2 * 1024 * 1024)
                if "AUTH_FAILED" in text or "auth-failure" in text:
                    raise vpn.ApiError("VPN daemon authentication was rejected")
                if control.connected() and "Initialization Sequence Completed" in text:
                    control.verify_pid(owned.pid)
                    if manager.processes(owned) != [owned]:
                        raise vpn.RuntimeSafetyError("VPN daemon identity changed during startup")
                    authentication.unlink(missing_ok=True)
                    success = True
                    print(f"CONNECTED {environment} daemon", flush=True)
                    return 0
                time.sleep(0.2)
            raise vpn.RuntimeSafetyError("VPN daemon did not reach CONNECTED within 90 seconds")
    finally:
        if control is not None:
            control.close()
        if not success:
            # sudo can still be preparing to exec OpenVPN. Its liveness must be
            # resolved before absence of an OpenVPN PID permits file cleanup.
            launcher_alive = False
            if child is not None and child.poll() is None:
                try:
                    child.wait(timeout=3)
                except (subprocess.TimeoutExpired, OSError):
                    launcher_alive = True
            # Even a failed launcher can leave a child. Identify it before cleanup.
            if owned is None and log is not None:
                try:
                    owned = manager.record_connection(environment, config, log=log)
                except (vpn.VpnError, OSError):
                    pass
            stopped = False
            if owned is not None:
                cleanup_control = None
                try:
                    if manager.processes(owned):
                        cleanup_control = manager.management_control(owned)
                        manager.stop_connection(owned, cleanup_control)
                    else:
                        manager.cleanup_connection(owned)
                    stopped = True
                except (vpn.VpnError, OSError, EOFError):
                    print("ERROR: daemon cleanup could not be verified; ownership and private files retained; use --disconnect",
                          file=sys.stderr)
                finally:
                    if cleanup_control is not None:
                        cleanup_control.close()
            else:
                try:
                    stopped = (not launch_attempted or (child is not None and not launcher_alive
                               and not manager.processes(manager.load_state())))
                except (vpn.VpnError, OSError):
                    print("ERROR: daemon process inspection failed; private startup files retained", file=sys.stderr)
            if stopped:
                if intent is not None:
                    manager.cleanup_connection(intent)
                config.unlink(missing_ok=True)
                if log is not None:
                    log.unlink(missing_ok=True)
            if launcher_alive:
                print("ERROR: launcher is still running; startup ownership and private files retained; no force kill attempted",
                      file=sys.stderr)
            elif launch_attempted and child is None:
                print("ERROR: launcher startup is uncertain; pending ownership and private files retained",
                      file=sys.stderr)
