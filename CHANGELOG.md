# Changelog

## 0.1.0 — 2026-10-13

Initial release for existing NAVER Cloud SSL VPN profiles on macOS.

- Switch between dev and audit, with one VPN active at a time.
- Run OpenVPN as a native daemon that stays connected after Terminal closes.
- Inspect with `--status`, stop with `--disconnect`, and migrate foreground connections with `--reconnect`.
- Reuse an already connected environment without another login, OTP, or restart.
- Store ID/password in private local files and remove temporary OTP files after startup or failure.
- Require verified TLS, strict app signatures, and PID/start/config ownership before controlling a tunnel.

If the NAVER app owns the management connection, disconnect once in that app before using the wrapper. Reboot or server session expiry can require reconnection and a fresh OTP; automatic startup and restoration of a failed switch are not provided.

Validation: 59 unit tests and the skill validator passed. A real dev daemon survived Terminal closure, and its target database identity was checked independently.
