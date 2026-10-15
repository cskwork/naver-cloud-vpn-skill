---
name: naver-cloud-vpn
description: VPN for AIDT dev/audit private network (10.0.x): status, connect, switch, or disconnect the NAVER Cloud SSL VPN dev or audit tunnel from the terminal. Use when ssh/connect.sh, kubectl, or the dev/audit DB times out on 10.0.x, or the user asks "vpn 연결", "심사 DB 터널", "개발계/심사계 VPN". Production excluded.
---

# NAVER Cloud VPN

Use `scripts/vpn.py` for the default dev (`vpn2361`) and audit (`vpn2203`) profiles. Production is excluded. Run commands from the skill directory. For other installed profiles, use the generic `scripts/naver_vpn.py` connector described in README.md.

## Authorization and secrets

- An explicit user request to connect, switch, or disconnect authorizes that network change. Do not ask again for the same authorized action.
- `--status` is read-only. It reads no credentials, performs no authentication, and reports process identity, management state, and mode separately.
- `--setup` only saves ID/password locally. Enter secrets directly in the user's Mac Terminal through `getpass`; never accept or expose them in chat, command arguments, environment variables, or logs.
- Store credentials only in `~/.config/naver-cloud-vpn/{dev,audit}.env`, mode `0600`, in a private directory. OTP is interactive and never stored persistently. A sudo prompt needs the **Mac login password**.

## Commands

```bash
python3 scripts/vpn.py --status
python3 scripts/vpn.py --setup
python3 scripts/vpn.py audit
python3 scripts/vpn.py dev
python3 scripts/vpn.py --disconnect
```

Agent flow: the agent cannot type the Mac password or OTP. Run `vpn --status` (`~/.local/bin/vpn` links to this folder's `vpn`); if `active` is empty, open the user's Terminal with `open -a Terminal <skill>/dev.command` (audit: `audit.command`), ask the user for OTP, then poll `vpn --status` until `CONNECTED`. The terminal command is the only connect path: GUI app clicks and computer-use stay out of it.

A successful default connection runs the installed OpenVPN binary in its native daemon mode. The command returns only after the exact process identity, management PID, management `CONNECTED` state, and initialization-complete log marker agree. Closing Terminal afterward keeps that selected tunnel running. Only **one of dev or audit** runs at a time; switching gracefully stops the old tunnel before starting the new one. No Python supervisor or boot-time service is installed.

Running the already connected environment returns without OTP, sudo, or restarting it. An older foreground connection remains Terminal-dependent: the command says so. Migrate it only through an authorized explicit reconnect:

```bash
python3 scripts/vpn.py dev --reconnect
```

## Guardrails and failures

- Validate the installed profile, selected credential file, API TLS, app signature, and signer. Never disable TLS verification or deep, strict code-signature checks.
- OpenVPN accepts one management client. If the NAVER app owns it, stop before sudo/authentication or network changes and ask the user to click **Disconnect once in the NAVER app**, then rerun the requested command. Never take over the GUI connection.
- Disconnect only a verified dev/audit process whose management `pid` matches its executable/config/start identity. Recheck before `signal SIGTERM`, then require actual exit within 10 seconds. Never force kill. Unknown, production, ambiguous, and multiple VPN processes are refused.
- An app-generated `Contents/vpn/auth-file.txt` is the only tolerated pre-disconnect signature mismatch. With no tunnel remaining, move that regular, user-owned, single-link file without reading it into a private `app-auth-backup-*` directory, set `0600`, then require full strict signature verification.
- Daemon startup is bounded to 90 seconds, plus bounded graceful cleanup. A zero launcher exit is not connection proof. Remove the temporary OTP file on success and failure. Keep private profile/log files only while the tunnel or an uncertain launcher may still need them; remove them after verified disconnect.
- A pending startup record fences new transitions while its launcher is alive or cannot be identified. Report `pending`/unknown rather than disconnected. Preserve ownership and private files after an unverified stop; never overwrite that record with a new launch.
- ID/password and OTP authentication happen after the old tunnel stops. Failed authentication leaves it disconnected; there is no automatic restoration. Server session expiry or a network interruption can still end a daemon tunnel; a fresh OTP may be needed to reconnect.
- `CONNECTED` proves tunnel initialization, not the identity of services behind private addresses. Verify the target environment independently when needed.
