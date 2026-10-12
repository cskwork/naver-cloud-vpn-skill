# NAVER Cloud VPN skill

Connect or switch existing NAVER Cloud SSL VPN profiles on macOS from Terminal. A successful connection runs as a native OpenVPN daemon, so **closing Terminal keeps the selected VPN connected**. The wrapper runs **dev or audit, one at a time**.

## Requirements

- macOS, Python 3.10 or newer, and the installed, signed NAVER Cloud SSL VPN app.
- Existing VPN profiles and valid credentials. The convenience wrapper defaults to dev `vpn2361` and audit `vpn2203`; production is excluded.
- Terminal access for the initial ID/password setup, sudo authorization, and OTP. There are no pip dependencies, sudoers changes, or services installed at boot.

The bundled app version 1.1.3 and OpenVPN 2.5.7 informed this implementation. Other app versions must pass the same signature, signer, profile, and protocol checks.

## Install and run

```bash
git clone https://github.com/cskwork/naver-cloud-vpn-skill.git
cd naver-cloud-vpn-skill
python3 scripts/vpn.py --setup
python3 scripts/vpn.py audit
python3 scripts/vpn.py --status
python3 scripts/vpn.py dev
python3 scripts/vpn.py --disconnect
```

`--setup` saves separate local credential files for both environments without authenticating. Use `dev --setup` or `audit --setup` to save just one. Missing credentials are also prompted for on first connection. All secrets are entered directly in Terminal, never in chat or command arguments. If sudo displays `Password:`, enter your **Mac login password**, not the VPN password. Enter the fresh OTP at `OTP:`.

Wait for `CONNECTED <environment> daemon` before closing Terminal. This requires a verified process and management PID, management state `CONNECTED`, and OpenVPN's initialization-complete marker. A launcher exit code of zero alone does not count.

The same environment can be requested again without another OTP or restart. Switching environments stops the old VPN before starting the new one. Explicitly disconnect with `--disconnect`; it needs no credential read, OTP, or sudo prompt. An optional environment, such as `audit --disconnect`, refuses to stop a different active environment.

For a connection created by an older foreground version, `--status` reports `mode: foreground`. Keep its Terminal open until an authorized reconnect migrates it:

```bash
python3 scripts/vpn.py dev --reconnect
```

To install as an agent skill, place the repository under your agent's skills directory. `SKILL.md` is the entry point. The Python commands also work independently of an agent.

## Initial NAVER app disconnect

OpenVPN permits a single management client. If the NAVER app is connected, click **Disconnect once in that app**, then run the wrapper. The wrapper refuses an occupied management connection before requesting sudo or changing the VPN. It does not automate the GUI or take over its socket. Later wrapper-owned connections can be switched through their verified management connection.

## Local files and failure behavior

Configuration lives under `~/.config/naver-cloud-vpn/`, outside this repository. Credential files and runtime profile/log files are `0600`; their directories are private. OTP files are deleted after startup or failure. A successful daemon retains its private profile/log and ownership record until verified disconnect, which removes them.

A legacy app-generated authentication file can invalidate the app's sealed resources. The wrapper accepts only that exact extra-file diagnostic before disconnect, moves the file without reading it into a private backup directory, and requires full deep, strict signature verification before launching anything. It never disables signature or TLS verification.

Startup has a 90-second deadline and bounded graceful cleanup. Unknown, production, ambiguous, or multiple OpenVPN processes are refused. Stops use the PID-verified local management command `signal SIGTERM`, never a force kill. A failed stop or uncertain launcher preserves its ownership record and private files and blocks another launch; status reports a pending or unknown state. Resolve that reported process before retrying.

Authentication occurs after the previous tunnel stops. A failed password/OTP or failed connection leaves the previous tunnel disconnected; automatic restoration is not provided. Closing Terminal after successful daemon startup does not deliberately disconnect it, but server session expiry, sleep, or network loss may still do so. Reconnection can require another OTP.

Status separates process presence, mode, and management state. Tunnel initialization does not prove which backend environment a private address reaches; check that service separately if necessary.

## Generic existing-profile connector

For other profile aliases, use `scripts/naver_vpn.py`. Create a private `0600` file at `~/.config/naver-cloud-vpn/.env`:

```dotenv
NAVER_VPN_PROFILE=Exact installed profile alias
NAVER_VPN_USERNAME=your-id
NAVER_VPN_PASSWORD=your-password
```

```bash
python3 scripts/naver_vpn.py --check --profile "Exact installed profile alias"
python3 scripts/naver_vpn.py --auth-check
sudo -v
python3 scripts/naver_vpn.py --connect
```

`--check` reads no credentials and does not authenticate. `--auth-check` sends ID/password to the TLS-verified VPN endpoint; run it only when credential verification is intended. This generic `--connect` remains foreground and disconnects when its Terminal session ends. Use the dev/audit wrapper for native daemon behavior.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Tests cover credential privacy, profile and signature checks, production refusal, PID/start/config ownership, management protocol, concurrent transitions, daemon readiness, startup interruption and timeout cleanup, pending launch fences, explicit disconnect, and a synthetic detached process that survives its launcher. They make no real VPN authentication request.
