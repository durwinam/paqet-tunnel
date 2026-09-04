# paqet-tunnel

Easy installer for tunneling VPN traffic through a middle server using [paqet](https://github.com/hanselime/paqet) — raw packet-level tunneling that bypasses network restrictions.

**Version:** v2.1.0

**Web Panel:** Glassmorphism control panel on port `6102`

**Maintainer:** durwinam

## How it works

Clients connect to **Server A** (the Iran entry point), which tunnels traffic over an encrypted paqet/KCP link to **Server B** (abroad), where your V2Ray/X-UI runs. You only change the IP in your VPN client from Server B to Server A — nothing else.

```
Client ──▶ Server A (Iran) ══ paqet tunnel ══▶ Server B (abroad) ──▶ V2Ray
```

## Install

Run on **both** servers (as root):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/durwinam/paqet-tunnel/main/install.sh)
```

The first run is a guided wizard: it asks whether this machine is the abroad server or the Iran server, auto-detects the network, and walks you through the rest.

## Setup (two steps)

**1. Server B (abroad)** — choose **Abroad server (B)**:
- Confirm the detected network, pick the paqet port (default `8888`), enter your V2Ray port(s).
- Copy the **Connection String** it prints at the end (`paqet://…`).

**2. Server A (Iran)** — choose **Iran entry server (A)**:
- Give the tunnel a name, then **paste the Connection String** — it fills in the IP, port, key, and ports automatically.
- A health check confirms the tunnel is live.

Then point your VPN client at **Server A's IP** instead of Server B's.

> To reach more abroad servers, run Server A setup again with a different tunnel name.

## ⚠️ Required: V2Ray must listen on 0.0.0.0

On **Server B**, set your V2Ray/X-UI inbound **Listen IP** to `0.0.0.0` (not the public IP, not empty). paqet delivers traffic to `127.0.0.1:PORT`, so V2Ray must accept localhost connections.

## Handy menu options

- **c** — Health check (verify the tunnel end-to-end)
- **k** — Show the Connection String again (Server B)
- **3** Status · **5** Edit config · **6** Manage tunnels · **u** Uninstall
- **i** — Install as the `paqet-tunnel` command (then just run `paqet-tunnel`)

## Commands

```bash
# Server B
systemctl status paqet
journalctl -u paqet -f

# Server A (per tunnel — <name> is your tunnel name)
systemctl status paqet-<name>
journalctl -u paqet-<name> -f
```

## Troubleshooting

- **`connection lost, retrying` / health check fails** — on Server A, the paqet port must be Server B's **tunnel port** (e.g. `8888`), not the V2Ray port. Re-run setup, or paste the Connection String so it's filled in automatically.
- **Clients can't connect** — confirm V2Ray listens on `0.0.0.0`, and the cloud firewall allows the paqet port on Server B.
- **Download blocked in Iran** — grab the paqet binary from [releases](https://github.com/hanselime/paqet/releases) and give the installer the local file path when prompted.
- **High latency** — usually the underlying Iran↔abroad route. Compare with a direct `ping` between the two servers; the tunnel can't go faster than that baseline.

## Requirements

Linux (Ubuntu / Debian / CentOS), root access, `libpcap` and `iptables` (auto-installed).

## Credits & License

Built on [paqet](https://github.com/hanselime/paqet) by hanselime. MIT License.


## Web Panel

The optional Web Panel is a separate management layer and does not replace or rewrite the existing paqet tunnel engine. Install it from the project directory as root:

```bash
bash panel/install.sh
```

Open `http://SERVER_IP:6102`. The installer generates a unique admin password and prints it once.

Panel features include Glass UI, Dark/Light/System themes, animated loading screen, custom PAQET logo, tunnel topology, service controls, ping, packet-loss diagnostics, server-side speed test, system metrics and journal logs.

## Credits

The tunnel engine is based on [paqet](https://github.com/hanselime/paqet) by hanselime. Original project attribution is preserved; Web Panel and project modifications are by `durwinam`.
