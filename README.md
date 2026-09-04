# paqet-tunnel

A lightweight installer and web management layer for tunneling VPN traffic with [paqet](https://github.com/hanselime/paqet).

**Version:** v2.1.0
**Author / Maintainer:** durwinam
**Original author attribution:** g3ntrix
**Web Panel:** `6102`

## ✨ Web Panel

The new Web Panel is an independent management layer. The existing paqet tunnel setup and service model are kept intact; the panel controls and observes the existing services instead of replacing the tunnel engine.

### Included

- 🧊 Glassmorphism UI with animated background
- 🌑 Dark / ☀️ Light / 🌓 System theme
- ✨ Animated loading screen and page transitions
- 🧩 Custom inline SVG visual system
- 🌍 Abroad / Iran tunnel visualization
- 📡 Ping and packet-loss diagnostics
- ⚡ Server-side speed-test integration when `speedtest` or `speedtest-cli` is installed
- 📊 CPU / RAM / disk / uptime monitoring
- 🔗 Tunnel service start / stop / restart
- 📋 Recent systemd logs
- 🔐 Admin login with generated initial password
- 📱 Responsive mobile layout

## Install

Run the existing installer as root on the relevant tunnel server:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/durwinam/paqet-tunnel/main/install.sh)
```

After the tunnel is configured, choose the Web Panel option from the installer menu. The panel listens on:

```text
http://SERVER_IP:6102
```

The panel is managed as `paqet-panel.service` and starts automatically after reboot.

> Open TCP port `6102` in your VPS/cloud firewall if the panel must be reachable remotely.

## Tunnel architecture

The tunnel architecture remains the same:

```text
Client → Server A (Iran entry) ══ paqet/KCP ══→ Server B (abroad) → V2Ray/X-UI
```

The Web Panel is an additional control plane:

```text
                 PAQET TUNNEL
                       │
          ┌────────────┴────────────┐
          │                         │
      Tunnel Core               Web Panel
      Existing flow              :6102
          │                         │
      paqet/systemd          Dashboard / Tunnels
                              Network / Logs / Settings
```

## First login

On first panel installation, a strong random password is generated under:

```text
/opt/paqet/panel/auth.json
```

The installer prints the initial password. Change it from **Settings → Password** after signing in.

## Credits & License

This project integrates with and builds around [paqet](https://github.com/hanselime/paqet) by hanselime.

Copyright attribution is retained for the original project author while `durwinam` is the current author/maintainer of this project version.

MIT License.
