# PAQET Tunnel Web Panel

Glassmorphism management UI for `paqet-tunnel`. The panel is intentionally separated from the existing tunnel engine and reads/controls the existing `systemd` services and `/opt/paqet` configs.

## Port

`6102`

## Install

From the project directory as root:

```bash
bash panel/install.sh
```

Then open:

```text
http://SERVER_IP:6102
```

The panel does not rewrite the tunnel configuration or replace the existing paqet setup flow.
