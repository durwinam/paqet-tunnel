#!/bin/bash
set -e
[ "$(id -u)" -eq 0 ] || { echo 'Run as root.'; exit 1; }
BASE="/opt/paqet-panel"
PORT="6102"
mkdir -p "$BASE/static/assets"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$SCRIPT_DIR/server.py" "$BASE/server.py"
cp -f "$SCRIPT_DIR/static/"*.html "$BASE/static/"
cp -f "$SCRIPT_DIR/static/"*.js "$BASE/static/"
cp -f "$SCRIPT_DIR/static/"*.css "$BASE/static/"
cp -rf "$SCRIPT_DIR/static/assets/." "$BASE/static/assets/"
PASS=$(python3 - <<'PY2'
import secrets
print(''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789') for _ in range(14)))
PY2
)
HASH=$(printf '%s' "$PASS" | sha256sum | awk '{print $1}')
cat >"$BASE/credentials.json" <<CREDS
{"username":"admin","password_hash":"$HASH"}
CREDS
chmod 600 "$BASE/credentials.json"
cat >/etc/systemd/system/paqet-panel.service <<EOF
[Unit]
Description=PAQET Tunnel Web Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$BASE
Environment=PAQET_PANEL_PORT=$PORT
ExecStart=/usr/bin/env python3 $BASE/server.py
Restart=always
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/opt/paqet-panel

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now paqet-panel.service
printf '\nPAQET Web Panel installed.\nURL: http://SERVER_IP:%s\nUsername: admin\nPassword: %s\nService: paqet-panel\n\n' "$PORT" "$PASS"
