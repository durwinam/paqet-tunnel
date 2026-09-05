#!/bin/bash
set -euo pipefail

PANEL_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PANEL_DIR="/opt/paqet/panel"

if [ "$(id -u)" -ne 0 ]; then
  echo "[x] Please run as root."
  exit 1
fi

mkdir -p "$PANEL_DIR/static/assets"
cp "$PANEL_SRC/server.py" "$PANEL_DIR/server.py"
cp "$PANEL_SRC/paqet-panel.service" /etc/systemd/system/paqet-panel.service
cp "$PANEL_SRC/static/index.html" "$PANEL_DIR/static/index.html"
cp -a "$PANEL_SRC/static/assets/." "$PANEL_DIR/static/assets/"
chmod 700 "$PANEL_DIR" "$PANEL_DIR/server.py"
find "$PANEL_DIR/static" -type f -exec chmod 644 {} +

systemctl daemon-reload
systemctl enable --now paqet-panel

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo
echo "PAQET Web Panel is ready."
echo "URL: http://${IP:-SERVER_IP}:6102"
echo "Username: admin"
if [ -f "$PANEL_DIR/auth.json" ]; then
  grep -o '"generated_password": "[^"]*"' "$PANEL_DIR/auth.json" | sed 's/"generated_password": "//;s/"$//' | awk '{print "Initial password: " $0}' || true
fi
echo ""
echo "Panel service: paqet-panel.service"
