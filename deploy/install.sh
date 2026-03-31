#!/usr/bin/env bash
# install.sh — deploy rgstr on a Linux server
# Usage: sudo ./deploy/install.sh
set -euo pipefail

BINARY_SRC="${1:-./rgstr-linux-amd64}"
INSTALL_DIR="/opt/rgstr"
DATA_DIR="/var/lib/rgstr"
SERVICE_USER="rgstr"

if [[ $EUID -ne 0 ]]; then
  echo "error: run as root (sudo $0)" >&2
  exit 1
fi

echo "==> Creating user and directories"
id -u "$SERVICE_USER" &>/dev/null || useradd --system --no-create-home \
  --shell /sbin/nologin --home-dir "$INSTALL_DIR" "$SERVICE_USER"

mkdir -p "$INSTALL_DIR" "$DATA_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR" "$DATA_DIR"
chmod 750 "$INSTALL_DIR" "$DATA_DIR"

echo "==> Installing binary"
install -o root -g root -m 755 "$BINARY_SRC" "$INSTALL_DIR/rgstr"

echo "==> Installing systemd unit"
install -o root -g root -m 644 ./deploy/rgstr.service /etc/systemd/system/rgstr.service

# Optional: environment file for secrets (not tracked in git)
if [[ ! -f /etc/rgstr/env ]]; then
  mkdir -p /etc/rgstr
  cat > /etc/rgstr/env <<'EOF'
# Uncomment and fill in to enable authentication
# RGSTR_AUTH_ENABLED=true
# RGSTR_AUTH_SECRET=change-me-in-production
# RGSTR_USERS=alice:$2a$10$...
EOF
  chmod 600 /etc/rgstr/env
  chown root:root /etc/rgstr/env
  echo "    Created /etc/rgstr/env — edit to configure auth"
fi

echo "==> Enabling and starting service"
systemctl daemon-reload
systemctl enable rgstr
systemctl restart rgstr

echo ""
echo "Done. Status:"
systemctl status rgstr --no-pager
echo ""
echo "Registry running at http://$(hostname -I | awk '{print $1}'):5000"
echo "Test: curl http://localhost:5000/v2/"
