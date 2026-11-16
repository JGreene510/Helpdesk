#!/usr/bin/env bash
# Helpdesk v4 — setup for a Raspberry Pi or other small Ubuntu/Debian box.
# Run as your normal user (NOT with sudo):   bash setup.sh
set -euo pipefail

cd "$(dirname "$0")"
APP_DIR="$(pwd)"

if [ "$(id -u)" -eq 0 ]; then
  echo "Please run this as a normal user, not root. The service should not run as root." >&2
  exit 1
fi

echo
echo "================================================"
echo "  Helpdesk v4 — setup"
echo "================================================"
echo

# ── Node.js 18+ from the distro's own packages (no curl | bash) ──────────────
need_node() {
  ! command -v node >/dev/null 2>&1 || [ "$(node -p 'process.versions.node.split(".")[0]')" -lt 18 ]
}
if need_node; then
  echo "Node.js 18 or newer is required."
  read -r -p "Install nodejs and npm with apt now? [y/N] " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    sudo apt-get update && sudo apt-get install -y nodejs npm
  else
    echo "Install Node.js 18+ and run setup.sh again."; exit 1
  fi
  if need_node; then
    echo "The Node.js available from apt is still older than 18. Install a current LTS from https://nodejs.org and re-run." >&2
    exit 1
  fi
fi
echo "  Node: $(node -v)   npm: $(npm -v)"
echo

# ── Dependencies (only nodemailer, used for optional email) ──────────────────
npm install --omit=dev --no-fund
npm audit --omit=dev --audit-level=high || echo "  (npm audit reported issues above; consider: npm update)"
echo

# ── Coming from an older version? Offer to bring the tickets and logins along ─
OLD_DIR=""
for cand in "$APP_DIR/../helpdesk-v3" "$HOME/helpdesk-v3" "$HOME/shared/helpdesk-v3"; do
  if [ -d "$cand" ] && [ "$(cd "$cand" && pwd)" != "$APP_DIR" ] && { [ -f "$cand/users.json" ] || [ -f "$cand/tickets.json" ]; }; then
    OLD_DIR="$(cd "$cand" && pwd)"; break
  fi
done
if [ -n "$OLD_DIR" ] && [ ! -f users.json ] && [ ! -f tickets.json ]; then
  echo "Found your existing Helpdesk (v3) with its data in:"
  echo "    $OLD_DIR"
  read -r -p "Copy its tickets, logins and email settings into this v4 folder? [y/N] " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    for f in tickets.json users.json email-config.json; do
      [ -f "$OLD_DIR/$f" ] && cp -p "$OLD_DIR/$f" "$APP_DIR/$f" && echo "  copied $f"
    done
    echo "  (The old folder is left untouched, as a backup.)"
  fi
  echo
fi

# ── Config / data files: owner-only permissions ──────────────────────────────
[ -f email-config.json ] || cp email-config.example.json email-config.json
chmod 600 email-config.json
chmod 600 users.json tickets.json 2>/dev/null || true

# ── systemd unit generated for THIS user and folder ──────────────────────────
RUN_USER="$(id -un)"
NODE_BIN="$(command -v node)"
UNIT_TMP="$(mktemp)"
trap 'rm -f "$UNIT_TMP"' EXIT
sed -e "s|__USER__|$RUN_USER|g" -e "s|__APPDIR__|$APP_DIR|g" -e "s|__NODE__|$NODE_BIN|g" helpdesk.service > "$UNIT_TMP"

echo "The service will run as '$RUN_USER' from $APP_DIR"
read -r -p "Install and start the systemd service now? [y/N] " ans
LOCAL_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"

if [[ "$ans" =~ ^[Yy]$ ]]; then
  sudo install -m 644 "$UNIT_TMP" /etc/systemd/system/helpdesk.service
  sudo systemctl daemon-reload
  sudo systemctl enable helpdesk
  sudo systemctl restart helpdesk      # restart so a re-run picks up an updated service file
  sleep 3
  echo
  echo "First-run administrator login (shown once; you must change it at first login):"
  sudo journalctl -u helpdesk -n 40 --no-pager | grep -E 'username|password' \
    || echo "  Not found in the log. Run:  node server.js --reset-admin"
  echo
  echo "  Status : sudo systemctl status helpdesk"
  echo "  Logs   : sudo journalctl -u helpdesk -f"
else
  echo
  echo "Not installed. To run it in the foreground instead:  node server.js"
  echo "To install later:  sudo install -m 644 <generated unit> /etc/systemd/system/helpdesk.service"
fi

echo
echo "  Open  http://${LOCAL_IP:-<this-machine>}:3000   (plain HTTP: keep it on your LAN, do not port-forward it)"
echo "  Admin login  →  click 'Admin Login'"
echo "  Next steps in plain English: see Install.txt, Part 8 (first login)"
echo "  Later updates:  bash update.sh   (see Update.txt)"
echo
