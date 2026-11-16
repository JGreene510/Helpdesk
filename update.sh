#!/usr/bin/env bash
# Helpdesk — update to a newer version in one step.
#
#   bash update.sh                      (finds the newest helpdesk-v*.zip for you)
#   bash update.sh /path/to/the.zip     (or name the zip yourself)
#
# Your tickets, logins and email settings are never inside the zip, so they
# are never touched. Run as your normal user (NOT with sudo).
#
# Everything lives inside main() and is called on the LAST line, so it is safe
# for this very file to be replaced while the update runs.
main() {
  set -euo pipefail
  local APP_DIR; APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  if [ "$(id -u)" -eq 0 ]; then echo "Please run this as a normal user, not root." >&2; return 1; fi
  command -v unzip >/dev/null 2>&1 || { echo "The 'unzip' program is missing. Install it with:  sudo apt install unzip" >&2; return 1; }

  local ZIP="${1:-}"
  if [ -z "$ZIP" ]; then
    ZIP="$(ls -t "$HOME"/helpdesk-v*.zip "$HOME"/shared/helpdesk-v*.zip "$HOME"/Downloads/helpdesk-v*.zip \
                 "$APP_DIR"/../helpdesk-v*.zip "$APP_DIR"/helpdesk-v*.zip 2>/dev/null | head -n 1 || true)"
  fi
  if [ -z "$ZIP" ] || [ ! -f "$ZIP" ]; then
    echo "I could not find a helpdesk zip file." >&2
    echo "Put the new zip in your home folder, or run:  bash update.sh /full/path/to/the.zip" >&2
    return 1
  fi

  local OLDVER NEWVER TMP
  OLDVER="$(node -p "require('$APP_DIR/package.json').version" 2>/dev/null || echo unknown)"
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' RETURN

  echo
  echo "Using zip   : $ZIP"
  echo "Updating    : $APP_DIR   (currently version $OLDVER)"
  unzip -q "$ZIP" -d "$TMP"
  local SRC; SRC="$(find "$TMP" -maxdepth 2 -name server.js -not -path '*/node_modules/*' -printf '%h\n' | head -n 1)"
  if [ -z "$SRC" ] || [ ! -f "$SRC/package.json" ]; then echo "That zip does not look like Helpdesk (no server.js)." >&2; return 1; fi
  NEWVER="$(node -p "require('$SRC/package.json').version" 2>/dev/null || echo unknown)"
  echo "New version : $NEWVER"
  if [ "$NEWVER" = "$OLDVER" ]; then
    echo
    echo "NOTE: this zip is the SAME version you already have ($OLDVER)."
    echo "      If you expected something newer, you picked up an old zip file."
  fi
  if [ -z "${HELPDESK_UPDATE_YES:-}" ]; then
    local ans; read -r -p "Go ahead and update? [y/N] " ans
    case "$ans" in [Yy]*) ;; *) echo "Nothing was changed."; return 0 ;; esac
  fi

  # Safety copy of the data, kept in a dated folder next to the app
  local BK="$APP_DIR/backup-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$BK"; chmod 700 "$BK"
  for f in tickets.json users.json email-config.json; do [ -f "$APP_DIR/$f" ] && cp -p "$APP_DIR/$f" "$BK/"; done
  echo "Data backup : $BK"

  # Copy program files over the old ones. Data files are not in the zip.
  cp -a "$SRC"/. "$APP_DIR"/
  chmod +x "$APP_DIR/setup.sh" "$APP_DIR/update.sh" 2>/dev/null || true
  chmod 600 "$APP_DIR"/email-config.json "$APP_DIR"/users.json "$APP_DIR"/tickets.json 2>/dev/null || true

  if [ -z "${HELPDESK_UPDATE_SKIP_NPM:-}" ]; then
    echo "Fetching anything new the program needs..."
    ( cd "$APP_DIR" && npm install --omit=dev --no-fund )
  fi

  if [ -z "${HELPDESK_UPDATE_SKIP_SERVICE:-}" ]; then
    # Refresh the service file too (the zip may change it), then restart.
    local UNIT_TMP; UNIT_TMP="$(mktemp)"
    sed -e "s|__USER__|$(id -un)|g" -e "s|__APPDIR__|$APP_DIR|g" -e "s|__NODE__|$(command -v node)|g" "$APP_DIR/helpdesk.service" > "$UNIT_TMP"
    sudo install -m 644 "$UNIT_TMP" /etc/systemd/system/helpdesk.service
    rm -f "$UNIT_TMP"
    sudo systemctl daemon-reload
    sudo systemctl restart helpdesk
    sleep 3
    echo
    sudo systemctl is-active --quiet helpdesk && echo "Helpdesk is running." || echo "Helpdesk did NOT start. Run:  sudo journalctl -u helpdesk -n 30 --no-pager"
  fi

  echo
  echo "Done. Now running version: $(node -p "require('$APP_DIR/package.json').version")"
  echo "Reload the web page (Ctrl+Shift+R). The version is shown next to the word Helpdesk at the top."
  echo
}
main "$@"; exit $?
