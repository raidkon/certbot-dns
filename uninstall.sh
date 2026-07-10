#!/bin/sh
# Удаление certbot-dns, установленного через install.sh.
#
#   curl -fsSL https://github.com/raidkon/certbot-dns/raw/master/uninstall.sh -o uninstall-certbot-dns.sh
#   sudo sh ./uninstall-certbot-dns.sh --dry-run
#   sudo sh ./uninstall-certbot-dns.sh
#
# Опции:
#   --dry-run    только показать действия
#   --purge      удалить /etc/certbot-dns и /var/lib/certbot-dns
#   -h, --help   справка

set -eu

INSTALL_BIN="/usr/local/bin/certbot-dns"
CONFIG_DIR="/etc/certbot-dns"
DATA_DIR="/var/lib/certbot-dns"
SERVICE_NAME="certbot-dns"
USER_NAME="certbot-dns"
GROUP_NAME="certbot-dns"

DRY_RUN=0
PURGE=0

log() { printf '%s\n' "$*"; }
log_dry() { printf '[DRY-RUN] %s\n' "$*"; }

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    log_dry "$*"
  else
    "$@"
  fi
}

usage() {
  sed -n '2,11p' "$0"
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --purge) PURGE=1 ;;
    -h | --help) usage ;;
    *)
      log "Неизвестный аргумент: $1" >&2
      exit 2
      ;;
  esac
  shift
done

if [ "$(id -u)" -ne 0 ]; then
  log "Ошибка: нужны права root (sudo)." >&2
  exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
  run systemctl stop "$SERVICE_NAME.service" 2>/dev/null || true
  run systemctl disable "$SERVICE_NAME.service" 2>/dev/null || true
  run rm -f \
    "/etc/systemd/system/${SERVICE_NAME}.service" \
    "/usr/lib/systemd/system/${SERVICE_NAME}.service" \
    "/lib/systemd/system/${SERVICE_NAME}.service"
  run systemctl daemon-reload
fi

run rm -f "$INSTALL_BIN"

if [ "$PURGE" -eq 1 ]; then
  run rm -rf "$CONFIG_DIR" "$DATA_DIR"
  if getent passwd "$USER_NAME" >/dev/null 2>&1; then
    run userdel --system "$USER_NAME" 2>/dev/null || run userdel "$USER_NAME" 2>/dev/null || true
  fi
  if getent group "$GROUP_NAME" >/dev/null 2>&1; then
    run groupdel "$GROUP_NAME" 2>/dev/null || true
  fi
  log "Удалены конфиг, данные, пользователь $USER_NAME"
else
  log "Конфиг ($CONFIG_DIR) и данные ($DATA_DIR) сохранены. Полное удаление: --purge"
fi

log "certbot-dns удалён"
