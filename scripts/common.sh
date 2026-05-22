#!/bin/sh
# Общие функции для install.sh / uninstall.sh (запуск из клонированного репозитория).
# install.sh, скачанный через curl, самодостаточен и этот файл не использует.

REPO="${CERTBOT_DNS_REPO:-raidkon/certbot-dns}"
INSTALL_BIN="${CERTBOT_DNS_INSTALL_BIN:-/usr/local/bin/certbot-dns}"
CONFIG_DIR="${CERTBOT_DNS_CONFIG_DIR:-/etc/certbot-dns}"
DATA_DIR="${CERTBOT_DNS_DATA_DIR:-/var/lib/certbot-dns}"
SERVICE_NAME="${CERTBOT_DNS_SERVICE:-certbot-dns}"
USER_NAME="${CERTBOT_DNS_USER:-certbot-dns}"
GROUP_NAME="${CERTBOT_DNS_GROUP:-certbot-dns}"

log() {
  printf '%s\n' "$*"
}

log_dry() {
  printf '[DRY-RUN] %s\n' "$*"
}

run() {
  if [ "${DRY_RUN:-0}" -eq 1 ]; then
    log_dry "$*"
  else
    "$@"
  fi
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    log "Ошибка: нужны права root (sudo)." >&2
    exit 1
  fi
}

detect_arch() {
  machine="$(uname -m)"
  case "$machine" in
    x86_64 | amd64) echo amd64 ;;
    aarch64 | arm64) echo arm64 ;;
    *)
      log "Неподдерживаемая архитектура: $machine (нужен amd64 или arm64)." >&2
      exit 1
      ;;
  esac
}

resolve_tag() {
  version="$1"
  if [ "$version" = "latest" ]; then
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
      | head -n 1
  else
    printf '%s' "$version"
  fi
}

tag_to_version() {
  printf '%s' "$1" | sed 's/^v//'
}
