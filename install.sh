#!/bin/sh
# Установка certbot-dns из GitHub Release (схема A).
#
#   curl -fsSL https://github.com/raidkon/certbot-dns/raw/master/install.sh -o get-certbot-dns.sh
#   sudo sh ./get-certbot-dns.sh --dry-run
#   sudo sh ./get-certbot-dns.sh
#
# Опции:
#   --dry-run          только показать действия
#   --version TAG      v1.0.0 или latest (по умолчанию latest)
#   --no-start         не включать и не запускать systemd
#   -h, --help         справка

set -eu

REPO="${CERTBOT_DNS_REPO:-raidkon/certbot-dns}"
INSTALL_BIN="/usr/local/bin/certbot-dns"
CONFIG_DIR="/etc/certbot-dns"
DATA_DIR="/var/lib/certbot-dns"
SERVICE_NAME="certbot-dns"
USER_NAME="certbot-dns"
GROUP_NAME="certbot-dns"

DRY_RUN=0
VERSION="latest"
NO_START=0

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
  sed -n '2,12p' "$0"
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --version)
      shift
      VERSION="${1:?укажите версию после --version}"
      ;;
    --no-start) NO_START=1 ;;
    -h | --help) usage ;;
    *)
      log "Неизвестный аргумент: $1" >&2
      exit 2
      ;;
  esac
  shift
done

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
  if [ "$VERSION" = "latest" ]; then
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
      | head -n 1
  else
    printf '%s' "$VERSION"
  fi
}

ensure_user() {
  if ! getent group "$GROUP_NAME" >/dev/null 2>&1; then
    run groupadd --system "$GROUP_NAME"
  else
    log "Группа уже существует: $GROUP_NAME"
  fi

  if ! getent passwd "$USER_NAME" >/dev/null 2>&1; then
    run useradd --system --gid "$GROUP_NAME" --home-dir "$DATA_DIR" \
      --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
  else
    log "Пользователь уже существует: $USER_NAME"
  fi
}

prepare_data_dir() {
  run mkdir -p "$DATA_DIR/acme-state" "$DATA_DIR/certs"
  run chown -R "$USER_NAME:$GROUP_NAME" "$DATA_DIR"
  run chmod 750 "$DATA_DIR"
}

install_config_if_missing() {
  if [ -f "$CONFIG_DIR/config.toml" ]; then
    log "Конфиг уже есть, не перезаписываем: $CONFIG_DIR/config.toml"
    return 0
  fi

  if [ -f "$CONFIG_DIR/config.example.toml" ]; then
    run cp "$CONFIG_DIR/config.example.toml" "$CONFIG_DIR/config.toml"
    run chmod 640 "$CONFIG_DIR/config.toml"
    run chown root:"$GROUP_NAME" "$CONFIG_DIR/config.toml"
    log "Создан $CONFIG_DIR/config.toml из config.example.toml"
    return 0
  fi

  log "Предупреждение: config.example.toml не найден в $CONFIG_DIR" >&2
}

install_env_if_missing() {
  if [ -f "$CONFIG_DIR/env" ]; then
    log "Файл env уже есть: $CONFIG_DIR/env"
    return 0
  fi

  if [ -f "$CONFIG_DIR/env.example" ]; then
    run cp "$CONFIG_DIR/env.example" "$CONFIG_DIR/env"
    run chmod 600 "$CONFIG_DIR/env"
    run chown root:root "$CONFIG_DIR/env"
    log "Создан $CONFIG_DIR/env — задайте FASTDNS_API_TOKEN"
    return 0
  fi

  log "Предупреждение: env.example не найден в $CONFIG_DIR" >&2
}

enable_service() {
  run systemctl daemon-reload
  run systemctl enable "$SERVICE_NAME.service"
  if [ "$NO_START" -eq 1 ]; then
    log "Пропуск запуска (--no-start). Включите позже: systemctl start $SERVICE_NAME"
    return 0
  fi
  run systemctl restart "$SERVICE_NAME.service"
  log "Сервис $SERVICE_NAME запущен"
}

main() {
  need_root

  if [ "$(uname -s)" != "Linux" ]; then
    log "Поддерживается только Linux." >&2
    exit 1
  fi

  ARCH="$(detect_arch)"
  TAG="$(resolve_tag)"
  if [ -z "$TAG" ]; then
    log "Не удалось определить версию (нет Release?). Укажите --version vX.Y.Z" >&2
    exit 1
  fi

  VER="$(printf '%s' "$TAG" | sed 's/^v//')"
  TARBALL="certbot-dns_${VER}_linux_${ARCH}.tar.gz"
  BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
  TARBALL_URL="${BASE_URL}/${TARBALL}"
  SUMS_URL="${BASE_URL}/SHA256SUMS"

  log "Установка certbot-dns ${TAG} (${ARCH})"
  log "Источник: $TARBALL_URL"

  TMP=""
  if [ "$DRY_RUN" -eq 0 ]; then
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT INT HUP TERM
  fi

  if [ "$DRY_RUN" -eq 1 ]; then
    log_dry "curl -fsSL $SUMS_URL"
    log_dry "curl -fsSL -o $TARBALL $TARBALL_URL"
    log_dry "sha256sum -c (проверка $TARBALL)"
    log_dry "tar -xzf $TARBALL -C /"
  else
    curl -fsSL "$SUMS_URL" -o "$TMP/SHA256SUMS"
    curl -fsSL "$TARBALL_URL" -o "$TMP/$TARBALL"
    (
      cd "$TMP"
      grep -F "$TARBALL" SHA256SUMS | sha256sum -c -
    )
    tar -xzf "$TMP/$TARBALL" -C /
  fi

  run chmod 755 "$INSTALL_BIN"

  ensure_user
  prepare_data_dir
  run mkdir -p "$CONFIG_DIR"
  install_config_if_missing
  install_env_if_missing

  if command -v systemctl >/dev/null 2>&1; then
    enable_service
  else
    log "systemctl не найден — пропуск настройки сервиса"
  fi

  log ""
  log "Готово."
  log "  1. Отредактируйте $CONFIG_DIR/config.toml (email, domains)"
  log "  2. Задайте FASTDNS_API_TOKEN в $CONFIG_DIR/env"
  if [ "$NO_START" -eq 1 ] || ! command -v systemctl >/dev/null 2>&1; then
    log "  3. systemctl start $SERVICE_NAME"
  fi
  log "  journalctl -u $SERVICE_NAME -f"
}

main "$@"
