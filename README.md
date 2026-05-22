# certbot-dns

Утилита на Go для автоматического выпуска и продления TLS-сертификатов Let's Encrypt через **DNS-01** с провайдером [FastVPS FastDNS](https://fastdns.fv.ee/).

Один TOML-конфиг описывает несколько групп доменов (wildcard и apex), режим однократного запуска или демона, чекпоинты при обрыве выпуска и версионирование сертификатов на диске.

## Установка (Linux, systemd)

```bash
curl -fsSL https://github.com/raidkon/certbot-dns/raw/master/install.sh -o get-certbot-dns.sh
sudo sh ./get-certbot-dns.sh --dry-run
sudo sh ./get-certbot-dns.sh
```

Скрипт скачивает бинарник и файлы из [GitHub Release](https://github.com/raidkon/certbot-dns/releases) (tar.gz с systemd unit и примерами конфигурации), создаёт пользователя `certbot-dns`, каталоги и сервис.

После установки:

```bash
sudo nano /etc/certbot-dns/config.toml   # email, domains
sudo nano /etc/certbot-dns/env           # FASTDNS_API_TOKEN=...
sudo systemctl restart certbot-dns
sudo journalctl -u certbot-dns -f
```

Опции: `--version v1.0.0`, `--no-start`. Удаление: [uninstall.sh](uninstall.sh) (`--purge` — конфиг и данные).

## Возможности

- ACME v2 (Let's Encrypt production / staging)
- DNS-01 через API FastDNS (последовательная публикация TXT — совместимо с ограничениями API)
- Разбор списка `domains` в несколько сертификатов (wildcard → `wc-*`, одиночный apex → `apex-*`)
- Автопродление по `renew_before_days`
- Возобновление прерванного выпуска (`.obtain-checkpoint.json`)
- Каталоги выпуска `YYYY-MM-DD/` и symlink `live/` на актуальную версию
- Режимы `once` и `daemon` (установщик настраивает **daemon** + systemd)
- Docker-образ на distroless

## Сборка из исходников

```bash
sudo mkdir -p /etc/certbot-dns
sudo cp config.example.toml /etc/certbot-dns/config.toml

export FASTDNS_API_TOKEN="ваш-токен"

cd src && go run . -config /etc/certbot-dns/config.toml
```

Без флага `-config` используется путь `/etc/certbot-dns/config.toml`.

## Docker

### docker-compose (опубликованный образ)

При релизе (`git tag v1.0.0`) в [GitHub Container Registry](https://github.com/raidkon/certbot-dns/pkgs/container/certbot-dns) публикуется multi-arch образ:

`ghcr.io/raidkon/certbot-dns:latest` · `ghcr.io/raidkon/certbot-dns:v1.0.0`

```bash
cp docker-compose.example.yml docker-compose.yml
cp config.docker.example.toml config.toml
cp .env.example .env
# отредактируйте config.toml (email, domains) и .env (FASTDNS_API_TOKEN)
mkdir -p data
sudo chown -R 1000:1000 data

docker compose up -d
docker compose logs -f certbot-dns
```

По умолчанию процесс работает от **1000:1000**. Другой пользователь — через `user:` в compose или `CERTBOT_DNS_UID` / `CERTBOT_DNS_GID` в `.env`; каталог `data/` на хосте должен иметь те же права (`chown`).

Конкретная версия образа:

```bash
CERTBOT_DNS_VERSION=v1.0.0 docker compose up -d
```

Первый раз пакет GHCR может быть приватным — в настройках пакета на GitHub выберите **Public**.

### Локальная сборка образа

```bash
docker build -f docker/Dockerfile -t certbot-dns:local .
docker run --rm \
  -e FASTDNS_API_TOKEN=... \
  -v "$(pwd)/config.docker.example.toml:/etc/certbot-dns/config.toml:ro" \
  -v certbot-dns-data:/var/lib/certbot-dns \
  certbot-dns:local
```

## Релизы

```bash
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions собирает:

- `certbot-dns_*_linux_{amd64,arm64}.tar.gz` (бинарник, systemd unit, config/env example) + `SHA256SUMS`;
- Docker-образ `ghcr.io/raidkon/certbot-dns` с тегами `v1.0.0`, `1.0.0`, `latest` (linux/amd64 + arm64).

## Документация

| Язык | Файл |
|------|------|
| Русский | [docs/ru.md](docs/ru.md) |
| English | [docs/en.md](docs/en.md) |

## Лицензия

[MIT](LICENSE)
