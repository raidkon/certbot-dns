# certbot-dns

Утилита на Go для автоматического выпуска и продления TLS-сертификатов Let's Encrypt через **DNS-01** с провайдером [FastVPS FastDNS](https://fastdns.fv.ee/).

Один TOML-конфиг описывает несколько групп доменов (wildcard и apex), режим однократного запуска или демона, чекпоинты при обрыве выпуска и версионирование сертификатов на диске.

## Возможности

- ACME v2 (Let's Encrypt production / staging)
- DNS-01 через API FastDNS (последовательная публикация TXT — совместимо с ограничениями API)
- Разбор списка `domains` в несколько сертификатов (wildcard → `wc-*`, одиночный apex → `apex-*`)
- Автопродление по `renew_before_days`
- Возобновление прерванного выпуска (`.obtain-checkpoint.json`)
- Каталоги выпуска `YYYY-MM-DD/` и symlink `live/` на актуальную версию
- Режимы `once` и `daemon`
- Docker-образ на distroless

## Быстрый старт

```bash
sudo mkdir -p /etc/certbot-dns
sudo cp config.example.toml /etc/certbot-dns/config.toml
# отредактируйте email, domains, FASTDNS_API_TOKEN

export FASTDNS_API_TOKEN="ваш-токен"

cd src && go run . -config /etc/certbot-dns/config.toml
```

Без флага `-config` используется путь `/etc/certbot-dns/config.toml`.

Или через Docker:

```bash
docker build -f docker/Dockerfile -t certbot-dns:latest .
docker run --rm \
  -e FASTDNS_API_TOKEN=... \
  -v "$(pwd)/config.toml:/etc/certbot-dns/config.toml:ro" \
  -v certbot-dns-state:/var/certs/.acme-state \
  -v certbot-dns-out:/var/certs/out \
  certbot-dns:latest
```

## Документация

| Язык | Файл |
|------|------|
| Русский | [docs/ru.md](docs/ru.md) |
| English | [docs/en.md](docs/en.md) |

## Лицензия

См. репозиторий; использование на свой риск. Для production рекомендуется сначала проверить выпуск на `acme.directory = "staging"`.
