# Документация certbot-dns

Утилита `certs-acme` выпускает и продлевает сертификаты Let's Encrypt методом **DNS-01**, управляя TXT-записями через API **FastVPS FastDNS**.

## Содержание

1. [Требования](#требования)
2. [Установка и сборка](#установка-и-сборка)
3. [Конфигурация](#конфигурация)
4. [Разбор доменов и каталоги](#разбор-доменов-и-каталоги)
5. [DNS-01 и FastDNS](#dns-01-и-fastdns)
6. [Продление и режим daemon](#продление-и-режим-daemon)
7. [Чекпоинт выпуска](#чекпоинт-выпуска)
8. [Docker](#docker)
9. [Логирование](#логирование)
10. [Устранение неполадок](#устранение-неполадок)

## Требования

- Go 1.25+ (или Docker)
- Аккаунт FastVPS с включённым FastDNS и API-токеном
- Домены, делегированные в FastDNS (зона должна быть доступна через API)
- Контактный email для регистрации ACME

## Установка и сборка

### Из исходников

```bash
git clone https://github.com/raidkon/certbot-dns.git
cd certbot-dns
cp config.example.toml config.toml
# отредактируйте config.toml

export FASTDNS_API_TOKEN="ваш-токен"

cd src
go build -o certs-acme .
./certs-acme -config ../config.toml
```

Флаг `-config` задаёт путь к TOML (по умолчанию `config.toml` в текущей директории).

### Бинарник без установки Go

```bash
cd src && go run . -config ../config.toml
```

## Конфигурация

Полный пример — файл [`config.example.toml`](../config.example.toml) в корне репозитория.

### Секция `[acme]`

| Параметр | Описание |
|----------|----------|
| `email` | Email ACME-аккаунта (обязателен) |
| `directory` | `production` — боевой LE; `staging` — тестовый каталог |
| `state_dir` | Каталог для `account.key` и `registration.json` (по умолчанию `.acme-state`) |
| `user_agent` | Необязательно; по умолчанию `certbot-dns/1` |

### Секция `[fastdns]`

| Параметр | Описание |
|----------|----------|
| `api_token` | Токен API; рекомендуется `${FASTDNS_API_TOKEN}` из окружения |
| `api_url` | Необязательно; базовый URL API (по умолчанию клиент использует fastdns.fv.ee) |

### Секция `[dns_challenge]`

| Параметр | Описание |
|----------|----------|
| `propagation_timeout` | Максимальное ожидание появления TXT в DNS (например `24h`) |
| `propagation_interval` | Пауза между проверками (например `10m`) |
| `recursive_resolvers` | Список `host:port` для pre-check TXT; если не задан — `8.8.8.8:53` и `1.1.1.1:53` |

Явные резолверы нужны в закрытых сетях. Не полагайтесь только на `127.0.0.53` (systemd-resolved): кэш часто не совпадает с тем, что видит Let's Encrypt.

### Блоки `[[certificates]]`

| Параметр | Описание |
|----------|----------|
| `id` | Метка для логов (необязательно) |
| `domains` | Список имён; см. [разбор доменов](#разбор-доменов-и-каталоги) |
| `output_dir` | Базовый каталог для выпусков этого блока |
| `key_type` | `ec256`, `ec384`, `rsa2048`, … (по умолчанию `ec256`) |
| `renew_before_days` | За сколько дней до `NotAfter` перевыпускать (по умолчанию `25`) |

Поле `zone` в конфиге **не используется**: зона FastDNS выводится автоматически как последние две метки apex-домена.

### Секция `[runtime]`

| Параметр | Описание |
|----------|----------|
| `mode` | `once` — один проход и выход; `daemon` — бесконечный цикл |
| `poll_when_ok` | В daemon: максимальная пауза, если все сертификаты свежие (например `24h`) |
| `loglevel` | `debug`, `verbose`, `info`, `warning`, `error`, `fatal` |

Переменные окружения подставляются в строки конфига через `${VAR}`.

## Разбор доменов и каталоги

Один блок `[[certificates]]` с несколькими именами в `domains` может превратиться в **несколько** отдельных сертификатов.

### Wildcard

- `*.example.com` → SAN: `*.example.com` и `example.com` (apex добавляется автоматически)
- Каталог: `{output_dir}/wc-example-com/`
- Зона FastDNS: `example.com`

### Одиночный apex

- `example.com` без подходящего wildcard в том же списке → отдельный сертификат
- Каталог: `{output_dir}/apex-example-com/`

### Поддомен на один уровень под wildcard

- При `*.example.com` имя `www.example.com` попадает в ту же wildcard-группу

### Несколько wildcard в одном блоке

```toml
[[certificates]]
id = "multi"
domains = [
  "*.example.com",
  "*.demo.example.com",
  "other.net",
]
output_dir = "./out/multi"
```

Создаются каталоги `wc-example-com`, `wc-demo-example-com`, `apex-other-net`.

### Структура файлов на диске

```
output_dir/wc-example-com/
  live -> 2026-05-22          # symlink на актуальный выпуск
  2026-05-22/
    fullchain.pem
    privkey.pem
    issuer.pem                # если есть
  .obtain-checkpoint.json     # только во время незавершённого выпуска
```

Чтение существующего сертификата: сначала `live/fullchain.pem`, иначе legacy `fullchain.pem` в корне `output_dir`.

## DNS-01 и FastDNS

Перед выпуском утилита один раз вызывает `GetRecords` для каждой уникальной зоны — проверка токена и доступа.

При публикации challenge:

1. Удаляются старые TXT с тем же относительным именем (остатки сорванных выпусков)
2. TXT создаётся **последовательно** (не параллельно): у FastDNS два одновременных `AppendRecords` на одно имя часто завершаются ошибкой
3. После проверки LE запись удаляется (`CleanUp`)

Имя зоны в API: для `host.example.com` и `*.server.example.com` используется `example.com` (последние две метки). Для зон типа `co.uk` эвристика может быть неточной — учитывайте это при планировании.

## Продление и режим daemon

### Режим `once`

Один проход по всем сертификатам: проверка срока, выпуск при необходимости, код выхода `0` при успехе.

Подходит для cron/systemd timer:

```cron
0 3 * * * /usr/local/bin/certs-acme -config /etc/certbot-dns/config.toml
```

### Режим `daemon`

После каждого цикла процесс засыпает до ближайшего срока продления (но не дольше `poll_when_ok`). Если fullchain отсутствует или битый — пауза около минуты.

Условие перевыпуска: нет `fullchain` **или** текущее время ≥ `NotAfter - renew_before_days`.

## Чекпоинт выпуска

Файл `.obtain-checkpoint.json` в каталоге выпуска сохраняет:

- URI заказа ACME
- ID созданных TXT в FastDNS
- PEM закрытого ключа (после генерации CSR)

При следующем запуске выпуск **продолжается** с того же заказа, без создания дубликатов TXT. После успешной записи сертификата чекпоинт удаляется.

Если список `domains` изменился — старый чекпоинт игнорируется и создаётся новый заказ.

При «зависшем» invalid-заказе удалите `.obtain-checkpoint.json` вручную и запустите снова.

## Docker

Сборка из корня репозитория:

```bash
docker build -f docker/Dockerfile -t certbot-dns:latest .
```

Пример `docker-compose.yml`:

```yaml
services:
  certbot-dns:
    build:
      context: .
      dockerfile: docker/Dockerfile
    image: certbot-dns:latest
    environment:
      FASTDNS_API_TOKEN: ${FASTDNS_API_TOKEN}
    volumes:
      - ./config.toml:/etc/certs/config.toml:ro
      - acme-state:/var/certs/.acme-state
      - certs-out:/var/certs/out
    restart: unless-stopped

volumes:
  acme-state:
  certs-out:
```

В `config.toml` для контейнера задайте пути относительно `/var/certs`, например:

```toml
[acme]
state_dir = "/var/certs/.acme-state"

[[certificates]]
output_dir = "/var/certs/out/sites"
```

## Логирование

| Уровень | Назначение |
|---------|------------|
| `debug` | Максимум деталей + файл:строка в каждой записи |
| `verbose` | Как debug по фильтру, без file:line |
| `info` | Штатная работа (рекомендуется) |
| `warning` / `error` | Только предупреждения и ошибки |
| `fatal` | Критические сообщения и немедленный выход |

Логи lego (библиотека ACME) перенаправляются в тот же slog.

## Устранение неполадок

### Зона недоступна через FastDNS API

Проверьте токен, что домен делегирован в FastDNS и имя зоны совпадает с последними двумя метками apex (см. лог `проверка зоны FastDNS`).

### AppendRecords с пустым message

Часто из-за лимита «одна TXT на имя» или остатков старых `_acme-challenge`. Утилита пытается очистить конфликтующие TXT перед `Present`; при повторении проверьте панель FastDNS вручную.

### TXT не распространяется

Увеличьте `propagation_timeout` / уменьшите `propagation_interval`. Задайте `recursive_resolvers`, доступные из вашей сети.

### Staging vs production

Для первых тестов установите `directory = "staging"`. Staging-сертификаты браузеры не доверяют, но лимиты мягче.

### Коды выхода

| Код | Причина |
|-----|---------|
| `0` | Успех (режим `once`) |
| `1` | Ошибка выпуска, зоны или цикла daemon |
| `2` | Ошибка конфигурации или аргументов |

---

English documentation: [docs/en.md](en.md)
