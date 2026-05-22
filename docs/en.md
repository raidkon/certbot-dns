# certbot-dns documentation

The `certs-acme` utility issues and renews Let's Encrypt TLS certificates using **DNS-01** challenges, managing TXT records via the **FastVPS FastDNS** API.

## Table of contents

1. [Requirements](#requirements)
2. [Installation and build](#installation-and-build)
3. [Configuration](#configuration)
4. [Domain expansion and output layout](#domain-expansion-and-output-layout)
5. [DNS-01 and FastDNS](#dns-01-and-fastdns)
6. [Renewal and daemon mode](#renewal-and-daemon-mode)
7. [Obtain checkpoint](#obtain-checkpoint)
8. [Docker](#docker)
9. [Logging](#logging)
10. [Troubleshooting](#troubleshooting)

## Requirements

- Go 1.25+ (or Docker)
- FastVPS account with FastDNS enabled and an API token
- Domains delegated to FastDNS (the zone must be reachable via the API)
- Contact email for ACME registration

## Installation and build

### From source

```bash
git clone https://github.com/raidkon/certbot-dns.git
cd certbot-dns
cp config.example.toml /etc/certbot-dns/config.toml
# edit config.toml

export FASTDNS_API_TOKEN="your-token"

cd src
go build -o certs-acme .
./certs-acme
```

The `-config` flag sets the TOML path; default is `/etc/certbot-dns/config.toml`.

### Run without installing a binary

```bash
cd src && go run . -config ../config.toml
```

## Configuration

See [`config.example.toml`](../config.example.toml) in the repository root for a full annotated example.

### `[acme]` section

| Parameter | Description |
|-----------|-------------|
| `email` | ACME account email (required) |
| `directory` | `production` — live Let's Encrypt; `staging` — test directory |
| `state_dir` | Directory for `account.key` and `registration.json` (default `.acme-state`) |
| `user_agent` | Optional; default `certbot-dns/1` |

### `[fastdns]` section

| Parameter | Description |
|-----------|-------------|
| `api_token` | API token; prefer `${FASTDNS_API_TOKEN}` from the environment |
| `api_url` | Optional base API URL (client default: fastdns.fv.ee) |

### `[dns_challenge]` section

| Parameter | Description |
|-----------|-------------|
| `propagation_timeout` | Max wait for TXT to appear in DNS (e.g. `24h`) |
| `propagation_interval` | Delay between checks (e.g. `10m`) |
| `recursive_resolvers` | List of `host:port` for TXT pre-check; if unset — `8.8.8.8:53` and `1.1.1.1:53` |

Set explicit resolvers on private networks. Do not rely only on `127.0.0.53` (systemd-resolved): its cache often differs from what Let's Encrypt sees.

### `[[certificates]]` blocks

| Parameter | Description |
|-----------|-------------|
| `id` | Optional label for logs |
| `domains` | Name list; see [domain expansion](#domain-expansion-and-output-layout) |
| `output_dir` | Base directory for this block's certificates |
| `key_type` | `ec256`, `ec384`, `rsa2048`, … (default `ec256`) |
| `renew_before_days` | Renew this many days before `NotAfter` (default `25`) |

There is **no** `zone` field in config: the FastDNS zone is derived as the last two labels of the apex domain.

### `[runtime]` section

| Parameter | Description |
|-----------|-------------|
| `mode` | `once` — single pass then exit; `daemon` — loop forever |
| `poll_when_ok` | In daemon mode: max sleep when all certs are fresh (e.g. `24h`) |
| `loglevel` | `debug`, `verbose`, `info`, `warning`, `error`, `fatal` |

Environment variables are expanded in config strings via `${VAR}`.

## Domain expansion and output layout

One `[[certificates]]` block with multiple `domains` entries may produce **several** separate certificates.

### Wildcard

- `*.example.com` → SAN: `*.example.com` and `example.com` (apex added automatically)
- Directory: `{output_dir}/wc-example-com/`
- FastDNS zone: `example.com`

### Standalone apex

- `example.com` without a matching wildcard in the same list → separate certificate
- Directory: `{output_dir}/apex-example-com/`

### One-level subdomain under a wildcard

- With `*.example.com`, the name `www.example.com` joins the same wildcard group

### Multiple wildcards in one block

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

Creates `wc-example-com`, `wc-demo-example-com`, and `apex-other-net` directories.

### On-disk layout

```
output_dir/wc-example-com/
  live -> 2026-05-22          # symlink to the current release
  2026-05-22/
    fullchain.pem
    privkey.pem
    issuer.pem                # when available
  .obtain-checkpoint.json     # only during an incomplete obtain
```

Existing certificates are read from `live/fullchain.pem` first, then legacy `fullchain.pem` in the output root.

## DNS-01 and FastDNS

Before issuance, the tool calls `GetRecords` once per unique zone to verify the token and access.

During challenge handling:

1. Old TXT records with the same relative name are removed (leftovers from failed runs)
2. TXT records are published **sequentially** (not in parallel): FastDNS often rejects two concurrent `AppendRecords` calls for the same name
3. After LE validation, the record is deleted (`CleanUp`)

API zone name: for `host.example.com` and `*.server.example.com` the zone is `example.com` (last two labels). For public suffixes like `co.uk` the heuristic may be wrong — plan accordingly.

## Renewal and daemon mode

### `once` mode

Single pass over all certificates: check expiry, obtain if needed, exit `0` on success.

Suitable for cron or systemd timers:

```cron
0 3 * * * /usr/local/bin/certs-acme -config /etc/certbot-dns/config.toml
```

### `daemon` mode

After each cycle the process sleeps until the nearest renewal time (capped by `poll_when_ok`). If fullchain is missing or corrupt, sleep is about one minute.

Renewal triggers when fullchain is absent **or** current time ≥ `NotAfter - renew_before_days`.

## Obtain checkpoint

The file `.obtain-checkpoint.json` in the output directory stores:

- ACME order URI
- FastDNS TXT record IDs
- Private key PEM (after CSR key generation)

On the next run, issuance **resumes** the same order without duplicating TXT records. The checkpoint is removed after a successful write.

If `domains` changed, the old checkpoint is discarded and a new order is created.

For a stuck invalid order, delete `.obtain-checkpoint.json` manually and run again.

## Docker

Build from the repository root:

```bash
docker build -f docker/Dockerfile -t certbot-dns:latest .
```

Example `docker-compose.yml`:

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
      - ./config.toml:/etc/certbot-dns/config.toml:ro
      - acme-state:/var/certs/.acme-state
      - certs-out:/var/certs/out
    restart: unless-stopped

volumes:
  acme-state:
  certs-out:
```

Inside the container, use paths under `/var/certs` in `config.toml`:

```toml
[acme]
state_dir = "/var/certs/.acme-state"

[[certificates]]
output_dir = "/var/certs/out/sites"
```

## Logging

| Level | Purpose |
|-------|---------|
| `debug` | Maximum detail + file:line on each line |
| `verbose` | Same filter as debug, without file:line |
| `info` | Normal operation (recommended) |
| `warning` / `error` | Warnings and errors only |
| `fatal` | Critical messages and immediate exit |

lego library logs are forwarded to the same slog handler.

## Troubleshooting

### Zone unavailable via FastDNS API

Verify the token, that the domain is delegated to FastDNS, and that the zone name matches the last two apex labels (see log line `проверка зоны FastDNS` / zone check).

### AppendRecords with empty error message

Often caused by a one-TXT-per-name limit or stale `_acme-challenge` records. The tool purges conflicting TXT before `Present`; if it persists, inspect the FastDNS panel manually.

### TXT not propagating

Increase `propagation_timeout` or decrease `propagation_interval`. Set `recursive_resolvers` reachable from your network.

### Staging vs production

Use `directory = "staging"` for first tests. Staging certificates are untrusted in browsers but have relaxed rate limits.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success (`once` mode) |
| `1` | Obtain failure, zone error, or daemon cycle error |
| `2` | Configuration or argument error |

---

Russian documentation: [docs/ru.md](ru.md)
