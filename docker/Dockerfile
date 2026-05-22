# syntax=docker/dockerfile:1
#
# Сборка (контекст — корень репозитория):
#   docker build -f docker/Dockerfile -t certbot-dns:latest .
#
# Запуск (конфиг и данные — тома; FASTDNS_API_TOKEN из env или secrets):
#   docker run --rm \
#     -e FASTDNS_API_TOKEN=... \
#     -v /path/to/config.toml:/etc/certbot-dns/config.toml:ro \
#     -v certbot-dns-data:/var/lib/certbot-dns \
#     certbot-dns:latest
#
# Опубликованный образ (после git tag v*):
#   ghcr.io/raidkon/certbot-dns:latest
# См. docker-compose.example.yml

# Образ Go: при необходимости подтянется toolchain из go.mod (1.25) через GOTOOLCHAIN.
FROM golang:1.24-bookworm AS builder

ENV GOTOOLCHAIN=auto

WORKDIR /src

COPY src/go.mod src/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY src/ ./

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/certbot-dns .

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/certbot-dns /usr/local/bin/certbot-dns

WORKDIR /var/lib/certbot-dns

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/certbot-dns"]
