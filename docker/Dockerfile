# syntax=docker/dockerfile:1
#
# Сборка (контекст — корень репозитория):
#   docker build -f docker/Dockerfile -t certbot-dns:latest .
#
# Запуск (конфиг и данные — тома; FASTDNS_API_TOKEN из env или secrets):
#   docker run --rm \
#     -e FASTDNS_API_TOKEN=... \
#     -v /path/to/config.toml:/etc/certs/config.toml:ro \
#     -v certbot-dns-acme-state:/var/certs/.acme-state \
#     -v certbot-dns-out:/var/certs/out \
#     certbot-dns:latest
#
# При относительных путях в config.toml (state_dir, output_dir) задайте WORKDIR или
# монтируйте том на /var/certs и запускайте с -config /etc/certs/config.toml.

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
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/certs-acme .

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/certs-acme /usr/local/bin/certs-acme

WORKDIR /var/certs

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/certs-acme"]
CMD ["-config", "/etc/certs/config.toml"]
