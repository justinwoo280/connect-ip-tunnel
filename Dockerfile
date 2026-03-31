# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w -X connect-ip-tunnel/server.Version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)" \
    -trimpath \
    -o /out/connect-ip-tunnel \
    ./cmd/app

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM alpine:3.21

# TUN 设备和路由操作需要的工具
RUN apk add --no-cache \
    ca-certificates \
    iproute2 \
    iptables \
    ip6tables \
    && rm -rf /var/cache/apk/*

COPY --from=builder /out/connect-ip-tunnel /usr/local/bin/connect-ip-tunnel

# 默认配置目录
RUN mkdir -p /etc/connect-ip-tunnel/certs

WORKDIR /etc/connect-ip-tunnel

# 暴露端口：
#   443  → QUIC/HTTP3 主服务
#   9090 → 管理 API / Prometheus metrics
EXPOSE 443/udp
EXPOSE 9090/tcp

ENTRYPOINT ["/usr/local/bin/connect-ip-tunnel"]
CMD ["server", "--config", "/etc/connect-ip-tunnel/config.json"]
