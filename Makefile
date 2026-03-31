.PHONY: build test bench gen-certs deploy clean

BINARY := connect-ip-tunnel
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X connect-ip-tunnel/server.Version=$(VERSION)

# ── 构建 ──────────────────────────────────────────────────────────────────────
build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -trimpath -o bin/$(BINARY) ./cmd/app

build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -trimpath -o bin/$(BINARY)-linux-amd64 ./cmd/app

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -trimpath -o bin/$(BINARY)-linux-arm64 ./cmd/app

build-darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -trimpath -o bin/$(BINARY)-darwin-arm64 ./cmd/app

build-all: build-linux-amd64 build-linux-arm64 build-darwin-arm64

# ── 测试 ──────────────────────────────────────────────────────────────────────
test:
	go test ./...

test-verbose:
	go test -v ./...

test-race:
	go test -race ./...

# ── Benchmark ─────────────────────────────────────────────────────────────────
bench:
	go test -bench=. -benchmem -benchtime=3s ./engine/ ./server/

bench-flow:
	go test -bench=BenchmarkFlow -benchmem -benchtime=5s ./engine/

# ── 证书生成（开发/测试用，生产请使用正式 CA）──────────────────────────────────
gen-certs:
	@mkdir -p deploy/certs
	@echo "Generating CA..."
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
		-keyout deploy/certs/ca.key -out deploy/certs/ca.crt \
		-days 3650 -nodes -subj "/CN=connect-ip-tunnel-ca"
	@echo "Generating server cert..."
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
		-keyout deploy/certs/server.key -out deploy/certs/server.csr \
		-nodes -subj "/CN=server.connect-ip.local"
	openssl x509 -req -in deploy/certs/server.csr \
		-CA deploy/certs/ca.crt -CAkey deploy/certs/ca.key -CAcreateserial \
		-out deploy/certs/server.crt -days 365 \
		-extfile <(printf "subjectAltName=DNS:server.connect-ip.local,IP:127.0.0.1")
	@echo "Generating client cert..."
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
		-keyout deploy/certs/client.key -out deploy/certs/client.csr \
		-nodes -subj "/CN=client-01"
	openssl x509 -req -in deploy/certs/client.csr \
		-CA deploy/certs/ca.crt -CAkey deploy/certs/ca.key -CAcreateserial \
		-out deploy/certs/client.crt -days 365
	@echo "Certs generated in deploy/certs/"

# ── Docker ────────────────────────────────────────────────────────────────────
docker-build:
	docker build -t connect-ip-tunnel:$(VERSION) .

docker-build-multiarch:
	docker buildx build --platform linux/amd64,linux/arm64 \
		-t connect-ip-tunnel:$(VERSION) --push .

deploy-init:
	@mkdir -p deploy/server deploy/client deploy/prometheus deploy/grafana/provisioning/datasources
	@cp config.server.example.json deploy/server/config.json 2>/dev/null || true
	@cp config.client.example.json deploy/client/config.json 2>/dev/null || true
	@echo "Edit deploy/server/config.json and deploy/client/config.json before starting"

up: deploy-init
	docker compose up -d

up-monitoring: deploy-init
	docker compose --profile monitoring up -d

down:
	docker compose down

logs:
	docker compose logs -f

# ── 清理 ──────────────────────────────────────────────────────────────────────
clean:
	rm -rf bin/
	docker compose down --volumes 2>/dev/null || true
