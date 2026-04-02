#!/usr/bin/env bash
# =============================================================================
# connect-ip-tunnel 服务端一键部署脚本
# 支持：Docker 模式 / systemd 裸机模式
# 自动生成自签名证书（CA + Server）
# =============================================================================
set -euo pipefail

# ── 颜色输出 ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
section() { echo -e "\n${BOLD}${BLUE}══ $* ══${NC}"; }

# ── 默认配置 ──────────────────────────────────────────────────────────────────
DEPLOY_MODE=""                         # docker | systemd
INSTALL_DIR="/opt/connect-ip-tunnel"   # systemd 模式安装目录
CERT_DIR=""                            # 证书目录（各模式不同）
CONFIG_FILE=""                         # 配置文件路径

# 服务端参数（交互时填写）
SERVER_PORT="443"
ADMIN_PORT="9090"
IPV4_POOL="10.233.0.0/16"
IPV6_POOL="fd00::/64"
ENABLE_NAT="true"
NAT_IFACE=""
TUN_NAME="tun0"
TUN_MTU="1400"
SERVER_CN="connect-ip-server"         # 证书 CN / SAN
CERTSRV_PORT="8443"                   # certsrv 监听端口（留空则不启动）
CERTSRV_ENABLED="true"

# Docker 相关
DOCKER_IMAGE="connect-ip-tunnel:local"
DOCKER_DATA_DIR="$INSTALL_DIR/data"    # 容器可写数据目录（certsrv DB 等）
CONTAINER_NAME="connect-ip-server"
DOCKER_CONFIG_DIR="/opt/connect-ip-tunnel/docker"

# systemd 相关
BINARY_NAME="connect-ip-tunnel"
SERVICE_NAME="connect-ip-tunnel"
GO_VERSION_MIN="1.22"

# =============================================================================
# 工具函数
# =============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "此脚本需要 root 权限运行"
        error "请使用: sudo bash $0"
        exit 1
    fi
}

detect_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        armv7l)  echo "arm"   ;;
        *)
            error "不支持的架构: $arch"
            exit 1
            ;;
    esac
}

command_exists() {
    command -v "$1" &>/dev/null
}

prompt() {
    # prompt "提示" "默认值" -> 返回用户输入或默认值
    # 注意：提示符输出到 stderr，避免被 $() 捕获时混入返回值
    local msg="$1"
    local default="${2:-}"
    local input
    if [[ -n "$default" ]]; then
        echo -en "${CYAN}  → ${msg} [${default}]: ${NC}" >&2
    else
        echo -en "${CYAN}  → ${msg}: ${NC}" >&2
    fi
    read -r input
    echo "${input:-$default}"
}

prompt_yn() {
    local msg="$1"
    local default="${2:-y}"
    local input
    echo -en "${CYAN}  → ${msg} [${default}]: ${NC}" >&2
    read -r input
    input="${input:-$default}"
    [[ "$input" =~ ^[Yy] ]]
}

# =============================================================================
# 证书生成（CA + 服务端 + 客户端，mTLS 模式）
# =============================================================================

gen_certs() {
    local cert_dir="$1"
    local cn="$2"

    section "生成自签名证书（mTLS 模式）"
    mkdir -p "$cert_dir"

    if [[ -f "$cert_dir/server.crt" && -f "$cert_dir/client.crt" ]]; then
        warn "证书已存在: $cert_dir/"
        if ! prompt_yn "是否重新生成所有证书？" "n"; then
            info "跳过证书生成，使用已有证书"
            return 0
        fi
    fi

    info "生成 CA 根证书..."
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "$cert_dir/ca.key" \
        -out "$cert_dir/ca.crt" \
        -days 3650 -nodes \
        -subj "/CN=connect-ip-tunnel-ca" \
        2>/dev/null

    info "生成服务端证书..."
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "$cert_dir/server.key" \
        -out "$cert_dir/server.csr" \
        -nodes -subj "/CN=${cn}" \
        2>/dev/null
    openssl x509 -req \
        -in "$cert_dir/server.csr" \
        -CA "$cert_dir/ca.crt" \
        -CAkey "$cert_dir/ca.key" \
        -CAcreateserial \
        -out "$cert_dir/server.crt" \
        -days 3650 \
        -extfile <(printf "subjectAltName=DNS:%s,IP:127.0.0.1" "$cn") \
        2>/dev/null

    info "生成客户端证书（mTLS 认证用）..."
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "$cert_dir/client.key" \
        -out "$cert_dir/client.csr" \
        -nodes -subj "/CN=connect-ip-client" \
        2>/dev/null
    openssl x509 -req \
        -in "$cert_dir/client.csr" \
        -CA "$cert_dir/ca.crt" \
        -CAkey "$cert_dir/ca.key" \
        -CAcreateserial \
        -out "$cert_dir/client.crt" \
        -days 3650 \
        2>/dev/null

    rm -f "$cert_dir/server.csr" "$cert_dir/client.csr" "$cert_dir/ca.srl"
    chmod 600 "$cert_dir/ca.key" "$cert_dir/server.key" "$cert_dir/client.key"
    chmod 644 "$cert_dir/ca.crt" "$cert_dir/server.crt" "$cert_dir/client.crt"

    info "证书生成完成:"
    info "  CA 证书:      $cert_dir/ca.crt"
    info "  服务端证书:   $cert_dir/server.crt"
    info "  服务端私钥:   $cert_dir/server.key"
    info "  客户端证书:   $cert_dir/client.crt  ← 分发给客户端"
    info "  客户端私钥:   $cert_dir/client.key  ← 分发给客户端"
}

# =============================================================================
# 生成服务端配置文件
# =============================================================================

gen_server_config() {
    local config_file="$1"
    local cert_prefix="${2:-/etc/connect-ip-tunnel/certs}"  # 容器内或系统路径

    info "生成服务端配置文件: $config_file"

    # 构建 nat_interface
    local nat_iface_str='""'
    [[ -n "$NAT_IFACE" ]] && nat_iface_str="\"$NAT_IFACE\""

    # 构建 certsrv 配置段
    local certsrv_section=""
    if [[ "$CERTSRV_ENABLED" == "true" && -n "$CERTSRV_PORT" ]]; then
        # db_path 放在可写目录 /var/lib/connect-ip-tunnel/（Docker 模式）
        # 或 cert_prefix 同级目录（systemd 模式）
        local db_path
        if [[ "$cert_prefix" == "/etc/connect-ip-tunnel/certs" ]]; then
            # Docker 模式：用独立可写挂载目录
            db_path="/var/lib/connect-ip-tunnel/certsrv.db"
        else
            # systemd 模式：放在安装目录下
            db_path="${cert_prefix%/certs}/certsrv.db"
        fi
        certsrv_section=",
    \"certsrv\": {
      \"listen\":       \":${CERTSRV_PORT}\",
      \"db_path\":      \"${db_path}\",
      \"ca_cert_file\": \"${cert_prefix}/ca.crt\",
      \"ca_key_file\":  \"${cert_prefix}/ca.key\"
    }"
    fi

    # 构建 crl_url（certsrv 启用时自动配置）
    # 注意：session_cache_size 后面需要逗号，crl_interval 末尾不能有逗号（JSON 不支持 trailing comma）
    local crl_config=""
    if [[ "$CERTSRV_ENABLED" == "true" && -n "$CERTSRV_PORT" ]]; then
        crl_config=",
      \"crl_url\":             \"https://127.0.0.1:${CERTSRV_PORT}/crl.pem\",
      \"crl_interval\":        \"10m\""
    fi

    cat > "$config_file" <<EOF
{
  "mode": "server",
  "server": {
    "listen": ":${SERVER_PORT}",
    "uri_template": "/.well-known/masque/ip",
    "admin_listen": ":${ADMIN_PORT}",
    "tun": {
      "name": "${TUN_NAME}",
      "mtu": ${TUN_MTU}
    },
    "tls": {
      "cert_file":           "${cert_prefix}/server.crt",
      "key_file":            "${cert_prefix}/server.key",
      "enable_mtls":         true,
      "client_ca_file":      "${cert_prefix}/ca.crt",
      "enable_pqc":          true,
      "enable_session_cache": true,
      "session_cache_size":  256${crl_config}
    },
    "http3": {
      "enable_datagrams":        true,
      "max_idle_timeout":        "60s",
      "keep_alive_period":       "20s",
      "disable_path_mtu_probe":  false,
      "initial_stream_window":   16777216,
      "max_stream_window":       67108864,
      "initial_conn_window":     33554432,
      "max_conn_window":         134217728
    },
    "ipv4_pool":    "${IPV4_POOL}",
    "ipv6_pool":    "${IPV6_POOL}",
    "enable_nat":   ${ENABLE_NAT},
    "nat_interface": ${nat_iface_str}${certsrv_section}
  }
}
EOF
    info "配置文件已生成"
}

# =============================================================================
# 交互式配置收集
# =============================================================================

collect_config() {
    section "服务端参数配置"

    SERVER_PORT=$(prompt "监听端口 (UDP)" "$SERVER_PORT")
    ADMIN_PORT=$(prompt "管理/Metrics 端口 (TCP)" "$ADMIN_PORT")
    IPV4_POOL=$(prompt "IPv4 地址池 (CIDR)" "$IPV4_POOL")
    IPV6_POOL=$(prompt "IPv6 地址池 (CIDR)" "$IPV6_POOL")
    TUN_MTU=$(prompt "TUN MTU" "$TUN_MTU")

    echo ""
    if prompt_yn "启用 NAT（让客户端流量通过服务器上网）？" "y"; then
        ENABLE_NAT="true"
        # 自动检测默认网卡
        local default_iface
        default_iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || echo "")
        NAT_IFACE=$(prompt "NAT 出口网卡（留空自动检测）" "$default_iface")
    else
        ENABLE_NAT="false"
    fi

    echo ""
    SERVER_CN=$(prompt "证书 CN（域名或 IP，用于客户端验证）" "$(hostname -f 2>/dev/null || echo connect-ip-server)")

    echo ""
    if prompt_yn "启用 certsrv 证书管理面板？（推荐）" "y"; then
        CERTSRV_ENABLED="true"
        CERTSRV_PORT=$(prompt "certsrv 监听端口（HTTPS）" "$CERTSRV_PORT")
    else
        CERTSRV_ENABLED="false"
        CERTSRV_PORT=""
    fi
}

# =============================================================================
# Docker 模式部署
# =============================================================================

deploy_docker() {
    section "Docker 模式部署"

    # 检查依赖
    if ! command_exists docker; then
        error "未找到 docker，请先安装 Docker"
        info "安装参考: https://docs.docker.com/engine/install/"
        exit 1
    fi

    if ! command_exists openssl; then
        error "未找到 openssl，请先安装: apt install openssl / yum install openssl"
        exit 1
    fi

    # 收集配置
    collect_config

    # 目录结构
    CERT_DIR="$DOCKER_CONFIG_DIR/certs"
    CONFIG_FILE="$DOCKER_CONFIG_DIR/config.json"
    mkdir -p "$DOCKER_CONFIG_DIR" "$CERT_DIR" "$DOCKER_DATA_DIR"

    # 生成证书
    gen_certs "$CERT_DIR" "$SERVER_CN"

    # 生成配置（容器内路径）
    gen_server_config "$CONFIG_FILE" "/etc/connect-ip-tunnel/certs"

    section "构建 Docker 镜像"
    # 判断是否在项目根目录
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [[ -f "$script_dir/Dockerfile" ]]; then
        info "在项目目录中构建镜像..."
        docker build -t "$DOCKER_IMAGE" "$script_dir" 2>&1 | tail -5
        info "镜像构建完成: $DOCKER_IMAGE"
    else
        warn "未找到 Dockerfile，尝试从 GitHub 拉取预构建镜像..."
        DOCKER_IMAGE="ghcr.io/connect-ip-tunnel/connect-ip-tunnel:latest"
        docker pull "$DOCKER_IMAGE" || {
            error "无法获取镜像，请在项目目录中运行此脚本"
            exit 1
        }
    fi

    section "启动容器"

    # 停止并删除旧容器
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        warn "发现已存在的容器 $CONTAINER_NAME，正在停止..."
        docker stop "$CONTAINER_NAME" 2>/dev/null || true
        docker rm "$CONTAINER_NAME" 2>/dev/null || true
    fi

    docker run -d \
        --name "$CONTAINER_NAME" \
        --restart unless-stopped \
        --cap-add NET_ADMIN \
        --cap-add SYS_MODULE \
        --device /dev/net/tun \
        --sysctl net.ipv4.ip_forward=1 \
        --sysctl net.ipv6.conf.all.forwarding=1 \
        -p "${SERVER_PORT}:${SERVER_PORT}/udp" \
        -p "${ADMIN_PORT}:${ADMIN_PORT}/tcp" \
        -p "${CERTSRV_PORT}:${CERTSRV_PORT}/tcp" \
        -v "$DOCKER_CONFIG_DIR:/etc/connect-ip-tunnel:ro" \
        -v "$DOCKER_DATA_DIR:/var/lib/connect-ip-tunnel" \
        "$DOCKER_IMAGE" \
        server --config /etc/connect-ip-tunnel/config.json

    info "容器已启动: $CONTAINER_NAME"

    # 健康检查
    section "等待服务就绪"
    local retries=12
    local i=0
    while [[ $i -lt $retries ]]; do
        if docker exec "$CONTAINER_NAME" wget -qO- "http://localhost:${ADMIN_PORT}/healthz" &>/dev/null; then
            info "服务健康检查通过 ✓"
            break
        fi
        sleep 2
        ((i++))
    done

    if [[ $i -eq $retries ]]; then
        warn "健康检查超时，请检查日志: docker logs $CONTAINER_NAME"
    fi

    print_summary "docker"
}

# =============================================================================
# systemd 模式部署
# =============================================================================

deploy_systemd() {
    section "systemd 裸机模式部署"

    # 检查依赖
    if ! command_exists openssl; then
        error "未找到 openssl"
        exit 1
    fi

    if ! command_exists go && ! command_exists "$INSTALL_DIR/bin/$BINARY_NAME"; then
        error "未找到 Go 编译器，且没有预编译二进制"
        info "请先安装 Go $GO_VERSION_MIN+ 或将编译好的二进制放到 $INSTALL_DIR/bin/$BINARY_NAME"
        info "Go 安装参考: https://golang.org/dl/"
        exit 1
    fi

    # 收集配置
    collect_config

    # 目录结构
    CERT_DIR="$INSTALL_DIR/certs"
    CONFIG_FILE="$INSTALL_DIR/config.json"
    mkdir -p "$INSTALL_DIR/bin" "$CERT_DIR"

    # 编译二进制
    section "编译二进制"
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [[ -f "$script_dir/go.mod" ]]; then
        info "在项目目录编译..."
        local arch
        arch=$(detect_arch)
        CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
            go build -ldflags="-s -w" -trimpath \
            -o "$INSTALL_DIR/bin/$BINARY_NAME" \
            "$script_dir/cmd/app" 2>&1
        info "编译完成: $INSTALL_DIR/bin/$BINARY_NAME"
    elif [[ -f "$INSTALL_DIR/bin/$BINARY_NAME" ]]; then
        info "使用已有二进制: $INSTALL_DIR/bin/$BINARY_NAME"
    else
        error "找不到源代码或预编译二进制，无法继续"
        exit 1
    fi

    chmod +x "$INSTALL_DIR/bin/$BINARY_NAME"

    # 生成证书
    gen_certs "$CERT_DIR" "$SERVER_CN"

    # 生成配置（系统路径）
    gen_server_config "$CONFIG_FILE" "$CERT_DIR"

    # 开启内核转发
    section "配置内核参数"
    cat > /etc/sysctl.d/99-connect-ip-tunnel.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
    sysctl -p /etc/sysctl.d/99-connect-ip-tunnel.conf >/dev/null 2>&1
    info "内核转发已启用"

    # 创建系统用户
    if ! id "connect-ip" &>/dev/null; then
        useradd -r -s /sbin/nologin -d "$INSTALL_DIR" connect-ip 2>/dev/null || true
        info "创建系统用户: connect-ip"
    fi

    # 设置目录权限
    chown -R connect-ip:connect-ip "$INSTALL_DIR" 2>/dev/null || true
    chmod 700 "$CERT_DIR"

    # 写 systemd 服务文件
    section "注册 systemd 服务"
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=connect-ip-tunnel Server (HTTP/3 CONNECT-IP L3 Tunnel)
Documentation=https://github.com/connect-ip-tunnel/connect-ip-tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=${INSTALL_DIR}/bin/${BINARY_NAME} -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

# TUN 设备和网络操作权限
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

# 日志
StandardOutput=journal
StandardError=journal
SyslogIdentifier=connect-ip-tunnel

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}.service"
    systemctl restart "${SERVICE_NAME}.service"

    # 等待服务启动
    section "等待服务就绪"
    local retries=12
    local i=0
    while [[ $i -lt $retries ]]; do
        if curl -sf "http://127.0.0.1:${ADMIN_PORT}/healthz" &>/dev/null; then
            info "服务健康检查通过 ✓"
            break
        fi
        sleep 2
        ((i++))
    done

    if [[ $i -eq $retries ]]; then
        warn "健康检查超时，请检查日志: journalctl -u ${SERVICE_NAME} -n 50"
    fi

    print_summary "systemd"
}

# =============================================================================
# 部署完成摘要
# =============================================================================

print_summary() {
    local mode="$1"
    local public_ip
    public_ip=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null || \
                curl -s --max-time 3 https://ifconfig.me 2>/dev/null || \
                hostname -I | awk '{print $1}')

    echo ""
    echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${GREEN}║         connect-ip-tunnel 服务端部署完成！           ║${NC}"
    echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}运行模式:${NC}   $mode"
    echo -e "  ${BOLD}服务端IP:${NC}   $public_ip"
    echo -e "  ${BOLD}隧道端口:${NC}   UDP ${SERVER_PORT}"
    echo -e "  ${BOLD}管理端口:${NC}   TCP ${ADMIN_PORT}"
    echo -e "  ${BOLD}IPv4 池:${NC}    ${IPV4_POOL}"
    echo -e "  ${BOLD}IPv6 池:${NC}    ${IPV6_POOL}"
    echo -e "  ${BOLD}NAT:${NC}        ${ENABLE_NAT}"
    if [[ "$CERTSRV_ENABLED" == "true" && -n "$CERTSRV_PORT" ]]; then
    echo ""
    echo -e "  ${BOLD}${CYAN}CertSrv 证书管理面板:${NC}"
    echo -e "    地址:  https://${public_ip}:${CERTSRV_PORT}"
    echo -e "    默认账号: admin / admin（首次登录强制修改密码+绑定2FA）"
    echo -e "    CRL:   https://127.0.0.1:${CERTSRV_PORT}/crl.pem"
    fi
    echo ""
    echo -e "  ${BOLD}证书目录:${NC}   ${CERT_DIR}"
    echo -e "  ${BOLD}配置文件:${NC}   ${CONFIG_FILE}"
    echo ""

    echo -e "  ${BOLD}客户端配置参考:${NC}"
    echo -e "  ┌─────────────────────────────────────────────────────"
    echo -e "  │ {"
    echo -e "  │   \"mode\": \"client\","
    echo -e "  │   \"client\": {"
    echo -e "  │     \"tun\": { \"name\": \"tun0\", \"mtu\": ${TUN_MTU} },"
    echo -e "  │     \"tls\": {"
    echo -e "  │       \"server_name\":      \"${SERVER_CN}\","
    echo -e "  │       \"insecure_skip_verify\": true,"
    echo -e "  │       \"client_cert_file\": \"/path/to/client.crt\","
    echo -e "  │       \"client_key_file\":  \"/path/to/client.key\","
    echo -e "  │       \"enable_pqc\":       true"
    echo -e "  │     },"
    echo -e "  │     \"connect_ip\": {"
    echo -e "  │       \"addr\":             \"${public_ip}:${SERVER_PORT}\","
    echo -e "  │       \"uri\":              \"/.well-known/masque/ip\","
    echo -e "  │       \"authority\":        \"${SERVER_CN}\","
    echo -e "  │       \"enable_reconnect\": true"
    echo -e "  │     }"
    echo -e "  │   }"
    echo -e "  │ }"
    echo -e "  └─────────────────────────────────────────────────────"
    echo ""

    # 管理命令提示
    echo -e "  ${BOLD}常用命令:${NC}"
    if [[ "$mode" == "docker" ]]; then
        echo -e "    查看日志:  docker logs -f ${CONTAINER_NAME}"
        echo -e "    停止服务:  docker stop ${CONTAINER_NAME}"
        echo -e "    重启服务:  docker restart ${CONTAINER_NAME}"
        echo -e "    查看会话:  curl http://localhost:${ADMIN_PORT}/api/v1/sessions"
        echo -e "    查看指标:  curl http://localhost:${ADMIN_PORT}/metrics"
    else
        echo -e "    查看日志:  journalctl -u ${SERVICE_NAME} -f"
        echo -e "    停止服务:  systemctl stop ${SERVICE_NAME}"
        echo -e "    重启服务:  systemctl restart ${SERVICE_NAME}"
        echo -e "    查看状态:  systemctl status ${SERVICE_NAME}"
        echo -e "    查看会话:  curl http://localhost:${ADMIN_PORT}/api/v1/sessions"
        echo -e "    查看指标:  curl http://localhost:${ADMIN_PORT}/metrics"
    fi

    echo ""
    echo -e "  ${BOLD}客户端所需证书文件（需复制到客户端）:${NC}"
    echo -e "    ${CERT_DIR}/client.crt ← 客户端身份证书（由本 CA 签发，出示给服务端验证）"
    echo -e "    ${CERT_DIR}/client.key ← 客户端私钥"
    echo -e "    ${CERT_DIR}/ca.crt     ← CA 根证书（可选，客户端用于验证服务端证书是否合法）"
    echo -e ""
    echo -e "  ${BOLD}服务端只需持有:${NC}"
    echo -e "    ${CERT_DIR}/ca.crt     ← 用于验证客户端证书是否由本 CA 签发"
    echo -e "    ${CERT_DIR}/server.crt / server.key ← 服务端自身身份证书"
    echo ""
}

# =============================================================================
# 卸载功能
# =============================================================================

uninstall() {
    section "卸载 connect-ip-tunnel"

    warn "此操作将删除服务、配置文件和证书"
    if ! prompt_yn "确认卸载？" "n"; then
        info "已取消"
        exit 0
    fi

    # 停止 Docker 容器
    if command_exists docker && docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        info "停止并删除 Docker 容器..."
        docker stop "$CONTAINER_NAME" 2>/dev/null || true
        docker rm "$CONTAINER_NAME" 2>/dev/null || true
    fi

    # 停止 systemd 服务
    if systemctl list-units --type=service 2>/dev/null | grep -q "$SERVICE_NAME"; then
        info "停止 systemd 服务..."
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload
    fi

    # 删除文件
    rm -rf "$INSTALL_DIR" "$DOCKER_CONFIG_DIR"
    rm -f /etc/sysctl.d/99-connect-ip-tunnel.conf

    # 删除系统用户
    userdel connect-ip 2>/dev/null || true

    info "卸载完成"
}

# =============================================================================
# 主菜单
# =============================================================================

show_banner() {
    echo -e "${BOLD}${CYAN}"
    echo "  ██████╗ ██████╗ ███╗   ██╗███╗   ██╗███████╗ ██████╗████████╗"
    echo "  ██╔════╝██╔═══██╗████╗  ██║████╗  ██║██╔════╝██╔════╝╚══██╔══╝"
    echo "  ██║     ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║        ██║   "
    echo "  ██║     ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║        ██║   "
    echo "  ╚██████╗╚██████╔╝██║ ╚████║██║ ╚████║███████╗╚██████╗   ██║   "
    echo "   ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝ ╚═════╝   ╚═╝  "
    echo -e "${NC}"
    echo -e "  ${BOLD}connect-ip-tunnel${NC} — HTTP/3 + CONNECT-IP L3 隧道服务端一键部署"
    echo ""
}

main() {
    show_banner
    check_root

    # 解析命令行参数
    local action="${1:-}"

    case "$action" in
        docker)
            DEPLOY_MODE="docker"
            ;;
        systemd)
            DEPLOY_MODE="systemd"
            ;;
        uninstall)
            uninstall
            exit 0
            ;;
        "")
            # 交互式选择
            section "选择部署模式"
            echo "  1) Docker 模式    （推荐，隔离性好，需要已安装 Docker）"
            echo "  2) systemd 模式   （裸机运行，需要 Go 编译环境或预编译二进制）"
            echo "  3) 卸载"
            echo ""
            local choice
            choice=$(prompt "请选择 [1/2/3]" "1")
            case "$choice" in
                1) DEPLOY_MODE="docker"   ;;
                2) DEPLOY_MODE="systemd"  ;;
                3) uninstall; exit 0      ;;
                *) error "无效选择"; exit 1 ;;
            esac
            ;;
        *)
            error "未知参数: $action"
            echo "用法: $0 [docker|systemd|uninstall]"
            exit 1
            ;;
    esac

    # 执行对应模式部署
    case "$DEPLOY_MODE" in
        docker)  deploy_docker  ;;
        systemd) deploy_systemd ;;
    esac
}

main "$@"
