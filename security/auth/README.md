# CONNECT-IP 认证方案

## 当前方案：mTLS（双向 TLS）

本项目统一使用 **mTLS（Mutual TLS）** 作为唯一认证方式。

认证在 TLS 握手阶段完成，无需 HTTP 层额外鉴权 Header。

### 工作原理

```
客户端                          服务端
  │                               │
  │── TLS ClientHello ──────────►│
  │◄─ TLS ServerHello + cert ────│  ← 服务端出示 server.crt
  │── client cert ───────────────►│  ← 客户端出示 client.crt
  │   TLS 握手完成                │  ← 服务端用 ca.crt 验证客户端证书
  │── CONNECT-IP 请求 ───────────►│  ← 无需 Authorization Header
```

### 证书结构

| 文件 | 用途 | 持有方 |
|------|------|--------|
| `ca.crt` | CA 根证书 | **服务端**（验证客户端证书）/ 客户端（可选，验证服务端证书）|
| `ca.key` | CA 私钥 | 服务端（仅签发证书时使用，签完可离线保存）|
| `server.crt` / `server.key` | 服务端身份证书（由 CA 签发）| 服务端 |
| `client.crt` / `client.key` | 客户端身份证书（由 CA 签发，出示给服务端认证）| **客户端** |

**认证流程说明**：
- 服务端持有 `ca.crt`，用它验证客户端出示的 `client.crt` 是否由本 CA 签发
- 客户端持有 `client.crt + client.key`，在 TLS 握手时出示给服务端
- 客户端不需要持有 `ca.crt` 也能完成 mTLS（除非要验证服务端证书合法性）
- 服务端不需要知道 `client.crt` 本身，只要它是 `ca.crt` 签发的即可

### 服务端配置

```json
{
  "mode": "server",
  "server": {
    "tls": {
      "cert_file":      "/etc/connect-ip-tunnel/certs/server.crt",
      "key_file":       "/etc/connect-ip-tunnel/certs/server.key",
      "enable_mtls":    true,
      "client_ca_file": "/etc/connect-ip-tunnel/certs/ca.crt"
    }
  }
}
```

### 客户端配置

```json
{
  "mode": "client",
  "client": {
    "tls": {
      "server_name":      "proxy.example.com",
      "client_cert_file": "/etc/connect-ip-tunnel/certs/client.crt",
      "client_key_file":  "/etc/connect-ip-tunnel/certs/client.key"
    }
  }
}
```

### 证书生成（快速开始）

使用 `deploy.sh` 一键生成：

```bash
sudo bash deploy.sh
```

或手动生成：

```bash
# 1. CA 根证书
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout ca.key -out ca.crt -days 3650 -nodes \
    -subj "/CN=connect-ip-tunnel-ca"

# 2. 服务端证书
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout server.key -out server.csr -nodes -subj "/CN=your-server-cn"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -days 3650 \
    -extfile <(printf "subjectAltName=DNS:your-server-cn,IP:127.0.0.1")

# 3. 客户端证书
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout client.key -out client.csr -nodes -subj "/CN=connect-ip-client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt -days 3650

# 将 client.crt + client.key + ca.crt 分发给客户端
```

---

## ⚠️ 已废弃：HTTP 层鉴权（Bearer / Basic / Custom Header）

HTTP 层鉴权方案（Bearer Token、Basic Auth、Custom Header）**已完全废弃**，原因：

1. `github.com/quic-go/connect-ip-go` 库的 `Dial` 函数不支持注入自定义 HTTP Header
2. mTLS 在 TLS 握手阶段完成认证，安全性更高，无需依赖 HTTP 层
3. mTLS 天然防止中间人攻击，而 Bearer Token 在 HTTP/3 中仍有暴露风险

`security/auth/` 包已移除，请勿在配置中添加 `auth` 字段。

## 参考资料

- [IETF CONNECT-IP Draft](https://www.ietf.org/archive/id/draft-ietf-masque-connect-ip-04.html)
- [RFC 8446 - TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [mTLS 原理](https://www.cloudflare.com/learning/access-management/what-is-mutual-tls/)
