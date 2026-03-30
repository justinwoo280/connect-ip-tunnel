# CONNECT-IP 鉴权方案

## 概述

根据 IETF MASQUE 工作组的 CONNECT-IP 草案规范，代理服务器应该限制对已认证用户的访问。本实现支持多种鉴权方式。

## 支持的鉴权方法

### 1. Bearer Token（推荐）

使用 HTTP Authorization header 传递 Bearer Token：

```json
{
  "connect_ip": {
    "addr": "proxy.example.com:443",
    "uri": "/.well-known/masque/ip",
    "auth": {
      "method": "bearer",
      "bearer_token": "your-secret-token-here"
    }
  }
}
```

HTTP 请求示例：
```
CONNECT-IP /.well-known/masque/ip HTTP/3
Host: proxy.example.com
Authorization: Bearer your-secret-token-here
```

### 2. HTTP Basic Auth

使用标准的 HTTP Basic Authentication：

```json
{
  "connect_ip": {
    "addr": "proxy.example.com:443",
    "uri": "/.well-known/masque/ip",
    "auth": {
      "method": "basic",
      "username": "user",
      "password": "pass"
    }
  }
}
```

HTTP 请求示例：
```
CONNECT-IP /.well-known/masque/ip HTTP/3
Host: proxy.example.com
Authorization: Basic dXNlcjpwYXNz
```

### 3. Custom Header（兼容 ewp-core）

使用自定义 header 传递认证信息（例如 UUID）：

```json
{
  "connect_ip": {
    "addr": "proxy.example.com:443",
    "uri": "/.well-known/masque/ip",
    "auth": {
      "method": "custom",
      "header_name": "X-Auth-Token",
      "header_value": "550e8400-e29b-41d4-a716-446655440000"
    }
  }
}
```

HTTP 请求示例：
```
CONNECT-IP /.well-known/masque/ip HTTP/3
Host: proxy.example.com
X-Auth-Token: 550e8400-e29b-41d4-a716-446655440000
```

### 4. None（无鉴权）

仅用于测试环境：

```json
{
  "connect_ip": {
    "addr": "proxy.example.com:443",
    "uri": "/.well-known/masque/ip",
    "auth": {
      "method": "none"
    }
  }
}
```

## 实现限制

**重要提示**：由于 `github.com/quic-go/connect-ip-go` 库当前版本不支持在 `Dial` 函数中注入自定义 HTTP header，本实现需要以下两种方案之一：

### 方案 A：Fork connect-ip-go 库（推荐）

1. Fork `github.com/quic-go/connect-ip-go`
2. 修改 `Dial` 函数签名，添加 `headers map[string]string` 参数
3. 在构造 CONNECT-IP 请求时注入这些 header
4. 使用 fork 版本替换依赖

### 方案 B：手动实现 CONNECT-IP 协议

参考 RFC 草案手动实现 CONNECT-IP 握手流程：

1. 创建 HTTP/3 请求：`CONNECT-IP <uri-template>`
2. 添加必要的 capsule 协议支持
3. 处理 ADDRESS_ASSIGN 和 ROUTE_ADVERTISEMENT capsules
4. 实现 IP 包的封装/解封装

## 服务端鉴权验证

服务端应该：

1. 检查 `Authorization` header 或自定义 header
2. 验证 token/credentials 有效性
3. 如果鉴权失败，返回 `401 Unauthorized` 或 `403 Forbidden`
4. 实施速率限制和防暴力破解措施
5. 记录鉴权失败的审计日志

## 安全建议

1. **始终使用 TLS**：CONNECT-IP 必须运行在 HTTPS/3 上
2. **启用 ECH**：隐藏 SNI 和鉴权信息
3. **Token 轮换**：定期更换 Bearer Token
4. **最小权限**：限制每个 token 的访问范围
5. **监控异常**：检测异常流量模式

## 参考资料

- [IETF CONNECT-IP Draft](https://www.ietf.org/archive/id/draft-ietf-masque-connect-ip-04.html)
- [RFC 9110 - HTTP Semantics (Authorization)](https://www.rfc-editor.org/rfc/rfc9110.html#name-authorization)
- [RFC 7617 - HTTP Basic Authentication](https://www.rfc-editor.org/rfc/rfc7617.html)
