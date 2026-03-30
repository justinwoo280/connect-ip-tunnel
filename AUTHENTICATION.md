# CONNECT-IP 鉴权实现方案

## 当前状态

鉴权框架已完成设计和实现，但由于上游库限制，**暂时无法完全生效**。

### 已完成

✅ **鉴权模块设计** (`security/auth/`)
- 支持 4 种鉴权方式：Bearer Token、HTTP Basic、Custom Header、None
- 完整的配置验证和错误处理
- 清晰的 API 设计

✅ **配置结构** (`option/config.go`)
- `ConnectIPConfig.Auth` 字段完整定义
- JSON 配置加载支持

✅ **集成准备** (`engine/engine.go`)
- 配置读取和验证逻辑
- 警告日志提示功能未生效

✅ **文档**
- `security/auth/README.md` - 详细的鉴权方案说明
- `config.example.json` - 配置示例

### 待完成

⏳ **connect-ip-go 库支持**

当前阻塞点：`github.com/quic-go/connect-ip-go` 的 `Dial` 函数不支持自定义 HTTP header。

```go
// 当前签名
func Dial(ctx context.Context, conn *http3.ClientConn, template *uritemplate.Template) (*Conn, *http.Response, error)

// 需要的签名（方案 A）
func DialWithHeaders(ctx context.Context, conn *http3.ClientConn, template *uritemplate.Template, headers http.Header) (*Conn, *http.Response, error)
```

## 实现路径

### 方案 A：贡献上游（推荐）

1. **Fork connect-ip-go**
   ```bash
   git clone https://github.com/quic-go/connect-ip-go
   cd connect-ip-go
   git checkout -b feature/custom-headers
   ```

2. **修改 Dial 函数**
   - 添加 `headers http.Header` 参数
   - 在构造 CONNECT-IP 请求时注入 headers
   - 保持向后兼容（可选参数或新函数）

3. **提交 PR**
   - 编写测试用例
   - 更新文档
   - 提交到上游仓库

4. **更新依赖**
   ```bash
   go get github.com/quic-go/connect-ip-go@latest
   ```

### 方案 B：临时 Fork（快速方案）

1. **创建私有 fork**
   ```bash
   git clone https://github.com/quic-go/connect-ip-go
   cd connect-ip-go
   # 修改代码
   git commit -am "Add custom headers support"
   git push origin main
   ```

2. **更新 go.mod**
   ```go
   replace github.com/quic-go/connect-ip-go => github.com/your-org/connect-ip-go v0.1.1-custom
   ```

3. **启用鉴权**
   - 移除 `engine.go` 中的警告日志
   - 取消注释鉴权逻辑
   - 传递 headers 到 `Dial` 函数

### 方案 C：手动实现 CONNECT-IP（完全控制）

如果上游不接受 PR，可以手动实现 CONNECT-IP 协议：

1. **创建 `tunnel/connectip/dial.go`**
   - 参考 RFC 草案实现握手流程
   - 支持 capsule 协议
   - 处理 ADDRESS_ASSIGN 和 ROUTE_ADVERTISEMENT

2. **优点**
   - 完全控制实现细节
   - 可以添加自定义功能
   - 不依赖上游更新

3. **缺点**
   - 维护成本高
   - 需要跟进协议更新

## 代码修改示例

### connect-ip-go 库修改（方案 A/B）

```go
// client.go
func DialWithHeaders(ctx context.Context, conn *http3.ClientConn, template *uritemplate.Template, headers http.Header) (*Conn, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, template.Expand(nil), nil)
	if err != nil {
		return nil, nil, err
	}
	
	// 注入自定义 headers
	for k, v := range headers {
		req.Header[k] = v
	}
	
	req.Proto = "connect-ip"
	req.Header.Set("Capsule-Protocol", "?1")
	
	// ... 其余逻辑
}
```

### 本项目修改（启用鉴权）

```go
// engine/engine.go
if e.cfg.ConnectIP.Auth.Method != "" && e.cfg.ConnectIP.Auth.Method != "none" {
	authCfg := securityauth.Config{
		Method:      securityauth.AuthMethod(e.cfg.ConnectIP.Auth.Method),
		BearerToken: e.cfg.ConnectIP.Auth.BearerToken,
		Username:    e.cfg.ConnectIP.Auth.Username,
		Password:    e.cfg.ConnectIP.Auth.Password,
		HeaderName:  e.cfg.ConnectIP.Auth.HeaderName,
		HeaderValue: e.cfg.ConnectIP.Auth.HeaderValue,
	}
	if err := authCfg.Validate(); err != nil {
		startErr = fmt.Errorf("engine: invalid auth config: %w", err)
		return
	}
	
	// 构造 HTTP headers
	headers := make(http.Header)
	authProvider := securityauth.NewProvider(authCfg)
	dummyReq, _ := http.NewRequest("GET", "/", nil)
	_ = authProvider.ApplyToRequest(dummyReq)
	for k, v := range dummyReq.Header {
		headers[k] = v
	}
	
	// 使用带 headers 的 Dial
	conn, resp, err := connectipgo.DialWithHeaders(ctx, clientConn, tmpl, headers)
	// ...
}
```

## 测试鉴权

### 服务端验证

使用支持鉴权的 CONNECT-IP 服务器（例如 Cloudflare WARP、自建代理）：

```bash
# 测试 Bearer Token
curl -X CONNECT-IP \
  -H "Authorization: Bearer your-token" \
  https://proxy.example.com/.well-known/masque/ip

# 预期响应：200 OK（成功）或 401 Unauthorized（失败）
```

### 客户端测试

```bash
# 编译
go build -o connect-ip-tunnel ./cmd/app

# 运行（需要 root 权限）
sudo ./connect-ip-tunnel -config config.json

# 检查日志
# 成功：[engine] started: tun=tun0 server=proxy.example.com:443
# 失败：[engine] error: connectip: authentication failed (status 401)
```

## 安全建议

1. **生产环境必须启用鉴权**
   - 禁止使用 `method: "none"`
   - 定期轮换 token

2. **配合 ECH 使用**
   - 隐藏 SNI 和鉴权信息
   - 防止中间人嗅探

3. **监控和审计**
   - 记录鉴权失败事件
   - 检测异常流量模式

4. **速率限制**
   - 服务端实施 IP 级别限流
   - 防止暴力破解

## 参考资料

- [IETF CONNECT-IP Draft](https://www.ietf.org/archive/id/draft-ietf-masque-connect-ip-04.html) - Section 10: Security Considerations
- [RFC 9110 - HTTP Authorization](https://www.rfc-editor.org/rfc/rfc9110.html#name-authorization)
- [quic-go/connect-ip-go](https://github.com/quic-go/connect-ip-go)

## 时间线

- ✅ 2025-03-29: 鉴权框架设计完成
- ⏳ 待定: 等待 connect-ip-go 库支持或 fork 实现
- ⏳ 待定: 完整鉴权功能上线
