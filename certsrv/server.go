package certsrv

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Config 是 certsrv 的配置
type Config struct {
	Listen     string `json:"listen"`       // 监听地址，如 ":8443"
	DBPath     string `json:"db_path"`      // SQLite 路径，如 "/etc/connect-ip-tunnel/certsrv.db"
	CACertFile string `json:"ca_cert_file"` // CA 证书路径
	CAKeyFile  string `json:"ca_key_file"`  // CA 私钥路径
	TLSCert    string `json:"tls_cert"`     // certsrv 自身 HTTPS 证书（可复用 server.crt）
	TLSKey     string `json:"tls_key"`      // certsrv 自身 HTTPS 私钥
}

// Server 是 certsrv 的主服务
type Server struct {
	cfg  Config
	auth *authService
	ca   *CAService
	db   *DB
	keys *keyStore // 一次性私钥 token store
	http *http.Server
	log  *slog.Logger
}

// New 创建并初始化 certsrv
func New(cfg Config, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}

	db, err := openDB(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("certsrv: open db: %w", err)
	}

	auth := newAuthService(db)
	if err := auth.EnsureDefaultAdmin(); err != nil {
		return nil, fmt.Errorf("certsrv: init admin: %w", err)
	}

	ca, err := newCAService(cfg.CACertFile, cfg.CAKeyFile, db)
	if err != nil {
		return nil, fmt.Errorf("certsrv: init CA: %w", err)
	}

	s := &Server{cfg: cfg, auth: auth, ca: ca, db: db, keys: newKeyStore(), log: log}
	s.http = &http.Server{
		Addr:         cfg.Listen,
		Handler:      s.routes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return s, nil
}

// Start 启动 HTTPS 服务（阻塞）
func (s *Server) Start() error {
	s.log.Info("certsrv listening", "addr", s.cfg.Listen)
	if s.cfg.TLSCert != "" && s.cfg.TLSKey != "" {
		return s.http.ListenAndServeTLS(s.cfg.TLSCert, s.cfg.TLSKey)
	}
	// 无证书时降级为 HTTP（开发用）
	s.log.Warn("certsrv: no TLS cert configured, running plain HTTP")
	return s.http.ListenAndServe()
}

// Shutdown 优雅关闭
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// Close 关闭数据库
func (s *Server) Close() error {
	return s.db.Close()
}

// ── 路由 ─────────────────────────────────────────────────────────────────────

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// 静态文件（内嵌）— 不带方法前缀，兼容 HEAD/GET
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFiles))))

	// 首页
	mux.HandleFunc("GET /{$}", s.handleIndex)

	// 公开接口
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("POST /login", s.handleLogin)           // login 自带 rate limit，无需 CSRF（未登录）
	mux.HandleFunc("POST /logout", s.csrfProtect(s.handleLogout))
	mux.HandleFunc("GET /setup", s.handleSetupPage)
	mux.HandleFunc("POST /setup", s.csrfProtect(s.handleSetup))
	mux.HandleFunc("GET /setup/totp", s.handleTOTPPage)
	mux.HandleFunc("POST /setup/totp", s.csrfProtect(s.handleTOTPConfirm))

	// CRL（公开，供服务端拉取）
	mux.HandleFunc("GET /crl.pem", s.handleCRL)
	mux.HandleFunc("GET /ca.crt", s.handleCACert)

	// 需要登录的接口
	mux.HandleFunc("GET /certs", s.requireAuth(s.handleCertList))
	mux.HandleFunc("GET /certs/issue", s.requireAuth(s.handleIssuePage))
	mux.HandleFunc("POST /certs/issue", s.requireAuth(s.csrfProtect(s.handleIssue)))
	mux.HandleFunc("POST /certs/revoke", s.requireAuth(s.csrfProtect(s.handleRevoke)))
	mux.HandleFunc("GET /certs/download/{serial}", s.requireAuth(s.handleDownload))

	// API（JSON）— Bearer token 场景不需要 CSRF，但需要登录
	mux.HandleFunc("GET /api/v1/certs", s.requireAuth(s.apiListCerts))
	mux.HandleFunc("POST /api/v1/certs/issue", s.requireAuth(s.apiIssueCert))
	mux.HandleFunc("POST /api/v1/certs/revoke", s.requireAuth(s.apiRevokeCert))

	return mux
}

// ── 中间件 ────────────────────────────────────────────────────────────────────

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, ok := s.auth.GetSessionUser(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// csrfProtect 对所有需要登录的 POST 请求验证 CSRF token。
// token 由前端表单的隐藏字段 _csrf 携带，值与 session cookie 绑定。
// 利用 SameSite=Strict cookie 已经提供基础防护，此处作为额外防御层。
func (s *Server) csrfProtect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			cookie, err := r.Cookie(sessionCookieName)
			if err != nil {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			expected := cookie.Value
			if len(expected) > 16 {
				expected = expected[:16]
			}
			// 支持两种方式提交 CSRF token：
			// 1. form 隐藏字段 _csrf（HTML form 表单）
			// 2. X-CSRF-Token header（fetch/XHR JSON 请求）
			formToken := r.FormValue("_csrf")
			headerToken := r.Header.Get("X-CSRF-Token")
			token := formToken
			if token == "" {
				token = headerToken
			}
			if token != expected {
				s.log.Warn("CSRF check failed", "ip", r.RemoteAddr,
					"has_form", formToken != "", "has_header", headerToken != "")
				http.Error(w, "forbidden: invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

// ── 页面 handlers ─────────────────────────────────────────────────────────────

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	_, ok := s.auth.GetSessionUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/certs", http.StatusSeeOther)
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	serveHTML(w, "login.html")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	totpCode := r.FormValue("totp")

	// 取真实客户端 IP（兼容反向代理）
	ip := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ip = strings.SplitN(xff, ",", 2)[0]
	} else if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip = xri
	}

	token, needSetup, err := s.auth.Login(username, password, totpCode, ip)
	if err != nil {
		s.log.Warn("login failed", "username", username, "ip", ip, "err", err)
		// 统一返回 error=1，不泄露具体原因（防止用户名枚举）
		http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
		return
	}

	s.auth.SetSessionCookie(w, token)
	if needSetup {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/certs", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.auth.Logout(cookie.Value)
	}
	s.auth.ClearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	serveHTML(w, "setup.html")
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	username, ok := s.auth.GetSessionUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	newPass := r.FormValue("password")
	confirmPass := r.FormValue("confirm_password")

	if newPass != confirmPass {
		http.Redirect(w, r, "/setup?error=password_mismatch", http.StatusSeeOther)
		return
	}
	if err := s.auth.ChangePassword(username, newPass); err != nil {
		http.Redirect(w, r, "/setup?error="+err.Error(), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/setup/totp", http.StatusSeeOther)
}

func (s *Server) handleTOTPPage(w http.ResponseWriter, r *http.Request) {
	username, ok := s.auth.GetSessionUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	secret, qrBase64, err := s.auth.GenerateTOTPSecret(username)
	if err != nil {
		http.Error(w, "generate TOTP failed", http.StatusInternalServerError)
		return
	}

	// ⚠️ 安全修复：secret 存入服务端 session，不暴露给客户端（除了 QR 码）
	// 防止客户端篡改 secret 来绕过 MFA
	cookie, _ := r.Cookie(sessionCookieName)
	if cookie != nil {
		s.auth.sessions.setTOTPSecret(cookie.Value, secret)
	}

	// 只将 QR 码传给前端，secret 不再暴露
	data := map[string]string{
		"qrBase64": qrBase64,
	}
	serveHTMLWithData(w, "totp.html", data)
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	username, ok := s.auth.GetSessionUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// ⚠️ 安全修复：从服务端 session 取 secret，忽略客户端传来的 secret 字段
	// 防止攻击者伪造 secret 绑定自己的 TOTP
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	secret, ok := s.auth.sessions.popTOTPSecret(cookie.Value)
	if !ok {
		// secret 不存在或已过期（需要重新访问 /setup/totp 生成）
		http.Redirect(w, r, "/setup/totp?error=expired", http.StatusSeeOther)
		return
	}

	code := r.FormValue("code")
	if err := s.auth.ConfirmTOTP(username, secret, code); err != nil {
		http.Redirect(w, r, "/setup/totp?error=1", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/certs", http.StatusSeeOther)
}

func (s *Server) handleCertList(w http.ResponseWriter, r *http.Request) {
	serveHTML(w, "index.html")
}

func (s *Server) handleIssuePage(w http.ResponseWriter, r *http.Request) {
	serveHTML(w, "issue.html")
}

// validateCN 校验证书 CN 字段：仅允许字母、数字、连字符、下划线、点，长度 1-64
func validateCN(cn string) error {
	if len(cn) == 0 || len(cn) > 64 {
		return fmt.Errorf("CN must be 1-64 characters")
	}
	for _, c := range cn {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return fmt.Errorf("CN contains invalid character: %q", c)
		}
	}
	return nil
}

// validateSerial 校验 serial：纯十六进制字符串
func validateSerial(serial string) error {
	if len(serial) == 0 || len(serial) > 64 {
		return fmt.Errorf("invalid serial")
	}
	for _, c := range serial {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return fmt.Errorf("invalid serial format")
		}
	}
	return nil
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	cn := strings.TrimSpace(r.FormValue("cn"))
	note := strings.TrimSpace(r.FormValue("note"))

	// 输入校验
	if err := validateCN(cn); err != nil {
		http.Redirect(w, r, "/certs/issue?error=invalid_cn", http.StatusSeeOther)
		return
	}
	if len(note) > 256 {
		note = note[:256]
	}

	days := 365
	if d := r.FormValue("days"); d != "" {
		fmt.Sscanf(d, "%d", &days)
	}
	if days < 1 {
		days = 1
	}
	if days > 3650 { // 最长 10 年
		days = 3650
	}

	cert, err := s.ca.IssueCert(cn, note, days)
	if err != nil {
		s.log.Error("issue cert failed", "cn", cn, "err", err)
		// 不暴露内部错误详情
		http.Redirect(w, r, "/certs/issue?error=issue_failed", http.StatusSeeOther)
		return
	}

	// 私钥存入一次性 token store（10分钟有效，取出即删）
	token := s.keys.put(cert.KeyPEM)

	// 重定向到下载页，携带一次性 token
	http.Redirect(w, r, "/certs/download/"+cert.Serial+"?token="+token, http.StatusSeeOther)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	serial := r.FormValue("serial")
	reason := r.FormValue("reason")

	// serial 格式校验，防止注入
	if err := validateSerial(serial); err != nil {
		http.Error(w, "invalid serial", http.StatusBadRequest)
		return
	}
	if reason == "" {
		reason = "unspecified"
	}
	// reason 白名单
	validReasons := map[string]bool{
		"unspecified": true, "keyCompromise": true,
		"caCompromise": true, "affiliationChanged": true,
		"superseded": true, "cessationOfOperation": true,
	}
	if !validReasons[reason] {
		reason = "unspecified"
	}

	if err := s.ca.RevokeCert(serial, reason); err != nil {
		s.log.Error("revoke cert failed", "serial", serial, "err", err)
		http.Error(w, "revoke failed", http.StatusBadRequest) // 不暴露内部错误
		return
	}
	http.Redirect(w, r, "/certs?revoked=1", http.StatusSeeOther)
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")

	// 检查是否请求特定文件（直接下载，不需要token）
	switch r.URL.Query().Get("file") {
	case "cert":
		cert, err := s.db.GetCertBySerial(serial)
		if err != nil || cert == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="client-%s.crt"`, cert.CN))
		w.Write([]byte(cert.CertPEM))
		return
	case "ca":
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="ca.crt"`)
		w.Write(s.ca.CACertPEM())
		return
	}

	// 主下载页：服务端渲染，携带私钥（一次性 token）
	cert, err := s.db.GetCertBySerial(serial)
	if err != nil || cert == nil {
		http.NotFound(w, r)
		return
	}

	// 一次性取出私钥（取出即从内存删除）
	token := r.URL.Query().Get("token")
	keyPEM, hasKey := s.keys.pop(token)

	serveHTMLWithData(w, "download.html", map[string]any{
		"Cert":   cert,
		"KeyPEM": keyPEM,
		"HasKey": hasKey,
		"CaPEM":  string(s.ca.CACertPEM()),
	})
}

// handleDownloadZip 打包下载（POST，需要私钥——私钥在签发时一次性返回，这里无法重新获取）
// 实际上需要在签发时就提供下载，这里仅提供 cert + ca
func (s *Server) handleDownloadZip(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	cert, err := s.db.GetCertBySerial(serial)
	if err != nil || cert == nil {
		http.NotFound(w, r)
		return
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	addFile := func(name, content string) {
		f, _ := zw.Create(name)
		f.Write([]byte(content))
	}

	addFile("client.crt", cert.CertPEM)
	addFile("ca.crt", string(s.ca.CACertPEM()))
	addFile("config-template.json", clientConfigTemplate(cert.CN))
	zw.Close()

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="connect-ip-client-%s.zip"`, cert.CN))
	w.Write(buf.Bytes())
}

// ── 公开端点 ──────────────────────────────────────────────────────────────────

func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	crl, err := s.ca.GetCRL()
	if err != nil {
		http.Error(w, "generate CRL failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Cache-Control", "max-age=3600")
	w.Write(crl)
}

func (s *Server) handleCACert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(s.ca.CACertPEM())
}

// ── JSON API ──────────────────────────────────────────────────────────────────

func (s *Server) apiListCerts(w http.ResponseWriter, r *http.Request) {
	certs, err := s.db.ListCerts()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, certs)
}

type issueRequest struct {
	CN   string `json:"cn"`
	Note string `json:"note"`
	Days int    `json:"days"`
}

func (s *Server) apiIssueCert(w http.ResponseWriter, r *http.Request) {
	var req issueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := validateCN(req.CN); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Days <= 0 {
		req.Days = 365
	}
	if req.Days > 3650 {
		req.Days = 3650
	}
	if len(req.Note) > 256 {
		req.Note = req.Note[:256]
	}
	cert, err := s.ca.IssueCert(req.CN, req.Note, req.Days)
	if err != nil {
		s.log.Error("api issue cert failed", "cn", req.CN, "err", err)
		jsonError(w, "issue failed", http.StatusInternalServerError)
		return
	}
	jsonOK(w, cert)
}

type revokeRequest struct {
	Serial string `json:"serial"`
	Reason string `json:"reason"`
}

func (s *Server) apiRevokeCert(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := validateSerial(req.Serial); err != nil {
		jsonError(w, "invalid serial", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		req.Reason = "unspecified"
	}
	if err := s.ca.RevokeCert(req.Serial, req.Reason); err != nil {
		s.log.Error("api revoke cert failed", "serial", req.Serial, "err", err)
		jsonError(w, "revoke failed", http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]string{"status": "revoked"})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": v})
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": msg})
}

func clientConfigTemplate(cn string) string {
	return fmt.Sprintf(`{
  "mode": "client",
  "client": {
    "tun": { "name": "tun0", "mtu": 1420 },
    "tls": {
      "server_name":      "your-server.example.com",
      "client_cert_file": "/path/to/client.crt",
      "client_key_file":  "/path/to/client.key",
      "enable_pqc":       true
    },
    "connect_ip": {
      "addr":            "your-server.example.com:443",
      "uri":             "/.well-known/masque/ip",
      "authority":       "your-server.example.com",
      "enable_reconnect": true
    }
  }
}
/* CN: %s */`, cn)
}
