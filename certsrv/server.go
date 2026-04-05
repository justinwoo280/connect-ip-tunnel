package certsrv

import (
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

	// 审计日志轮转
	AuditLogDir     string // JSONL 导出目录，留空则只删不导出
	AuditRetainDays int    // DB 内保留天数，默认 30

	// TrustedProxy 为 true 时才信任 X-Forwarded-For / X-Real-IP 头取客户端 IP。
	// 仅在 certsrv 前有可信反向代理时开启，否则攻击者可伪造头绕过登录限速。
	TrustedProxy bool
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

	// 启动审计日志轮转后台任务（每天凌晨 2:00 UTC 执行）
	go s.auditRotateLoop()

	return s, nil
}

// auditRotateLoop 每天凌晨 2:00 UTC 执行一次审计日志轮转。
// 将超过保留期的记录导出为 JSONL 文件（若配置了 AuditLogDir）后从 DB 删除。
func (s *Server) auditRotateLoop() {
	for {
		now := time.Now().UTC()
		// 计算下一个凌晨 2:00 UTC
		next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, time.UTC)
		if !next.After(now) {
			next = next.Add(24 * time.Hour)
		}
		timer := time.NewTimer(next.Sub(now))
		<-timer.C
		timer.Stop()

		retainDays := s.cfg.AuditRetainDays
		if retainDays <= 0 {
			retainDays = 30
		}
		exported, deleted, err := s.db.RotateAuditLog(s.cfg.AuditLogDir, retainDays)
		if err != nil {
			s.log.Error("audit rotate failed", "err", err)
		} else if deleted > 0 {
			s.log.Info("audit log rotated",
				"exported", exported,
				"deleted", deleted,
				"retain_days", retainDays,
				"dir", s.cfg.AuditLogDir,
			)
		}
	}
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
	mux.HandleFunc("GET /setup", s.requireAuth(s.handleSetupPage))
	mux.HandleFunc("POST /setup", s.requireAuth(s.csrfProtect(s.handleSetup)))
	mux.HandleFunc("GET /setup/totp", s.requireAuth(s.handleTOTPPage))
	mux.HandleFunc("POST /setup/totp", s.requireAuth(s.csrfProtect(s.handleTOTPConfirm)))

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
			// 使用完整 session token 做 CSRF 比较，不截断，保持 256bit 熵
			expected := cookie.Value
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
				s.log.Warn("CSRF check failed", "ip", s.clientIP(r),
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

	ip := s.clientIP(r)

	token, needSetup, err := s.auth.Login(username, password, totpCode, ip)
	if err != nil {
		s.log.Warn("login failed", "username", username, "ip", ip, "err", err)
		s.db.InsertAuditLog("login_fail", username, ip, err.Error(), false)
		// 统一返回 error=1，不泄露具体原因（防止用户名枚举）
		http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
		return
	}

	if needSetup {
		s.db.InsertAuditLog("login_ok", username, ip, "first login, redirect to setup", true)
	} else {
		s.db.InsertAuditLog("login_ok", username, ip, "", true)
	}
	s.auth.SetSessionCookie(w, token)
	if needSetup {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/certs", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	username, _ := s.auth.GetSessionUser(r)
	ip := s.clientIP(r)
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.auth.Logout(cookie.Value)
	}
	s.db.InsertAuditLog("logout", username, ip, "", true)
	s.auth.ClearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	errMsg := ""
	switch r.URL.Query().Get("error") {
	case "password_mismatch":
		errMsg = "两次输入的密码不一致，请重试"
	case "change_failed":
		errMsg = "密码修改失败，请确保密码至少 8 位"
	}
	serveHTMLWithData(w, "setup.html", map[string]any{
		"CSRFToken": s.auth.GetCSRFToken(r),
		"Error":     errMsg,
	})
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	username, ok := s.auth.GetSessionUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	ip := s.clientIP(r)

	newPass := r.FormValue("password")
	confirmPass := r.FormValue("confirm_password")

	if newPass != confirmPass {
		s.db.InsertAuditLog("password_change", username, ip, "password mismatch", false)
		http.Redirect(w, r, "/setup?error=password_mismatch", http.StatusSeeOther)
		return
	}
	if err := s.auth.ChangePassword(username, newPass); err != nil {
		s.db.InsertAuditLog("password_change", username, ip, err.Error(), false)
		// 不将内部错误暴露到 URL，只返回通用错误码
		http.Redirect(w, r, "/setup?error=change_failed", http.StatusSeeOther)
		return
	}
	s.db.InsertAuditLog("password_change", username, ip, "", true)
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

	// 只将 QR 码和 CSRF token 传给前端，secret 不再暴露
	showError := r.URL.Query().Get("error") != ""
	serveHTMLWithData(w, "totp.html", map[string]any{
		"qrBase64":  qrBase64,
		"CSRFToken": s.auth.GetCSRFToken(r),
		"Error":     showError,
	})
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	username, ok := s.auth.GetSessionUser(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	ip := s.clientIP(r)

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
		s.db.InsertAuditLog("totp_bind", username, ip, "invalid TOTP code", false)
		http.Redirect(w, r, "/setup/totp?error=1", http.StatusSeeOther)
		return
	}
	s.db.InsertAuditLog("totp_bind", username, ip, "", true)
	http.Redirect(w, r, "/certs", http.StatusSeeOther)
}

func (s *Server) handleCertList(w http.ResponseWriter, r *http.Request) {
	serveHTMLWithData(w, "index.html", map[string]any{
		"CSRFToken": s.auth.GetCSRFToken(r),
	})
}

func (s *Server) handleIssuePage(w http.ResponseWriter, r *http.Request) {
	errMsg := ""
	switch r.URL.Query().Get("error") {
	case "invalid_cn":
		errMsg = "CN 格式不合法，仅允许字母、数字、连字符、下划线、点，长度 1-64"
	case "issue_failed":
		errMsg = "证书签发失败，请检查服务器日志"
	}
	serveHTMLWithData(w, "issue.html", map[string]any{
		"CSRFToken": s.auth.GetCSRFToken(r),
		"Error":     errMsg,
	})
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

	username, _ := s.auth.GetSessionUser(r)
	cert, err := s.ca.IssueCert(cn, note, days)
	if err != nil {
		s.log.Error("issue cert failed", "cn", cn, "err", err)
		s.db.InsertAuditLog("cert_issue", username, s.clientIP(r), "cn="+cn+" err="+err.Error(), false)
		// 不暴露内部错误详情
		http.Redirect(w, r, "/certs/issue?error=issue_failed", http.StatusSeeOther)
		return
	}
	s.db.InsertAuditLog("cert_issue", username, s.clientIP(r), "cn="+cn+" serial="+cert.Serial, true)

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

	username, _ := s.auth.GetSessionUser(r)
	if err := s.ca.RevokeCert(serial, reason); err != nil {
		s.log.Error("revoke cert failed", "serial", serial, "err", err)
		s.db.InsertAuditLog("cert_revoke", username, s.clientIP(r), "serial="+serial+" err="+err.Error(), false)
		http.Error(w, "revoke failed", http.StatusBadRequest) // 不暴露内部错误
		return
	}
	s.db.InsertAuditLog("cert_revoke", username, s.clientIP(r), "serial="+serial+" reason="+reason, true)
	http.Redirect(w, r, "/certs?revoked=1", http.StatusSeeOther)
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")

	// 格式校验，与 handleRevoke / apiRevokeCert 保持一致
	if err := validateSerial(serial); err != nil {
		http.NotFound(w, r)
		return
	}

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
	apiUser, _ := s.auth.GetSessionUser(r)
	cert, err := s.ca.IssueCert(req.CN, req.Note, req.Days)
	if err != nil {
		s.log.Error("api issue cert failed", "cn", req.CN, "err", err)
		s.db.InsertAuditLog("cert_issue", apiUser, s.clientIP(r), "api cn="+req.CN+" err="+err.Error(), false)
		jsonError(w, "issue failed", http.StatusInternalServerError)
		return
	}
	s.db.InsertAuditLog("cert_issue", apiUser, s.clientIP(r), "api cn="+req.CN+" serial="+cert.Serial, true)
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
	apiUser, _ := s.auth.GetSessionUser(r)
	if err := s.ca.RevokeCert(req.Serial, req.Reason); err != nil {
		s.log.Error("api revoke cert failed", "serial", req.Serial, "err", err)
		s.db.InsertAuditLog("cert_revoke", apiUser, s.clientIP(r), "api serial="+req.Serial+" err="+err.Error(), false)
		jsonError(w, "revoke failed", http.StatusInternalServerError)
		return
	}
	s.db.InsertAuditLog("cert_revoke", apiUser, s.clientIP(r), "api serial="+req.Serial+" reason="+req.Reason, true)
	jsonOK(w, map[string]string{"status": "revoked"})
}

// ── helpers ───────────────────────────────────────────────────────────────────

// clientIP 从请求中提取真实客户端 IP。
// 只有在 Config.TrustedProxy=true 时才信任 X-Forwarded-For / X-Real-IP，
// 否则直接使用 TCP 层的 RemoteAddr，防止攻击者伪造头绕过限速。
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustedProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}
	return r.RemoteAddr
}

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
