package certsrv

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"image/png"
	"net/http"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookieName = "certsrv_session"
	sessionTTL        = 24 * time.Hour
	bcryptCost        = 12
)

// ── Session Store（内存）────────────────────────────────────────────────────

type session struct {
	username    string
	expiresAt   time.Time
	totpSecret  string // 临时存储待确认的 TOTP secret，确认后清除
}

type sessionStore struct {
	mu   sync.RWMutex
	data map[string]*session
}

func newSessionStore() *sessionStore {
	s := &sessionStore{data: make(map[string]*session)}
	go s.gc() // 后台清理过期 session
	return s
}

func (s *sessionStore) create(username string) string {
	token := randHex(32)
	s.mu.Lock()
	s.data[token] = &session{username: username, expiresAt: time.Now().Add(sessionTTL)}
	s.mu.Unlock()
	return token
}

func (s *sessionStore) get(token string) (*session, bool) {
	s.mu.RLock()
	sess, ok := s.data[token]
	s.mu.RUnlock()
	if !ok || time.Now().After(sess.expiresAt) {
		return nil, false
	}
	return sess, true
}

func (s *sessionStore) delete(token string) {
	s.mu.Lock()
	delete(s.data, token)
	s.mu.Unlock()
}

// setTOTPSecret 将待确认的 TOTP secret 存入 session（服务端保存，不信任客户端）
func (s *sessionStore) setTOTPSecret(token, secret string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.data[token]
	if !ok || time.Now().After(sess.expiresAt) {
		return false
	}
	sess.totpSecret = secret
	return true
}

// popTOTPSecret 取出并清除 session 中的待确认 TOTP secret（一次性）
func (s *sessionStore) popTOTPSecret(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.data[token]
	if !ok || time.Now().After(sess.expiresAt) || sess.totpSecret == "" {
		return "", false
	}
	secret := sess.totpSecret
	sess.totpSecret = "" // 清除，防止重放
	return secret, true
}

func (s *sessionStore) gc() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for k, v := range s.data {
			if now.After(v.expiresAt) {
				delete(s.data, k)
			}
		}
		s.mu.Unlock()
	}
}

// ── Rate Limiter（登录暴力破解防护）─────────────────────────────────────────

const (
	maxLoginAttempts = 10              // 每个 IP 最大失败次数
	loginLockout     = 15 * time.Minute // 锁定时间
)

type loginAttempt struct {
	count     int
	lockedAt  time.Time
	firstFail time.Time
}

type rateLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttempt
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{attempts: make(map[string]*loginAttempt)}
	go rl.gc()
	return rl
}

// Allow 检查 IP 是否允许登录，返回 false 表示被限速
func (rl *rateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	a, ok := rl.attempts[ip]
	if !ok {
		return true
	}
	if !a.lockedAt.IsZero() {
		// 锁定中：检查是否已过锁定期
		if time.Since(a.lockedAt) > loginLockout {
			delete(rl.attempts, ip)
			return true
		}
		return false
	}
	return true
}

// RecordFailure 记录登录失败
func (rl *rateLimiter) RecordFailure(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	a, ok := rl.attempts[ip]
	if !ok {
		a = &loginAttempt{firstFail: time.Now()}
		rl.attempts[ip] = a
	}
	a.count++
	if a.count >= maxLoginAttempts {
		a.lockedAt = time.Now()
	}
}

// RecordSuccess 登录成功，清除计数
func (rl *rateLimiter) RecordSuccess(ip string) {
	rl.mu.Lock()
	delete(rl.attempts, ip)
	rl.mu.Unlock()
}

func (rl *rateLimiter) gc() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		for ip, a := range rl.attempts {
			if !a.lockedAt.IsZero() && time.Since(a.lockedAt) > loginLockout {
				delete(rl.attempts, ip)
			} else if a.lockedAt.IsZero() && time.Since(a.firstFail) > loginLockout {
				delete(rl.attempts, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// ── Auth 核心逻辑 ────────────────────────────────────────────────────────────

type authService struct {
	db       *DB
	sessions *sessionStore
	limiter  *rateLimiter
}

func newAuthService(db *DB) *authService {
	return &authService{db: db, sessions: newSessionStore(), limiter: newRateLimiter()}
}

// EnsureDefaultAdmin 确保数据库里有默认 admin 账号
func (a *authService) EnsureDefaultAdmin() error {
	admin, err := a.db.GetAdmin("admin")
	if err != nil {
		return err
	}
	if admin != nil {
		return nil // 已存在
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcryptCost)
	if err != nil {
		return err
	}
	return a.db.CreateDefaultAdmin(string(hash))
}

// Login 验证用户名+密码+TOTP，返回 session token
// 返回 needSetup=true 表示需要首次初始化
// ip 用于速率限制（传 r.RemoteAddr 或 X-Real-IP）
func (a *authService) Login(username, password, totpCode, ip string) (token string, needSetup bool, err error) {
	// 速率限制检查
	if !a.limiter.Allow(ip) {
		return "", false, fmt.Errorf("too many login attempts, please try again later")
	}

	admin, err := a.db.GetAdmin(username)
	if err != nil {
		return "", false, err
	}
	if admin == nil {
		a.limiter.RecordFailure(ip)
		return "", false, fmt.Errorf("invalid credentials")
	}

	// 验证密码（恒定时间比较，防止时序攻击）
	if err := bcrypt.CompareHashAndPassword([]byte(admin.PassHash), []byte(password)); err != nil {
		a.limiter.RecordFailure(ip)
		return "", false, fmt.Errorf("invalid credentials")
	}

	// 首次登录，跳过 TOTP，直接返回临时 session 用于初始化
	if admin.FirstLogin {
		a.limiter.RecordSuccess(ip)
		token = a.sessions.create(username)
		return token, true, nil
	}

	// 验证 TOTP
	if !admin.TOTPEnabled {
		a.limiter.RecordFailure(ip)
		return "", false, fmt.Errorf("TOTP not configured")
	}
	valid, err := totp.ValidateCustom(totpCode, admin.TOTPSecret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil || !valid {
		a.limiter.RecordFailure(ip)
		return "", false, fmt.Errorf("invalid TOTP code")
	}

	a.limiter.RecordSuccess(ip)
	token = a.sessions.create(username)
	return token, false, nil
}

// Logout 注销 session
func (a *authService) Logout(token string) {
	a.sessions.delete(token)
}

// GetSessionUser 从请求中获取已登录用户名
func (a *authService) GetSessionUser(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", false
	}
	sess, ok := a.sessions.get(cookie.Value)
	if !ok {
		return "", false
	}
	return sess.username, true
}

// GetCSRFToken 从请求的 session 中派生 CSRF token。
// CSRF token = session token 本身（只有同源页面才能读到服务端注入到 HTML 里的值）。
// 调用方应将其注入到 HTML 表单隐藏字段，而不是让 JS 读 HttpOnly cookie。
func (a *authService) GetCSRFToken(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// SetSessionCookie 在响应中写入 session cookie
func (a *authService) SetSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true, // 仅通过 HTTPS 传输，防止明文泄露
		SameSite: http.SameSiteStrictMode, // Strict 比 Lax 更安全，防 CSRF
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

// ClearSessionCookie 清除 session cookie
func (a *authService) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
	})
}

// ResetAdmin 重置指定管理员的密码并清除 2FA 绑定，使其回到首次登录状态。
// 此操作只修改 admin 表，不触碰 certificates 表，证书状态完全不受影响。
// newPassword 为空时自动生成一个随机强密码并返回。
func ResetAdmin(dbPath, username, newPassword string) (finalPassword string, err error) {
	db, err := openDB(dbPath)
	if err != nil {
		return "", fmt.Errorf("open db: %w", err)
	}
	defer db.Close()

	// 确认账号存在
	admin, err := db.GetAdmin(username)
	if err != nil {
		db.InsertAuditLog("admin_reset", username, "cli", "query failed: "+err.Error(), false)
		return "", fmt.Errorf("query admin: %w", err)
	}
	if admin == nil {
		db.InsertAuditLog("admin_reset", username, "cli", "user not found", false)
		return "", fmt.Errorf("admin %q not found in database", username)
	}

	// 未提供密码时随机生成
	if newPassword == "" {
		newPassword = randHex(10) // 20 个十六进制字符，足够强
	}
	if len(newPassword) < 8 {
		db.InsertAuditLog("admin_reset", username, "cli", "password too short", false)
		return "", fmt.Errorf("password must be at least 8 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}

	if err := db.ResetAdminAuth(username, string(hash)); err != nil {
		db.InsertAuditLog("admin_reset", username, "cli", "db update failed: "+err.Error(), false)
		return "", fmt.Errorf("reset admin: %w", err)
	}

	// 成功：写审计记录（不记录密码本身）
	db.InsertAuditLog("admin_reset", username, "cli", "password and 2FA reset via CLI", true)

	return newPassword, nil
}

// ChangePassword 修改密码
func (a *authService) ChangePassword(username, newPassword string) error {
	if len(newPassword) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcryptCost)
	if err != nil {
		return err
	}
	return a.db.UpdateAdminPassword(username, string(hash))
}

// GenerateTOTPSecret 生成新的 TOTP 密钥，返回 secret 和 QR 码 PNG（base64）
func (a *authService) GenerateTOTPSecret(username string) (secret, qrBase64 string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "connect-ip-tunnel",
		AccountName: username,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", "", fmt.Errorf("generate totp: %w", err)
	}

	// 生成 QR 码图片
	img, err := key.Image(256, 256)
	if err != nil {
		return "", "", fmt.Errorf("generate qr image: %w", err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", "", fmt.Errorf("encode qr png: %w", err)
	}
	qrBase64 = base64.StdEncoding.EncodeToString(buf.Bytes())
	return key.Secret(), qrBase64, nil
}

// ConfirmTOTP 验证用户输入的 TOTP 码并持久化 secret
func (a *authService) ConfirmTOTP(username, secret, code string) error {
	valid, err := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil || !valid {
		return fmt.Errorf("invalid TOTP code")
	}
	return a.db.UpdateAdminTOTP(username, secret)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
