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
	username  string
	expiresAt time.Time
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

// ── Auth 核心逻辑 ────────────────────────────────────────────────────────────

type authService struct {
	db       *DB
	sessions *sessionStore
}

func newAuthService(db *DB) *authService {
	return &authService{db: db, sessions: newSessionStore()}
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
func (a *authService) Login(username, password, totpCode string) (token string, needSetup bool, err error) {
	admin, err := a.db.GetAdmin(username)
	if err != nil {
		return "", false, err
	}
	if admin == nil {
		return "", false, fmt.Errorf("invalid credentials")
	}

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(admin.PassHash), []byte(password)); err != nil {
		return "", false, fmt.Errorf("invalid credentials")
	}

	// 首次登录，跳过 TOTP，直接返回临时 session 用于初始化
	if admin.FirstLogin {
		token = a.sessions.create(username)
		return token, true, nil
	}

	// 验证 TOTP
	if !admin.TOTPEnabled {
		return "", false, fmt.Errorf("TOTP not configured")
	}
	valid, err := totp.ValidateCustom(totpCode, admin.TOTPSecret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil || !valid {
		return "", false, fmt.Errorf("invalid TOTP code")
	}

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

// SetSessionCookie 在响应中写入 session cookie
func (a *authService) SetSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
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
		MaxAge:   -1,
	})
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
