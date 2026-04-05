package certsrv

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// DB 封装 SQLite 连接
type DB struct {
	conn *sql.DB
}

// Certificate 代表一张已签发的客户端证书
type Certificate struct {
	ID           int64
	Serial       string
	CN           string
	Note         string
	CertPEM      string
	KeyPEM       string // 仅签发时返回，不持久化存储私钥
	IssuedAt     time.Time
	ExpiresAt    time.Time
	Revoked      bool
	RevokedAt    *time.Time
	RevokeReason string
}

// Admin 代表管理员账号
type Admin struct {
	ID          int64
	Username    string
	PassHash    string
	TOTPSecret  string
	TOTPEnabled bool
	FirstLogin  bool
}

// openDB 打开（或创建）SQLite 数据库并建表
func openDB(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	conn.SetMaxOpenConns(1) // SQLite 不支持并发写
	if err := migrate(conn); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &DB{conn: conn}, nil
}

func migrate(conn *sql.DB) error {
	_, err := conn.Exec(`
	PRAGMA journal_mode=WAL;
	PRAGMA foreign_keys=ON;

	CREATE TABLE IF NOT EXISTS admin (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		username     TEXT NOT NULL UNIQUE,
		pass_hash    TEXT NOT NULL,
		totp_secret  TEXT NOT NULL DEFAULT '',
		totp_enabled INTEGER NOT NULL DEFAULT 0,
		first_login  INTEGER NOT NULL DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS certificates (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		serial        TEXT NOT NULL UNIQUE,
		cn            TEXT NOT NULL,
		note          TEXT NOT NULL DEFAULT '',
		cert_pem      TEXT NOT NULL,
		issued_at     DATETIME NOT NULL,
		expires_at    DATETIME NOT NULL,
		revoked       INTEGER NOT NULL DEFAULT 0,
		revoked_at    DATETIME,
		revoke_reason TEXT NOT NULL DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_certs_serial  ON certificates(serial);
	CREATE INDEX IF NOT EXISTS idx_certs_revoked ON certificates(revoked);

	CREATE TABLE IF NOT EXISTS audit_log (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		ts         DATETIME NOT NULL,
		action     TEXT NOT NULL,
		username   TEXT NOT NULL DEFAULT '',
		ip         TEXT NOT NULL DEFAULT '',
		detail     TEXT NOT NULL DEFAULT '',
		ok         INTEGER NOT NULL DEFAULT 1
	);

	CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log(ts);
	CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
	`)
	return err
}

// ── Admin ────────────────────────────────────────────────────────────────────

func (db *DB) GetAdmin(username string) (*Admin, error) {
	row := db.conn.QueryRow(
		`SELECT id, username, pass_hash, totp_secret, totp_enabled, first_login
		 FROM admin WHERE username = ?`, username)
	var a Admin
	var totpEnabled, firstLogin int
	err := row.Scan(&a.ID, &a.Username, &a.PassHash, &a.TOTPSecret, &totpEnabled, &firstLogin)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.TOTPEnabled = totpEnabled == 1
	a.FirstLogin = firstLogin == 1
	return &a, nil
}

func (db *DB) CreateDefaultAdmin(passHash string) error {
	_, err := db.conn.Exec(
		`INSERT OR IGNORE INTO admin (username, pass_hash, first_login)
		 VALUES ('admin', ?, 1)`, passHash)
	return err
}

func (db *DB) UpdateAdminPassword(username, passHash string) error {
	_, err := db.conn.Exec(
		`UPDATE admin SET pass_hash = ? WHERE username = ?`, passHash, username)
	return err
}

func (db *DB) UpdateAdminTOTP(username, secret string) error {
	_, err := db.conn.Exec(
		`UPDATE admin SET totp_secret = ?, totp_enabled = 1, first_login = 0
		 WHERE username = ?`, secret, username)
	return err
}

// ResetAdminAuth 重置管理员密码并清除 2FA，将账号恢复到"首次登录"状态。
// 登录后会强制走 /setup 流程重新设置密码和绑定 2FA。
// 证书表完全不受影响。
func (db *DB) ResetAdminAuth(username, passHash string) error {
	res, err := db.conn.Exec(
		`UPDATE admin
		 SET pass_hash    = ?,
		     totp_secret  = '',
		     totp_enabled = 0,
		     first_login  = 1
		 WHERE username = ?`, passHash, username)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("admin %q not found", username)
	}
	return nil
}

// ── Certificates ─────────────────────────────────────────────────────────────

func (db *DB) InsertCert(c *Certificate) error {
	_, err := db.conn.Exec(
		`INSERT INTO certificates (serial, cn, note, cert_pem, issued_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		c.Serial, c.CN, c.Note, c.CertPEM,
		c.IssuedAt.UTC().Format(time.RFC3339),
		c.ExpiresAt.UTC().Format(time.RFC3339),
	)
	return err
}

func (db *DB) ListCerts() ([]*Certificate, error) {
	rows, err := db.conn.Query(
		`SELECT id, serial, cn, note, cert_pem, issued_at, expires_at,
		        revoked, revoked_at, revoke_reason
		 FROM certificates ORDER BY issued_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []*Certificate
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, rows.Err()
}

func (db *DB) GetCertBySerial(serial string) (*Certificate, error) {
	row := db.conn.QueryRow(
		`SELECT id, serial, cn, note, cert_pem, issued_at, expires_at,
		        revoked, revoked_at, revoke_reason
		 FROM certificates WHERE serial = ?`, serial)
	c, err := scanCert(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

func (db *DB) RevokeCert(serial, reason string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := db.conn.Exec(
		`UPDATE certificates SET revoked=1, revoked_at=?, revoke_reason=?
		 WHERE serial=? AND revoked=0`, now, reason, serial)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("cert not found or already revoked: %s", serial)
	}
	return nil
}

// ListRevokedSerials 返回所有已吊销证书的序列号和吊销时间（用于生成 CRL）
func (db *DB) ListRevokedSerials() ([]revokedEntry, error) {
	rows, err := db.conn.Query(
		`SELECT serial, revoked_at FROM certificates WHERE revoked=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []revokedEntry
	for rows.Next() {
		var e revokedEntry
		var revokedAt string
		if err := rows.Scan(&e.Serial, &revokedAt); err != nil {
			return nil, err
		}
		e.RevokedAt, _ = time.Parse(time.RFC3339, revokedAt)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

type revokedEntry struct {
	Serial    string
	RevokedAt time.Time
}

// ── helpers ───────────────────────────────────────────────────────────────────

type scanner interface {
	Scan(dest ...any) error
}

func scanCert(s scanner) (*Certificate, error) {
	var c Certificate
	var issuedAt, expiresAt string
	var revoked int
	var revokedAt sql.NullString

	err := s.Scan(
		&c.ID, &c.Serial, &c.CN, &c.Note, &c.CertPEM,
		&issuedAt, &expiresAt,
		&revoked, &revokedAt, &c.RevokeReason,
	)
	if err != nil {
		return nil, err
	}
	c.Revoked = revoked == 1
	c.IssuedAt, _ = time.Parse(time.RFC3339, issuedAt)
	c.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	if revokedAt.Valid {
		t, _ := time.Parse(time.RFC3339, revokedAt.String)
		c.RevokedAt = &t
	}
	return &c, nil
}

// ── Audit Log ─────────────────────────────────────────────────────────────────

// AuditEntry 代表一条审计记录
type AuditEntry struct {
	ID       int64
	TS       time.Time
	Action   string
	Username string
	IP       string
	Detail   string
	OK       bool
}

// InsertAuditLog 写入一条审计记录（fire-and-forget，失败只打印不影响主流程）
func (db *DB) InsertAuditLog(action, username, ip, detail string, ok bool) {
	okInt := 1
	if !ok {
		okInt = 0
	}
	db.conn.Exec(
		`INSERT INTO audit_log (ts, action, username, ip, detail, ok)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339), action, username, ip, detail, okInt,
	)
}

// ListAuditLog 返回最近 limit 条审计记录（按时间倒序）
func (db *DB) ListAuditLog(limit int) ([]*AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := db.conn.Query(
		`SELECT id, ts, action, username, ip, detail, ok
		 FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts string
		var okInt int
		if err := rows.Scan(&e.ID, &ts, &e.Action, &e.Username, &e.IP, &e.Detail, &okInt); err != nil {
			return nil, err
		}
		e.TS, _ = time.Parse(time.RFC3339, ts)
		e.OK = okInt == 1
		entries = append(entries, &e)
	}
	return entries, rows.Err()
}

// RotateAuditLog 将超过 retainDays 天的审计记录导出到 JSONL 文件后从 DB 删除。
// 导出文件路径：<dir>/audit-<YYYY-MM-DD>.jsonl（按执行日期命名，追加写入）。
// retainDays <= 0 时使用默认值 30。
// 返回导出条数和删除条数。
func (db *DB) RotateAuditLog(dir string, retainDays int) (exported, deleted int, err error) {
	if retainDays <= 0 {
		retainDays = 30
	}
	cutoff := time.Now().UTC().Add(-time.Duration(retainDays) * 24 * time.Hour).Format(time.RFC3339)

	// 查出需要清理的记录
	rows, err := db.conn.Query(
		`SELECT id, ts, action, username, ip, detail, ok
		 FROM audit_log WHERE ts < ? ORDER BY id ASC`, cutoff)
	if err != nil {
		return 0, 0, fmt.Errorf("query expired audit: %w", err)
	}
	defer rows.Close()

	var toDelete []int64
	var buf []byte

	for rows.Next() {
		var e AuditEntry
		var ts string
		var okInt int
		if err := rows.Scan(&e.ID, &ts, &e.Action, &e.Username, &e.IP, &e.Detail, &okInt); err != nil {
			return 0, 0, fmt.Errorf("scan audit row: %w", err)
		}
		e.TS, _ = time.Parse(time.RFC3339, ts)
		e.OK = okInt == 1
		toDelete = append(toDelete, e.ID)

		// 序列化为 JSON 行
		line, err := json.Marshal(map[string]any{
			"id":       e.ID,
			"ts":       e.TS.Format(time.RFC3339),
			"action":   e.Action,
			"username": e.Username,
			"ip":       e.IP,
			"detail":   e.Detail,
			"ok":       e.OK,
		})
		if err != nil {
			return 0, 0, fmt.Errorf("marshal audit entry: %w", err)
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	if err := rows.Err(); err != nil {
		return 0, 0, fmt.Errorf("iterate audit rows: %w", err)
	}
	if len(toDelete) == 0 {
		return 0, 0, nil // 没有过期记录
	}

	// 追加写入 JSONL 文件（dir 为空则跳过导出）
	if dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return 0, 0, fmt.Errorf("create audit log dir: %w", err)
		}
		filename := fmt.Sprintf("%s/audit-%s.jsonl", dir, time.Now().UTC().Format("2006-01-02"))
		f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return 0, 0, fmt.Errorf("open audit export file: %w", err)
		}
		if _, err := f.Write(buf); err != nil {
			f.Close()
			return 0, 0, fmt.Errorf("write audit export: %w", err)
		}
		f.Close()
		exported = len(toDelete)
	}

	// 批量删除（SQLite 单写串行，分批避免长锁）
	const batchSize = 200
	for i := 0; i < len(toDelete); i += batchSize {
		end := i + batchSize
		if end > len(toDelete) {
			end = len(toDelete)
		}
		batch := toDelete[i:end]
		// 构造 IN (?,?,?...) 占位符
		placeholders := make([]string, len(batch))
		args := make([]any, len(batch))
		for j, id := range batch {
			placeholders[j] = "?"
			args[j] = id
		}
		query := "DELETE FROM audit_log WHERE id IN (" + strings.Join(placeholders, ",") + ")"
		if _, err := db.conn.Exec(query, args...); err != nil {
			return exported, deleted, fmt.Errorf("delete audit batch: %w", err)
		}
		deleted += len(batch)
	}

	return exported, deleted, nil
}

func (db *DB) Close() error {
	return db.conn.Close()
}
