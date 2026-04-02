package certsrv

import (
	"database/sql"
	"fmt"
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

func (db *DB) Close() error {
	return db.conn.Close()
}
