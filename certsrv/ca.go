package certsrv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

// CAService 负责证书签发、吊销和 CRL 生成
type CAService struct {
	mu      sync.RWMutex
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	db      *DB
	crlPEM  []byte    // 缓存的最新 CRL
	crlNext time.Time // 下次需要重新生成 CRL 的时间
}

func newCAService(caCertFile, caKeyFile string, db *DB) (*CAService, error) {
	caCert, caKey, err := loadCA(caCertFile, caKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}
	svc := &CAService{caCert: caCert, caKey: caKey, db: db}
	// 启动时生成一次 CRL
	if err := svc.refreshCRL(); err != nil {
		return nil, fmt.Errorf("initial CRL: %w", err)
	}
	return svc, nil
}

// IssueCert 签发一张新的客户端证书
// cn: Common Name（设备/用户标识）
// note: 备注（界面显示用）
// days: 有效期（天）
func (ca *CAService) IssueCert(cn, note string, days int) (*Certificate, error) {
	if cn == "" {
		return nil, fmt.Errorf("CN cannot be empty")
	}
	if days <= 0 || days > 3650 {
		return nil, fmt.Errorf("days must be between 1 and 3650")
	}

	// 生成客户端密钥对
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	// 生成序列号
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now().UTC()
	expires := now.Add(time.Duration(days) * 24 * time.Hour)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: ca.caCert.Subject.Organization,
		},
		NotBefore:             now.Add(-10 * time.Second), // 时钟偏差容忍
		NotAfter:              expires,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, &privKey.PublicKey, ca.caKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	// 编码为 PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert := &Certificate{
		Serial:    serial.Text(16), // hex 序列号
		CN:        cn,
		Note:      note,
		CertPEM:   string(certPEM),
		KeyPEM:    string(keyPEM), // 仅此次返回，不存库
		IssuedAt:  now,
		ExpiresAt: expires,
	}

	if err := ca.db.InsertCert(cert); err != nil {
		return nil, fmt.Errorf("save cert: %w", err)
	}

	return cert, nil
}

// RevokeCert 吊销证书并刷新 CRL
func (ca *CAService) RevokeCert(serial, reason string) error {
	if err := ca.db.RevokeCert(serial, reason); err != nil {
		return err
	}
	// 吊销后立即刷新 CRL
	return ca.refreshCRL()
}

// GetCRL 返回当前缓存的 CRL PEM（必要时重新生成）
func (ca *CAService) GetCRL() ([]byte, error) {
	ca.mu.RLock()
	if time.Now().Before(ca.crlNext) {
		crl := ca.crlPEM
		ca.mu.RUnlock()
		return crl, nil
	}
	ca.mu.RUnlock()

	// 过期，重新生成
	if err := ca.refreshCRL(); err != nil {
		return nil, err
	}
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.crlPEM, nil
}

// refreshCRL 重新生成 CRL 并缓存
func (ca *CAService) refreshCRL() error {
	entries, err := ca.db.ListRevokedSerials()
	if err != nil {
		return fmt.Errorf("list revoked: %w", err)
	}

	now := time.Now().UTC()
	nextUpdate := now.Add(24 * time.Hour) // CRL 有效期 24h

	revokedCerts := make([]x509.RevocationListEntry, 0, len(entries))
	for _, e := range entries {
		serialInt := new(big.Int)
		serialInt.SetString(e.Serial, 16)
		revokedCerts = append(revokedCerts, x509.RevocationListEntry{
			SerialNumber:   serialInt,
			RevocationTime: e.RevokedAt,
		})
	}

	tmpl := &x509.RevocationList{
		RevokedCertificateEntries: revokedCerts,
		ThisUpdate:                now,
		NextUpdate:                nextUpdate,
		SignatureAlgorithm:        x509.ECDSAWithSHA256,
		Number:                    big.NewInt(time.Now().Unix()), // Go 1.21+ 要求非 nil
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, tmpl, ca.caCert, ca.caKey)
	if err != nil {
		return fmt.Errorf("create CRL: %w", err)
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})

	ca.mu.Lock()
	ca.crlPEM = crlPEM
	ca.crlNext = nextUpdate.Add(-1 * time.Hour) // 提前 1h 刷新
	ca.mu.Unlock()

	return nil
}

// CACertPEM 返回 CA 证书 PEM（供客户端下载）
func (ca *CAService) CACertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.caCert.Raw,
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func loadCA(certFile, keyFile string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read key: %w", err)
	}

	// 解析证书
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("invalid CA cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}
	if !cert.IsCA {
		return nil, nil, fmt.Errorf("cert is not a CA certificate")
	}

	// 解析私钥：同时支持 PKCS#8（"PRIVATE KEY"）和 SEC1（"EC PRIVATE KEY"）两种格式
	// openssl genpkey 生成 PKCS#8，openssl ecparam+eckey 生成 SEC1
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("invalid CA key PEM")
	}
	var key *ecdsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY": // PKCS#8
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse CA key (PKCS8): %w", err)
		}
		var ok bool
		key, ok = parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("CA key is not an ECDSA key (got %T)", parsed)
		}
	case "EC PRIVATE KEY": // SEC1
		var err error
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse CA key (SEC1): %w", err)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported CA key PEM type: %s", block.Type)
	}

	return cert, key, nil
}
