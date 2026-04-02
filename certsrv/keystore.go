package certsrv

import (
	"sync"
	"time"
)

const keyTTL = 10 * time.Minute

// keyStore 是一个内存中的一次性私钥存储器。
// 私钥在签发时存入，下载页取出后立即删除（一次性）。
// 未被取出的私钥在 TTL 到期后自动清除。
type keyStore struct {
	mu   sync.Mutex
	data map[string]keyEntry
}

type keyEntry struct {
	keyPEM    string
	expiresAt time.Time
}

func newKeyStore() *keyStore {
	ks := &keyStore{data: make(map[string]keyEntry)}
	go ks.gc()
	return ks
}

// put 存入私钥，返回一次性 token
func (ks *keyStore) put(keyPEM string) string {
	token := randHex(32)
	ks.mu.Lock()
	ks.data[token] = keyEntry{
		keyPEM:    keyPEM,
		expiresAt: time.Now().Add(keyTTL),
	}
	ks.mu.Unlock()
	return token
}

// pop 取出私钥并立即删除（一次性）
// 返回 (keyPEM, true) 若 token 有效且未过期
// 返回 ("", false) 若 token 不存在或已过期
func (ks *keyStore) pop(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()

	entry, ok := ks.data[token]
	delete(ks.data, token) // 无论是否有效，取出即删
	if !ok || time.Now().After(entry.expiresAt) {
		return "", false
	}
	return entry.keyPEM, true
}

// gc 后台定期清理过期的 token
func (ks *keyStore) gc() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		ks.mu.Lock()
		for k, v := range ks.data {
			if now.After(v.expiresAt) {
				delete(ks.data, k)
			}
		}
		ks.mu.Unlock()
	}
}
