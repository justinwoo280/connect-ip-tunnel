package server

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"
)

// ── 响应结构体 ────────────────────────────────────────────────────────────────

type apiSession struct {
	ID           string    `json:"id"`
	Status       string    `json:"status"`
	RemoteAddr   string    `json:"remote_addr"`
	AssignedIPv4 string    `json:"assigned_ipv4,omitempty"`
	AssignedIPv6 string    `json:"assigned_ipv6,omitempty"`
	BytesRx      uint64    `json:"bytes_rx"`
	BytesTx      uint64    `json:"bytes_tx"`
	PacketsRx    uint64    `json:"packets_rx"`
	PacketsTx    uint64    `json:"packets_tx"`
	CreatedAt    time.Time `json:"created_at"`
	UptimeSeconds float64  `json:"uptime_seconds"`
}

type apiIPPoolStats struct {
	IPv4 apiPoolFamily `json:"ipv4"`
	IPv6 apiPoolFamily `json:"ipv6"`
}

type apiPoolFamily struct {
	Allocated int `json:"allocated"`
}

type apiGlobalStats struct {
	Sessions  apiSessionStats  `json:"sessions"`
	System    apiSystemStats   `json:"system"`
	IPPool    apiIPPoolStats   `json:"ip_pool"`
	Timestamp time.Time        `json:"timestamp"`
}

type apiSessionStats struct {
	Active int `json:"active"`
}

type apiSystemStats struct {
	ActiveGoroutines int    `json:"active_goroutines"`
	MemAllocMB       uint64 `json:"mem_alloc_mb"`
	MemSysMB         uint64 `json:"mem_sys_mb"`
	NumGC            uint32 `json:"num_gc"`
}

type apiErrorResponse struct {
	Error string `json:"error"`
}

// ── 挂载路由 ─────────────────────────────────────────────────────────────────

// RegisterAPIRoutes 将所有管理 API 路由注册到 mux。
func (s *Server) RegisterAPIRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/sessions", s.handleSessions)
	mux.HandleFunc("/api/v1/sessions/", s.handleSession)
	mux.HandleFunc("/api/v1/stats", s.handleStats)
	mux.HandleFunc("/api/v1/ippool/stats", s.handleIPPoolStats)
	mux.HandleFunc("/api/v1/version", s.handleVersion)
}

// ── 处理函数 ─────────────────────────────────────────────────────────────────

// GET /api/v1/sessions
// DELETE /api/v1/sessions/{id}
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listSessions(w, r)
	default:
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		// fallback for Go < 1.22: parse from URL path
		id = r.URL.Path[len("/api/v1/sessions/"):]
	}
	if id == "" {
		apiError(w, http.StatusBadRequest, "missing session id")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.getSession(w, r, id)
	case http.MethodDelete:
		s.deleteSession(w, r, id)
	default:
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) listSessions(w http.ResponseWriter, _ *http.Request) {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	result := make([]apiSession, 0, len(s.sessions))
	for _, sess := range s.sessions {
		result = append(result, sessionToAPI(sess))
	}
	apiJSON(w, http.StatusOK, result)
}

func (s *Server) getSession(w http.ResponseWriter, _ *http.Request, id string) {
	s.sessionsMu.RLock()
	sess, ok := s.sessions[id]
	s.sessionsMu.RUnlock()

	if !ok {
		apiError(w, http.StatusNotFound, "session not found")
		return
	}
	apiJSON(w, http.StatusOK, sessionToAPI(sess))
}

func (s *Server) deleteSession(w http.ResponseWriter, _ *http.Request, id string) {
	s.sessionsMu.RLock()
	sess, ok := s.sessions[id]
	s.sessionsMu.RUnlock()

	if !ok {
		apiError(w, http.StatusNotFound, "session not found")
		return
	}
	_ = sess.Close()
	apiJSON(w, http.StatusOK, map[string]string{"status": "disconnected", "id": id})
}

// GET /api/v1/stats
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	s.sessionsMu.RLock()
	activeSessions := len(s.sessions)
	s.sessionsMu.RUnlock()

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	poolStats := IPPoolStats{}
	if s.ipPool != nil {
		poolStats = s.ipPool.Stats()
	}

	resp := apiGlobalStats{
		Sessions: apiSessionStats{
			Active: activeSessions,
		},
		System: apiSystemStats{
			ActiveGoroutines: runtime.NumGoroutine(),
			MemAllocMB:       ms.Alloc / 1024 / 1024,
			MemSysMB:         ms.Sys / 1024 / 1024,
			NumGC:            ms.NumGC,
		},
		IPPool: apiIPPoolStats{
			IPv4: apiPoolFamily{Allocated: poolStats.IPv4Allocated},
			IPv6: apiPoolFamily{Allocated: poolStats.IPv6Allocated},
		},
		Timestamp: time.Now().UTC(),
	}
	apiJSON(w, http.StatusOK, resp)
}

// GET /api/v1/ippool/stats
func (s *Server) handleIPPoolStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.ipPool == nil {
		apiError(w, http.StatusServiceUnavailable, "ip pool not initialized")
		return
	}
	stats := s.ipPool.Stats()
	apiJSON(w, http.StatusOK, stats)
}

// GET /api/v1/version
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	apiJSON(w, http.StatusOK, map[string]string{
		"version": Version,
		"go":      runtime.Version(),
	})
}

// ── 辅助函数 ─────────────────────────────────────────────────────────────────

func sessionToAPI(sess *Session) apiSession {
	rx, tx, prx, ptx := sess.Stats()
	s := apiSession{
		ID:            sess.id,
		Status:        "active",
		RemoteAddr:    sess.remoteAddr,
		BytesRx:       rx,
		BytesTx:       tx,
		PacketsRx:     prx,
		PacketsTx:     ptx,
		CreatedAt:     sess.createdAt,
		UptimeSeconds: time.Since(sess.createdAt).Seconds(),
	}
	if sess.assignedIPv4.IsValid() {
		s.AssignedIPv4 = sess.assignedIPv4.String()
	}
	if sess.assignedIPv6.IsValid() {
		s.AssignedIPv6 = sess.assignedIPv6.String()
	}
	return s
}

func apiJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, code int, msg string) {
	apiJSON(w, code, apiErrorResponse{Error: msg})
}
