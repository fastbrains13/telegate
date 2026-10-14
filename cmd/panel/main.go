package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fastbrains13/telegate/internal/auth"
	"github.com/fastbrains13/telegate/internal/generator"
	"github.com/fastbrains13/telegate/internal/state"
)

//go:embed all:ui
var uiFS embed.FS

// ============================================================
//  Models
// ============================================================

type ClientSession struct {
	IP        string `json:"ip"`
	Country   string `json:"country"`
	ISP       string `json:"isp"`
	Protocol  string `json:"protocol"`
	Outbound  string `json:"outbound"`
	BytesSent int64  `json:"bytes_sent"`
}

type WebProxyConfig struct {
	Enabled      bool   `json:"enabled"`
	HostMode     string `json:"host_mode"`
	CustomDomain string `json:"custom_domain"`
	Port         int    `json:"port"`
	Secret       string `json:"secret"`
	WSPath       string `json:"ws_path"`
	FallbackURL  string `json:"fallback_url"`
	MaxClients   int    `json:"max_clients"`
	UpstreamType string `json:"upstream_type"`
	VlessURL     string `json:"vless_url"`
}

type MTProtoConfig struct {
	Enabled       bool   `json:"enabled"`
	HostMode      string `json:"host_mode"`
	CustomDomain  string `json:"custom_domain"`
	Port          int    `json:"port"`
	Secret        string `json:"secret"`
	FakeTLSDomain string `json:"fake_tls_domain"`
	AdTag         string `json:"ad_tag"`
	MaxClients    int    `json:"max_clients"`
	UpstreamType  string `json:"upstream_type"`
	VlessURL      string `json:"vless_url"`
}

type NodeStatus struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	IP          string          `json:"ip"`
	Token       string          `json:"token"`
	LastSeen    time.Time       `json:"last_seen"`
	IsOnline    bool            `json:"is_online"`
	ActiveConns []ClientSession `json:"active_conns"`
	UptimeSec   int64           `json:"uptime_sec"`
	WebProxy    WebProxyConfig  `json:"web_proxy"`
	MTProto     MTProtoConfig   `json:"mtproto"`
}

type GlobalState struct {
	mu                 sync.RWMutex           `json:"-"`
	AdminUser          string                 `json:"admin_user"`
	AdminPasswordHash  string                 `json:"admin_password_hash"`
	BlacklistCIDR      []string               `json:"blacklist_cidr"`
	BlacklistCountries []string               `json:"blacklist_countries"`
	Nodes              map[string]*NodeStatus `json:"nodes"`
}

// ============================================================
//  Config & App
// ============================================================

type Config struct {
	ListenAddr string
	StateFile  string
	AdminUser  string
	AdminPass  string
	AgentTTL   time.Duration
	LogLevel   string
}

func loadConfig() Config {
	get := func(key, def string) string {
		if v := os.Getenv("TELEGATE_" + key); v != "" {
			return v
		}
		return def
	}
	return Config{
		ListenAddr: get("LISTEN_ADDR", ":8080"),
		StateFile:  get("STATE_FILE", "/data/telegate_state.json"),
		AdminUser:  get("ADMIN_USER", "admin"),
		AdminPass:  get("ADMIN_PASS", "admin"),
		AgentTTL:   24 * time.Hour,
		LogLevel:   get("LOG_LEVEL", "info"),
	}
}

type App struct {
	state *GlobalState
	store *state.Store
	auth  *auth.Manager
	mux   *http.ServeMux
	cfg   Config
}

// setupLogging настраивает структурированное логирование slog.
func setupLogging(level string) {
	lv := new(slog.LevelVar)
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		lv.Set(slog.LevelInfo)
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv})
	slog.SetDefault(slog.New(handler))
}

func NewApp(cfg Config) *App {
	setupLogging(cfg.LogLevel)

	s := &GlobalState{
		AdminUser:          cfg.AdminUser,
		BlacklistCIDR:      []string{"185.220.101.0/24"},
		BlacklistCountries: []string{"CN", "IR"},
		Nodes:              make(map[string]*NodeStatus),
	}

	st := state.New(cfg.StateFile)
	if err := st.Load(); err != nil {
		slog.Warn("Не удалось загрузить state, создаётся новый", "err", err)
	} else {
		raw := st.GetRaw()
		if len(raw) > 0 {
			s.mu.Lock()
			_ = json.Unmarshal(raw, s)
			s.mu.Unlock()
		}
	}

	// Migrate plaintext password to hash on first run
	if s.AdminPasswordHash == "" {
		hash, err := auth.HashPassword(cfg.AdminPass)
		if err != nil {
			slog.Error("bcrypt hash", "err", err)
		} else {
			s.AdminPasswordHash = hash
		}
	}

	a := &App{
		state: s,
		store: st,
		auth:  auth.New(5, 900), // 5 attempts / 15 min
		mux:   http.NewServeMux(),
		cfg:   cfg,
	}

	return a
}

// GetRaw returns marshalled state for the store.
func (a *App) getRawState() ([]byte, error) {
	a.state.mu.RLock()
	defer a.state.mu.RUnlock()
	return json.MarshalIndent(a.state, "", "  ")
}

// saveState атомарно сохраняет.
func (a *App) saveState() error {
	data, err := a.getRawState()
	if err != nil {
		return err
	}
	return a.store.AtomicSave(data)
}

// ============================================================
//  Helpers
// ============================================================

func genHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func defaultWebConfig() WebProxyConfig {
	return WebProxyConfig{
		Enabled:      true,
		HostMode:     "ip",
		Port:         443,
		Secret:       genHex(16),
		WSPath:       "/",
		FallbackURL:  "https://ya.ru",
		MaxClients:   0,
		UpstreamType: "direct",
	}
}

func defaultMTProtoConfig() MTProtoConfig {
	domainHex := hex.EncodeToString([]byte("yandex.ru"))
	return MTProtoConfig{
		Enabled:       true,
		HostMode:      "ip",
		Port:          8443,
		Secret:        "ee" + genHex(16) + domainHex,
		FakeTLSDomain: "yandex.ru",
		MaxClients:    0,
		UpstreamType:  "direct",
	}
}

// ============================================================
//  Middleware
// ============================================================

// authMiddleware — проверяет сессию. Для POST/PUT/DELETE также проверяет CSRF.
func (a *App) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("telegate_session")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ok, _ := a.auth.ValidateSession(cookie.Value)
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// CSRF для мутающих методов
		if r.Method != "GET" && r.Method != "HEAD" {
			if !a.checkCSRF(r) {
				http.Error(w, "CSRF token mismatch", http.StatusForbidden)
				return
			}
		}

		next(w, r)
	}
}

// checkCSRF проверяет X-CSRF-Token header против cookie.
func (a *App) checkCSRF(r *http.Request) bool {
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		return false
	}
	cookie, err := r.Cookie("telegate_csrf")
	if err != nil {
		return false
	}
	return token == cookie.Value
}

// agentTokenMiddleware проверяет токен агента.
func (a *App) agentTokenMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer == r.Header.Get("Authorization") {
			bearer = ""
		}

		nodeID := r.URL.Query().Get("node_id")
		a.state.mu.RLock()
		node, exists := a.state.Nodes[nodeID]
		valid := exists && node.Token == bearer
		a.state.mu.RUnlock()

		if !valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ============================================================
//  SSE Event Broker (push-уведомления агентам)
// ============================================================

type eventBroker struct {
	mu   sync.Mutex
	subs map[string][]chan struct{}
}

func newEventBroker() *eventBroker {
	return &eventBroker{subs: make(map[string][]chan struct{})}
}

func (eb *eventBroker) subscribe(nodeID string) chan struct{} {
	eb.mu.Lock()
	ch := make(chan struct{}, 1)
	eb.subs[nodeID] = append(eb.subs[nodeID], ch)
	eb.mu.Unlock()
	return ch
}

func (eb *eventBroker) unsubscribe(nodeID string, ch chan struct{}) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	subs := eb.subs[nodeID]
	for i, c := range subs {
		if c == ch {
			eb.subs[nodeID] = append(subs[:i], subs[i+1:]...)
			close(ch)
			return
		}
	}
}

func (eb *eventBroker) publish(nodeID string) {
	eb.mu.Lock()
	for _, ch := range eb.subs[nodeID] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	eb.mu.Unlock()
}

var broker = newEventBroker()

// ============================================================
//  Handlers
// ============================================================

func (a *App) setupRoutes() {
	// --- Public ---
	a.mux.HandleFunc("POST /api/auth/login", a.handleLogin)
	a.mux.HandleFunc("POST /api/auth/logout", a.handleLogout)
	a.mux.HandleFunc("GET /api/auth/me", a.handleAuthMe)
	a.mux.HandleFunc("GET /api/health", a.handleHealth)
	a.mux.HandleFunc("GET /metrics", a.handleMetrics)
	a.mux.HandleFunc("GET /bootstrap", a.handleBootstrap)
	a.mux.HandleFunc("GET /agent-bin", a.handleAgentBin)

	// --- Auth required ---
	a.mux.HandleFunc("GET /api/state", a.authMiddleware(a.handleState))
	a.mux.HandleFunc("POST /api/nodes/create", a.authMiddleware(a.handleNodeCreate))
	a.mux.HandleFunc("DELETE /api/nodes/delete", a.authMiddleware(a.handleNodeDelete))
	a.mux.HandleFunc("POST /api/nodes/save-proxy", a.authMiddleware(a.handleNodeSaveProxy))
	a.mux.HandleFunc("POST /api/blacklist/ip", a.authMiddleware(a.handleBlacklistIP))
	a.mux.HandleFunc("DELETE /api/blacklist/ip", a.authMiddleware(a.handleBlacklistIP))
	a.mux.HandleFunc("POST /api/blacklist/country", a.authMiddleware(a.handleBlacklistCountry))
	a.mux.HandleFunc("DELETE /api/blacklist/country", a.authMiddleware(a.handleBlacklistCountry))

	// --- Agent ---
	a.mux.HandleFunc("POST /api/agent/heartbeat", a.agentTokenMiddleware(a.handleAgentHeartbeat))
	a.mux.HandleFunc("GET /api/agent/config", a.agentTokenMiddleware(a.handleAgentConfig))
	a.mux.HandleFunc("GET /api/agent/events", a.handleAgentEvents)
}

// GET /api/health
func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// GET /metrics
func (a *App) handleMetrics(w http.ResponseWriter, r *http.Request) {
	a.state.mu.RLock()
	total := len(a.state.Nodes)
	online := 0
	for _, node := range a.state.Nodes {
		if node.IsOnline {
			online++
		}
	}
	a.state.mu.RUnlock()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP telegate_nodes_total\n# TYPE telegate_nodes_total gauge\ntelelate_nodes_total %d\n", total)
	fmt.Fprintf(w, "# HELP telegate_nodes_online\n# TYPE telegate_nodes_online gauge\ntelelate_nodes_online %d\n", online)
}

// POST /api/auth/login
func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !a.auth.AllowLogin() {
		http.Error(w, "Слишком много попыток. Подождите", http.StatusTooManyRequests)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	a.state.mu.RLock()
	validUser := creds.Username == a.state.AdminUser
	validHash := auth.CheckPasswordHash(creds.Password, a.state.AdminPasswordHash)
	a.state.mu.RUnlock()

	if !validUser || !validHash {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Неверный логин или пароль"})
		return
	}

	token, _ := a.auth.CreateSession(a.cfg.AgentTTL)
	csrftoken := genHex(16)

	// Session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "telegate_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(a.cfg.AgentTTL),
	})

	// CSRF cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "telegate_csrf",
		Value:    csrftoken,
		Path:     "/",
		HttpOnly: false,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(a.cfg.AgentTTL),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "csrf_token": csrftoken})
}

// POST /api/auth/logout
func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("telegate_session"); err == nil {
		a.auth.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "telegate_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
	})
	http.SetCookie(w, &http.Cookie{
		Name:   "telegate_csrf",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
		Secure: r.TLS != nil,
	})
	w.WriteHeader(http.StatusOK)
}

// GET /api/auth/me
func (a *App) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("telegate_session")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	ok, _ := a.auth.ValidateSession(cookie.Value)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"username": a.state.AdminUser,
		"status":   "authenticated",
	})
}

// GET /api/state
func (a *App) handleState(w http.ResponseWriter, r *http.Request) {
	a.state.mu.RLock()
	defer a.state.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a.state)
}

// POST /api/nodes/create
func (a *App) handleNodeCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		IP   string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	nodeID := "node-" + genHex(4)
	token := "tok_" + genHex(16)

	a.state.mu.Lock()
	a.state.Nodes[nodeID] = &NodeStatus{
		ID:          nodeID,
		Name:        body.Name,
		IP:          body.IP,
		Token:       token,
		LastSeen:    time.Now(),
		IsOnline:    false,
		ActiveConns: []ClientSession{},
		WebProxy:    defaultWebConfig(),
		MTProto:     defaultMTProtoConfig(),
	}
	a.state.mu.Unlock()
	a.saveState()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"id":    nodeID,
		"token": token,
	})
}

// DELETE /api/nodes/delete
func (a *App) handleNodeDelete(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	a.state.mu.Lock()
	delete(a.state.Nodes, id)
	a.state.mu.Unlock()
	a.saveState()
	w.WriteHeader(http.StatusOK)
}

// POST /api/nodes/save-proxy
func (a *App) handleNodeSaveProxy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID   string         `json:"node_id"`
		WebProxy WebProxyConfig `json:"web_proxy"`
		MTProto  MTProtoConfig  `json:"mtproto"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NodeID == "" {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	a.state.mu.Lock()
	node, exists := a.state.Nodes[req.NodeID]
	if !exists {
		a.state.mu.Unlock()
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	}
	node.WebProxy = req.WebProxy
	node.MTProto = req.MTProto
	a.state.mu.Unlock()

	if err := a.saveState(); err != nil {
		slog.Error("save state", "err", err)
	}

	broker.publish(req.NodeID)
	slog.Info("Config saved for node", "id", req.NodeID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// POST/DELETE /api/blacklist/ip
func (a *App) handleBlacklistIP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var body struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		a.state.mu.Lock()
		a.state.BlacklistCIDR = append(a.state.BlacklistCIDR, body.IP)
		a.state.mu.Unlock()

	case http.MethodDelete:
		ip := r.URL.Query().Get("ip")
		a.state.mu.Lock()
		filtered := []string{}
		for _, item := range a.state.BlacklistCIDR {
			if item != ip {
				filtered = append(filtered, item)
			}
		}
		a.state.BlacklistCIDR = filtered
		a.state.mu.Unlock()
	}
	a.saveState()
	w.WriteHeader(http.StatusOK)
}

// POST/DELETE /api/blacklist/country
func (a *App) handleBlacklistCountry(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var body struct {
			Country string `json:"country"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Country == "" {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		a.state.mu.Lock()
		a.state.BlacklistCountries = append(a.state.BlacklistCountries, strings.ToUpper(strings.TrimSpace(body.Country)))
		a.state.mu.Unlock()

	case http.MethodDelete:
		c := strings.ToUpper(r.URL.Query().Get("country"))
		a.state.mu.Lock()
		filtered := []string{}
		for _, item := range a.state.BlacklistCountries {
			if item != c {
				filtered = append(filtered, item)
			}
		}
		a.state.BlacklistCountries = filtered
		a.state.mu.Unlock()
	}
	a.saveState()
	w.WriteHeader(http.StatusOK)
}

// POST /api/agent/heartbeat
func (a *App) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		NodeID            string          `json:"node_id"`
		UptimeSeconds     int64           `json:"uptime_seconds"`
		ActiveConnections []ClientSession `json:"active_connections"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	a.state.mu.Lock()
	if node, exists := a.state.Nodes[payload.NodeID]; exists {
		node.LastSeen = time.Now()
		node.IsOnline = true
		node.UptimeSec = payload.UptimeSeconds
		if len(payload.ActiveConnections) > 0 {
			node.ActiveConns = payload.ActiveConnections
		}
	}
	a.state.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

// GET /api/agent/config — возвращает sing-box + mtproto конфиги.
func (a *App) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")

	a.state.mu.RLock()
	node, exists := a.state.Nodes[nodeID]
	blCIDR := a.state.BlacklistCIDR
	blCountries := a.state.BlacklistCountries
	a.state.mu.RUnlock()

	if !exists {
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	}

	vlessTarget := ""
	if node.WebProxy.UpstreamType == "vless" {
		vlessTarget = node.WebProxy.VlessURL
	}

	singboxJSON, err := generator.BuildDualProxyConfig(generator.ProxyOptions{
		WebProxyEnabled:    node.WebProxy.Enabled,
		WebProxyPort:       node.WebProxy.Port,
		WebProxyPath:       node.WebProxy.WSPath,
		MTProtoEnabled:     node.MTProto.Enabled,
		MTProtoPort:        node.MTProto.Port,
		MTProtoSecret:      node.MTProto.Secret,
		MTProtoSNI:         node.MTProto.FakeTLSDomain,
		VlessURL:           vlessTarget,
		BlacklistCIDR:      blCIDR,
		BlacklistCountries: blCountries,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// MTProto конфиг для mtg (TOML).
	mtprotoTOML := ""
	if node.MTProto.Enabled {
		mtprotoTOML, _ = generator.BuildMTProtoTOML(generator.MTProtoOptions{
			BindAddr: "0.0.0.0",
			Port:     node.MTProto.Port,
			Secret:   node.MTProto.Secret,
		})
	}

	// Возвращаем оба конфига в JSON.
	resp := map[string]string{
		"singbox": string(singboxJSON),
		"mtproto": mtprotoTOML,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GET /api/agent/events — SSE (Server-Sent Events) push.
func (a *App) handleAgentEvents(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	if nodeID == "" {
		http.Error(w, "node_id required", http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := broker.subscribe(nodeID)
	defer broker.unsubscribe(nodeID, ch)

	fmt.Fprintf(w, "event: connected\ndata: {\"node_id\":\"%s\"}\n\n", nodeID)
	flusher.Flush()

	for {
		select {
		case <-ch:
			fmt.Fprintf(w, "event: config_updated\ndata: {\"node_id\":\"%s\"}\n\n", nodeID)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// Bootstrap
func (a *App) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	nodeID := r.URL.Query().Get("id")
	host := r.Host

	script := fmt.Sprintf(`#!/usr/bin/env bash
set -e
echo "=== [TeleGate] Подключение ноды %s к панели ==="
systemctl stop telegate-agent 2>/dev/null || true
rm -f /usr/local/bin/telegate-agent

if ! command -v sing-box &> /dev/null; then
    echo "-> Установка ядра Sing-box..."
    bash -c "$(curl -fsSL https://sing-box.app/install.sh)" || true
fi

echo "-> Загрузка агента TeleGate..."
curl -fsSL "http://%s/agent-bin" -o /usr/local/bin/telegate-agent
chmod +x /usr/local/bin/telegate-agent

mkdir -p /etc/telegate
cat << SERVICE > /etc/systemd/system/telegate-agent.service
[Unit]
Description=TeleGate Node Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/telegate-agent -master "http://%s" -token "%s" -id "%s"
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now telegate-agent
systemctl restart telegate-agent
echo "=== Нода успешно подключена к панели! ==="
`, nodeID, host, host, token, nodeID)

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(script))
}

// Agent bin
func (a *App) handleAgentBin(w http.ResponseWriter, r *http.Request) {
	agentPath := "/root/telegate-agent"
	if _, err := os.Stat(agentPath); os.IsNotExist(err) {
		agentPath = "./telegate-agent"
	}
	if _, err := os.Stat(agentPath); os.IsNotExist(err) {
		http.Error(w, "Agent binary not found", http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, agentPath)
}

// ============================================================
//  Static files
// ============================================================

func (a *App) serveStatic() {
	subFS, err := fs.Sub(uiFS, "ui")
	if err != nil {
		slog.Error("fs.Sub", "err", err)
		return
	}

	// Serve pages from ui root
	a.mux.Handle("/", http.FileServer(http.FS(subFS)))
}

// ============================================================
//  Background tasks
// ============================================================

func (a *App) backgroundTasks(ctx context.Context) {
	// Session cleanup
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				a.auth.Cleanup()
			case <-ctx.Done():
				return
			}
		}
	}()

	// Online status checker
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				now := time.Now()
				a.state.mu.Lock()
				for _, n := range a.state.Nodes {
					n.IsOnline = now.Sub(n.LastSeen) < 15*time.Second
				}
				a.state.mu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// ============================================================
//  Main
// ============================================================

func main() {
	cfg := loadConfig()
	app := NewApp(cfg)

	// Routes
	app.setupRoutes()
	app.serveStatic()

	// Background
	ctx, cancel := context.WithCancel(context.Background())
	app.backgroundTasks(ctx)

	// Server
	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: app.mux,
	}

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		slog.Info("Shutting down server...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		srv.Shutdown(shutdownCtx)
	}()

	// Signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		slog.Info("Signal received, shutting down...")
		cancel()
	}()

	slog.Info("TeleGate Panel запущен", "addr", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("Server error", "err", err)
		os.Exit(1)
	}
	slog.Info("Server stopped")
}
