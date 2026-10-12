package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fastbrains13/telegate/internal/generator"
)

//go:embed ui/*
var uiFS embed.FS

type ClientSession struct {
	IP        string    `json:"ip"`
	Country   string    `json:"country"`
	ISP       string    `json:"isp"`
	Protocol  string    `json:"protocol"`
	Outbound  string    `json:"outbound"`
	BytesSent int64     `json:"bytes_sent"`
	Connected time.Time `json:"connected"`
}

type WebProxyConfig struct {
	Enabled      bool   `json:"enabled"`
	HostMode     string `json:"host_mode"` // "ip" или "domain"
	CustomDomain string `json:"custom_domain"`
	Port         int    `json:"port"`
	Secret       string `json:"secret"`
	WSPath       string `json:"ws_path"`
	FallbackURL  string `json:"fallback_url"`
	MaxClients   int    `json:"max_clients"`
	UpstreamType string `json:"upstream_type"` // "direct" или "vless"
	VlessURL     string `json:"vless_url"`
}

type MTProtoConfig struct {
	Enabled       bool   `json:"enabled"`
	HostMode      string `json:"host_mode"` // "ip" или "domain"
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
	AdminPassword      string                 `json:"admin_password"`
	BlacklistCIDR      []string               `json:"blacklist_cidr"`
	BlacklistCountries []string               `json:"blacklist_countries"`
	Nodes              map[string]*NodeStatus `json:"nodes"`
}

var (
	stateFile = "/data/telegate_state.json"
	sessions  = make(map[string]time.Time)
	sessMu    sync.RWMutex
	state     = GlobalState{
		AdminUser:          "admin",
		AdminPassword:      "admin",
		BlacklistCIDR:      []string{"185.220.101.0/24"},
		BlacklistCountries: []string{"CN", "IR"},
		Nodes:              make(map[string]*NodeStatus),
	}
)

func genHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func defaultWebConfig() WebProxyConfig {
	return WebProxyConfig{
		Enabled:      true,
		HostMode:     "ip",
		CustomDomain: "",
		Port:         443,
		Secret:       genHex(16),
		WSPath:       "/",
		FallbackURL:  "https://ya.ru",
		MaxClients:   0,
		UpstreamType: "direct",
		VlessURL:     "",
	}
}

func defaultMTProtoConfig() MTProtoConfig {
	domainHex := hex.EncodeToString([]byte("yandex.ru"))
	return MTProtoConfig{
		Enabled:       true,
		HostMode:      "ip",
		CustomDomain:  "",
		Port:          8443,
		Secret:        "ee" + genHex(16) + domainHex,
		FakeTLSDomain: "yandex.ru",
		AdTag:         "",
		MaxClients:    0,
		UpstreamType:  "direct",
		VlessURL:      "",
	}
}

func saveState() {
	state.mu.RLock()
	defer state.mu.RUnlock()
	data, err := json.MarshalIndent(state, "", "  ")
	if err == nil {
		_ = os.WriteFile(stateFile, data, 0644)
	}
}

func loadState() {
	data, err := os.ReadFile(stateFile)
	if err == nil {
		state.mu.Lock()
		_ = json.Unmarshal(data, &state)
		state.mu.Unlock()
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("telegate_session")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		sessMu.RLock()
		expire, exists := sessions[cookie.Value]
		sessMu.RUnlock()

		if !exists || time.Now().After(expire) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func main() {
	loadState()

	go func() {
		for {
			time.Sleep(5 * time.Second)
			state.mu.Lock()
			now := time.Now()
			for _, n := range state.Nodes {
				n.IsOnline = now.Sub(n.LastSeen) < 15*time.Second
			}
			state.mu.Unlock()
		}
	}()

	http.HandleFunc("/agent-bin", func(w http.ResponseWriter, r *http.Request) {
		agentPath := "/root/telegate-agent"
		if _, err := os.Stat(agentPath); os.IsNotExist(err) {
			agentPath = "./telegate-agent"
		}
		http.ServeFile(w, r, agentPath)
	})

	http.HandleFunc("/bootstrap", func(w http.ResponseWriter, r *http.Request) {
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
	})

	http.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		state.mu.RLock()
		valid := creds.Username == state.AdminUser && creds.Password == state.AdminPassword
		state.mu.RUnlock()

		if !valid {
			http.Error(w, "Неверный логин или пароль", http.StatusUnauthorized)
			return
		}

		b := make([]byte, 32)
		rand.Read(b)
		token := hex.EncodeToString(b)

		sessMu.Lock()
		sessions[token] = time.Now().Add(24 * time.Hour)
		sessMu.Unlock()

		http.SetCookie(w, &http.Cookie{
			Name:     "telegate_session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Expires:  time.Now().Add(24 * time.Hour),
		})
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	http.HandleFunc("/api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("telegate_session"); err == nil {
			sessMu.Lock()
			delete(sessions, c.Value)
			sessMu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "telegate_session",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})
		w.WriteHeader(http.StatusOK)
	})

	http.HandleFunc("/api/auth/me", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("telegate_session")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		sessMu.RLock()
		expire, exists := sessions[cookie.Value]
		sessMu.RUnlock()

		if !exists || time.Now().After(expire) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"username":"admin","status":"authenticated"}`))
	})

	http.HandleFunc("/api/state", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		state.mu.RLock()
		defer state.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state)
	}))

	http.HandleFunc("/api/nodes/save-proxy", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			NodeID   string         `json:"node_id"`
			WebProxy WebProxyConfig `json:"web_proxy"`
			MTProto  MTProtoConfig  `json:"mtproto"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.NodeID == "" {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		state.mu.Lock()
		node, exists := state.Nodes[req.NodeID]
		if !exists {
			state.mu.Unlock()
			http.Error(w, "Нода не найдена", http.StatusNotFound)
			return
		}
		node.WebProxy = req.WebProxy
		node.MTProto = req.MTProto
		state.mu.Unlock()

		saveState()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success"}`))
	}))

	http.HandleFunc("/api/nodes/create", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name string `json:"name"`
			IP   string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		nodeID := "node-" + genHex(4)
		token := "tok_" + genHex(16)

		state.mu.Lock()
		state.Nodes[nodeID] = &NodeStatus{
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
		state.mu.Unlock()
		saveState()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"id":    nodeID,
			"token": token,
		})
	}))

	http.HandleFunc("/api/nodes/delete", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		state.mu.Lock()
		delete(state.Nodes, id)
		state.mu.Unlock()
		saveState()
		w.WriteHeader(http.StatusOK)
	}))

	http.HandleFunc("/api/blacklist/ip", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var body struct{ IP string `json:"ip"` }
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			state.mu.Lock()
			state.BlacklistCIDR = append(state.BlacklistCIDR, body.IP)
			state.mu.Unlock()
			saveState()
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodDelete {
			ip := r.URL.Query().Get("ip")
			state.mu.Lock()
			filtered := []string{}
			for _, item := range state.BlacklistCIDR {
				if item != ip {
					filtered = append(filtered, item)
				}
			}
			state.BlacklistCIDR = filtered
			state.mu.Unlock()
			saveState()
			w.WriteHeader(http.StatusOK)
			return
		}
	}))

	http.HandleFunc("/api/blacklist/country", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var body struct{ Country string `json:"country"` }
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Country == "" {
				http.Error(w, "Bad request", http.StatusBadRequest)
				return
			}
			state.mu.Lock()
			state.BlacklistCountries = append(state.BlacklistCountries, strings.ToUpper(strings.TrimSpace(body.Country)))
			state.mu.Unlock()
			saveState()
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodDelete {
			c := strings.ToUpper(r.URL.Query().Get("country"))
			state.mu.Lock()
			filtered := []string{}
			for _, item := range state.BlacklistCountries {
				if item != c {
					filtered = append(filtered, item)
				}
			}
			state.BlacklistCountries = filtered
			state.mu.Unlock()
			saveState()
			w.WriteHeader(http.StatusOK)
			return
		}
	}))

	http.HandleFunc("/api/agent/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			NodeID            string          `json:"node_id"`
			UptimeSeconds     int64           `json:"uptime_seconds"`
			ActiveConnections []ClientSession `json:"active_connections"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		state.mu.Lock()
		if node, exists := state.Nodes[payload.NodeID]; exists {
			node.LastSeen = time.Now()
			node.IsOnline = true
			node.UptimeSec = payload.UptimeSeconds
			if len(payload.ActiveConnections) > 0 {
				node.ActiveConns = payload.ActiveConnections
			}
		}
		state.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	http.HandleFunc("/api/agent/config", func(w http.ResponseWriter, r *http.Request) {
		nodeID := r.URL.Query().Get("node_id")

		state.mu.RLock()
		node, exists := state.Nodes[nodeID]
		blCIDR := state.BlacklistCIDR
		blCountries := state.BlacklistCountries
		state.mu.RUnlock()

		if !exists {
			http.Error(w, "Node not found", http.StatusNotFound)
			return
		}

		vlessTarget := ""
		if node.WebProxy.UpstreamType == "vless" {
			vlessTarget = node.WebProxy.VlessURL
		}

		cfgJSON, err := generator.BuildDualProxyConfig(generator.ProxyOptions{
			WebProxyEnabled:    node.WebProxy.Enabled,
			WebProxyPort:       node.WebProxy.Port,
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
		w.Header().Set("Content-Type", "application/json")
		w.Write(cfgJSON)
	})

	subFS, err := fs.Sub(uiFS, "ui")
	if err == nil {
		http.Handle("/", http.FileServer(http.FS(subFS)))
	}

	log.Println("[TeleGate Panel] Запуск на :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
