package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
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

type NodeStatus struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	IP          string          `json:"ip"`
	Token       string          `json:"token"`
	LastSeen    time.Time       `json:"last_seen"`
	ActiveConns []ClientSession `json:"active_conns"`
	UptimeSec   int64           `json:"uptime_sec"`
}

type GlobalState struct {
	mu                 sync.RWMutex          `json:"-"`
	AdminUser          string                `json:"admin_user"`
	AdminPassword      string                `json:"admin_password"`
	Port               int                   `json:"port"`
	Domain             string                `json:"domain"`
	WSPath             string                `json:"ws_path"`
	FallbackURL        string                `json:"fallback_url"`
	VlessUpstream      string                `json:"vless_upstream"`
	VlessEnabled       bool                  `json:"vless_enabled"`
	BlacklistCIDR      []string              `json:"blacklist_cidr"`
	BlacklistCountries []string              `json:"blacklist_countries"`
	Nodes              map[string]*NodeStatus `json:"nodes"`
}

var (
	stateFile = "/data/telegate_state.json"
	sessions  = make(map[string]time.Time)
	sessMu    sync.RWMutex
	state     = GlobalState{
		AdminUser:          "admin",
		AdminPassword:      "admin",
		Port:               443,
		Domain:             "tg-web.myproxynode.org",
		WSPath:             "/api/v1/tg-gateway",
		FallbackURL:        "https://ya.ru",
		VlessUpstream:      "vless://b83c21a4-9e32-4299-8ab2-94fa108a7b90@fra-core-01.relays.net:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=speedtest.net&fp=chrome&pbk=Z19xK3L0x9j4...#EU-Relay",
		VlessEnabled:       true,
		BlacklistCIDR:      []string{"185.220.101.0/24", "45.154.255.8"},
		BlacklistCountries: []string{"CN", "IR", "KP"},
		Nodes:              make(map[string]*NodeStatus),
	}
)

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

func generateToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
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

	if len(state.Nodes) == 0 {
		state.Nodes["node-eu-01"] = &NodeStatus{
			ID:        "node-eu-01",
			Name:      "Node-EU-01 (Amsterdam)",
			IP:        "185.192.110.42",
			Token:     "tok_eu01_master",
			LastSeen:  time.Now(),
			UptimeSec: 86400,
			ActiveConns: []ClientSession{
				{IP: "178.62.204.15", Country: "NL", ISP: "DigitalOcean", Protocol: "Web Proxy", Outbound: "-> VLESS Upstream", BytesSent: 44800000, Connected: time.Now().Add(-14 * time.Minute)},
				{IP: "91.108.56.110", Country: "DE", ISP: "Hetzner", Protocol: "MTProto", Outbound: "-> Direct (DC4)", BytesSent: 126000000, Connected: time.Now().Add(-64 * time.Minute)},
			},
		}
	}

	// AUTH API
	http.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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

		state.mu.RLock()
		valid := creds.Username == state.AdminUser && creds.Password == state.AdminPassword
		state.mu.RUnlock()

		if !valid {
			http.Error(w, "Неверный логин или пароль", http.StatusUnauthorized)
			return
		}

		token := generateToken(32)
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

	// PROTECTED API
	http.HandleFunc("/api/state", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		state.mu.RLock()
		defer state.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state)
	}))

	http.HandleFunc("/api/config/save", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var payload struct {
			Port          int    `json:"port"`
			Domain        string `json:"domain"`
			WSPath        string `json:"ws_path"`
			FallbackURL   string `json:"fallback_url"`
			VlessUpstream string `json:"vless_upstream"`
			VlessEnabled  bool   `json:"vless_enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		state.mu.Lock()
		state.Port = payload.Port
		state.Domain = payload.Domain
		state.WSPath = payload.WSPath
		state.FallbackURL = payload.FallbackURL
		state.VlessUpstream = payload.VlessUpstream
		state.VlessEnabled = payload.VlessEnabled
		state.mu.Unlock()

		saveState()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success"}`))
	}))

	http.HandleFunc("/api/nodes/create", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Name string `json:"name"`
			IP   string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		nodeID := "node-" + generateToken(4)
		token := "tok_" + generateToken(16)

		state.mu.Lock()
		state.Nodes[nodeID] = &NodeStatus{
			ID:          nodeID,
			Name:        body.Name,
			IP:          body.IP,
			Token:       token,
			LastSeen:    time.Now(),
			ActiveConns: []ClientSession{},
		}
		state.mu.Unlock()
		saveState()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"id":    nodeID,
			"token": token,
		})
	}))

	http.HandleFunc("/api/blacklist/ip", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var body struct {
				IP string `json:"ip"`
			}
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

	// AGENT API
	http.HandleFunc("/api/agent/config", func(w http.ResponseWriter, r *http.Request) {
		state.mu.RLock()
		defer state.mu.RUnlock()

		vlessTarget := ""
		if state.VlessEnabled {
			vlessTarget = state.VlessUpstream
		}

		cfgJSON, err := generator.BuildSingboxConfig(
			state.Port,
			vlessTarget,
			state.BlacklistCIDR,
			state.BlacklistCountries,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(cfgJSON)
	})

	// STATIC UI
	subFS, err := fs.Sub(uiFS, "ui")
	if err == nil {
		http.Handle("/", http.FileServer(http.FS(subFS)))
	}

	log.Println("[TeleGate Panel] Запуск на :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
