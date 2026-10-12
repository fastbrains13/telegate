package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
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
	LastSeen    time.Time       `json:"last_seen"`
	ActiveConns []ClientSession `json:"active_conns"`
	UptimeSec   int64           `json:"uptime_sec"`
}

type GlobalState struct {
	mu                 sync.RWMutex
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

var state = GlobalState{
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

func init() {
	state.Nodes["node-eu-01"] = &NodeStatus{
		ID:        "node-eu-01",
		Name:      "Node-EU-01 (Amsterdam)",
		IP:        "185.192.110.42",
		LastSeen:  time.Now(),
		UptimeSec: 86400,
		ActiveConns: []ClientSession{
			{IP: "178.62.204.15", Country: "NL", ISP: "DigitalOcean", Protocol: "Web Proxy", Outbound: "-> VLESS Upstream", BytesSent: 44800000, Connected: time.Now().Add(-14 * time.Minute)},
			{IP: "91.108.56.110", Country: "DE", ISP: "Hetzner", Protocol: "MTProto", Outbound: "-> Direct (DC4)", BytesSent: 126000000, Connected: time.Now().Add(-64 * time.Minute)},
			{IP: "46.242.12.89", Country: "RU", ISP: "Rostelecom", Protocol: "Web Proxy", Outbound: "-> VLESS Upstream", BytesSent: 8500000, Connected: time.Now().Add(-2 * time.Minute)},
		},
	}
}

func main() {
	http.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		state.mu.RLock()
		defer state.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state)
	})

	http.HandleFunc("/api/config/save", func(w http.ResponseWriter, r *http.Request) {
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

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "success",
			"message": "Конфигурация обновлена",
		})
	})

	http.HandleFunc("/api/blacklist/ip", func(w http.ResponseWriter, r *http.Request) {
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
			w.WriteHeader(http.StatusOK)
			return
		}
	})

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

	subFS, err := fs.Sub(uiFS, "ui")
	if err == nil {
		http.Handle("/", http.FileServer(http.FS(subFS)))
	}

	log.Println("==================================================")
	log.Println("TeleGate Master Panel запущена на порту :8080")
	log.Println("Открыть в браузере: http://localhost:8080")
	log.Println("==================================================")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
