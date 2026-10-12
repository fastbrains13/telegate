package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"

	"github.com/fastbrains13/telegate/internal/generator"
)

//go:embed ui/*
var uiFS embed.FS

type ProxyState struct {
	Port               int      `json:"port"`
	VlessUpstream      string   `json:"vless_upstream"`
	BlacklistIPs       []string `json:"blacklist_ips"`
	BlacklistCountries []string `json:"blacklist_countries"`
}

var currentState = ProxyState{
	Port:               443,
	VlessUpstream:      "",
	BlacklistIPs:       []string{"185.220.101.0/24"},
	BlacklistCountries: []string{"cn", "ir"},
}

func main() {
	http.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":             "online",
			"active_connections": 142,
			"config":             currentState,
		})
	})

	http.HandleFunc("/api/config/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var newState ProxyState
		if err := json.NewDecoder(r.Body).Decode(&newState); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		currentState = newState

		rawConfig, err := generator.BuildSingboxConfig(
			currentState.Port,
			currentState.VlessUpstream,
			currentState.BlacklistIPs,
			currentState.BlacklistCountries,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(rawConfig)
	})

	subFS, err := fs.Sub(uiFS, "ui")
	if err == nil {
		http.Handle("/", http.FileServer(http.FS(subFS)))
	}

	log.Println("[TeleGate Panel] Server listening on :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
