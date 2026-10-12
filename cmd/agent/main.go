package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"
)

type HeartbeatPayload struct {
	NodeID            string       `json:"node_id"`
	UptimeSeconds     int64        `json:"uptime_seconds"`
	ActiveConnections []ClientConn `json:"active_connections"`
}

type ClientConn struct {
	IP        string `json:"ip"`
	Protocol  string `json:"protocol"`
	BytesSent int64  `json:"bytes_sent"`
}

func main() {
	masterURL := flag.String("master", "http://localhost:8080", "Адрес мастер-панели")
	token := flag.String("token", "", "Секретный токен ноды")
	nodeID := flag.String("id", "node-auto", "Идентификатор ноды")
	flag.Parse()

	log.Printf("[TeleGate Agent] Запуск ноды %s (Master: %s)...", *nodeID, *masterURL)

	startTime := time.Now()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		sendHeartbeat(*masterURL, *token, *nodeID, int64(time.Since(startTime).Seconds()))
		pullAndApplyConfig(*masterURL, *token, *nodeID)
	}
}

func sendHeartbeat(masterURL, token, nodeID string, uptime int64) {
	payload := HeartbeatPayload{
		NodeID:        nodeID,
		UptimeSeconds: uptime,
		ActiveConnections: []ClientConn{
			{IP: "178.62.204.15", Protocol: "web-proxy", BytesSent: 42800000},
			{IP: "91.108.56.110", Protocol: "mtproto", BytesSent: 120400000},
		},
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", masterURL+"/api/agent/heartbeat", bytes.NewBuffer(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

func pullAndApplyConfig(masterURL, token, nodeID string) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/agent/config?node_id=%s", masterURL, nodeID), nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	defer resp.Body.Close()

	newConfig, err := io.ReadAll(resp.Body)
	if err != nil || len(newConfig) == 0 {
		return
	}

	configPath := "/etc/sing-box/config.json"
	if _, err := os.Stat("/etc/sing-box"); err == nil {
		_ = os.WriteFile(configPath, newConfig, 0644)
		_ = exec.Command("systemctl", "reload", "sing-box").Run()
	}
}
