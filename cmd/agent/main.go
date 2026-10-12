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
	"strings"
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
	token := flag.String("token", "", "Секретный токен авторизации ноды")
	nodeID := flag.String("id", "node-auto", "Идентификатор ноды")
	proxyPort := flag.Int("port", 443, "Порт прокси для отслеживания сокетов")
	flag.Parse()

	log.Printf("[TeleGate Agent] Нода %s активна. Синхронизация с %s...", *nodeID, *masterURL)

	startTime := time.Now()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		conns := collectActiveSockets(*proxyPort)
		sendHeartbeat(*masterURL, *token, *nodeID, int64(time.Since(startTime).Seconds()), conns)
		pullAndApplyConfig(*masterURL, *token, *nodeID)
	}
}

// collectActiveSockets парсит вывод ss для получения реальных входящих IP клиентов
func collectActiveSockets(port int) []ClientConn {
	out, err := exec.Command("ss", "-nt", fmt.Sprintf("sport = :%d", port)).Output()
	if err != nil {
		return []ClientConn{}
	}

	lines := strings.Split(string(out), "\n")
	var conns []ClientConn
	seen := make(map[string]bool)

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "ESTAB" {
			peer := fields[4]
			ip := peer
			if idx := strings.LastIndex(peer, ":"); idx != -1 {
				ip = peer[:idx]
			}
			ip = strings.Trim(ip, "[]")
			if ip != "" && !seen[ip] {
				seen[ip] = true
				conns = append(conns, ClientConn{
					IP:        ip,
					Protocol:  "Web Proxy",
					BytesSent: 1024 * 1024,
				})
			}
		}
	}
	return conns
}

func sendHeartbeat(masterURL, token, nodeID string, uptime int64, conns []ClientConn) {
	payload := HeartbeatPayload{
		NodeID:            nodeID,
		UptimeSeconds:     uptime,
		ActiveConnections: conns,
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
