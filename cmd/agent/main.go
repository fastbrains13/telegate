package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// HeartbeatPayload — отправка статуса на панель.
type HeartbeatPayload struct {
	NodeID            string       `json:"node_id"`
	UptimeSeconds     int64        `json:"uptime_seconds"`
	ActiveConnections []ClientConn `json:"active_connections"`
}

// ClientConn — одно активное соединение клиента.
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

	// 1. SSE — мгновенный pull при изменении конфига на панели.
	go func() {
		for {
			if err := subscribeConfigEvents(*masterURL, *token, *nodeID); err != nil {
				log.Printf("[SSE] соединение прервано: %v — переподключение через 5с", err)
			}
			time.Sleep(5 * time.Second)
		}
	}()

	// 2. Heartbeat + fallback pull каждые 5 секунд.
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		conns := collectActiveSockets(*proxyPort)
		sendHeartbeat(*masterURL, *token, *nodeID, int64(time.Since(startTime).Seconds()), conns)
		pullAndApplyConfig(*masterURL, *token, *nodeID)
	}
}

// subscribeConfigEvents подключается к SSE-стриму панели.
// При событии config_updated немедленно забирает и применяет конфиг.
func subscribeConfigEvents(masterURL, token, nodeID string) error {
	url := fmt.Sprintf("%s/api/agent/events?node_id=%s", masterURL, nodeID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "text/event-stream")

	client := &http.Client{} // без таймаута — длинное соединение
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: config_updated") {
			log.Printf("[SSE] получено уведомление об обновлении конфига — применяю...")
			pullAndApplyConfig(masterURL, token, nodeID)
		}
	}
	return scanner.Err()
}

// collectActiveSockets парсит вывод ss для получения входящих IP клиентов.
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

// pullAndApplyConfig забирает конфиг с панели и применяет его к sing-box и mtg.
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

	var configs struct {
		Singbox string `json:"singbox"`
		Mtproto string `json:"mtproto"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&configs); err != nil {
		return
	}

	// Sing-box (Web Proxy / VLESS / routing).
	if configs.Singbox != "" {
		if _, err := os.Stat("/etc/sing-box"); err == nil {
			if changed, _ := writeIfChanged("/etc/sing-box/config.json", []byte(configs.Singbox)); changed {
				_ = exec.Command("systemctl", "reload", "sing-box").Run()
				log.Printf("[config] sing-box перечитан")
			}
		}
	}

	// MTProto (mtg v2 — TOML config).
	if configs.Mtproto != "" {
		mtgDir := "/etc/telegate"
		if _, err := os.Stat(mtgDir); os.IsNotExist(err) {
			os.MkdirAll(mtgDir, 0755)
		}
		if changed, _ := writeIfChanged(mtgDir+"/mtg.toml", []byte(configs.Mtproto)); changed {
			_ = exec.Command("systemctl", "restart", "telegate-mtproto").Run()
			log.Printf("[config] mtproto перечитан")
		}
	}
}

// writeIfConfigChanged сравнивает новый конфиг с существующим.
func writeIfChanged(path string, data []byte) (bool, error) {
	old, err := os.ReadFile(path)
	if err == nil && bytes.Equal(old, data) {
		return false, nil // без изменений — не трогаем рантайм
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return false, err
	}
	return true, nil
}
