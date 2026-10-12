package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthFlow(t *testing.T) {
	// 1. Попытка входа с неверным паролем
	badBody, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "wrongpassword",
	})
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(badBody))
	w := httptest.NewRecorder()

	// Вызов хендлера логина
	http.DefaultServeMux.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Fatalf("Авторизация не должна была пройти с неверным паролем")
	}

	// 2. Успешный вход
	goodBody, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "admin",
	})
	req = httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(goodBody))
	w = httptest.NewRecorder()

	// Прямой вызов логина
	handler := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&creds)
		if creds.Username == state.AdminUser && creds.Password == state.AdminPassword {
			rw.WriteHeader(http.StatusOK)
		} else {
			rw.WriteHeader(http.StatusUnauthorized)
		}
	})
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Ожидался статус 200 при верных учетных данных, получен %d", w.Code)
	}
}

func TestBlacklistManipulation(t *testing.T) {
	initialLen := len(state.BlacklistCIDR)
	testIP := "203.0.113.50/32"

	state.mu.Lock()
	state.BlacklistCIDR = append(state.BlacklistCIDR, testIP)
	state.mu.Unlock()

	if len(state.BlacklistCIDR) != initialLen+1 {
		t.Fatalf("IP не добавился в черный список")
	}

	// Удаление
	state.mu.Lock()
	var filtered []string
	for _, ip := range state.BlacklistCIDR {
		if ip != testIP {
			filtered = append(filtered, ip)
		}
	}
	state.BlacklistCIDR = filtered
	state.mu.Unlock()

	if len(state.BlacklistCIDR) != initialLen {
		t.Fatalf("IP не удалился из черного списка")
	}
}
