package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func newTestApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{
		ListenAddr: ":0",
		StateFile:  filepath.Join(dir, "state.json"),
		AdminUser:  "admin",
		AdminPass:  "secret",
		AgentTTL:   time.Hour,
		LogLevel:   "error",
	}
	app := NewApp(cfg)
	app.setupRoutes()
	return app
}

// login аутентифицируется и возвращает значения session- и csrf-куки.
func login(t *testing.T, app *App, password string) (session, csrf string, code int) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	app.mux.ServeHTTP(w, req)

	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case "telegate_session":
			session = c.Value
		case "telegate_csrf":
			csrf = c.Value
		}
	}
	return session, csrf, w.Code
}

// makeAuthedRequest создаёт запрос с правильными session+csrf куки и CSRF-хедером.
func makeAuthedRequest(t *testing.T, app *App, session, csrf, method, path string, body []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBuffer(body))
	req.AddCookie(&http.Cookie{Name: "telegate_session", Value: session})
	req.AddCookie(&http.Cookie{Name: "telegate_csrf", Value: csrf})
	req.Header.Set("X-CSRF-Token", csrf)
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	app := newTestApp(t)
	_, _, code := login(t, app, "wrong")
	if code == http.StatusOK {
		t.Fatal("login с неверным паролем не должен проходить")
	}
}

func TestLoginAcceptsCorrectPassword(t *testing.T) {
	app := newTestApp(t)
	session, csrf, code := login(t, app, "secret")
	if code != http.StatusOK {
		t.Fatalf("ожидался 200, получен %d", code)
	}
	if session == "" || csrf == "" {
		t.Fatal("не установлены session- и csrf-куки")
	}
}

func TestStateRequiresAuth(t *testing.T) {
	app := newTestApp(t)
	req := httptest.NewRequest("GET", "/api/state", nil)
	w := httptest.NewRecorder()
	app.mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался 401 без сессии, получен %d", w.Code)
	}
}

func TestMutatingEndpointRequiresCSRF(t *testing.T) {
	app := newTestApp(t)
	session, csrf, _ := login(t, app, "secret")

	// POST с CSRF-заголовком и куки -> 200 (успех)
	body, _ := json.Marshal(map[string]any{"name": "n1"})
	req := makeAuthedRequest(t, app, session, csrf, "POST", "/api/nodes/create", body)
	w := httptest.NewRecorder()
	app.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("ожидался 200 с CSRF, получен %d", w.Code)
	}

	// POST без куки telegate_csrf -> 403
	body, _ = json.Marshal(map[string]any{"name": "n2"})
	req2 := httptest.NewRequest("POST", "/api/nodes/create", bytes.NewBuffer(body))
	req2.AddCookie(&http.Cookie{Name: "telegate_session", Value: session})
	req2.Header.Set("X-CSRF-Token", csrf)
	w2 := httptest.NewRecorder()
	app.mux.ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("ожидался 403 без csrf-куки, получен %d", w2.Code)
	}
}

func TestBlacklistFlow(t *testing.T) {
	app := newTestApp(t)
	session, csrf, _ := login(t, app, "secret")

	// add IP
	req := makeAuthedRequest(t, app, session, csrf, "POST", "/api/blacklist/ip", []byte(`{"ip":"203.0.113.9"}`))
	w := httptest.NewRecorder()
	app.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("добавление IP вернуло %d: %s", w.Code, w.Body.String())
	}

	// verify present
	req = httptest.NewRequest("GET", "/api/state", nil)
	req.AddCookie(&http.Cookie{Name: "telegate_session", Value: session})
	w = httptest.NewRecorder()
	app.mux.ServeHTTP(w, req)

	var st GlobalState
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("state не парсится: %v", err)
	}
	found := false
	for _, ip := range st.BlacklistCIDR {
		if ip == "203.0.113.9" {
			found = true
		}
	}
	if !found {
		t.Fatal("IP не найден в черном списке")
	}

	// delete IP
	req = makeAuthedRequest(t, app, session, csrf, "DELETE", "/api/blacklist/ip?ip=203.0.113.9", nil)
	w = httptest.NewRecorder()
	app.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("удаление IP вернуло %d", w.Code)
	}
}

func TestNodeCreateAndDelete(t *testing.T) {
	app := newTestApp(t)
	session, csrf, _ := login(t, app, "secret")

	req := makeAuthedRequest(t, app, session, csrf, "POST", "/api/nodes/create", []byte(`{"name":"node-a","ip":"1.2.3.4"}`))
	w := httptest.NewRecorder()
	app.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("создание ноды вернуло %d: %s", w.Code, w.Body.String())
	}

	var created map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("ответ не парсится: %v", err)
	}
	if created["id"] == "" || created["token"] == "" {
		t.Fatal("не возвращены id/token ноды")
	}

	// delete node
	req = makeAuthedRequest(t, app, session, csrf, "DELETE", "/api/nodes/delete?id="+created["id"], nil)
	w = httptest.NewRecorder()
	app.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("удаление ноды вернуло %d", w.Code)
	}
}

func TestAgentHeartbeatRequiresToken(t *testing.T) {
	app := newTestApp(t)
	req := httptest.NewRequest("POST", "/api/agent/heartbeat?node_id=node-x", bytes.NewBuffer([]byte(`{"node_id":"node-x"}`)))
	w := httptest.NewRecorder()
	app.mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("heartbeat без токена вернул %d, ожидался 401", w.Code)
	}
}

// Ensure cookie jar helper compiles (guards accidental import drift).
var _ = cookiejar.New
