package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

// generateToken возвращает криптографически стойкий hex-токен (32 байта).
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenSecret возвращает hex-секрет длиной n байт (используется для токенов нод и секретов прокси).
func GenSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Manager управляет хешированием паролей, лимитами и сессиями.
type Manager struct {
	mu       sync.RWMutex
	limiter  *rate.Limiter
	sessions map[string]time.Time
}

// New создаёт менеджер авторизации.
// loginAttempts — макс. попыток входа; windowSeconds — окно для rate limit.
func New(loginAttempts int, windowSeconds int) *Manager {
	return &Manager{
		limiter:  rate.NewLimiter(rate.Every(time.Duration(windowSeconds)*time.Second), loginAttempts),
		sessions: make(map[string]time.Time),
	}
}

// HashPassword хеширует пароль через bcrypt.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPasswordHash сравнивает пароль с хешем.
func CheckPasswordHash(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// AllowLogin проверяет rate limit. Возвращает false, если превышен лимит.
func (m *Manager) AllowLogin() bool {
	return m.limiter.Allow()
}

// CreateSession создаёт новую сессию с TTL.
func (m *Manager) CreateSession(ttl time.Duration) (token string, err error) {
	token, err = generateToken()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.sessions[token] = time.Now().Add(ttl)
	m.mu.Unlock()
	return token, nil
}

// ValidateSession проверяет валидность сессии.
func (m *Manager) ValidateSession(token string) (bool, error) {
	m.mu.RLock()
	expire, exists := m.sessions[token]
	m.mu.RUnlock()

	if !exists {
		return false, ErrSessionNotFound
	}
	if time.Now().After(expire) {
		m.DeleteSession(token)
		return false, ErrSessionExpired
	}
	return true, nil
}

// DeleteSession удаляет сессию.
func (m *Manager) DeleteSession(token string) {
	m.mu.Lock()
	delete(m.sessions, token)
	m.mu.Unlock()
}

// ExpireAll старше 15 минут — автоочистка.
func (m *Manager) Cleanup() {
	m.mu.Lock()
	now := time.Now()
	for token, expire := range m.sessions {
		if now.After(expire) {
			delete(m.sessions, token)
		}
	}
	m.mu.Unlock()
}

// Errors
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrRateLimited     = errors.New("too many login attempts, try again later")
)
