package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Store — потокобезопасное хранилище с атомарным сохранением на диск.
type Store struct {
	path string
	mu   sync.RWMutex
	data []byte // raw JSON для точного сохранения
}

// New создаёт хранилище по пути.
func New(path string) *Store {
	return &Store{path: path}
}

// Load загружает состояние из файла.
func (s *Store) Load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // новый файл — ничего грузить не надо
		}
		return fmt.Errorf("load state: %w", err)
	}
	s.mu.Lock()
	s.data = data
	s.mu.Unlock()
	return nil
}

// Save атомарно сохраняет состояние.
func (s *Store) Save() error {
	s.mu.RLock()
	data := make([]byte, len(s.data))
	copy(data, s.data)
	s.mu.RUnlock()

	if len(data) == 0 {
		return nil
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("save state mkdir: %w", err)
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("save state write tmp: %w", err)
	}

	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("save state rename: %w", err)
	}
	return nil
}

// Set обновляет состояние и готовит JSON.
func (s *Store) Set(v interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	data = append(data, '\n')
	s.data = data
	return nil
}

// Get возвращает копию raw JSON.
func (s *Store) Get() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.data == nil {
		return nil, fmt.Errorf("state not loaded")
	}
	cpy := make([]byte, len(s.data))
	copy(cpy, s.data)
	return cpy, nil
}

// GetRaw возвращает сырые байты состояния (nil если пусто).
func (s *Store) GetRaw() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data
}

// AtomicSave пишет data атомарно (tmp + rename) без повторного маршалинга.
func (s *Store) AtomicSave(data []byte) error {
	s.mu.Lock()
	s.data = data
	s.mu.Unlock()

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("atomic save mkdir: %w", err)
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("atomic save write tmp: %w", err)
	}

	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("atomic save rename: %w", err)
	}
	return nil
}

// Update — функция для безопасного обновления данных.
// Функция получает pointer на структуру, модифицирует его, и Save() вызовется
// самостоятельно, если вернёт nil.
type Updater func(v interface{}) error

// UpdateAndSave применяет мутацию и сохраняет атомарно.
func (s *Store) UpdateAndSave(v interface{}, fn func(v interface{}) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := fn(v); err != nil {
		return err
	}

	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	data = append(data, '\n')
	s.data = data

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("save state mkdir: %w", err)
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("save state write tmp: %w", err)
	}

	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("save state rename: %w", err)
	}
	return nil
}
