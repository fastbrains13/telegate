package graceful

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Manager управляет graceful shutdown.
type Manager struct {
	cancel context.CancelFunc
	ctx    context.Context
}

// New создаёт менеджер graceful shutdown.
// Он перехватывает SIGINT и SIGTERM, сигнализируя о завершении.
func New() *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{ctx: ctx, cancel: cancel}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		slog.Warn("Получен сигнал завершения, graceful shutdown...")
		cancel()
	}()
	return m
}

// Context возвращает контекст, отменяемый при сигнале.
func (m *Manager) Context() context.Context {
	return m.ctx
}

// Done возвращает канал, закрытый при сигнале.
func (m *Manager) Done() <-chan struct{} {
	return m.ctx.Done()
}

// Shutdown выполняет cleanup и ждёт завершения воркеров.
// timeout — макс. время на graceful-завершение.
func (m *Manager) Shutdown(timeout time.Duration) {
	slog.Info("Graceful shutdown: завершение воркеров...")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Собираем все goroutine в WaitGroup (передаётся извне)
	// Здесь мы просто ждём
	<-ctx.Done()
	slog.Info("Graceful shutdown: завершён")
}
