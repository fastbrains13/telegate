package generator

import (
	"fmt"
	"strings"
)

// MTProtoOptions — параметры для генерации конфига mtg (https://github.com/9seconds/mtg v2).
//
// Sing-box НЕ поддерживает MTProto нативно, поэтому для MTProto-прокси на ноде
// используется внешний бинарник mtg, читающий TOML-конфиг.
type MTProtoOptions struct {
	// BindAddr — адрес прослушивания, например "0.0.0.0" или "::".
	BindAddr string
	// Port — порт прослушивания.
	Port int
	// Secret — MTProto-секрет в hex-формате (начинается с "ee" для Fake-TLS).
	Secret string
	// Concurrency — максимум одновременных соединений (0 = по умолчанию mtg).
	Concurrency int
}

// BuildMTProtoTOML формирует минимальный валидный TOML-конфиг для `mtg run`.
// Обязательные поля mtg v2: secret и bind-to.
//
// Пример результата:
//
//	secret = "ee473ce5...676f6f676c652e636f6d"
//	bind-to = "0.0.0.0:8443"
func BuildMTProtoTOML(opts MTProtoOptions) (string, error) {
	if opts.Secret == "" {
		return "", fmt.Errorf("mtproto: secret обязателен")
	}

	bindAddr := opts.BindAddr
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}
	port := opts.Port
	if port == 0 {
		port = 8443
	}

	var b strings.Builder
	b.WriteString("# TeleGate MTProto (mtg v2) — сгенерировано автоматически\n")
	b.WriteString("# https://github.com/9seconds/mtg\n\n")
	fmt.Fprintf(&b, "secret = %q\n", opts.Secret)
	fmt.Fprintf(&b, "bind-to = %q\n", fmt.Sprintf("%s:%d", bindAddr, port))

	if opts.Concurrency > 0 {
		b.WriteString("\n[network]\n")
		fmt.Fprintf(&b, "max-connections = %d\n", opts.Concurrency)
	}

	return b.String(), nil
}

// MTProtoServiceUnit — systemd-юнит для запуска mtg на ноде.
func MTProtoServiceUnit(configPath string) string {
	return fmt.Sprintf(`[Unit]
Description=TeleGate MTProto proxy (mtg)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mtg run %s
Restart=always
RestartSec=3
DynamicUser=true
LimitNOFILE=65536
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`, configPath)
}
