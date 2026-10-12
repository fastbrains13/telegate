package generator

import (
	"encoding/json"
	"testing"
)

func TestBuildDualProxyConfig(t *testing.T) {
	opts := ProxyOptions{
		WebProxyEnabled:    true,
		WebProxyPort:       443,
		MTProtoEnabled:     true,
		MTProtoPort:        8443,
		MTProtoSNI:         "yandex.ru",
		VlessURL:           "vless://b83c21a4-9e32-4299-8ab2-94fa108a7b90@speedtest.net:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=speedtest.net&fp=chrome&pbk=Z19xK3L0x9j4&sid=1a2b#Relay",
		BlacklistCIDR:      []string{"185.220.101.0/24", "1.1.1.1"},
		BlacklistCountries: []string{"CN", "IR", "RU"},
	}

	raw, err := BuildDualProxyConfig(opts)
	if err != nil {
		t.Fatalf("Ошибка генерации конфигурации: %v", err)
	}

	var parsed Config
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("Сгенерированный конфиг не валидный JSON: %v", err)
	}

	// Проверка inbounds
	if len(parsed.Inbounds) != 2 {
		t.Errorf("Ожидалось 2 inbound (web + mtproto), получено: %d", len(parsed.Inbounds))
	}

	// Проверка правил маршрутизации
	if len(parsed.Route.Rules) != 2 {
		t.Errorf("Ожидалось 2 правила блокировки (CIDR + GeoIP), получено: %d", len(parsed.Route.Rules))
	}

	// Проверка VLESS Reality Outbound
	var foundVless bool
	for _, out := range parsed.Outbounds {
		if out.Tag == "vless-upstream" {
			foundVless = true
			if out.TLS == nil || out.TLS.Reality == nil || out.TLS.Reality.PublicKey != "Z19xK3L0x9j4" {
				t.Errorf("Некорректно распарсен Reality Public Key: %+v", out.TLS)
			}
		}
	}
	if !foundVless {
		t.Errorf("VLESS Outbound не найден в конфигурации")
	}
}

func TestInvalidVlessLink(t *testing.T) {
	_, err := ParseVlessLink("invalid://test")
	if err == nil {
		t.Errorf("Ожидалась ошибка для невалидной ссылки")
	}
}
