package generator

import (
	"encoding/json"
	"testing"
)

func TestBuildSingboxConfig(t *testing.T) {
	vlessURL := "vless://b83c21a4-9e32-4299-8ab2-94fa108a7b90@speedtest.net:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=speedtest.net&fp=chrome&pbk=Z19xK3L0x9j4&sid=1a2b#Test"
	blacklistCIDR := []string{"1.1.1.0/24"}
	blacklistCountries := []string{"CN", "IR"}

	data, err := BuildSingboxConfig(8443, vlessURL, blacklistCIDR, blacklistCountries)
	if err != nil {
		t.Fatalf("Ошибка генерации конфига: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Сгенерированный конфиг не является валидным JSON: %v", err)
	}
}
