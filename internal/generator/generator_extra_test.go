package generator

import (
	"strings"
	"testing"
)

func TestParseVlessLinkWithWSTransport(t *testing.T) {
	link := "vless://11111111-2222-3333-4444-555555555555@example.com:8443" +
		"?encryption=none&security=tls&sni=example.com&fp=firefox&type=ws&path=%2Fws&host=example.com#ws"

	out, err := ParseVlessLink(link)
	if err != nil {
		t.Fatalf("парсинг VLESS не удался: %v", err)
	}

	if out.Network != "ws" {
		t.Errorf("ожинался network=ws, получено %q", out.Network)
	}
	if out.Transport == nil || out.Transport.Type != "ws" {
		t.Fatalf("transport не распарсен: %+v", out.Transport)
	}
	if out.Transport.Path != "/ws" {
		t.Errorf("ожинался path=/ws, получено %q", out.Transport.Path)
	}
	if out.TLS == nil || out.TLS.ServerName != "example.com" {
		t.Errorf("TLS не распарсен корректно: %+v", out.TLS)
	}
}

func TestParseVlessLinkGRPC(t *testing.T) {
	link := "vless://uuid-here@host:443?type=grpc&serviceName=grpcsvc&security=tls&sni=host"
	out, err := ParseVlessLink(link)
	if err != nil {
		t.Fatalf("парсинг VLESS не удался: %v", err)
	}
	if out.Transport == nil || out.Transport.ServiceName != "grpcsvc" {
		t.Errorf("grpc serviceName не распарсен: %+v", out.Transport)
	}
}

func TestBuildMTProtoTOML(t *testing.T) {
	toml, err := BuildMTProtoTOML(MTProtoOptions{
		BindAddr: "0.0.0.0",
		Port:     8443,
		Secret:   "ee473ce5d4958eb5f968c87680a23854a0676f6f676c652e636f6d",
	})
	if err != nil {
		t.Fatalf("ошибка генерации TOML: %v", err)
	}

	if !strings.Contains(toml, `secret = "ee473ce5`) {
		t.Errorf("TOML не содержит secret:\n%s", toml)
	}
	if !strings.Contains(toml, `bind-to = "0.0.0.0:8443"`) {
		t.Errorf("TOML не содержит bind-to:\n%s", toml)
	}
}

func TestBuildMTProtoTOMLRequiresSecret(t *testing.T) {
	if _, err := BuildMTProtoTOML(MTProtoOptions{Port: 8443}); err == nil {
		t.Error("ожидалась ошибка при пустом secret")
	}
}
