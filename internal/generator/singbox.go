package generator

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type Config struct {
	Log       LogConfig   `json:"log"`
	Inbounds  []Inbound   `json:"inbounds"`
	Outbounds []Outbound  `json:"outbounds"`
	Route     RouteConfig `json:"route"`
}

type LogConfig struct {
	Level     string `json:"level"`
	Timestamp bool   `json:"timestamp"`
}

type Inbound struct {
	Type                     string            `json:"type"`
	Tag                      string            `json:"tag"`
	Listen                   string            `json:"listen"`
	ListenPort               int               `json:"listen_port"`
	Sniff                    bool              `json:"sniff,omitempty"`
	SniffOverrideDestination bool              `json:"sniff_override_destination,omitempty"`
	Users                    []InboundUser     `json:"users,omitempty"`
	TLS                      *InboundTLSConfig `json:"tls,omitempty"`
	// Поля для HTTP/WS inbound (Telegram Web Proxy)
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
}

type InboundUser struct {
	Name   string `json:"name,omitempty"`
	Secret string `json:"secret,omitempty"`
}

type InboundTLSConfig struct {
	Enabled    bool   `json:"enabled"`
	ServerName string `json:"server_name,omitempty"`
}

type Outbound struct {
	Type           string           `json:"type"`
	Tag            string           `json:"tag"`
	Server         string           `json:"server,omitempty"`
	ServerPort     int              `json:"server_port,omitempty"`
	UUID           string           `json:"uuid,omitempty"`
	Flow           string           `json:"flow,omitempty"`
	PacketEncoding string           `json:"packet_encoding,omitempty"`
	Network        string           `json:"network,omitempty"`
	TLS            *TLSConfig       `json:"tls,omitempty"`
	Transport      *TransportConfig `json:"transport,omitempty"`
}

type TLSConfig struct {
	Enabled    bool           `json:"enabled"`
	ServerName string         `json:"server_name,omitempty"`
	Insecure   bool           `json:"insecure,omitempty"`
	UTLS       *UTLSConfig    `json:"utls,omitempty"`
	Reality    *RealityConfig `json:"reality,omitempty"`
}

type UTLSConfig struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type RealityConfig struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id,omitempty"`
}

// TransportConfig — настройки транспорта VLESS (ws/grpc/http).
type TransportConfig struct {
	Type        string            `json:"type,omitempty"`
	Path        string            `json:"path,omitempty"`
	Host        string            `json:"host,omitempty"`
	ServiceName string            `json:"service_name,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}

type RouteConfig struct {
	Rules               []Rule `json:"rules"`
	Final               string `json:"final"`
	AutoDetectInterface bool   `json:"auto_detect_interface"`
}

type Rule struct {
	IPCIDR   []string `json:"ip_cidr,omitempty"`
	GeoIP    []string `json:"geoip,omitempty"`
	Outbound string   `json:"outbound"`
}

type ProxyOptions struct {
	WebProxyEnabled bool
	WebProxyPort    int
	WebProxyPath    string

	MTProtoEnabled bool
	MTProtoPort    int
	MTProtoSecret  string
	MTProtoSNI     string

	VlessURL           string
	BlacklistCIDR      []string
	BlacklistCountries []string
}

func BuildDualProxyConfig(opts ProxyOptions) ([]byte, error) {
	cfg := Config{
		Log: LogConfig{
			Level:     "info",
			Timestamp: true,
		},
		Inbounds: []Inbound{},
		Outbounds: []Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: "block", Tag: "block"},
		},
		Route: RouteConfig{
			Rules:               []Rule{},
			Final:               "direct",
			AutoDetectInterface: true,
		},
	}

	// 1. Inbound Web Proxy — HTTP inbound для приёма трафика Telegram Web Proxy.
	//    Telegram подключается по HTTP/HTTPS с PUT-запросом к /proxy?secret=...
	if opts.WebProxyEnabled && opts.WebProxyPort > 0 {
		path := opts.WebProxyPath
		if path == "" {
			path = "/"
		}
		cfg.Inbounds = append(cfg.Inbounds, Inbound{
			Type:       "http",
			Tag:        "tg-web-inbound",
			Listen:     "::",
			ListenPort: opts.WebProxyPort,
			Path:       path,
		})
	}

	// 2. Inbound MTProto Fake-TLS
	if opts.MTProtoEnabled && opts.MTProtoPort > 0 {
		inboundMT := Inbound{
			Type:       "shadowsocks", // Либо нативный туннель sing-box
			Tag:        "tg-mtproto-inbound",
			Listen:     "::",
			ListenPort: opts.MTProtoPort,
		}
		if opts.MTProtoSNI != "" {
			inboundMT.TLS = &InboundTLSConfig{
				Enabled:    true,
				ServerName: opts.MTProtoSNI,
			}
		}
		cfg.Inbounds = append(cfg.Inbounds, inboundMT)
	}

	// 3. Черный список IP / CIDR
	if len(opts.BlacklistCIDR) > 0 {
		cfg.Route.Rules = append(cfg.Route.Rules, Rule{
			IPCIDR:   opts.BlacklistCIDR,
			Outbound: "block",
		})
	}

	// 4. Черный список стран (GeoIP)
	if len(opts.BlacklistCountries) > 0 {
		countries := make([]string, len(opts.BlacklistCountries))
		for i, c := range opts.BlacklistCountries {
			countries[i] = strings.ToLower(c)
		}
		cfg.Route.Rules = append(cfg.Route.Rules, Rule{
			GeoIP:    countries,
			Outbound: "block",
		})
	}

	// 5. Исходящий маршрут (Direct или VLESS Relay)
	if opts.VlessURL != "" {
		vlessOutbound, err := ParseVlessLink(opts.VlessURL)
		if err != nil {
			return nil, fmt.Errorf("ошибка парсинга VLESS: %w", err)
		}
		cfg.Outbounds = append(cfg.Outbounds, *vlessOutbound)
		cfg.Route.Final = "vless-upstream"
	}

	return json.MarshalIndent(cfg, "", "  ")
}

func ParseVlessLink(raw string) (*Outbound, error) {
	if !strings.HasPrefix(raw, "vless://") {
		return nil, fmt.Errorf("ссылка должна начинаться с vless://")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		port = 443
	}

	uuid := u.User.Username()
	if uuid == "" {
		return nil, fmt.Errorf("UUID не найден в ссылке")
	}

	q := u.Query()
	out := &Outbound{
		Type:           "vless",
		Tag:            "vless-upstream",
		Server:         u.Hostname(),
		ServerPort:     port,
		UUID:           uuid,
		Flow:           q.Get("flow"),
		PacketEncoding: "xudp",
	}

	// Транспорт: tcp, ws, grpc, http
	transportType := q.Get("type")
	if transportType != "" && transportType != "tcp" {
		out.Network = transportType
		out.Transport = &TransportConfig{
			Type: transportType,
		}
		switch transportType {
		case "ws":
			out.Transport.Path = q.Get("path")
			out.Transport.Host = q.Get("host")
			if ht := q.Get("headerType"); ht != "" {
				out.Transport.Headers = map[string]string{"Host": ht}
			}
		case "grpc":
			out.Transport.ServiceName = q.Get("serviceName")
			if mh := q.Get("mode"); mh != "" {
				out.Transport.Host = mh
			}
		case "http":
			out.Transport.Path = q.Get("path")
			out.Transport.Host = q.Get("host")
		}
	}

	security := strings.ToLower(q.Get("security"))
	if security == "reality" || security == "tls" {
		out.TLS = &TLSConfig{
			Enabled:    true,
			ServerName: q.Get("sni"),
		}

		fp := q.Get("fp")
		if fp == "" {
			fp = "chrome"
		}
		out.TLS.UTLS = &UTLSConfig{
			Enabled:     true,
			Fingerprint: fp,
		}

		if security == "reality" {
			out.TLS.Reality = &RealityConfig{
				Enabled:   true,
				PublicKey: q.Get("pbk"),
				ShortID:   q.Get("sid"),
			}
		}
	}

	return out, nil
}
