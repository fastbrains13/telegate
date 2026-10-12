package generator

import (
	"encoding/json"
	"net/url"
	"strconv"
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
	Type   string `json:"type"`
	Tag    string `json:"tag"`
	Listen string `json:"listen"`
	Port   int    `json:"listen_port"`
}

type Outbound struct {
	Type       string     `json:"type"`
	Tag        string     `json:"tag"`
	Server     string     `json:"server,omitempty"`
	ServerPort int        `json:"server_port,omitempty"`
	UUID       string     `json:"uuid,omitempty"`
	Flow       string     `json:"flow,omitempty"`
	TLS        *TLSConfig `json:"tls,omitempty"`
}

type TLSConfig struct {
	Enabled    bool          `json:"enabled"`
	ServerName string        `json:"server_name,omitempty"`
	Reality    *RealityConfig `json:"reality,omitempty"`
}

type RealityConfig struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id,omitempty"`
}

type RouteConfig struct {
	Rules []Rule `json:"rules"`
}

type Rule struct {
	IPCIDR   []string `json:"ip_cidr,omitempty"`
	GeoIP    []string `json:"geoip,omitempty"`
	Outbound string   `json:"outbound"`
}

func BuildSingboxConfig(webProxyPort int, vlessURL string, blacklistCIDR []string, blacklistCountries []string) ([]byte, error) {
	cfg := Config{
		Log: LogConfig{Level: "info", Timestamp: true},
		Inbounds: []Inbound{
			{
				Type:   "mixed",
				Tag:    "tg-inbound",
				Listen: "::",
				Port:   webProxyPort,
			},
		},
		Outbounds: []Outbound{
			{Type: "direct", Tag: "direct"},
			{Type: "block", Tag: "block"},
		},
		Route: RouteConfig{Rules: []Rule{}},
	}

	if len(blacklistCIDR) > 0 {
		cfg.Route.Rules = append(cfg.Route.Rules, Rule{
			IPCIDR:   blacklistCIDR,
			Outbound: "block",
		})
	}

	if len(blacklistCountries) > 0 {
		cfg.Route.Rules = append(cfg.Route.Rules, Rule{
			GeoIP:    blacklistCountries,
			Outbound: "block",
		})
	}

	if vlessURL != "" {
		if vlessOutbound, err := parseVlessLink(vlessURL); err == nil {
			cfg.Outbounds = append(cfg.Outbounds, *vlessOutbound)
			cfg.Route.Rules = append(cfg.Route.Rules, Rule{
				Outbound: "vless-upstream",
			})
		}
	} else {
		cfg.Route.Rules = append(cfg.Route.Rules, Rule{
			Outbound: "direct",
		})
	}

	return json.MarshalIndent(cfg, "", "  ")
}

func parseVlessLink(raw string) (*Outbound, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(u.Port())
	q := u.Query()

	out := &Outbound{
		Type:       "vless",
		Tag:        "vless-upstream",
		Server:     u.Hostname(),
		ServerPort: port,
		UUID:       u.User.Username(),
		Flow:       q.Get("flow"),
	}

	if q.Get("security") == "reality" {
		out.TLS = &TLSConfig{
			Enabled:    true,
			ServerName: q.Get("sni"),
			Reality: &RealityConfig{
				Enabled:   true,
				PublicKey: q.Get("pbk"),
				ShortID:   q.Get("sid"),
			},
		}
	}
	return out, nil
}
