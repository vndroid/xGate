// Package config 加载并校验 xgate 的 YAML 配置。
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	API               API           `yaml:"api"`
	DB                string        `yaml:"db"`
	NFT               NFT           `yaml:"nft"`
	Conntrack         Conntrack     `yaml:"conntrack"`
	ReconcileInterval time.Duration `yaml:"reconcile_interval"`
	MinPrefixLen      MinPrefixLen  `yaml:"min_prefix_len"`
	Forwards          []Forward     `yaml:"forwards"`
}

type API struct {
	// Listen 为 "host:port" 或 "unix:/path/to.sock"。
	Listen    string `yaml:"listen"`
	Token     string `yaml:"token"`
	TokenFile string `yaml:"token_file"`
	TLS       TLS    `yaml:"tls"`
}

type TLS struct {
	Cert     string `yaml:"cert"`
	Key      string `yaml:"key"`
	ClientCA string `yaml:"client_ca"` // 设置后启用 mTLS
}

type NFT struct {
	Binary string `yaml:"binary"`
	Table  string `yaml:"table"`
}

type Conntrack struct {
	Binary string `yaml:"binary"`
}

// MinPrefixLen 规定不加 force 时允许的最短前缀，用来挡住 0.0.0.0/0 这类过宽网段。
type MinPrefixLen struct {
	IPv4 int `yaml:"ipv4"`
	IPv6 int `yaml:"ipv6"`
}

type Forward struct {
	Name       string   `yaml:"name"`
	ListenPort uint16   `yaml:"listen_port"`
	TargetPort uint16   `yaml:"target_port"`
	Protocols  []string `yaml:"protocols"`
	// ProtectTarget 为 true 时丢弃从外部直接访问 target_port 的流量，
	// 只放行经过 redirect 的连接和来自 lo 的连接。
	ProtectTarget *bool `yaml:"protect_target"`
}

func (f Forward) Protected() bool { return f.ProtectTarget == nil || *f.ProtectTarget }

func Default() Config {
	return Config{
		API:               API{Listen: "127.0.0.1:7070"},
		DB:                "/var/lib/xgate/xgate.db",
		NFT:               NFT{Binary: "nft", Table: "xgate"},
		Conntrack:         Conntrack{Binary: "conntrack"},
		ReconcileInterval: 30 * time.Second,
		MinPrefixLen:      MinPrefixLen{IPv4: 8, IPv6: 32},
	}
}

// Load 读取配置文件，填充默认值并校验。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.API.TokenFile != "" {
		if cfg.API.Token != "" {
			return nil, errors.New("api.token and api.token_file are mutually exclusive")
		}
		b, err := os.ReadFile(cfg.API.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("read api.token_file: %w", err)
		}
		cfg.API.Token = strings.TrimSpace(string(b))
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

var identRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)

func (c *Config) Validate() error {
	if !identRe.MatchString(c.NFT.Table) {
		return fmt.Errorf("nft.table %q must match %s", c.NFT.Table, identRe)
	}
	if c.DB == "" {
		return errors.New("db must be set")
	}
	if c.ReconcileInterval < time.Second {
		return errors.New("reconcile_interval must be at least 1s")
	}
	if c.MinPrefixLen.IPv4 < 0 || c.MinPrefixLen.IPv4 > 32 || c.MinPrefixLen.IPv6 < 0 || c.MinPrefixLen.IPv6 > 128 {
		return errors.New("min_prefix_len out of range")
	}
	if err := c.API.validate(); err != nil {
		return err
	}
	if len(c.Forwards) == 0 {
		return errors.New("at least one entry in forwards is required")
	}
	names := map[string]bool{}
	listen := map[string]string{}
	for i := range c.Forwards {
		f := &c.Forwards[i]
		if f.Name == "" {
			f.Name = fmt.Sprintf("forward%d", i)
		}
		if names[f.Name] {
			return fmt.Errorf("duplicate forward name %q", f.Name)
		}
		names[f.Name] = true
		if f.ListenPort == 0 || f.TargetPort == 0 {
			return fmt.Errorf("forward %q: listen_port and target_port must be set", f.Name)
		}
		if f.ListenPort == f.TargetPort {
			return fmt.Errorf("forward %q: listen_port equals target_port", f.Name)
		}
		if len(f.Protocols) == 0 {
			f.Protocols = []string{"tcp", "udp"}
		}
		seen := map[string]bool{}
		for _, p := range f.Protocols {
			if p != "tcp" && p != "udp" {
				return fmt.Errorf("forward %q: unsupported protocol %q", f.Name, p)
			}
			if seen[p] {
				return fmt.Errorf("forward %q: duplicate protocol %q", f.Name, p)
			}
			seen[p] = true
			key := fmt.Sprintf("%s/%d", p, f.ListenPort)
			if other, ok := listen[key]; ok {
				return fmt.Errorf("forward %q: %s already used by forward %q", f.Name, key, other)
			}
			listen[key] = f.Name
		}
	}
	// 一个 forward 的监听端口不能同时是另一个 forward 受保护的目标端口，否则会被 input 链丢弃。
	for _, f := range c.Forwards {
		for _, g := range c.Forwards {
			if g.Protected() && f.ListenPort == g.TargetPort {
				return fmt.Errorf("forward %q listens on %d, which is the protected target port of %q", f.Name, f.ListenPort, g.Name)
			}
		}
	}
	return nil
}

func (a *API) validate() error {
	if (a.TLS.Cert == "") != (a.TLS.Key == "") {
		return errors.New("api.tls.cert and api.tls.key must be set together")
	}
	if a.TLS.ClientCA != "" && a.TLS.Cert == "" {
		return errors.New("api.tls.client_ca requires api.tls.cert and api.tls.key")
	}
	if path, ok := strings.CutPrefix(a.Listen, "unix:"); ok {
		if path == "" {
			return errors.New("api.listen: empty unix socket path")
		}
		return nil
	}
	host, _, err := net.SplitHostPort(a.Listen)
	if err != nil {
		return fmt.Errorf("api.listen: %w", err)
	}
	if a.Token == "" && a.TLS.ClientCA == "" && !isLoopback(host) {
		return fmt.Errorf("api.listen %q is not loopback: set api.token/api.token_file or api.tls.client_ca", a.Listen)
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}
