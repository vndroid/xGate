// Package config 加载并校验 xgate 的 YAML 配置。
package config

import (
	"errors"
	"fmt"
	"io/fs"
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
	SS                SS            `yaml:"ss"`
	ReconcileInterval time.Duration `yaml:"reconcile_interval"`
	MinPrefixLen      MinPrefixLen  `yaml:"min_prefix_len"`
	Limits            Limits        `yaml:"limits"`
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

// SS 是 iproute2 的 ss，删除白名单并断开连接时用来销毁后端 socket。
type SS struct {
	Binary string `yaml:"binary"`
}

// MinPrefixLen 规定不加 force 时允许的最短前缀，用来挡住 0.0.0.0/0 这类过宽网段。
// Limits 限制控制面的资源占用，防止 token 泄漏或脚本失控时拖垮控制面。
type Limits struct {
	// MaxEntries 是白名单有效条目的上限；达到上限后不能再新增，但可以更新已有条目。
	MaxEntries int `yaml:"max_entries"`
	// AuditRetention 是审计记录的保留时长，0 表示永久保留。
	AuditRetention Duration `yaml:"audit_retention"`
	// MaxTTL 是新增条目时 ttl 的上限；需要更久的条目应不设 ttl（永久）。
	MaxTTL Duration `yaml:"max_ttl"`
}

// Duration 是配置里可以写成 0 的时长。YAML 中裸的 0 是整数，yaml.v3 不能把整数
// 解码成 time.Duration，这里单独放行 0；其它不带单位的整数含义不明，仍然报错。
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode && n.ShortTag() == "!!int" {
		var i int64
		if err := n.Decode(&i); err == nil && i == 0 {
			*d = 0
			return nil
		}
	}
	var v time.Duration
	if err := n.Decode(&v); err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

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
		SS:                SS{Binary: "ss"},
		ReconcileInterval: 30 * time.Second,
		MinPrefixLen:      MinPrefixLen{IPv4: 8, IPv6: 32},
		Limits:            Limits{MaxEntries: 10000, AuditRetention: Duration(90 * 24 * time.Hour), MaxTTL: Duration(365 * 24 * time.Hour)},
	}
}

// Load 读取配置文件，填充默认值并校验。
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, FileError("config", err)
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
			return nil, FileError("api.token_file", err)
		}
		cfg.API.Token = strings.TrimSpace(string(b))
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// FileError 包装读取配置引用的文件时的错误。systemd 下控制面以 xgate 用户运行，
// 权限不足通常是沿用了只有 root 可读的文件，这里直接给出修复方法。
func FileError(field string, err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("read %s: %w (the service runs as user xgate: make the file readable by it and its parent directories searchable, e.g. chgrp xgate FILE && chmod 0640 FILE)", field, err)
	}
	return fmt.Errorf("read %s: %w", field, err)
}

var identRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)

// forwardNameRe 限制 forward 名称的字符集。名称会写进 nft 规则的 comment，nft 的
// 字符串不支持转义，引号等字符会让整个同步事务失败。
var forwardNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

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
	// 0 会让"前缀短于下限"的判断恒为假，0.0.0.0/0 不加 force 也能写入，所以至少为 1。
	if c.MinPrefixLen.IPv4 < 1 || c.MinPrefixLen.IPv4 > 32 {
		return fmt.Errorf("min_prefix_len.ipv4 must be between 1 and 32, got %d", c.MinPrefixLen.IPv4)
	}
	if c.MinPrefixLen.IPv6 < 1 || c.MinPrefixLen.IPv6 > 128 {
		return fmt.Errorf("min_prefix_len.ipv6 must be between 1 and 128, got %d", c.MinPrefixLen.IPv6)
	}
	if c.Limits.MaxEntries < 1 {
		return errors.New("limits.max_entries must be at least 1")
	}
	if c.Limits.AuditRetention < 0 {
		return errors.New("limits.audit_retention must not be negative")
	}
	if c.Limits.MaxTTL < Duration(time.Second) {
		return errors.New("limits.max_ttl must be at least 1s")
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
		if !forwardNameRe.MatchString(f.Name) {
			return fmt.Errorf("forward name %q must match %s", f.Name, forwardNameRe)
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
