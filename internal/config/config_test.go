package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(write(t, `
forwards:
  - listen_port: 35353
    target_port: 8080
`))
	if err != nil {
		t.Fatal(err)
	}
	f := cfg.Forwards[0]
	if f.Name != "forward0" || strings.Join(f.Protocols, ",") != "tcp,udp" || !f.Protected() {
		t.Errorf("unexpected forward defaults: %+v", f)
	}
	if cfg.Limits.MaxEntries != 10000 || cfg.Limits.AuditRetention != Duration(90*24*time.Hour) || cfg.Limits.MaxTTL != Duration(365*24*time.Hour) {
		t.Errorf("unexpected limits: %+v", cfg.Limits)
	}
	if cfg.ReconcileInterval != 30*time.Second || cfg.NFT.Table != "xgate" || cfg.API.Listen != "127.0.0.1:7070" {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadTokenFile(t *testing.T) {
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(write(t, `
api: {listen: "0.0.0.0:7070", token_file: "`+tok+`"}
forwards: [{listen_port: 35353, target_port: 8080}]
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.API.Token != "s3cret" {
		t.Errorf("token = %q", cfg.API.Token)
	}
}

func TestValidateErrors(t *testing.T) {
	cases := map[string]string{
		"public listen without auth": `
api: {listen: "0.0.0.0:7070"}
forwards: [{listen_port: 35353, target_port: 8080}]`,
		"no forwards": `db: /tmp/x.db`,
		"zero ipv4 min prefix": `
min_prefix_len: {ipv4: 0}
forwards: [{listen_port: 35353, target_port: 8080}]`,
		"zero ipv6 min prefix": `
min_prefix_len: {ipv6: 0}
forwards: [{listen_port: 35353, target_port: 8080}]`,
		"ipv4 min prefix too long": `
min_prefix_len: {ipv4: 33}
forwards: [{listen_port: 35353, target_port: 8080}]`,
		"zero max ttl": `
limits: {max_ttl: 0s}
forwards: [{listen_port: 35353, target_port: 8080}]`,
		"zero max entries": `
limits: {max_entries: 0}
forwards: [{listen_port: 35353, target_port: 8080}]`,
		"negative audit retention": `
limits: {audit_retention: -1h}
forwards: [{listen_port: 35353, target_port: 8080}]`,
		"same port": `
forwards: [{listen_port: 8080, target_port: 8080}]`,
		"bad protocol": `
forwards: [{listen_port: 35353, target_port: 8080, protocols: [sctp]}]`,
		"duplicate listen": `
forwards:
  - {name: a, listen_port: 35353, target_port: 8080}
  - {name: b, listen_port: 35353, target_port: 8081, protocols: [udp]}`,
		"listen on protected target": `
forwards:
  - {name: a, listen_port: 35353, target_port: 8080}
  - {name: b, listen_port: 8080, target_port: 9090}`,
		"bad table": `
nft: {table: "x-gate"}
forwards: [{listen_port: 35353, target_port: 8080}]`,
		"unknown field": `
forwards: [{listen_port: 35353, target_port: 8080, typo: 1}]`,
	}
	for name, content := range cases {
		if _, err := Load(write(t, content)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestLimitDurations(t *testing.T) {
	const fwd = "\nforwards: [{listen_port: 35353, target_port: 8080}]\n"
	for _, v := range []string{"0", "0s"} {
		cfg, err := Load(write(t, "limits: {audit_retention: "+v+"}"+fwd))
		if err != nil || cfg.Limits.AuditRetention != 0 {
			t.Errorf("audit_retention %s: %+v, %v; want 0 (keep forever)", v, cfg, err)
		}
	}
	cfg, err := Load(write(t, "limits: {audit_retention: 720h}"+fwd))
	if err != nil || cfg.Limits.AuditRetention != Duration(720*time.Hour) {
		t.Errorf("audit_retention 720h: %+v, %v", cfg, err)
	}
	// 不带单位的非零整数含义不明，必须报错。
	if _, err := Load(write(t, "limits: {audit_retention: 5}"+fwd)); err == nil {
		t.Error("audit_retention 5: expected error")
	}
	// max_ttl 没有"0 表示不限制"的语义，裸 0 要得到和 0s 一样清楚的校验错误。
	if _, err := Load(write(t, "limits: {max_ttl: 0}"+fwd)); err == nil || !strings.Contains(err.Error(), "at least 1s") {
		t.Errorf("max_ttl 0: %v, want the validation error", err)
	}
}

func TestForwardNames(t *testing.T) {
	for name, ok := range map[string]bool{
		"default":               true,
		"my-ssh.v2":             true,
		"2222_ssh":              true,
		`a"b`:                   false,
		`a\`:                    false,
		"café":                  false,
		"a\x00b":                false,
		"-leading-dash":         false,
		strings.Repeat("x", 64): true,
		strings.Repeat("x", 65): false,
	} {
		c := Default()
		c.Forwards = []Forward{{Name: name, ListenPort: 35353, TargetPort: 8080}}
		if err := c.Validate(); (err == nil) != ok {
			t.Errorf("name %q: err = %v, want ok=%v", name, err, ok)
		}
	}
}

func TestListenAcceptsUnixAndLoopback(t *testing.T) {
	for _, l := range []string{"unix:/run/xgate/api.sock", "[::1]:7070", "localhost:7070"} {
		c := Default()
		c.API.Listen = l
		c.Forwards = []Forward{{ListenPort: 35353, TargetPort: 8080}}
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", l, err)
		}
	}
}

func TestFileErrorHintsOnPermission(t *testing.T) {
	denied := &fs.PathError{Op: "open", Path: "/etc/xgate/token", Err: fs.ErrPermission}
	if err := FileError("api.token_file", denied); !errors.Is(err, fs.ErrPermission) || !strings.Contains(err.Error(), "chgrp xgate") {
		t.Errorf("permission error = %v, want a fix hint", err)
	}
	missing := &fs.PathError{Op: "open", Path: "/etc/xgate/token", Err: fs.ErrNotExist}
	if err := FileError("api.token_file", missing); strings.Contains(err.Error(), "chgrp") {
		t.Errorf("missing file error should not suggest chgrp: %v", err)
	}
}
