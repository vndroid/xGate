package config

import (
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
