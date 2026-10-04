// xgate：基于 CIDR 白名单的四层端口转发控制面。
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vndroid/xGate/internal/api"
	"github.com/vndroid/xGate/internal/config"
	"github.com/vndroid/xGate/internal/conntrack"
	"github.com/vndroid/xGate/internal/nft"
	"github.com/vndroid/xGate/internal/reconcile"
	"github.com/vndroid/xGate/internal/sockets"
	"github.com/vndroid/xGate/internal/store"
)

// version 在构建时通过 -ldflags "-X main.version=..." 注入。
var version = "dev"

const usage = `usage: xgate <command> [flags]

commands:
  serve    run the control plane (HTTP API + reconcile loop)
  render   print the nft transaction that would be applied now
  version  print version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "render":
		err = render(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("xgate", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "xgate:", err)
		os.Exit(1)
	}
}

func loadConfig(name string, args []string) (*config.Config, error) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	path := fs.String("config", "/etc/xgate/config.yaml", "path to config file")
	_ = fs.Parse(args) // ExitOnError：解析失败时直接退出
	return config.Load(*path)
}

type deps struct {
	store *store.Store
	rec   *reconcile.Reconciler
}

func build(cfg *config.Config, log *slog.Logger) (*deps, error) {
	st, err := store.Open(cfg.DB)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	rs := nft.Ruleset{Table: cfg.NFT.Table, Forwards: cfg.Forwards}
	rec := reconcile.New(st, nft.CmdExecutor{Binary: cfg.NFT.Binary}, rs, cfg.ReconcileInterval, log)
	return &deps{store: st, rec: rec}, nil
}

func render(args []string) error {
	cfg, err := loadConfig("render", args)
	if err != nil {
		return err
	}
	d, err := build(cfg, slog.Default())
	if err != nil {
		return err
	}
	defer func() { _ = d.store.Close() }()
	script, _, _, err := d.rec.Script(context.Background())
	if err != nil {
		return err
	}
	fmt.Print(script)
	return nil
}

func serve(args []string) error {
	cfg, err := loadConfig("serve", args)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	d, err := build(cfg, log)
	if err != nil {
		return err
	}
	defer func() { _ = d.store.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 启动时先完整同步一次，把规则和白名单原子地恢复到内核。
	st, err := d.rec.Sync(ctx)
	if err != nil {
		return fmt.Errorf("initial sync: %w", err)
	}
	log.Info("initial sync done", "entries", st.Entries, "elements", st.Elements, "version", version)

	go d.rec.Run(ctx)

	ln, err := listen(cfg.API)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler: (&api.Server{
			Store:     d.store,
			Rec:       d.rec,
			Killer:    conntrack.CmdKiller{Binary: cfg.Conntrack.Binary},
			Sockets:   sockets.CmdDestroyer{Binary: cfg.SS.Binary},
			Forwards:  cfg.Forwards,
			MinPrefix: cfg.MinPrefixLen,
			Token:     cfg.API.Token,
			Log:       log,
		}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	if cfg.API.TLS.Cert != "" {
		if srv.TLSConfig, err = tlsConfig(cfg.API.TLS); err != nil {
			return err
		}
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("api listening", "addr", cfg.API.Listen, "tls", cfg.API.TLS.Cert != "", "mtls", cfg.API.TLS.ClientCA != "")
		if cfg.API.TLS.Cert != "" {
			errc <- srv.ServeTLS(ln, cfg.API.TLS.Cert, cfg.API.TLS.Key)
		} else {
			errc <- srv.Serve(ln)
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	// 只停控制面；内核规则和白名单保持不变，转发不受影响。
	log.Info("shutting down; kernel rules are left in place")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func listen(c config.API) (net.Listener, error) {
	if path, ok := strings.CutPrefix(c.Listen, "unix:"); ok {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		ln, err := net.Listen("unix", path)
		if err != nil {
			return nil, err
		}
		if err := os.Chmod(path, 0o660); err != nil {
			_ = ln.Close()
			return nil, err
		}
		return ln, nil
	}
	return net.Listen("tcp", c.Listen)
}

func tlsConfig(c config.TLS) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.ClientCA != "" {
		pem, err := os.ReadFile(c.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("read client_ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("client_ca: no certificates found")
		}
		tc.ClientCAs, tc.ClientAuth = pool, tls.RequireAndVerifyClientCert
	}
	return tc, nil
}
