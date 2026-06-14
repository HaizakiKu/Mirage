package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/HaizakiKu/mirage/config"
	"github.com/HaizakiKu/mirage/core"
)

func defaultConfigPath() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "mirage", "config.yaml")
	}
	return "/etc/mirage.yaml"
}

func main() {
	cfgPath := flag.String("config", defaultConfigPath(), "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cfg.Mode {
	case "server":
		if cfg.Password == "" {
			log.Fatal("password is required in config")
		}
		if cfg.ACME.Domain == "" && (cfg.TLS.Cert == "" || cfg.TLS.Key == "") {
			log.Fatal("either acme.domain or tls.cert+tls.key must be set in config")
		}
		if cfg.Masquerade.URL == "" {
			log.Fatal("masquerade.url is required in config")
		}
		srv, err := core.NewServer(cfg.AsServerConfig())
		if err != nil {
			log.Fatalf("init server: %v", err)
		}
		if err := srv.Run(ctx); err != nil {
			log.Fatalf("server: %v", err)
		}
	case "client":
		if cfg.Server == "" {
			log.Fatal("server address is required in config")
		}
		if cfg.Password == "" {
			log.Fatal("password is required in config")
		}
		client, err := core.NewClient(cfg.AsClientConfig())
		if err != nil {
			log.Fatalf("init client: %v", err)
		}
		if err := client.Run(ctx); err != nil {
			log.Fatalf("client: %v", err)
		}
	}
}
