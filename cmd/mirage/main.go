package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/HaizakiKu/mirage/config"
	"github.com/HaizakiKu/mirage/core"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
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
		if cfg.TLS.Cert == "" || cfg.TLS.Key == "" {
			log.Fatal("tls.cert and tls.key are required in config")
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
