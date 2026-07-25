package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Terminalkid09/nyx/collaborator/config"
	"github.com/Terminalkid09/nyx/collaborator/dns"
	"github.com/Terminalkid09/nyx/collaborator/http"
	"github.com/Terminalkid09/nyx/collaborator/storage"
	"github.com/Terminalkid09/nyx/collaborator/webhook"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Println("Nyx Collaborator starting...")

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	store := storage.New(cfg.InteractionTTL)

	if cfg.WebhookURL != "" {
		notifier := webhook.New(cfg.WebhookURL)
		store.SetNotifier(notifier)
	}

	dnsSrv := dns.New(cfg, store)
	httpSrv := http.New(cfg, store)

	errCh := make(chan error, 2)

	go func() {
		if err := dnsSrv.Start(); err != nil {
			errCh <- err
		}
	}()

	go func() {
		if err := httpSrv.Start(); err != nil {
			errCh <- err
		}
	}()

	log.Printf("collaborator ready: domain=%s, dns=:%d, http=:%d",
		cfg.Domain, cfg.DNSPort, cfg.HTTPPort)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("received signal %v, shutting down", sig)
	case err := <-errCh:
		log.Fatalf("server error: %v", err)
	}
}
