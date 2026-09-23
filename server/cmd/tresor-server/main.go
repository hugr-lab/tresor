// tresor-server is the reference duckdb-secrets/1 service (specs/003): for tresor's tests and as an
// example to read, not for production.
//
//	tresor-server -config server.yaml
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hugr-lab/tresor/server/internal/api"
	"github.com/hugr-lab/tresor/server/internal/auth"
	"github.com/hugr-lab/tresor/server/internal/config"
	"github.com/hugr-lab/tresor/server/internal/store"
)

func main() {
	configPath := flag.String("config", "server.yaml", "the configuration file")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(*configPath, log); err != nil {
		log.Error("tresor-server stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(configPath string, log *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	var key []byte
	if cfg.Store.Path != "" {
		encoded := os.Getenv(cfg.Store.KeyEnv)
		if encoded == "" {
			return fmt.Errorf("the store key: %s is not set (32 bytes, base64)", cfg.Store.KeyEnv)
		}
		if key, err = base64.StdEncoding.DecodeString(encoded); err != nil {
			return fmt.Errorf("the store key in %s is not base64", cfg.Store.KeyEnv)
		}
	}
	st, err := store.Open(cfg.Store.Path, key)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           api.New(cfg, auth.NewVerifier(cfg.Issuers), st, log).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.Info("tresor-server listening", "listen", listener.Addr().String(), "api", cfg.PublicURL,
		"tls", cfg.TLS.Cert != "", "store", cfg.Store.Path != "")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errs := make(chan error, 1)
	go func() {
		if cfg.TLS.Cert != "" {
			errs <- server.ServeTLS(listener, cfg.TLS.Cert, cfg.TLS.Key)
		} else {
			errs <- server.Serve(listener)
		}
	}()
	select {
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}
