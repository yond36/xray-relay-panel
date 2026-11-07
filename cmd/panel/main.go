package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"xrayrelay/internal/api"
	"xrayrelay/internal/engine"
	"xrayrelay/internal/model"
	"xrayrelay/ui"
)

func main() {
	if err := run(); err != nil {
		slog.Error("panel stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	bind := flag.String("bind", env("XRAY_PANEL_BIND", "127.0.0.1:8080"), "HTTP listen address")
	data := flag.String("data", env("XRAY_PANEL_DATA", "./.local/panel"), "private persistent data directory")
	secure := flag.Bool("secure-cookies", os.Getenv("XRAY_PANEL_SECURE_COOKIES") == "1", "use Secure session cookies behind HTTPS")
	version := flag.Bool("version", false, "print version")
	flag.Parse()
	if *version {
		fmt.Println("Xray Relay Panel", model.Version)
		return nil
	}
	dir, err := filepath.Abs(*data)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	runtime := engine.New(engine.Options{DataDir: dir, CoreVersion: model.DefaultCoreVersion})
	app, err := api.New(api.Config{DataDir: dir, Runtime: runtime, SecureCookies: *secure})
	if err != nil {
		return err
	}
	defer app.Close()
	mux := http.NewServeMux()
	mux.Handle("/api/", app)
	mux.Handle("/sub/", app)
	mux.Handle("/healthz", app)
	mux.Handle("/", ui.Handler())
	server := &http.Server{Addr: *bind, Handler: securityHeaders(mux), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 1 << 20}
	shutdownCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() {
		slog.Info("panel ready", "address", *bind, "version", model.Version)
		done <- server.ListenAndServe()
	}()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-shutdownCtx.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
