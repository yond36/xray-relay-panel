package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"xrayrelay/internal/engine"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(engine.RunNodeCLI(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
