package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"asmtool/internal/app"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return app.RunCLI(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
}
