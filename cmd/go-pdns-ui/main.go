package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/croessner/go-pdns-ui/internal/app"
)

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-version", "version":
			fmt.Printf("go-pdns-ui version=%s commit=%s build_date=%s\n", version, commit, buildDate)
			return
		}
	}

	cfg := app.LoadConfigFromEnv()

	logger, err := app.NewLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "go-pdns-ui failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	logger.Info("build_info", "version", version, "commit", commit, "build_date", buildDate)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx, cfg, logger); err != nil {
		logger.Error("go-pdns-ui stopped with error", "error", err)
		os.Exit(1)
	}
}
