package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/croessner/go-pdns-ui/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	addr := ":8080"
	if err := app.Run(ctx, addr); err != nil {
		log.Printf("go-pdns-ui stopped with error: %v", err)
		os.Exit(1)
	}
}
