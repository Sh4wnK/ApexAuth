// Command apexauth runs the ApexAuth server (HTTP + gRPC).
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/Sh4wnK/ApexAuth/internal/config"
	"github.com/Sh4wnK/ApexAuth/internal/server"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load()
	if err != nil {
		log.Error("config", "error", err)
		os.Exit(1)
	}
	switch cfg.LogLevel {
	case "debug":
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	case "warn":
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	}

	deps, err := server.Build(context.Background(), cfg, log)
	if err != nil {
		log.Error("build", "error", err)
		os.Exit(1)
	}
	if err := server.Run(deps, cfg, log); err != nil {
		log.Error("run", "error", err)
		os.Exit(1)
	}
}
