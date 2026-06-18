// Command kapkan is the single-binary DDoS detection and mitigation daemon.
// It ingests flow telemetry, detects volumetric attacks against configured
// prefixes, and (when not in dry-run) triggers RTBH blackhole mitigation via
// embedded BGP, with notifications and a REST API.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/kapkan-io/kapkan/internal/app"
	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/logging"
)

func main() {
	var (
		configPath = flag.String("config", "configs/dev.yaml", "path to YAML config file")
		logFormat  = flag.String("log-format", "json", "log format: json or text")
		logLevel   = flag.String("log-level", "info", "log level: debug, info, warn, error")
	)
	flag.Parse()

	log := logging.New(*logFormat, *logLevel)
	if err := run(*configPath, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(configPath string, log *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	store := config.NewStore(configPath, cfg)

	log.Info("starting kapkan",
		"dry_run", cfg.DryRun, "networks", cfg.Networks, "thresholds", cfg.Thresholds)
	if cfg.DryRun {
		log.Warn("DRY-RUN mode: BGP announcements are simulated, never sent")
	} else {
		log.Warn("LIVE mode: BGP blackhole announcements WILL be sent to neighbors")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	application, err := app.New(store, log)
	if err != nil {
		return err
	}
	if err := application.Start(ctx); err != nil {
		return err
	}

	// SIGHUP triggers config hot-reload.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if _, err := store.Reload(); err != nil {
					log.Error("config reload failed; keeping previous config", "err", err)
				} else {
					log.Info("config reloaded")
				}
			}
		}
	}()

	log.Info("kapkan running")
	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-application.APIError():
		if err != nil {
			log.Error("api server stopped", "err", err)
		}
	}

	application.Stop()
	log.Info("kapkan stopped")
	return nil
}
