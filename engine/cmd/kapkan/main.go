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
	"strings"
	"syscall"

	"github.com/kapkan-io/kapkan/internal/app"
	"github.com/kapkan-io/kapkan/internal/buildinfo"
	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/logging"
)

func main() {
	var (
		configPath  = flag.String("config", "configs/dev.yaml", "path to YAML config file")
		logFormat   = flag.String("log-format", "json", "log format: json or text")
		logLevel    = flag.String("log-level", "info", "log level: debug, info, warn, error")
		dumpSchema  = flag.Bool("dump-schema", false, "print the config JSON schema to stdout and exit")
		checkConfig = flag.String("check-config", "", "validate the config file at this path and exit (0 = valid, 1 = invalid)")
		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	// Utility subcommands exit before the daemon starts; they never open
	// listeners or send announcements.
	if *showVersion {
		fmt.Println("kapkan", buildinfo.String())
		return
	}
	if *dumpSchema {
		b, err := config.GenerateSchema()
		if err != nil {
			fmt.Fprintln(os.Stderr, "dump-schema:", err)
			os.Exit(1)
		}
		if _, err := os.Stdout.Write(b); err != nil {
			fmt.Fprintln(os.Stderr, "dump-schema:", err)
			os.Exit(1)
		}
		return
	}
	if *checkConfig != "" {
		os.Exit(checkConfigFile(*checkConfig))
	}

	log := logging.New(*logFormat, *logLevel)
	if err := run(*configPath, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// checkConfigFile loads and fully validates a config file, printing a human
// summary of the resolved configuration (or the validation error) and returning
// the process exit code. It runs the engine's real Parse+validate chain, so it
// catches the cross-field rules a static schema cannot express, on the
// operator's own binary. The resolved per-group mitigation is shown so an
// inherited flowspec/divert that silently degrades on a total group is visible.
func checkConfigFile(path string) int {
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID  %s\n  %v\n", path, err)
		return 1
	}
	mode := "DRY-RUN (announcements simulated)"
	if !cfg.DryRun {
		mode = "LIVE (announcements WILL be sent)"
	}
	fmt.Printf("OK  %s\n", path)
	fmt.Printf("  mode:      %s\n", mode)
	fmt.Printf("  networks:  %s\n", strings.Join(cfg.Networks, ", "))
	fmt.Printf("  listeners: sflow=%q netflow=%q\n", cfg.Listen.SFlow, cfg.Listen.NetFlow)
	fmt.Printf("  groups:    %d (including the implicit global group)\n", len(cfg.Groups))
	for _, g := range cfg.Groups {
		fmt.Printf("    - %-20s calc=%-8s ban=%-5t  %s\n", g.Name, g.Calc, g.BanEnabled, ladderString(g.Escalation))
	}
	return 0
}

// ladderString renders a resolved escalation ladder, e.g.
// "none@0s -> flowspec@30s -> blackhole@120s".
func ladderString(stages []config.EscalationStage) string {
	if len(stages) == 0 {
		return "mitigation=none"
	}
	parts := make([]string, len(stages))
	for i, s := range stages {
		parts[i] = fmt.Sprintf("%s@%ds", s.Action, s.AfterSeconds)
	}
	return "mitigation=" + strings.Join(parts, " -> ")
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

	// Shut down asking BGP peers to retain kapkan's mitigation routes (Graceful
	// Restart) rather than flushing them the instant the session drops, so an
	// upgrade restart does not immediately un-mitigate active attacks.
	application.StopForRestart()
	log.Info("kapkan stopped")
	return nil
}
