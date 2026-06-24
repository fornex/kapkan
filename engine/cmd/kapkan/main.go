// Command kapkan is the single-binary DDoS detection and mitigation daemon.
// It ingests flow telemetry, detects volumetric attacks against configured
// prefixes, and (when not in dry-run) triggers RTBH blackhole mitigation via
// embedded BGP, with notifications and a REST API.
package main

import (
	"context"
	"errors"
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
	"github.com/kapkan-io/kapkan/internal/update"
)

func main() {
	var (
		configPath  = flag.String("config", "configs/dev.yaml", "path to YAML config file")
		logFormat   = flag.String("log-format", "json", "log format: json or text")
		logLevel    = flag.String("log-level", "info", "log level: debug, info, warn, error")
		dumpSchema  = flag.Bool("dump-schema", false, "print the config JSON schema to stdout and exit")
		checkConfig = flag.String("check-config", "", "validate the config file at this path and exit (0 = valid, 1 = invalid)")
		showVersion = flag.Bool("version", false, "print the version and exit")
		checkUpdate = flag.Bool("check-update", false, "check for a newer release and exit (0 = up to date, 10 = update available, 1 = error)")
		pidFile     = flag.String("pid-file", "/run/kapkan/kapkan.pid", "path to the pid file (written on start; read by -s)")
		signalCmd   = flag.String("s", "", "send a signal to the running kapkan and exit: "+signalNames)
	)
	flag.Parse()

	// Utility subcommands exit before the daemon starts; they never open
	// listeners or send announcements.
	if *showVersion {
		fmt.Println("kapkan", buildinfo.String())
		return
	}
	if *checkUpdate {
		os.Exit(checkForUpdate(*configPath))
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
	// `kapkan -s reload|stop|quit` signals a running daemon (via its pid file)
	// and exits — it never starts a daemon of its own.
	if *signalCmd != "" {
		if err := runSignalCommand(*signalCmd, *pidFile); err != nil {
			fmt.Fprintln(os.Stderr, "kapkan -s:", err)
			os.Exit(1)
		}
		return
	}

	log := logging.New(*logFormat, *logLevel)
	if err := run(*configPath, *pidFile, log); err != nil {
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

// checkForUpdate performs a one-shot update check and returns the process exit
// code: 0 (up to date / not comparable), 10 (a newer release is available), or 1
// (config or network error). It works regardless of update_check.enabled — that
// flag gates only the background poll — using the configured channel/url. It is
// the explicit, operator-initiated counterpart to the periodic check.
func checkForUpdate(path string) int {
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return 1
	}
	chk := update.New(update.Config{
		Channel: cfg.UpdateCheck.Channel,
		URL:     cfg.UpdateCheck.URL,
		Current: buildinfo.Version(),
	}, logging.New("text", "error"))

	st, err := chk.CheckOnce(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "update check: %v\n", err)
		return 1
	}
	fmt.Printf("current: %s\n", buildinfo.Version())
	sec := ""
	if st.Security {
		sec = "  (security)"
	}
	fmt.Printf("latest:  %s%s\n", st.LatestVersion, sec)
	if st.Available {
		fmt.Printf("A newer release is available: %s\n", st.URL)
		return 10
	}
	fmt.Println("kapkan is up to date.")
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

func run(configPath, pidPath string, log *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	store := config.NewStore(configPath, cfg)

	// Record our pid so `kapkan -s reload|stop` can find us. A failure here is
	// not fatal — the daemon runs fine, only the CLI signalling shortcut is
	// unavailable (e.g. in dev, where /run/kapkan does not exist). The file is
	// removed on clean shutdown.
	if pidPath != "" {
		if err := writePIDFile(pidPath); err != nil {
			log.Warn("could not write pid file; `kapkan -s reload` will not work", "path", pidPath, "err", err)
		} else {
			defer func() {
				if err := os.Remove(pidPath); err != nil && !errors.Is(err, os.ErrNotExist) {
					log.Warn("could not remove pid file on shutdown", "path", pidPath, "err", err)
				}
			}()
		}
	}

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
