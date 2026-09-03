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
	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/logging"
	"github.com/kapkan-io/kapkan/internal/update"
)

func main() {
	// The flags are declared and parsed in cli.go, unchanged in name, default
	// and behaviour — flag.ExitOnError is what flag.CommandLine has always used,
	// so a bad flag still prints usage and exits 2.
	f, err := parseFlags(os.Args[0], os.Args[1:], flag.ExitOnError)
	if err != nil {
		os.Exit(exitUsage) // unreachable under ExitOnError; kept so the error is not ignored
	}

	// POSITIONAL DISPATCH, and note where it sits: after flag.Parse, never
	// before. flag stops at the first non-flag argument, so a flags-only
	// invocation — which is every invocation kapkan has ever accepted — leaves
	// no arguments here and falls straight through to the code below, byte for
	// byte as it always did. See the header of cli.go.
	if len(f.args()) > 0 {
		os.Exit(runSubcommand(f, os.Stdout, os.Stderr))
	}

	// Utility subcommands exit before the daemon starts; they never open
	// listeners or send announcements.
	if f.showVersion {
		fmt.Println("kapkan", buildinfo.String())
		return
	}
	if f.checkUpdate {
		os.Exit(checkForUpdate(f.configPath))
	}
	if f.dumpSchema || f.dumpZonesSchema {
		name, gen := "dump-schema", config.GenerateSchema
		if f.dumpZonesSchema {
			name, gen = "dump-zones-schema", config.GenerateZonesSchema
		}
		b, err := gen()
		if err != nil {
			fmt.Fprintln(os.Stderr, name+":", err)
			os.Exit(1)
		}
		if _, err := os.Stdout.Write(b); err != nil {
			fmt.Fprintln(os.Stderr, name+":", err)
			os.Exit(1)
		}
		return
	}
	if f.checkConfig != "" {
		os.Exit(checkConfigFile(f.checkConfig))
	}
	// `kapkan -s reload|stop|quit` signals a running daemon (via its pid file)
	// and exits — it never starts a daemon of its own.
	if f.signalCmd != "" {
		if err := runSignalCommand(f.signalCmd, f.pidFile); err != nil {
			fmt.Fprintln(os.Stderr, "kapkan -s:", err)
			os.Exit(1)
		}
		return
	}

	log := logging.New(f.logFormat, f.logLevel)
	if err := run(f.configPath, f.pidFile, log); err != nil {
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
	printDataplaneWarnings(cfg)
	return 0
}

// printDataplaneWarnings reports the data-plane defects that are legal config
// but cannot be what the operator meant. They do not fail the check — the file
// loads, and the daemon will run it — so the exit code stays 0 and this is
// printed after the OK line.
//
// Today that is exactly one thing: a static rule that can never fire. It is
// worth catching here because here is the only place it can be caught BEFORE
// the traffic it was supposed to filter arrives; once running, the symptom is a
// rule counter that stays at zero, which looks like a quiet day.
func printDataplaneWarnings(cfg *config.Config) {
	if !cfg.DataplaneEnabled() {
		return
	}
	pol, err := dataplane.PolicyFromConfig(cfg)
	if err != nil {
		// Unreachable short of a bug: validate() already accepted every field
		// this parses. Say so rather than swallowing it.
		fmt.Printf("  WARNING: could not analyse the dataplane policy: %v\n", err)
		return
	}
	sh := dataplane.ShadowedStatics(pol)
	if len(sh) == 0 {
		return
	}
	fmt.Printf("  WARNING: %d static rule(s) can never fire (the allowlist is checked first, and\n"+
		"           static rules are first match wins — move the rule above the one that covers\n"+
		"           it, narrow the coverage, or delete it):\n", len(sh))
	for _, s := range sh {
		fmt.Printf("    - %s\n", s)
	}
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
				cfg, err := store.Reload()
				if err != nil {
					log.Error("config reload failed; keeping previous config", "err", err)
					continue
				}
				// State that lives outside this process — the data plane's
				// kernel maps — has to be written, not observed. The API's
				// reload route calls the same hook.
				application.ApplyReload(cfg)
				log.Info("config reloaded")
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
